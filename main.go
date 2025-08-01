package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/dgraph-io/ristretto"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/leonelquinteros/gotext"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	httphelper "github.com/zitadel/oidc/v3/pkg/http"
	"golang.org/x/text/language"
	"golang.org/x/time/rate"
	"gorm.io/gorm"
	"image"
	"image/png"
	"log"
	"lukechampine.com/blake3"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

func DRASL_DEBUG() bool {
	return os.Getenv("DRASL_DEBUG") != ""
}

func DRASL_TEST() bool {
	return os.Getenv("DRASL_TEST") != ""
}

var bodyDump = middleware.BodyDump(func(c echo.Context, reqBody, resBody []byte) {
	fmt.Printf("%s\n", reqBody)
	fmt.Printf("%s\n", resBody)
})

type App struct {
	FrontEndURL              string
	PublicURL                string
	APIURL                   string
	AuthURL                  string
	AccountURL               string
	ServicesURL              string
	SessionURL               string
	AuthlibInjectorURL       string
	DB                       *gorm.DB
	GetURLMutex              *KeyedMutex
	FSMutex                  *KeyedMutex
	RequestCache             *ristretto.Cache
	Config                   *Config
	TransientUsernameRegex   *regexp.Regexp
	ValidPlayerNameRegex     *regexp.Regexp
	Constants                *ConstantsType
	PlayerCertificateKeys    []rsa.PublicKey
	ProfilePropertyKeys      []rsa.PublicKey
	PrivateKey               *rsa.PrivateKey
	PrivateKeyB3Sum256       [256 / 8]byte
	PrivateKeyB3Sum512       [512 / 8]byte
	AEAD                     cipher.AEAD
	VerificationSkinTemplate *image.NRGBA
	OIDCProviderNames        []string
	OIDCProvidersByName      map[string]*OIDCProvider
	OIDCProvidersByIssuer    map[string]*OIDCProvider
	FallbackAPIServers       []FallbackAPIServer
	Locales                  map[language.Tag]*gotext.Locale
	DefaultLocale            *gotext.Locale
	LocaleTags               []language.Tag
}

func LogInfo(args ...any) {
	if !DRASL_TEST() {
		log.Println(args...)
	}
}

func LogError(err error, c *echo.Context) {
	if err != nil && !DRASL_TEST() {
		log.Println("Unexpected error in "+(*c).Request().Method+" "+(*c).Path()+":", err)
	}
}

func (app *App) HandleError(err error, c echo.Context) {
	path_ := c.Request().URL.Path
	var additionalErr error
	switch GetPathType(path_) {
	case PathTypeWeb:
		additionalErr = app.HandleWebError(err, &c)
	case PathTypeAPI:
		additionalErr = app.HandleAPIError(err, &c)
	case PathTypeYggdrasil:
		additionalErr = app.HandleYggdrasilError(err, &c)
	}
	if additionalErr != nil {
		LogError(fmt.Errorf("Additional error while handling an error: %w", additionalErr), &c)
	}
}

func makeRateLimiter(app *App) echo.MiddlewareFunc {
	requestsPerSecond := rate.Limit(app.Config.RateLimit.RequestsPerSecond)
	return middleware.RateLimiterWithConfig(middleware.RateLimiterConfig{
		Skipper: func(c echo.Context) bool {
			path_ := c.Path()
			switch GetPathType(path_) {
			case PathTypeWeb:
				switch path_ {
				case "/",
					"/web/create-player",
					"/web/delete-user",
					"/web/delete-player",
					"/web/login",
					"/web/logout",
					"/web/register",
					"/web/update-user",
					"/web/update-player":
					return false
				default:
					return true
				}
			case PathTypeAPI:
				// Skip rate-limiting API requests if they are an admin. TODO:
				// this checks the database twice: once here, and once in
				// withAPIToken. A better way might be to use echo middleware
				// for API authentication and run the authentication middleware
				// before the rate-limiting middleware.
				maybeUser, err := app.APIRequestToMaybeUser(c)
				if user, ok := maybeUser.Get(); err == nil && ok {
					return user.IsAdmin
				}
				return false
			default:
				return true
			}
		},
		// TODO write an IdentifierExtractor per authlib-injector spec "Limits should be placed on users, not client IPs"
		Store: middleware.NewRateLimiterMemoryStore(requestsPerSecond),
		DenyHandler: func(c echo.Context, identifier string, err error) error {
			return NewUserErrorWithCode(http.StatusTooManyRequests, "Too many requests. Try again later.")
		},
	})
}

func (app *App) MakeServer() *echo.Echo {
	e := echo.New()
	e.HideBanner = true
	e.HidePort = DRASL_TEST()
	e.HTTPErrorHandler = app.HandleError

	e.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			c.Response().Header().Set("X-Authlib-Injector-API-Location", app.AuthlibInjectorURL)
			return next(c)
		}
	})
	if app.Config.LogRequests {
		e.Use(middleware.Logger())
	}
	if DRASL_DEBUG() {
		e.Use(bodyDump)
	}
	if app.Config.RateLimit.Enable {
		e.Use(makeRateLimiter(app))
	}
	if app.Config.BodyLimit.Enable {
		limit := fmt.Sprintf("%dKIB", app.Config.BodyLimit.SizeLimitKiB)
		e.Use(middleware.BodyLimit(limit))
	}

	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: []string{"*"},
		Skipper: func(c echo.Context) bool {
			return !Contains([]string{
				DRASL_API_PREFIX + "/swagger.json",
				DRASL_API_PREFIX + "/openapi.json",
			}, c.Path()) && !strings.HasPrefix(c.Path(), "/web/texture/")
		},
	}))

	if len(app.Config.CORSAllowOrigins) > 0 {
		e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
			AllowOrigins: app.Config.CORSAllowOrigins,
			Skipper: func(c echo.Context) bool {
				return GetPathType(c.Path()) != PathTypeAPI
			},
		}))
	}

	e.Use(app.GetLanguageMiddleware())

	// Front
	if app.Config.EnableWebFrontEnd {
		t := NewTemplate(app)
		e.Renderer = t
		frontUser := FrontUser(app)

		e.GET("/", FrontRoot(app))
		g := e.Group("/web")
		g.GET("/admin", FrontAdmin(app))
		g.GET("/complete-registration", FrontCompleteRegistration(app))
		g.GET("/create-player-challenge", FrontCreatePlayerChallenge(app))
		g.GET("/manifest.webmanifest", FrontWebManifest(app))
		g.GET("/oidc-callback/:providerName", FrontOIDCCallback(app))
		g.GET("/player/:uuid", FrontPlayer(app))
		g.GET("/register-challenge", FrontRegisterChallenge(app))
		g.GET("/registration", FrontRegistration(app))
		g.GET("/user", frontUser)
		g.GET("/user/:uuid", frontUser)
		g.POST("/admin/delete-invite", FrontDeleteInvite(app))
		g.POST("/admin/new-invite", FrontNewInvite(app))
		g.POST("/admin/update-users", FrontUpdateUsers(app))
		g.POST("/create-player", FrontCreatePlayer(app))
		g.POST("/delete-player", FrontDeletePlayer(app))
		g.POST("/delete-user", FrontDeleteUser(app))
		g.POST("/login", FrontLogin(app))
		g.POST("/logout", FrontLogout(app))
		g.POST("/oidc-migrate", app.FrontOIDCMigrate())
		g.POST("/oidc-unlink", app.FrontOIDCUnlink())
		g.POST("/register", FrontRegister(app))
		g.POST("/update-player", FrontUpdatePlayer(app))
		g.POST("/update-user", FrontUpdateUser(app))
		g.Static("/public", path.Join(app.Config.DataDirectory, "public"))
	}
	e.Static("/web/texture/cape", path.Join(app.Config.StateDirectory, "cape"))
	e.Static("/web/texture/default-cape", path.Join(app.Config.StateDirectory, "default-cape"))
	e.Static("/web/texture/default-skin", path.Join(app.Config.StateDirectory, "default-skin"))
	e.Static("/web/texture/skin", path.Join(app.Config.StateDirectory, "skin"))

	// Drasl API
	apiSwagger := app.APISwagger()
	e.GET(DRASL_API_PREFIX+"/swagger.json", apiSwagger)
	e.GET(DRASL_API_PREFIX+"/openapi.json", apiSwagger)

	apiDeleteUser := app.APIDeleteUser()
	e.DELETE(DRASL_API_PREFIX+"/invites/:code", app.APIDeleteInvite())
	e.DELETE(DRASL_API_PREFIX+"/players/:uuid", app.APIDeletePlayer())
	e.DELETE(DRASL_API_PREFIX+"/user", apiDeleteUser)
	e.DELETE(DRASL_API_PREFIX+"/user/oidc-identities", app.APIDeleteOIDCIdentity())
	e.DELETE(DRASL_API_PREFIX+"/users/:uuid", apiDeleteUser)
	e.DELETE(DRASL_API_PREFIX+"/users/:uuid/oidc-identities", app.APIDeleteOIDCIdentity())

	apiGetUser := app.APIGetUser()
	e.GET(DRASL_API_PREFIX+"/challenge-skin", app.APIGetChallengeSkin())
	e.GET(DRASL_API_PREFIX+"/invites", app.APIGetInvites())
	e.GET(DRASL_API_PREFIX+"/players", app.APIGetPlayers())
	e.GET(DRASL_API_PREFIX+"/players/:uuid", app.APIGetPlayer())
	e.GET(DRASL_API_PREFIX+"/user", apiGetUser)
	e.GET(DRASL_API_PREFIX+"/users", app.APIGetUsers())
	e.GET(DRASL_API_PREFIX+"/users/:uuid", apiGetUser)

	apiUpdateUser := app.APIUpdateUser()
	e.PATCH(DRASL_API_PREFIX+"/players/:uuid", app.APIUpdatePlayer())
	e.PATCH(DRASL_API_PREFIX+"/user", apiUpdateUser)
	e.PATCH(DRASL_API_PREFIX+"/users/:uuid", apiUpdateUser)

	apiCreateOIDCIdentity := app.APICreateOIDCIdentity()
	e.POST(DRASL_API_PREFIX+"/invites", app.APICreateInvite())
	e.POST(DRASL_API_PREFIX+"/login", app.APILogin())
	e.POST(DRASL_API_PREFIX+"/players", app.APICreatePlayer())
	e.POST(DRASL_API_PREFIX+"/user/oidc-identities", apiCreateOIDCIdentity)
	e.POST(DRASL_API_PREFIX+"/users", app.APICreateUser())
	e.POST(DRASL_API_PREFIX+"/users/:uuid/oidc-identities", apiCreateOIDCIdentity)

	// authlib-injector
	e.GET("/authlib-injector", AuthlibInjectorRoot(app))
	e.GET("/authlib-injector/", AuthlibInjectorRoot(app))
	e.PUT("/authlib-injector/api/user/profile/:id/skin", app.AuthlibInjectorUploadTexture(TextureTypeSkin))
	e.PUT("/authlib-injector/api/user/profile/:id/cape", app.AuthlibInjectorUploadTexture(TextureTypeCape))
	e.DELETE("/authlib-injector/api/user/profile/:id/skin", app.AuthlibInjectorDeleteTexture(TextureTypeSkin))
	e.DELETE("/authlib-injector/api/user/profile/:id/cape", app.AuthlibInjectorDeleteTexture(TextureTypeCape))

	// Auth
	authAuthenticate := AuthAuthenticate(app)
	authInvalidate := AuthInvalidate(app)
	authRefresh := AuthRefresh(app)
	authSignout := AuthSignout(app)
	authValidate := AuthValidate(app)

	e.POST("/authenticate", authAuthenticate)
	e.POST("/invalidate", authInvalidate)
	e.POST("/refresh", authRefresh)
	e.POST("/signout", authSignout)
	e.POST("/validate", authValidate)

	e.GET("/auth", AuthServerInfo(app))
	e.POST("/auth/authenticate", authAuthenticate)
	e.POST("/auth/invalidate", authInvalidate)
	e.POST("/auth/refresh", authRefresh)
	e.POST("/auth/signout", authSignout)
	e.POST("/auth/validate", authValidate)

	e.GET("/authlib-injector/authserver", AuthServerInfo(app))
	e.POST("/authlib-injector/authserver/authenticate", authAuthenticate)
	e.POST("/authlib-injector/authserver/invalidate", authInvalidate)
	e.POST("/authlib-injector/authserver/refresh", authRefresh)
	e.POST("/authlib-injector/authserver/signout", authSignout)
	e.POST("/authlib-injector/authserver/validate", authValidate)

	// Account
	accountVerifySecurityLocation := AccountVerifySecurityLocation(app)
	accountPlayerNameToID := AccountPlayerNameToID(app)
	accountPlayerNamesToIDs := AccountPlayerNamesToIDs(app)

	e.GET("/user/security/location", accountVerifySecurityLocation)
	e.GET("/users/profiles/minecraft/:playerName", accountPlayerNameToID)
	e.POST("/profiles/minecraft", accountPlayerNamesToIDs)

	e.GET("/account/user/security/location", accountVerifySecurityLocation)
	e.GET("/account/users/profiles/minecraft/:playerName", accountPlayerNameToID)
	e.POST("/account/profiles/minecraft", accountPlayerNamesToIDs)

	e.GET("/authlib-injector/api/user/security/location", accountVerifySecurityLocation)
	e.GET("/authlib-injector/api/users/profiles/minecraft/:playerName", accountPlayerNameToID)
	e.POST("/authlib-injector/api/profiles/minecraft", accountPlayerNamesToIDs)

	// Session
	sessionHasJoined := SessionHasJoined(app)
	sessionCheckServer := SessionCheckServer(app)
	sessionJoin := SessionJoin(app)
	sessionJoinServer := SessionJoinServer(app)
	sessionProfile := SessionProfile(app, false)
	sessionBlockedServers := SessionBlockedServers(app)
	e.GET("/session/minecraft/hasJoined", sessionHasJoined)
	e.GET("/game/checkserver.jsp", sessionCheckServer)
	e.POST("/session/minecraft/join", sessionJoin)
	e.GET("/game/joinserver.jsp", sessionJoinServer)
	e.GET("/session/minecraft/profile/:id", sessionProfile)
	e.GET("/blockedservers", sessionBlockedServers)

	e.GET("/session/session/minecraft/hasJoined", sessionHasJoined)
	e.GET("/session/game/checkserver.jsp", sessionCheckServer)
	e.POST("/session/session/minecraft/join", sessionJoin)
	e.GET("/session/game/joinserver.jsp", sessionJoinServer)
	e.GET("/session/session/minecraft/profile/:id", sessionProfile)
	e.GET("/session/blockedservers", sessionBlockedServers)

	e.GET("/authlib-injector/sessionserver/session/minecraft/hasJoined", sessionHasJoined)
	e.GET("/authlib-injector/sessionserver/game/checkserver.jsp", sessionCheckServer)
	e.POST("/authlib-injector/sessionserver/session/minecraft/join", sessionJoin)
	e.GET("/authlib-injector/sessionserver/game/joinserver.jsp", sessionJoinServer)
	e.GET("/authlib-injector/sessionserver/session/minecraft/profile/:id", SessionProfile(app, true))
	e.GET("/authlib-injector/sessionserver/blockedservers", sessionBlockedServers)

	// Services
	servicesPlayerAttributes := ServicesPlayerAttributes(app)
	servicesPlayerCertificates := ServicesPlayerCertificates(app)
	servicesDeleteCape := ServicesHideCape(app)
	servicesDeleteSkin := ServicesResetSkin(app)
	servicesProfileInformation := ServicesProfileInformation(app)
	servicesNameAvailability := ServicesNameAvailability(app)
	servicesNameChange := ServicesNameChange(app)
	servicesBlocklist := ServicesBlocklist(app)
	servicesMSAMigration := ServicesMSAMigration(app)
	servicesUploadSkin := ServicesUploadSkin(app)
	servicesChangeName := ServicesChangeName(app)
	servicesPublicKeys := ServicesPublicKeys(app)
	servicesIDToPlayerName := app.ServicesIDToPlayerName()

	e.GET("/privileges", servicesPlayerAttributes)
	e.GET("/player/attributes", servicesPlayerAttributes)
	e.POST("/player/certificates", servicesPlayerCertificates)
	e.DELETE("/minecraft/profile/capes/active", servicesDeleteCape)
	e.DELETE("/minecraft/profile/skins/active", servicesDeleteSkin)
	e.GET("/minecraft/profile", servicesProfileInformation)
	e.GET("/minecraft/profile/name/:playerName/available", servicesNameAvailability)
	e.GET("/minecraft/profile/namechange", servicesNameChange)
	e.GET("/privacy/blocklist", servicesBlocklist)
	e.GET("/rollout/v1/msamigration", servicesMSAMigration)
	e.POST("/minecraft/profile/skins", servicesUploadSkin)
	e.PUT("/minecraft/profile/name/:playerName", servicesChangeName)
	e.GET("/publickeys", servicesPublicKeys)
	e.GET("/minecraft/profile/lookup/:id", servicesIDToPlayerName)
	e.GET("/minecraft/profile/lookup/name/:playerName", accountPlayerNameToID)
	e.POST("/minecraft/profile/lookup/bulk/byname", accountPlayerNamesToIDs)

	e.GET("/services/privileges", servicesPlayerAttributes)
	e.GET("/services/player/attributes", servicesPlayerAttributes)
	e.POST("/services/player/certificates", servicesPlayerCertificates)
	e.DELETE("/services/minecraft/profile/capes/active", servicesDeleteCape)
	e.DELETE("/services/minecraft/profile/skins/active", servicesDeleteSkin)
	e.GET("/services/minecraft/profile", servicesProfileInformation)
	e.GET("/services/minecraft/profile/name/:playerName/available", servicesNameAvailability)
	e.GET("/services/minecraft/profile/namechange", servicesNameChange)
	e.GET("/services/privacy/blocklist", servicesBlocklist)
	e.GET("/services/rollout/v1/msamigration", servicesMSAMigration)
	e.POST("/services/minecraft/profile/skins", servicesUploadSkin)
	e.PUT("/services/minecraft/profile/name/:playerName", servicesChangeName)
	e.GET("/services/publickeys", servicesPublicKeys)
	e.GET("/services/minecraft/profile/lookup/:id", servicesIDToPlayerName)
	e.GET("/services/minecraft/profile/lookup/name/:playerName", accountPlayerNameToID)
	e.POST("/services/minecraft/profile/lookup/bulk/byname", accountPlayerNamesToIDs)

	e.GET("/authlib-injector/minecraftservices/privileges", servicesPlayerAttributes)
	e.GET("/authlib-injector/minecraftservices/player/attributes", servicesPlayerAttributes)
	e.POST("/authlib-injector/minecraftservices/player/certificates", servicesPlayerCertificates)
	e.DELETE("/authlib-injector/minecraftservices/minecraft/profile/capes/active", servicesDeleteCape)
	e.DELETE("/authlib-injector/minecraftservices/minecraft/profile/skins/active", servicesDeleteSkin)
	e.GET("/authlib-injector/minecraftservices/minecraft/profile", servicesProfileInformation)
	e.GET("/authlib-injector/minecraftservices/minecraft/profile/name/:playerName/available", servicesNameAvailability)
	e.GET("/authlib-injector/minecraftservices/minecraft/profile/namechange", servicesNameChange)
	e.GET("/authlib-injector/minecraftservices/privacy/blocklist", servicesBlocklist)
	e.GET("/authlib-injector/minecraftservices/rollout/v1/msamigration", servicesMSAMigration)
	e.POST("/authlib-injector/minecraftservices/minecraft/profile/skins", servicesUploadSkin)
	e.PUT("/authlib-injector/minecraftservices/minecraft/profile/name/:playerName", servicesChangeName)
	e.GET("/authlib-injector/minecraftservices/publickeys", servicesPublicKeys)
	e.GET("/authlib-injector/minecraftservices/minecraft/profile/lookup/:id", servicesIDToPlayerName)
	e.GET("/authlib-injector/minecraftservices/minecraft/profile/lookup/name/:playerName", accountPlayerNameToID)
	e.POST("/authlib-injector/minecraftservices/minecraft/profile/lookup/bulk/byname", accountPlayerNamesToIDs)

	return e
}

func setup(config *Config) *App {
	_, err := os.Stat(config.StateDirectory)
	if err != nil {
		if os.IsNotExist(err) {
			log.Println("StateDirectory", config.StateDirectory, "does not exist, creating it.")
			err = os.MkdirAll(config.StateDirectory, 0700)
			Check(err)
		} else {
			log.Fatalf("Couldn't access StateDirectory %s: %s", config.StateDirectory, err)
		}
	}
	if _, err := os.Open(config.DataDirectory); err != nil {
		log.Fatalf("Couldn't access DataDirectory: %s", err)
	}

	// Locales
	locales := map[language.Tag]*gotext.Locale{}
	localeTags := make([]language.Tag, 0)
	localesPath := path.Join(config.DataDirectory, "locales")
	langPaths := Unwrap(filepath.Glob(path.Join(localesPath, "*")))
	defaultLang := "en-US" // TODO config option?
	var defaultLocale *gotext.Locale
	for _, lang_path := range langPaths {
		lang := filepath.Base(lang_path)
		tag, err := language.Parse(lang)
		if err != nil {
			log.Fatalf("Unrecognized language tag: %s", lang)
		}
		l := gotext.NewLocale(localesPath, lang)
		l.AddDomain("default")
		localeTags = append(localeTags, tag)
		locales[tag] = l
		if lang == defaultLang {
			defaultLocale = l
		}
	}

	// Crypto
	key := ReadOrCreateKey(config)
	keyBytes := Unwrap(x509.MarshalPKCS8PrivateKey(key))
	keyB3Sum256 := blake3.Sum256(keyBytes)
	keyB3Sum512 := blake3.Sum512(keyBytes)
	block, err := aes.NewCipher(keyB3Sum256[:])
	Check(err)
	aead, err := cipher.NewGCM(block)
	Check(err)

	// Database
	db, err := OpenDB(config)
	Check(err)

	// https://pkg.go.dev/github.com/dgraph-io/ristretto#readme-config
	cache := Unwrap(ristretto.NewCache(&config.RequestCache))

	// Precompile regexes
	var transientUsernameRegex *regexp.Regexp
	if config.TransientUsers.Allow {
		transientUsernameRegex = regexp.MustCompile(config.TransientUsers.UsernameRegex)
	}
	validPlayerNameRegex := regexp.MustCompile(config.ValidPlayerNameRegex)

	// Verification skin
	verificationSkinPath := path.Join(config.DataDirectory, "assets", "verification-skin.png")
	verificationSkinFile := Unwrap(os.Open(verificationSkinPath))
	verificationRGBA := Unwrap(png.Decode(verificationSkinFile))
	verificationSkinTemplate, ok := verificationRGBA.(*image.NRGBA)
	if !ok {
		log.Fatal("Invalid verification skin!")
	}

	// Keys, FallbackAPIServers
	fallbackAPIServers := make([]FallbackAPIServer, 0, len(config.FallbackAPIServers))
	playerCertificateKeys := make([]rsa.PublicKey, 0, 1)
	profilePropertyKeys := make([]rsa.PublicKey, 0, 1)
	profilePropertyKeys = append(profilePropertyKeys, key.PublicKey)
	playerCertificateKeys = append(playerCertificateKeys, key.PublicKey)

	for _, fallbackAPIServerConfig := range config.FallbackAPIServers {
		fallbackAPIServer := Unwrap(NewFallbackAPIServer(&fallbackAPIServerConfig))
		fallbackAPIServers = append(fallbackAPIServers, fallbackAPIServer)

		reqURL := Unwrap(url.JoinPath(fallbackAPIServerConfig.ServicesURL, "publickeys"))
		res, err := MakeHTTPClient().Get(reqURL)
		if err != nil {
			log.Printf("Couldn't access fallback API server at %s: %s\n", reqURL, err)
			continue
		}
		defer res.Body.Close()

		if res.StatusCode != http.StatusOK {
			log.Printf("Request to fallback API server at %s resulted in status code %d\n", reqURL, res.StatusCode)
			continue
		}

		var publicKeysRes PublicKeysResponse
		err = json.NewDecoder(res.Body).Decode(&publicKeysRes)
		if err != nil {
			log.Printf("Received invalid response from fallback API server at %s\n", reqURL)
			continue
		}

		for _, serializedKey := range publicKeysRes.ProfilePropertyKeys {
			publicKey, err := SerializedKeyToPublicKey(serializedKey)
			if err != nil {
				log.Printf("Received invalid profile property key from fallback API server at %s: %s\n", reqURL, err)
				continue
			}
			if !ContainsPublicKey(profilePropertyKeys, publicKey) {
				profilePropertyKeys = append(profilePropertyKeys, *publicKey)
			}
		}
		for _, serializedKey := range publicKeysRes.PlayerCertificateKeys {
			publicKey, err := SerializedKeyToPublicKey(serializedKey)
			if err != nil {
				log.Printf("Received invalid player certificate key from fallback API server at %s: %s\n", reqURL, err)
				continue
			}
			if !ContainsPublicKey(playerCertificateKeys, publicKey) {
				playerCertificateKeys = append(playerCertificateKeys, *publicKey)
			}
		}
		log.Printf("Fetched public keys from fallback API server %s", fallbackAPIServerConfig.Nickname)
	}

	// OIDC providers
	oidcProviderNames := make([]string, 0, len(config.RegistrationOIDC))
	oidcProvidersByName := map[string]*OIDCProvider{}
	oidcProvidersByIssuer := map[string]*OIDCProvider{}
	scopes := []string{"openid", "email"}
	for _, oidcConfig := range config.RegistrationOIDC {
		options := []rp.Option{
			rp.WithVerifierOpts(rp.WithIssuedAtOffset(1 * time.Minute)),
			rp.WithHTTPClient(MakeHTTPClient()),
			rp.WithSigningAlgsFromDiscovery(),
		}
		escapedProviderName := url.PathEscape(oidcConfig.Name)
		redirectURI, err := url.JoinPath(config.BaseURL, "web", "oidc-callback", escapedProviderName)
		if err != nil {
			log.Fatalf("Error creating OIDC redirect URI: %s", err)
		}
		if oidcConfig.PKCE {
			cookieHandler := httphelper.NewCookieHandler(keyB3Sum256[:], keyB3Sum256[:], httphelper.WithSameSite(http.SameSiteLaxMode))
			options = append(options, rp.WithPKCE(cookieHandler))
		}
		relyingParty, err := rp.NewRelyingPartyOIDC(context.Background(), oidcConfig.Issuer, oidcConfig.ClientID, oidcConfig.ClientSecret, redirectURI, scopes, options...)
		if err != nil {
			log.Fatalf("Error creating OIDC relying party: %s", err)
		}

		oidcProvider := OIDCProvider{
			RelyingParty: relyingParty,
			Config:       oidcConfig,
		}

		oidcProviderNames = append(oidcProviderNames, oidcConfig.Name)
		oidcProvidersByName[oidcConfig.Name] = &oidcProvider
		oidcProvidersByIssuer[oidcConfig.Issuer] = &oidcProvider
	}

	app := &App{
		RequestCache:             cache,
		Config:                   config,
		TransientUsernameRegex:   transientUsernameRegex,
		ValidPlayerNameRegex:     validPlayerNameRegex,
		Constants:                Constants,
		DB:                       db,
		FSMutex:                  &KeyedMutex{},
		GetURLMutex:              &KeyedMutex{},
		PrivateKey:               key,
		PrivateKeyB3Sum256:       keyB3Sum256,
		PrivateKeyB3Sum512:       keyB3Sum512,
		AEAD:                     aead,
		FrontEndURL:              config.BaseURL,
		PublicURL:                Unwrap(url.JoinPath(config.BaseURL, "web/public")),
		PlayerCertificateKeys:    playerCertificateKeys,
		ProfilePropertyKeys:      profilePropertyKeys,
		AccountURL:               Unwrap(url.JoinPath(config.BaseURL, "account")),
		AuthURL:                  Unwrap(url.JoinPath(config.BaseURL, "auth")),
		ServicesURL:              Unwrap(url.JoinPath(config.BaseURL, "services")),
		SessionURL:               Unwrap(url.JoinPath(config.BaseURL, "session")),
		AuthlibInjectorURL:       Unwrap(url.JoinPath(config.BaseURL, "authlib-injector")),
		APIURL:                   Unwrap(url.JoinPath(config.BaseURL, DRASL_API_PREFIX)),
		VerificationSkinTemplate: verificationSkinTemplate,
		OIDCProviderNames:        oidcProviderNames,
		OIDCProvidersByName:      oidcProvidersByName,
		OIDCProvidersByIssuer:    oidcProvidersByIssuer,
		FallbackAPIServers:       fallbackAPIServers,
		Locales:                  locales,
		DefaultLocale:            defaultLocale,
		LocaleTags:               localeTags,
	}

	// Post-setup

	// Make sure all DefaultAdmins are admins
	err = app.DB.Table("users").Where("username in (?)", config.DefaultAdmins).Updates(map[string]any{"is_admin": true}).Error
	Check(err)

	// Print an initial invite link if necessary
	if !DRASL_TEST() {
		newPlayerInvite := app.Config.RegistrationNewPlayer.Allow && config.RegistrationNewPlayer.RequireInvite
		existingPlayerInvite := app.Config.RegistrationExistingPlayer.Allow && config.RegistrationExistingPlayer.RequireInvite
		if newPlayerInvite || existingPlayerInvite {
			var count int64
			Check(app.DB.Model(&User{}).Count(&count).Error)
			if count == 0 {
				// No users, print an initial invite link to the console
				var invite Invite
				result := app.DB.First(&invite)
				if result.Error != nil {
					if errors.Is(result.Error, gorm.ErrRecordNotFound) {
						// No invites yet, so create one
						invite, err = app.CreateInvite()
						Check(err)
					} else {
						log.Fatal(result.Error)
					}
				}
				if app.Config.EnableWebFrontEnd {
					log.Println("No users found! Here's an invite URL:", Unwrap(app.InviteURL(&invite)))
				} else {
					log.Println("No users found! Here's an invite code:", invite.Code)
				}
			}
		}
	}

	return app
}

func (app *App) Run() {
	for _, fallbackAPIServer := range PtrSlice(app.FallbackAPIServers) {
		go app.PlayerNamesToIDsWorker(fallbackAPIServer)
	}
}

func main() {
	defaultConfigPath := path.Join(Constants.ConfigDirectory, "config.toml")

	configPath := flag.String("config", defaultConfigPath, "Path to config file")
	help := flag.Bool("help", false, "Show help message")
	flag.Parse()

	if *help {
		fmt.Println("Usage: drasl [options]")
		fmt.Println("Options:")
		flag.PrintDefaults()
		os.Exit(0)
	}

	config, _, err := ReadConfig(*configPath, true)
	if err != nil {
		log.Fatalf("Error in config: %s", err)
	}
	app := setup(&config)
	go app.Run()
	Check(app.MakeServer().Start(app.Config.ListenAddress))
}
