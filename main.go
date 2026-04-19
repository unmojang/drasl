package main

import (
	"container/list"
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
	"github.com/labstack/echo/v5"
	"github.com/labstack/echo/v5/middleware"
	"github.com/leonelquinteros/gotext"
	"github.com/samber/mo"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	httphelper "github.com/zitadel/oidc/v3/pkg/http"
	"golang.org/x/text/language"
	"gorm.io/gorm"
	"image"
	"image/png"
	"log"
	"lukechampine.com/blake3"
	"math"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

func DRASL_DEBUG() bool {
	return os.Getenv("DRASL_DEBUG") != ""
}

func DRASL_TEST() bool {
	return os.Getenv("DRASL_TEST") != ""
}

var bodyDump = middleware.BodyDump(func(c *echo.Context, reqBody []byte, resBody []byte, err error) {
	fmt.Printf("%s\n", reqBody)
	fmt.Printf("%s\n", resBody)
})

type App struct {
	BasePath                 string
	FrontEndURL              string
	FrontEndURLNoProto       string
	PublicURL                string
	PublicURLNoProto         string
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
	HeartbeatLruList         *list.List
	HeartbeatMutex           sync.RWMutex
	HeartbeatSaltMap         map[ServerKey]heartbeatSaltEntry
}

func LogInfo(args ...any) {
	if !DRASL_TEST() {
		log.Println(args...)
	}
}

func LogError(err error, c *echo.Context) {
	if err != nil && !DRASL_TEST() {
		log.Println("Unexpected error in "+(*c).Request().Method+" "+(*c).Request().URL.String()+":", err)
	}
}

func (app *App) HandleError(c *echo.Context, err error) {
	if resp, uErr := echo.UnwrapResponse(c.Response()); uErr == nil {
		if resp.Committed {
			return // response has been already sent to the client by handler or some middleware
		}
	}

	var additionalErr error

	baseRelative, baseRelativeErr := app.BaseRelativePath(c.Request().URL.Path)
	if baseRelativeErr == nil {
		switch app.GetPathType(baseRelative) {
		case PathTypeWeb:
			additionalErr = app.HandleWebError(err, c)
		case PathTypeAPI:
			additionalErr = app.HandleAPIError(err, c)
		case PathTypeYggdrasil:
			additionalErr = app.HandleYggdrasilError(err, c)
		}
	} else {
		if app.Config.EnableWebFrontEnd {
			additionalErr = app.HandleWebError(err, c)
		} else {
			additionalErr = app.HandleYggdrasilError(err, c)
		}
	}

	if additionalErr != nil {
		LogError(fmt.Errorf("Additional error while handling an error: %w", additionalErr), c)
	}
}

func (app *App) makeRateLimiter() echo.MiddlewareFunc {
	effectiveBurst := app.Config.RateLimit.Burst
	if app.Config.RateLimit.Burst == 0 {
		effectiveBurst = int(math.Max(1.0, math.Ceil(float64(app.Config.RateLimit.RequestsPerSecond))))
	}
	expiresIn := time.Duration(float64(effectiveBurst) / app.Config.RateLimit.RequestsPerSecond * float64(time.Second))

	return middleware.RateLimiterWithConfig(middleware.RateLimiterConfig{
		Skipper: func(c *echo.Context) bool {
			if !app.Config.RateLimit.Enable {
				return true
			}
			maybeUser, ok := c.Get(CONTEXT_KEY_MAYBE_USER).(mo.Option[User])
			if ok {
				if user, userOk := maybeUser.Get(); userOk {
					// Skip rate limiting if user is an admin
					return user.IsAdmin
				}
			}
			return false
		},
		IdentifierExtractor: func(c *echo.Context) (string, error) {
			// Per authlib-injector spec "Limits should be placed on users, not client IPs"
			maybeUser, ok := c.Get(CONTEXT_KEY_MAYBE_USER).(mo.Option[User])
			if ok {
				if user, userOk := maybeUser.Get(); userOk {
					return user.UUID, nil
				}
			}
			return c.RealIP(), nil
		},
		Store: middleware.NewRateLimiterMemoryStoreWithConfig(middleware.RateLimiterMemoryStoreConfig{
			Rate:      app.Config.RateLimit.RequestsPerSecond,
			Burst:     app.Config.RateLimit.Burst,
			ExpiresIn: expiresIn,
		}),
		DenyHandler: func(c *echo.Context, identifier string, err error) error {
			return &StatusError{UserError{Code: mo.Some(http.StatusTooManyRequests), Message: "Too many requests. Try again later."}}
		},
	})
}

func (app *App) MakeServer() *echo.Echo {
	e := echo.New()
	e.HTTPErrorHandler = app.HandleError
	e.Pre(middleware.RemoveTrailingSlash())

	e.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			val := app.AuthlibInjectorURL

			// Rewrite URL scheme to HTTP if being requested over it
			if u, err := url.Parse(val); err == nil && app.requestIsHTTP(c) && u.Scheme == "https" {
				u.Scheme = "http"
				val = u.String()
			}

			c.Response().Header().Set("X-Authlib-Injector-API-Location", val)
			return next(c)
		}
	})

	if app.Config.LogRequests {
		e.Use(middleware.RequestLogger())
	}
	if DRASL_DEBUG() {
		e.Use(bodyDump)
	}
	if app.Config.BodyLimit.Enable {
		e.Use(middleware.BodyLimit(1024 * app.Config.BodyLimit.SizeLimitKiB))
	}

	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: []string{"*"},
		Skipper: func(c *echo.Context) bool {
			baseRelative, err := app.BaseRelativePath(c.Path())
			if err != nil {
				return true
			}
			return !Contains([]string{
				DRASL_API_PREFIX + "/swagger.json",
				DRASL_API_PREFIX + "/openapi.json",
			}, baseRelative) && !strings.HasPrefix(baseRelative, "/web/texture/")
		},
	}))

	if len(app.Config.CORSAllowOrigins) > 0 {
		e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
			AllowOrigins: app.Config.CORSAllowOrigins,
			Skipper: func(c *echo.Context) bool {
				baseRelative, err := app.BaseRelativePath(c.Path())
				if err != nil {
					return true
				}
				return app.GetPathType(baseRelative) != PathTypeAPI
			},
		}))
	}

	e.Use(app.GetLanguageMiddleware())

	base := e.Group(app.BasePath)

	// Where applicable, rate limiting is done after token authentication, so we can rate limit individual users rather than IP addresses. Caveat: this means that hitting endpoints with an invalid browser token/accessToken/API token is effectively rate-unlimited. For us, authentication requires a database query; we trade off performance and statelessness for long-lived tokens with immediate revocation.
	rateLimiter := app.makeRateLimiter()

	// Used for routes where rate limiting should always be applied by RealIP, not by user
	rateLimitedUnauthenticated := base.Group("", rateLimiter)

	// Used by services and authlib-injector routes
	bearerRequireAuthentication := e.Group("", app.BearerRequireAuthentication(), rateLimiter)

	static := func(pathPrefix string, fsRoot string) {
		subFs := echo.MustSubFS(e.Filesystem, fsRoot)
		staticDirectoryHandler := echo.StaticDirectoryHandler(subFs, false)
		base.Add(
			http.MethodGet,
			pathPrefix+"*",
			staticDirectoryHandler,
		)
		base.Add(
			http.MethodHead,
			pathPrefix+"*",
			staticDirectoryHandler,
		)
	}

	// Front
	if app.Config.EnableWebFrontEnd {
		t := NewTemplate(app)
		e.Renderer = t
		frontUser := FrontUser(app)

		// Redirect / to base, rate-unlimited
		e.GET("/", func(c *echo.Context) error {
			return c.Redirect(http.StatusSeeOther, app.FrontEndURL)
		})

		// /web/public is rate-unlimited
		static("/web/public", path.Join(app.Config.DataDirectory, "public"))

		// Everything else is authenticated and rate limited
		web := base.Group("", app.BrowserAuthentication(), rateLimiter)
		requireAuthentication := web.Group("", app.BrowserRequireAuthentication())
		requireAdmin := requireAuthentication.Group("", app.BrowserRequireAdmin())

		requireAdmin.GET("/web/admin", FrontAdmin(app))
		requireAdmin.GET("/web/user/:uuid", frontUser)
		requireAdmin.POST("/web/admin/delete-invite", FrontDeleteInvite(app))
		requireAdmin.POST("/web/admin/new-invite", FrontNewInvite(app))
		requireAdmin.POST("/web/admin/update-users", FrontUpdateUsers(app))
		requireAuthentication.GET("/web/player/:uuid", FrontPlayer(app))
		requireAuthentication.GET("/web/user", frontUser)
		requireAuthentication.POST("/web/create-player", FrontCreatePlayer(app))
		requireAuthentication.POST("/web/delete-player", FrontDeletePlayer(app))
		requireAuthentication.POST("/web/delete-user", FrontDeleteUser(app))
		requireAuthentication.POST("/web/logout", FrontLogout(app))
		requireAuthentication.POST("/web/oidc-unlink", app.FrontOIDCUnlink())
		requireAuthentication.POST("/web/update-player", FrontUpdatePlayer(app))
		requireAuthentication.POST("/web/update-user", FrontUpdateUser(app))
		web.GET("", FrontRoot(app))
		web.GET("/web/complete-registration", FrontCompleteRegistration(app))
		web.GET("/web/create-player-challenge", FrontCreatePlayerChallenge(app))
		web.GET("/web/manifest.webmanifest", FrontWebManifest(app))
		web.GET("/web/oidc-callback/:providerName", FrontOIDCCallback(app))
		web.GET("/web/register-challenge", FrontRegisterChallenge(app))
		web.GET("/web/registration", FrontRegistration(app))
		web.POST("/web/login", FrontLogin(app))
		web.POST("/web/oidc-migrate", app.FrontOIDCMigrate())
		web.POST("/web/register", FrontRegister(app))
	}

	// Textures are rate-unlimited
	static("/web/texture/cape", path.Join(app.Config.StateDirectory, "cape"))
	static("/web/texture/default-cape", path.Join(app.Config.StateDirectory, "default-cape"))
	static("/web/texture/default-skin", path.Join(app.Config.StateDirectory, "default-skin"))
	static("/web/texture/skin", path.Join(app.Config.StateDirectory, "skin"))

	// Drasl API
	{
		apiSwagger := app.APISwagger()
		apiUpdateUser := app.APIUpdateUser()
		apiDeleteUser := app.APIDeleteUser()
		apiDeleteOIDCIdentity := app.APIDeleteOIDCIdentity()
		apiGetUser := app.APIGetUser()
		apiCreateOIDCIdentity := app.APICreateOIDCIdentity()

		// OpenAPI docs are rate-unlimited
		base.GET(DRASL_API_PREFIX+"/swagger.json", apiSwagger)
		base.GET(DRASL_API_PREFIX+"/openapi.json", apiSwagger)

		// Everything else is authenticated and rate limited
		draslAPI := e.Group("", app.APITokenAuthentication(), rateLimiter)
		requireAuthentication := draslAPI.Group("", app.APITokenRequireAuthentication())
		requireAdmin := requireAuthentication.Group("", app.APITokenAdmin())

		draslAPI.GET(DRASL_API_PREFIX+"/challenge-skin", app.APIGetChallengeSkin())
		draslAPI.POST(DRASL_API_PREFIX+"/login", app.APILogin())
		draslAPI.POST(DRASL_API_PREFIX+"/users", app.APICreateUser())

		requireAdmin.DELETE(DRASL_API_PREFIX+"/invites/:code", app.APIDeleteInvite())
		requireAdmin.GET(DRASL_API_PREFIX+"/invites", app.APIGetInvites())
		requireAdmin.GET(DRASL_API_PREFIX+"/players", app.APIGetPlayers())
		requireAdmin.GET(DRASL_API_PREFIX+"/users", app.APIGetUsers())
		requireAdmin.POST(DRASL_API_PREFIX+"/invites", app.APICreateInvite())

		requireAuthentication.DELETE(DRASL_API_PREFIX+"/players/:uuid", app.APIDeletePlayer())
		requireAuthentication.DELETE(DRASL_API_PREFIX+"/user", apiDeleteUser)
		requireAuthentication.DELETE(DRASL_API_PREFIX+"/user/oidc-identities", apiDeleteOIDCIdentity)
		requireAuthentication.DELETE(DRASL_API_PREFIX+"/users/:uuid", apiDeleteUser)
		requireAuthentication.DELETE(DRASL_API_PREFIX+"/users/:uuid/oidc-identities", apiDeleteOIDCIdentity)
		requireAuthentication.GET(DRASL_API_PREFIX+"/players/:uuid", app.APIGetPlayer())
		requireAuthentication.GET(DRASL_API_PREFIX+"/user", apiGetUser)
		requireAuthentication.GET(DRASL_API_PREFIX+"/users/:uuid", apiGetUser)
		requireAuthentication.PATCH(DRASL_API_PREFIX+"/players/:uuid", app.APIUpdatePlayer())
		requireAuthentication.PATCH(DRASL_API_PREFIX+"/user", apiUpdateUser)
		requireAuthentication.PATCH(DRASL_API_PREFIX+"/users/:uuid", apiUpdateUser)
		requireAuthentication.POST(DRASL_API_PREFIX+"/players", app.APICreatePlayer())
		requireAuthentication.POST(DRASL_API_PREFIX+"/user/oidc-identities", apiCreateOIDCIdentity)
		requireAuthentication.POST(DRASL_API_PREFIX+"/users/:uuid/oidc-identities", apiCreateOIDCIdentity)
	}

	// authlib-injector
	// GET /authlib-injector is rate-unlimited
	base.GET("/authlib-injector", AuthlibInjectorRoot(app))

	// Everything else is rate limited
	bearerRequireAuthentication.PUT("/authlib-injector/api/user/profile/:id/skin", app.AuthlibInjectorUploadTexture(TextureTypeSkin))
	bearerRequireAuthentication.PUT("/authlib-injector/api/user/profile/:id/cape", app.AuthlibInjectorUploadTexture(TextureTypeCape))
	bearerRequireAuthentication.DELETE("/authlib-injector/api/user/profile/:id/skin", app.AuthlibInjectorDeleteTexture(TextureTypeSkin))
	bearerRequireAuthentication.DELETE("/authlib-injector/api/user/profile/:id/cape", app.AuthlibInjectorDeleteTexture(TextureTypeCape))

	// Auth
	authAuthenticate := AuthAuthenticate(app)
	authInvalidate := AuthInvalidate(app)
	authRefresh := AuthRefresh(app)
	authSignout := AuthSignout(app)
	authValidate := AuthValidate(app)
	authServerInfo := AuthServerInfo(app)
	// authServerInfo is rate unlimited
	for _, route := range []string{"/auth", "/authlib-injector/authserver"} {
		base.GET(route, authServerInfo)
	}
	for _, prefix := range []string{"", "/auth", "/authlib-injector/authserver"} {
		// The Bind* middlewares parse and validate the AccessToken and ClientToken from the request to identify the user so we can rate limit by user.
		base.POST(prefix+"/invalidate", authInvalidate, app.BindAuthInvalidate(), rateLimiter)
		base.POST(prefix+"/refresh", authRefresh, app.BindAuthRefresh(), rateLimiter)
		base.POST(prefix+"/validate", authValidate, app.BindAuthValidate(), rateLimiter)
		// /authenticate and /signout are unauthenticated and take usernames and passwords, so they should be rate limited by RealIP
		rateLimitedUnauthenticated.POST(prefix+"/authenticate", authAuthenticate)
		rateLimitedUnauthenticated.POST(prefix+"/signout", authSignout)
	}

	// Account
	accountVerifySecurityLocation := AccountVerifySecurityLocation(app)
	accountPlayerNameToID := AccountPlayerNameToID(app)
	accountPlayerNamesToIDs := AccountPlayerNamesToIDs(app)
	for _, prefix := range []string{"", "/account", "/profiles", "/authlib-injector/api"} {
		rateLimitedUnauthenticated.GET(prefix+"/user/security/location", accountVerifySecurityLocation)
		rateLimitedUnauthenticated.GET(prefix+"/users/profiles/minecraft/:playerName", accountPlayerNameToID)
		rateLimitedUnauthenticated.POST(prefix+"/profiles/minecraft", accountPlayerNamesToIDs)
		rateLimitedUnauthenticated.GET(prefix+"/minecraft/profile/lookup/name/:playerName", accountPlayerNameToID)
		rateLimitedUnauthenticated.POST(prefix+"/minecraft/profile/lookup/bulk/byname", accountPlayerNamesToIDs)
	}

	// Session
	sessionHasJoined := SessionHasJoined(app)
	sessionCheckServer := SessionCheckServer(app)
	sessionJoin := SessionJoin(app)
	sessionJoinServer := SessionJoinServer(app)
	sessionProfile := SessionProfile(app, false)
	sessionBlockedServers := SessionBlockedServers(app)
	sessionHeartbeat := SessionHeartbeat(app)
	sessionGetMpPass := SessionGetMpPass(app)
	for _, prefix := range []string{"", "/session", "/authlib-injector/sessionserver"} {
		// Unauthenticated hasJoined routes should probably not be rate limited since they are called very frequently by Minecraft servers
		base.GET(prefix+"/session/minecraft/hasJoined", sessionHasJoined)
		base.GET(prefix+"/game/checkserver.jsp", sessionCheckServer)

		rateLimitedUnauthenticated.GET(prefix+"/session/minecraft/profile/:id", sessionProfile)
		rateLimitedUnauthenticated.GET(prefix+"/blockedservers", sessionBlockedServers)

		// Perform authentication first in Bind*, then rate limit
		base.POST(prefix+"/session/minecraft/join", sessionJoin, app.BindSessionJoin(), rateLimiter)
		base.GET(prefix+"/game/joinserver.jsp", sessionJoinServer, app.BindSessionJoinServer(), rateLimiter)

		// Classic protocol routes
		rateLimitedUnauthenticated.Any(prefix+"/heartbeat.jsp", sessionHeartbeat)
		bearerRequireAuthentication.GET(prefix+"/mppass", sessionGetMpPass)
	}

	// Services
	servicesPlayerAttributes := ServicesPlayerAttributes(app)
	servicesPlayerCertificates := ServicesPlayerCertificates(app)
	servicesHideCape := ServicesHideCape(app)
	servicesResetSkin := ServicesResetSkin(app)
	servicesProfileInformation := ServicesProfileInformation(app)
	servicesNameAvailability := ServicesNameAvailability(app)
	servicesNameChange := ServicesNameChange(app)
	servicesBlocklist := ServicesBlocklist(app)
	servicesMSAMigration := ServicesMSAMigration(app)
	servicesUploadSkin := ServicesUploadSkin(app)
	servicesChangeName := ServicesChangeName(app)
	servicesPublicKeys := ServicesPublicKeys(app)
	servicesIDToPlayerName := app.ServicesIDToPlayerName()
	for _, prefix := range []string{"", "/services", "/authlib-injector/minecraftservices"} {
		bearerRequireAuthentication.GET(prefix+"/privileges", servicesPlayerAttributes)
		bearerRequireAuthentication.GET(prefix+"/player/attributes", servicesPlayerAttributes)
		bearerRequireAuthentication.POST(prefix+"/player/certificates", servicesPlayerCertificates)
		bearerRequireAuthentication.DELETE(prefix+"/minecraft/profile/capes/active", servicesHideCape)
		bearerRequireAuthentication.DELETE(prefix+"/minecraft/profile/skins/active", servicesResetSkin)
		bearerRequireAuthentication.GET(prefix+"/minecraft/profile", servicesProfileInformation)
		bearerRequireAuthentication.GET(prefix+"/minecraft/profile/name/:playerName/available", servicesNameAvailability)
		bearerRequireAuthentication.GET(prefix+"/minecraft/profile/namechange", servicesNameChange)
		bearerRequireAuthentication.GET(prefix+"/privacy/blocklist", servicesBlocklist)
		bearerRequireAuthentication.GET(prefix+"/rollout/v1/msamigration", servicesMSAMigration)
		bearerRequireAuthentication.POST(prefix+"/minecraft/profile/skins", servicesUploadSkin)
		bearerRequireAuthentication.PUT(prefix+"/minecraft/profile/name/:playerName", servicesChangeName)

		base.GET(prefix+"/publickeys", servicesPublicKeys)
		rateLimitedUnauthenticated.GET(prefix+"/minecraft/profile/lookup/:id", servicesIDToPlayerName)
	}
	// These routes are duplicated by the account server
	for _, prefix := range []string{"/services", "/authlib-injector/minecraftservices"} {
		rateLimitedUnauthenticated.GET(prefix+"/minecraft/profile/lookup/name/:playerName", accountPlayerNameToID)
		rateLimitedUnauthenticated.POST(prefix+"/minecraft/profile/lookup/bulk/byname", accountPlayerNamesToIDs)
	}

	return e
}

func stripProto(s string) string {
    if i := strings.Index(s, "://"); i != -1 {
        return s[i+1:]
    }
    return s
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
			rp.WithVerifierOpts(
				rp.WithIssuedAtOffset(1*time.Minute),
				rp.WithIssuedAtMaxAge(10*time.Minute),
			),
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

	// Heartbeat
	heartbeatSaltMap := make(map[ServerKey]heartbeatSaltEntry)
	heartbeatLruList := list.New()

	basePath := Unwrap(url.Parse(config.BaseURL)).Path

	app := &App{
		BasePath:                 basePath,
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
		HeartbeatSaltMap:         heartbeatSaltMap,
		HeartbeatLruList:         heartbeatLruList,
	}

	app.PublicURLNoProto = stripProto(app.PublicURL)
	app.FrontEndURLNoProto = stripProto(app.FrontEndURL)

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

	app.RunPeriodicTasks()
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
	e := app.MakeServer()
	sc := echo.StartConfig{
		Address:    app.Config.ListenAddress,
		HideBanner: true,
		HidePort:   false,
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := sc.Start(ctx, e); err != nil && !errors.Is(err, http.ErrServerClosed) {
		Check(err)
	}
}
