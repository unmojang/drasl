package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/dgraph-io/ristretto"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
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
	"regexp"
	"sync"
)

var DEBUG = os.Getenv("DRASL_DEBUG") != ""

var bodyDump = middleware.BodyDump(func(c echo.Context, reqBody, resBody []byte) {
	fmt.Printf("%s\n", reqBody)
	fmt.Printf("%s\n", resBody)
})

type App struct {
	FrontEndURL              string
	AuthURL                  string
	AccountURL               string
	ServicesURL              string
	SessionURL               string
	AuthlibInjectorURL       string
	DB                       *gorm.DB
	FSMutex                  KeyedMutex
	RequestCache             *ristretto.Cache
	Config                   *Config
	TransientUsernameRegex   *regexp.Regexp
	ValidPlayerNameRegex     *regexp.Regexp
	Constants                *ConstantsType
	PlayerCertificateKeys    []rsa.PublicKey
	ProfilePropertyKeys      []rsa.PublicKey
	Key                      *rsa.PrivateKey
	KeyB3Sum512              []byte
	SkinMutex                *sync.Mutex
	VerificationSkinTemplate *image.NRGBA
}

func (app *App) LogError(err error, c *echo.Context) {
	if err != nil && !app.Config.TestMode {
		log.Println("Unexpected error in "+(*c).Request().Method+" "+(*c).Path()+":", err)
	}
}

func (app *App) HandleError(err error, c echo.Context) {
	path_ := c.Request().URL.Path
	var additionalErr error
	if IsYggdrasilPath(path_) {
		additionalErr = app.HandleYggdrasilError(err, &c)
	} else if IsAPIPath(path_) {
		additionalErr = app.HandleAPIError(err, &c)
	} else {
		// Web front end
		additionalErr = app.HandleWebError(err, &c)
	}
	if additionalErr != nil {
		app.LogError(fmt.Errorf("Additional error while handling an error: %w", additionalErr), &c)
	}
}

func makeRateLimiter(app *App) echo.MiddlewareFunc {
	requestsPerSecond := rate.Limit(app.Config.RateLimit.RequestsPerSecond)
	return middleware.RateLimiterWithConfig(middleware.RateLimiterConfig{
		Skipper: func(c echo.Context) bool {
			switch c.Path() {
			case "/",
				"/web/delete-user",
				"/web/login",
				"/web/logout",
				"/web/register",
				"/web/update":
				return false
			default:
				return true
			}
		},
		Store: middleware.NewRateLimiterMemoryStore(requestsPerSecond),
		DenyHandler: func(c echo.Context, identifier string, err error) error {
			path := c.Path()
			if IsYggdrasilPath(path) {
				return &echo.HTTPError{
					Code:     http.StatusTooManyRequests,
					Message:  "Too many requests. Try again later.",
					Internal: err,
				}
			} else {
				setErrorMessage(&c, "Too many requests. Try again later.")
				return c.Redirect(http.StatusSeeOther, getReturnURL(app, &c))
			}
		},
	})
}

func (app *App) MakeServer() *echo.Echo {
	e := echo.New()
	e.HideBanner = true
	e.HidePort = app.Config.TestMode
	e.HTTPErrorHandler = app.HandleError

	e.Pre(middleware.Rewrite(map[string]string{
		"/authlib-injector/authserver/*":        "/auth/$1",
		"/authlib-injector/api/*":               "/account/$1",
		"/authlib-injector/sessionserver/*":     "/session/$1",
		"/authlib-injector/minecraftservices/*": "/services/$1",
	}))
	e.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			c.Response().Header().Set("X-Authlib-Injector-API-Location", app.AuthlibInjectorURL)
			return next(c)
		}
	})
	if app.Config.LogRequests {
		e.Use(middleware.Logger())
	}
	if DEBUG {
		e.Use(bodyDump)
	}
	if app.Config.RateLimit.Enable {
		e.Use(makeRateLimiter(app))
	}
	if app.Config.BodyLimit.Enable {
		limit := fmt.Sprintf("%dKIB", app.Config.BodyLimit.SizeLimitKiB)
		e.Use(middleware.BodyLimit(limit))
	}

	// Front
	t := NewTemplate(app)
	e.Renderer = t
	e.GET("/", FrontRoot(app))
	e.GET("/web/manifest.webmanifest", FrontWebManifest(app))
	e.GET("/web/admin", FrontAdmin(app))
	e.GET("/web/challenge-skin", FrontChallengeSkin(app))
	e.GET("/web/profile", FrontProfile(app))
	e.GET("/web/registration", FrontRegistration(app))
	e.POST("/web/admin/delete-invite", FrontDeleteInvite(app))
	e.POST("/web/admin/new-invite", FrontNewInvite(app))
	e.POST("/web/admin/update-users", FrontUpdateUsers(app))
	e.POST("/web/delete-user", FrontDeleteUser(app))
	e.POST("/web/login", FrontLogin(app))
	e.POST("/web/logout", FrontLogout(app))
	e.POST("/web/register", FrontRegister(app))
	e.POST("/web/update-user", FrontUpdateUser(app))
	e.POST("/web/update-player", FrontUpdatePlayer(app))
	e.Static("/web/public", path.Join(app.Config.DataDirectory, "public"))
	e.Static("/web/texture/cape", path.Join(app.Config.StateDirectory, "cape"))
	e.Static("/web/texture/skin", path.Join(app.Config.StateDirectory, "skin"))
	e.Static("/web/texture/default-cape", path.Join(app.Config.StateDirectory, "default-cape"))
	e.Static("/web/texture/default-skin", path.Join(app.Config.StateDirectory, "default-skin"))

	// Drasl API
	e.GET("/drasl/api/v1/users", app.APIGetUsers())
	e.GET("/drasl/api/v1/users/:uuid", app.APIGetUser())
	e.GET("/drasl/api/v1/user", app.APIGetSelf())
	e.GET("/drasl/api/v1/invites", app.APIGetInvites())
	e.GET("/drasl/api/v1/challenge-skin", app.APIGetChallengeSkin())

	e.POST("/drasl/api/v1/users", app.APICreateUser())
	e.POST("/drasl/api/v1/invites", app.APICreateInvite())

	e.PATCH("/drasl/api/v1/users/:uuid", app.APIUpdateUser())
	e.PATCH("/drasl/api/v1/user", app.APIUpdateUser())

	e.DELETE("/drasl/api/v1/users/:uuid", app.APIDeleteUser())
	e.DELETE("/drasl/api/v1/user", app.APIDeleteSelf())
	e.DELETE("/drasl/api/v1/invite/:code", app.APIDeleteInvite())

	// authlib-injector
	e.GET("/authlib-injector", AuthlibInjectorRoot(app))
	e.GET("/authlib-injector/", AuthlibInjectorRoot(app))

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

	// Session
	sessionHasJoined := SessionHasJoined(app)
	sessionCheckServer := SessionCheckServer(app)
	sessionJoin := SessionJoin(app)
	sessionJoinServer := SessionJoinServer(app)
	sessionProfile := SessionProfile(app)
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
	e.POST("/services/minecraft/profile/lookup/bulk/byname", accountPlayerNamesToIDs)

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

	key := ReadOrCreateKey(config)
	keyBytes := Unwrap(x509.MarshalPKCS8PrivateKey(key))
	sum := blake3.Sum512(keyBytes)
	keyB3Sum512 := sum[:]

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

	// Keys
	playerCertificateKeys := make([]rsa.PublicKey, 0, 1)
	profilePropertyKeys := make([]rsa.PublicKey, 0, 1)
	profilePropertyKeys = append(profilePropertyKeys, key.PublicKey)
	playerCertificateKeys = append(playerCertificateKeys, key.PublicKey)

	for _, fallbackAPIServer := range config.FallbackAPIServers {
		reqURL := Unwrap(url.JoinPath(fallbackAPIServer.ServicesURL, "publickeys"))
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
	}

	app := &App{
		RequestCache:             cache,
		Config:                   config,
		TransientUsernameRegex:   transientUsernameRegex,
		ValidPlayerNameRegex:     validPlayerNameRegex,
		Constants:                Constants,
		DB:                       db,
		FSMutex:                  KeyedMutex{},
		Key:                      key,
		KeyB3Sum512:              keyB3Sum512,
		FrontEndURL:              config.BaseURL,
		PlayerCertificateKeys:    playerCertificateKeys,
		ProfilePropertyKeys:      profilePropertyKeys,
		AccountURL:               Unwrap(url.JoinPath(config.BaseURL, "account")),
		AuthURL:                  Unwrap(url.JoinPath(config.BaseURL, "auth")),
		ServicesURL:              Unwrap(url.JoinPath(config.BaseURL, "services")),
		SessionURL:               Unwrap(url.JoinPath(config.BaseURL, "session")),
		AuthlibInjectorURL:       Unwrap(url.JoinPath(config.BaseURL, "authlib-injector")),
		VerificationSkinTemplate: verificationSkinTemplate,
	}

	// Post-setup

	// Make sure all DefaultAdmins are admins
	err = app.DB.Table("users").Where("username in (?)", config.DefaultAdmins).Updates(map[string]interface{}{"is_admin": true}).Error
	Check(err)

	// Print an initial invite link if necessary
	if !app.Config.TestMode {
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
				log.Println("No users found! Here's an invite URL:", Unwrap(app.InviteURL(&invite)))
			}
		}
	}

	return app
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

	config := ReadOrCreateConfig(*configPath)
	app := setup(config)

	Check(app.MakeServer().Start(app.Config.ListenAddress))
}
