package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/dgraph-io/ristretto"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"golang.org/x/time/rate"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"strings"
	"sync"
)

const DEBUG = false

var bodyDump = middleware.BodyDump(func(c echo.Context, reqBody, resBody []byte) {
	fmt.Printf("%s\n", reqBody)
	fmt.Printf("%s\n", resBody)
})

type App struct {
	FrontEndURL                 string
	AuthURL                     string
	AccountURL                  string
	ServicesURL                 string
	SessionURL                  string
	AuthlibInjectorURL          string
	DB                          *gorm.DB
	FSMutex                     KeyedMutex
	RequestCache                *ristretto.Cache
	Config                      *Config
	AnonymousLoginUsernameRegex *regexp.Regexp
	Constants                   *ConstantsType
	PlayerCertificateKeys       []SerializedKey
	ProfilePropertyKeys         []SerializedKey
	Key                         *rsa.PrivateKey
	KeyB3Sum512                 []byte
	SkinMutex                   *sync.Mutex
}

func handleError(err error, c echo.Context) {
	if err != nil {
		c.Logger().Error(err)
	}
	if httpError, ok := err.(*echo.HTTPError); ok {
		if httpError.Code == http.StatusNotFound {
			if s, ok := httpError.Message.(string); ok {
				e := c.String(httpError.Code, s)
				Check(e)
				return
			}
		}
	}
	e := c.String(http.StatusInternalServerError, "Internal server error")
	Check(e)
}

func makeRateLimiter(app *App) echo.MiddlewareFunc {
	requestsPerSecond := rate.Limit(app.Config.RateLimit.RequestsPerSecond)
	return middleware.RateLimiterWithConfig(middleware.RateLimiterConfig{
		Skipper: func(c echo.Context) bool {
			switch c.Path() {
			case "/",
				"/drasl/delete-account",
				"/drasl/login",
				"/drasl/logout",
				"/drasl/register",
				"/drasl/update":
				return false
			default:
				return true
			}
		},
		Store: middleware.NewRateLimiterMemoryStore(requestsPerSecond),
		DenyHandler: func(c echo.Context, identifier string, err error) error {
			path := c.Path()
			split := strings.Split(path, "/")
			if path == "/" || (len(split) >= 2 && split[1] == "drasl") {
				setErrorMessage(&c, "Too many requests. Try again later.")
				return c.Redirect(http.StatusSeeOther, getReturnURL(app, &c))
			} else {
				return &echo.HTTPError{
					Code:     http.StatusTooManyRequests,
					Message:  "Too many requests. Try again later.",
					Internal: err,
				}
			}
		},
	})
}

func GetServer(app *App) *echo.Echo {
	e := echo.New()
	e.HideBanner = true
	e.HidePort = app.Config.HideListenAddress
	e.HTTPErrorHandler = handleError
	if app.Config.LogRequests {
		e.Use(middleware.Logger())
	}
	if DEBUG {
		e.Use(bodyDump)
	}
	if app.Config.RateLimit.Enable {
		e.Use(makeRateLimiter(app))
	}

	// Front
	t := NewTemplate(app)
	e.Renderer = t
	e.GET("/", FrontRoot(app))
	e.GET("/drasl/challenge-skin", FrontChallengeSkin(app))
	e.GET("/drasl/admin", FrontAdmin(app))
	e.GET("/drasl/profile", FrontProfile(app))
	e.GET("/drasl/registration", FrontRegistration(app))
	e.POST("/drasl/delete-account", FrontDeleteAccount(app))
	e.POST("/drasl/login", FrontLogin(app))
	e.POST("/drasl/logout", FrontLogout(app))
	e.POST("/drasl/register", FrontRegister(app))
	e.POST("/drasl/admin/new-invite", FrontNewInvite(app))
	e.POST("/drasl/admin/delete-invite", FrontDeleteInvite(app))
	e.POST("/drasl/admin/delete-user", FrontDeleteUser(app))
	e.POST("/drasl/admin/update-users", FrontUpdateUsers(app))
	e.POST("/drasl/update", FrontUpdate(app))
	e.Static("/drasl/public", path.Join(app.Config.DataDirectory, "public"))
	e.Static("/drasl/texture/cape", path.Join(app.Config.StateDirectory, "cape"))
	e.Static("/drasl/texture/skin", path.Join(app.Config.StateDirectory, "skin"))

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

	e.GET("/auth", AuthGetServerInfo(app))
	e.POST("/auth/authenticate", authAuthenticate)
	e.POST("/auth/invalidate", authInvalidate)
	e.POST("/auth/refresh", authRefresh)
	e.POST("/auth/signout", authSignout)
	e.POST("/auth/validate", authValidate)

	// authlib-injector
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

	// Session
	sessionHasJoined := SessionHasJoined(app)
	sessionJoin := SessionJoin(app)
	sessionProfile := SessionProfile(app)
	e.GET("/session/minecraft/hasJoined", sessionHasJoined)
	e.POST("/session/minecraft/join", sessionJoin)
	e.GET("/session/minecraft/profile/:id", sessionProfile)

	e.GET("/session/session/minecraft/hasJoined", sessionHasJoined)
	e.POST("/session/session/minecraft/join", sessionJoin)
	e.GET("/session/session/minecraft/profile/:id", sessionProfile)

	// authlib-injector
	e.GET("/authlib-injector/sessionserver/session/minecraft/hasJoined", sessionHasJoined)
	e.POST("/authlib-injector/sessionserver/session/minecraft/join", sessionJoin)
	e.GET("/authlib-injector/sessionserver/session/minecraft/profile/:id", sessionProfile)

	// Services
	servicesPlayerAttributes := ServicesPlayerAttributes(app)
	servicesPlayerCertificates := ServicesPlayerCertificates(app)
	servicesUUIDToNameHistory := ServicesUUIDToNameHistory(app)
	servicesDeleteCape := ServicesDeleteCape(app)
	servicesDeleteSkin := ServicesDeleteSkin(app)
	servicesProfileInformation := ServicesProfileInformation(app)
	servicesNameAvailability := ServicesNameAvailability(app)
	servicesNameChange := ServicesNameChange(app)
	servicesBlocklist := ServicesBlocklist(app)
	servicesMSAMigration := ServicesMSAMigration(app)
	servicesUploadSkin := ServicesUploadSkin(app)
	servicesChangeName := ServicesChangeName(app)
	servicesPublicKeys := ServicesPublicKeys(app)

	e.GET("/player/attributes", servicesPlayerAttributes)
	e.POST("/player/certificates", servicesPlayerCertificates)
	e.GET("/user/profiles/:uuid/names", servicesUUIDToNameHistory)
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

	e.GET("/services/player/attributes", servicesPlayerAttributes)
	e.POST("/services/player/certificates", servicesPlayerCertificates)
	e.GET("/services/user/profiles/:uuid/names", servicesUUIDToNameHistory)
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

	return e
}

func setup(config *Config) *App {
	key := ReadOrCreateKey(config)
	keyB3Sum512 := KeyB3Sum512(key)

	db_path := path.Join(config.StateDirectory, "drasl.db")
	db := Unwrap(gorm.Open(sqlite.Open(db_path), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	}))

	err := db.AutoMigrate(&User{})
	Check(err)

	err = db.AutoMigrate(&TokenPair{})
	Check(err)

	err = db.AutoMigrate(&Invite{})
	Check(err)

	cache := Unwrap(ristretto.NewCache(&ristretto.Config{
		NumCounters: 1e7,
		MaxCost:     1 << 30,
		BufferItems: 64,
	}))

	// Precompile regexes
	var anonymousLoginUsernameRegex *regexp.Regexp
	if config.AnonymousLogin.Allow {
		anonymousLoginUsernameRegex = Unwrap(regexp.Compile(config.AnonymousLogin.UsernameRegex))
	}

	playerCertificateKeys := make([]SerializedKey, 0, 1)
	profilePropertyKeys := make([]SerializedKey, 0, 1)
	publicKeyDer := Unwrap(x509.MarshalPKIXPublicKey(&key.PublicKey))
	serializedKey := SerializedKey{PublicKey: base64.StdEncoding.EncodeToString(publicKeyDer)}
	profilePropertyKeys = append(profilePropertyKeys, serializedKey)
	playerCertificateKeys = append(playerCertificateKeys, serializedKey)
	for _, fallbackAPIServer := range config.FallbackAPIServers {
		reqURL, err := url.JoinPath(fallbackAPIServer.ServicesURL, "publickeys")
		if err != nil {
			log.Println(err)
			continue
		}
		res, err := http.Get(reqURL)
		if err != nil {
			log.Println(err)
			continue
		}
		defer res.Body.Close()

		if res.StatusCode == http.StatusOK {
			var publicKeysRes PublicKeysResponse
			err = json.NewDecoder(res.Body).Decode(&publicKeysRes)
			if err != nil {
				log.Println(err)
				continue
			}
			profilePropertyKeys = append(profilePropertyKeys, publicKeysRes.ProfilePropertyKeys...)
			playerCertificateKeys = append(playerCertificateKeys, publicKeysRes.PlayerCertificateKeys...)
			break
		}
	}

	return &App{
		RequestCache:                cache,
		Config:                      config,
		AnonymousLoginUsernameRegex: anonymousLoginUsernameRegex,
		Constants:                   Constants,
		DB:                          db,
		FSMutex:                     KeyedMutex{},
		Key:                         key,
		KeyB3Sum512:                 keyB3Sum512,
		FrontEndURL:                 config.BaseURL,
		PlayerCertificateKeys:       playerCertificateKeys,
		ProfilePropertyKeys:         profilePropertyKeys,
		AccountURL:                  Unwrap(url.JoinPath(config.BaseURL, "account")),
		AuthURL:                     Unwrap(url.JoinPath(config.BaseURL, "auth")),
		ServicesURL:                 Unwrap(url.JoinPath(config.BaseURL, "services")),
		SessionURL:                  Unwrap(url.JoinPath(config.BaseURL, "session")),
		AuthlibInjectorURL:          Unwrap(url.JoinPath(config.BaseURL, "authlib-injector")),
	}
}

func runServer(e *echo.Echo, listenAddress string) {
	e.Logger.Fatal(e.Start(listenAddress))
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

	runServer(GetServer(app), app.Config.ListenAddress)
}
