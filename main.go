package main

import (
	"crypto/rsa"
	"flag"
	"fmt"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"golang.org/x/time/rate"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"html/template"
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
	DB                          *gorm.DB
	Config                      *Config
	AnonymousLoginUsernameRegex *regexp.Regexp
	Constants                   *ConstantsType
	Key                         *rsa.PrivateKey
	KeyB3Sum512                 *[]byte
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
				"/drasl/challenge-skin",
				"/drasl/profile",
				"/drasl/registration",
				"/drasl/public",
				"/drasl/texture/cape",
				"/drasl/texture/skin":
				return true
			default:
				return false
			}
		},
		Store: middleware.NewRateLimiterMemoryStore(requestsPerSecond),
		DenyHandler: func(c echo.Context, identifier string, err error) error {
			path := c.Path()
			split := strings.Split(path, "/")
			if path == "/" || (len(split) >= 2 && split[1] == "drasl") {
				setErrorMessage(&c, "Too many requests. Try again later.")
				return c.Redirect(http.StatusSeeOther, getReturnURL(&c, app.FrontEndURL))
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
	t := &Template{
		templates: template.Must(template.ParseGlob("view/*.html")),
	}
	e.Renderer = t
	e.GET("/", FrontRoot(app))
	e.GET("/drasl/challenge-skin", FrontChallengeSkin(app))
	e.GET("/drasl/profile", FrontProfile(app))
	e.GET("/drasl/registration", FrontRegistration(app))
	e.POST("/drasl/delete-account", FrontDeleteAccount(app))
	e.POST("/drasl/login", FrontLogin(app))
	e.POST("/drasl/logout", FrontLogout(app))
	e.POST("/drasl/register", FrontRegister(app))
	e.POST("/drasl/update", FrontUpdate(app))
	e.Static("/drasl/public", path.Join(app.Config.DataDirectory, "public"))
	e.Static("/drasl/texture/cape", path.Join(app.Config.StateDirectory, "cape"))
	e.Static("/drasl/texture/skin", path.Join(app.Config.StateDirectory, "skin"))

	// Auth
	authAuthenticate := AuthAuthenticate(app)
	authInvalidate := AuthInvalidate(app)
	authRefresh := AuthRefresh(app)
	authSignout := AuthSignout(app)
	authValidate := AuthValidate(app)

	e.Any("/authenticate", authAuthenticate) // TODO should these all be e.Any?
	e.Any("/invalidate", authInvalidate)
	e.Any("/refresh", authRefresh)
	e.Any("/signout", authSignout)
	e.Any("/validate", authValidate)

	e.Any("/auth/authenticate", authAuthenticate) // TODO should these all be e.Any?
	e.Any("/auth/invalidate", authInvalidate)
	e.Any("/auth/refresh", authRefresh)
	e.Any("/auth/signout", authSignout)
	e.Any("/auth/validate", authValidate)

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
	e.Any("/session/minecraft/hasJoined", sessionHasJoined) // TODO should these all be e.Any?
	e.Any("/session/minecraft/join", sessionJoin)
	e.Any("/session/minecraft/profile/:id", sessionProfile)

	e.Any("/session/session/minecraft/hasJoined", sessionHasJoined) // TODO should these all be e.Any?
	e.Any("/session/session/minecraft/join", sessionJoin)
	e.Any("/session/session/minecraft/profile/:id", sessionProfile)

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

	e.Any("/player/attributes", servicesPlayerAttributes)
	e.Any("/player/certificates", servicesPlayerCertificates)
	e.Any("/user/profiles/:uuid/names", servicesUUIDToNameHistory)
	e.DELETE("/minecraft/profile/capes/active", servicesDeleteCape)
	e.DELETE("/minecraft/profile/skins/active", servicesDeleteSkin)
	e.GET("/minecraft/profile", servicesProfileInformation)
	e.GET("/minecraft/profile/name/:playerName/available", servicesNameAvailability)
	e.GET("/minecraft/profile/namechange", servicesNameChange)
	e.GET("/privacy/blocklist", servicesBlocklist)
	e.GET("/rollout/v1/msamigration", servicesMSAMigration)
	e.POST("/minecraft/profile/skins", servicesUploadSkin)
	e.PUT("/minecraft/profile/name/:playerName", servicesChangeName)

	e.Any("/services/player/attributes", servicesPlayerAttributes)
	e.Any("/services/player/certificates", servicesPlayerCertificates)
	e.Any("/services/user/profiles/:uuid/names", servicesUUIDToNameHistory)
	e.DELETE("/services/minecraft/profile/capes/active", servicesDeleteCape)
	e.DELETE("/services/minecraft/profile/skins/active", servicesDeleteSkin)
	e.GET("/services/minecraft/profile", servicesProfileInformation)
	e.GET("/services/minecraft/profile/name/:playerName/available", servicesNameAvailability)
	e.GET("/services/minecraft/profile/namechange", servicesNameChange)
	e.GET("/services/privacy/blocklist", servicesBlocklist)
	e.GET("/services/rollout/v1/msamigration", servicesMSAMigration)
	e.POST("/services/minecraft/profile/skins", servicesUploadSkin)
	e.PUT("/services/minecraft/profile/name/:playerName", servicesChangeName)

	return e
}

func setup(config *Config) *App {
	key := ReadOrCreateKey(config)
	keyB3Sum512 := KeyB3Sum512(key)

	db_path := path.Join(config.StateDirectory, "drasl.db")
	db, err := gorm.Open(sqlite.Open(db_path), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	Check(err)

	err = db.AutoMigrate(&User{})
	Check(err)

	err = db.AutoMigrate(&TokenPair{})
	Check(err)

	var anonymousLoginUsernameRegex *regexp.Regexp
	if config.AnonymousLogin.Allow {
		anonymousLoginUsernameRegex, err = regexp.Compile(config.AnonymousLogin.UsernameRegex)
		Check(err)
	}
	return &App{
		Config:                      config,
		AnonymousLoginUsernameRegex: anonymousLoginUsernameRegex,
		Constants:                   Constants,
		DB:                          db,
		Key:                         key,
		KeyB3Sum512:                 &keyB3Sum512,
		FrontEndURL:                 config.BaseURL,
		AccountURL:                  Unwrap(url.JoinPath(config.BaseURL, "account")),
		AuthURL:                     Unwrap(url.JoinPath(config.BaseURL, "auth")),
		ServicesURL:                 Unwrap(url.JoinPath(config.BaseURL, "services")),
		SessionURL:                  Unwrap(url.JoinPath(config.BaseURL, "session")),
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
