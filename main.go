package main

import (
	"crypto/rsa"
	"fmt"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"html/template"
	"net/http"
	"path"
	"regexp"
	"sync"
)

const DEBUG = false

var bodyDump = middleware.BodyDump(func(c echo.Context, reqBody, resBody []byte) {
	fmt.Printf("%s\n", reqBody)
	fmt.Printf("%s\n", resBody)
})

type App struct {
	DB                          *gorm.DB
	Config                      *Config
	AnonymousLoginUsernameRegex *regexp.Regexp
	Constants                   *ConstantsType
	Key                         *rsa.PrivateKey
	KeyB3Sum512                 *[]byte
	SkinMutex                   *sync.Mutex
}

func handleError(err error, c echo.Context) {
	c.Logger().Error(err)
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

func GetFrontServer(app *App) *echo.Echo {
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
	t := &Template{
		templates: template.Must(template.ParseGlob("view/*.html")),
	}
	e.Renderer = t
	e.GET("/", FrontRoot(app))
	e.GET("/challenge-skin", FrontChallengeSkin(app))
	e.GET("/profile", FrontProfile(app))
	e.GET("/registration", FrontRegistration(app))
	e.POST("/register", FrontRegister(app))
	e.POST("/login", FrontLogin(app))
	e.POST("/logout", FrontLogout(app))
	e.POST("/update", FrontUpdate(app))
	e.POST("/delete-account", FrontDeleteAccount(app))
	e.Static("/texture/skin", path.Join(app.Config.DataDirectory, "skin"))
	e.Static("/texture/cape", path.Join(app.Config.DataDirectory, "cape"))
	e.Static("/public", "public")
	return e
}

func GetAuthServer(app *App) *echo.Echo {
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
	e.Any("/", AuthGetServerInfo(app))
	e.Any("/authenticate", AuthAuthenticate(app))
	e.Any("/refresh", AuthRefresh(app))
	e.Any("/validate", AuthValidate(app))
	e.Any("/signout", AuthSignout(app))
	e.Any("/invalidate", AuthInvalidate(app))
	return e
}

func GetAccountServer(app *App) *echo.Echo {
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
	e.GET("/users/profiles/minecraft/:playerName", AccountPlayerNameToID(app))
	e.POST("/profiles/minecraft", AccountPlayerNamesToIDs(app))
	e.GET("/user/security/location", AccountVerifySecurityLocation(app))
	return e
}

func GetSessionServer(app *App) *echo.Echo {
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
	e.Any("/session/minecraft/join", SessionJoin(app))
	e.Any("/session/minecraft/hasJoined", SessionHasJoined(app))
	e.Any("/session/minecraft/profile/:id", SessionProfile(app))
	return e
}

func GetServicesServer(app *App) *echo.Echo {
	e := echo.New()
	e.HideBanner = true
	e.HidePort = app.Config.HideListenAddress
	e.HTTPErrorHandler = handleError
	if app.Config.LogRequests {
		e.Use(middleware.Logger())
	}
	e.Any("/user/profiles/:uuid/names", ServicesUUIDToNameHistory(app))
	e.Any("/player/attributes", ServicesPlayerAttributes(app))
	e.Any("/player/certificates", ServicesPlayerCertificates(app))
	e.POST("/minecraft/profile/skins", ServicesUploadSkin(app))
	e.DELETE("/minecraft/profile/skins/active", ServicesDeleteSkin(app))
	e.DELETE("/minecraft/profile/capes/active", ServicesDeleteCape(app))
	e.GET("/minecraft/profile/namechange", ServicesNameChange(app))
	e.GET("/rollout/v1/msamigration", ServicesMSAMigration(app))
	return e
}

func setup(config *Config) *App {
	key := ReadOrCreateKey(config)
	keyB3Sum512 := KeyB3Sum512(key)

	db_path := path.Join(config.DataDirectory, "drasl.db")
	db, err := gorm.Open(sqlite.Open(db_path), &gorm.Config{})
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
	}
}

func runServer(e *echo.Echo, listenAddress string) {
	e.Logger.Fatal(e.Start(listenAddress))
}

func main() {
	config := ReadOrCreateConfig("./config.toml")
	app := setup(config)

	go runServer(GetFrontServer(app), app.Config.FrontEndServer.ListenAddress)
	go runServer(GetAuthServer(app), app.Config.AuthServer.ListenAddress)
	go runServer(GetAccountServer(app), app.Config.AccountServer.ListenAddress)
	go runServer(GetSessionServer(app), app.Config.SessionServer.ListenAddress)
	go runServer(GetServicesServer(app), app.Config.ServicesServer.ListenAddress)
	select {}
}
