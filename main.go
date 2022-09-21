package main

import (
	"crypto/rsa"
	"fmt"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"html/template"
	"log"
	"net/http"
	"path"
	"sync"
)

const DEBUG = false

var bodyDump = middleware.BodyDump(func(c echo.Context, reqBody, resBody []byte) {
	fmt.Printf("%s\n", reqBody)
	fmt.Printf("%s\n", resBody)
})

type App struct {
	DB        *gorm.DB
	Config    *Config
	Key       *rsa.PrivateKey
	KeyB3Sum *[]byte
	SkinMutex *sync.Mutex
}

func handleError(err error, c echo.Context) {
	c.Logger().Error(err)
	c.String(http.StatusInternalServerError, "Internal server error")
}

func runFrontServer(app *App) {
	e := echo.New()
	e.HideBanner = true
	e.HTTPErrorHandler = handleError
	t := &Template{
		templates: template.Must(template.ParseGlob("view/*.html")),
	}
	e.Renderer = t
	e.GET("/", FrontRoot(app))
	e.GET("/challenge-skin", FrontChallengeSkin(app))
	e.POST("/register", FrontRegister(app))
	e.POST("/login", FrontLogin(app))
	e.POST("/logout", FrontLogout(app))
	e.POST("/update", FrontUpdate(app))
	e.POST("/delete-account", FrontDeleteAccount(app))
	e.Static("/texture/skin", path.Join(app.Config.DataDirectory, "skin"))
	e.Static("/texture/cape", path.Join(app.Config.DataDirectory, "cape"))
	e.Static("/public", "public")
	e.Logger.Fatal(e.Start(":9090"))
}

func runAuthenticationServer(app *App) {
	e := echo.New()
	e.HideBanner = true
	e.HTTPErrorHandler = handleError
	e.Use(middleware.Logger())
	if DEBUG {
		e.Use(bodyDump)
	}
	e.Any("/", AuthGetServerInfo(app))
	e.Any("/authenticate", AuthAuthenticate(app))
	e.Any("/refresh", AuthRefresh(app))
	e.Any("/validate", AuthValidate(app))
	e.Any("/invalidate", AuthInvalidate(app))
	e.Any("/signout", AuthSignout(app))
	e.Logger.Fatal(e.Start(":9091"))
}

func runAccountServer(app *App) {
	e := echo.New()
	e.HideBanner = true
	e.HTTPErrorHandler = handleError
	e.Use(middleware.Logger())
	if DEBUG {
		e.Use(bodyDump)
	}
	e.Logger.Fatal(e.Start(":9092"))
}

func runSessionServer(app *App) {
	e := echo.New()
	e.HideBanner = true
	e.HTTPErrorHandler = handleError
	e.Use(middleware.Logger())
	if DEBUG {
		e.Use(bodyDump)
	}
	e.Any("/session/minecraft/join", SessionJoin(app))
	e.Any("/session/minecraft/hasJoined", SessionHasJoined(app))
	e.Any("/session/minecraft/profile/:id", SessionProfile(app))
	e.Logger.Fatal(e.Start(":9093"))
}

func runServicesServer(app *App) {
	e := echo.New()
	e.HideBanner = true
	e.HTTPErrorHandler = handleError
	e.Use(middleware.Logger())
	e.Any("/profiles/minecraft/:playerName", ServicesPlayerNameToUUID(app))
	e.Any("/profiles/minecraft", ServicesPlayerNamesToUUIDs(app))
	e.Any("/user/profiles/:uuid/names", ServicesUUIDToNameHistory(app))
	e.Any("/player/attributes", ServicesPlayerAttributes(app))
	e.Any("/player/certificates", ServicesPlayerCertificates(app))
	e.Any("/minecraft/profile/skins", ServicesUploadSkin(app))
	e.Logger.Fatal(e.Start(":9094"))
}

func main() {
	config := ReadOrCreateConfig("./config.toml")
	key := ReadOrCreateKey(config)
	keyB3Sum := KeyB3Sum(key)

	db_path := path.Join(config.DataDirectory, "drasl.db")
	db, err := gorm.Open(sqlite.Open(db_path), &gorm.Config{})
	if err != nil {
		log.Fatalf("Couldn't access db at %s", db_path)
	}

	db.AutoMigrate(&User{})
	db.AutoMigrate(&TokenPair{})

	app := &App{
		Config: config,
		DB:     db,
		Key:    key,
		KeyB3Sum: &keyB3Sum,
	}

	go runFrontServer(app)
	go runAuthenticationServer(app)
	go runSessionServer(app)
	go runAccountServer(app)
	go runServicesServer(app)
	select {}
}
