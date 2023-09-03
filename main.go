package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
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
	"lukechampine.com/blake3"
	"net/http"
	"net/url"
	"os"
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
	FrontEndURL            string
	AuthURL                string
	AccountURL             string
	ServicesURL            string
	SessionURL             string
	AuthlibInjectorURL     string
	DB                     *gorm.DB
	FSMutex                KeyedMutex
	RequestCache           *ristretto.Cache
	Config                 *Config
	TransientUsernameRegex *regexp.Regexp
	Constants              *ConstantsType
	PlayerCertificateKeys  []SerializedKey
	ProfilePropertyKeys    []SerializedKey
	Key                    *rsa.PrivateKey
	KeyB3Sum512            []byte
	SkinMutex              *sync.Mutex
}

func (app *App) LogError(err error, c *echo.Context) {
	if err != nil && !app.Config.TestMode {
		log.Println("Unexpected error in "+(*c).Request().Method+" "+(*c).Path()+":", err)
	}
}

func (app *App) HandleError(err error, c echo.Context) {
	if IsYggdrasilPath(c.Path()) {
		if httpError, ok := err.(*echo.HTTPError); ok {
			switch httpError.Code {
			case http.StatusNotFound,
				http.StatusRequestEntityTooLarge,
				http.StatusTooManyRequests,
				http.StatusMethodNotAllowed:
				c.JSON(httpError.Code, ErrorResponse{Path: Ptr(c.Request().URL.Path)})
				return
			}
		}
		app.LogError(err, &c)
		c.JSON(http.StatusInternalServerError, ErrorResponse{ErrorMessage: Ptr("internal server error")})
		return
	}
	if httpError, ok := err.(*echo.HTTPError); ok {
		switch httpError.Code {
		case http.StatusNotFound, http.StatusRequestEntityTooLarge, http.StatusTooManyRequests:
			if s, ok := httpError.Message.(string); ok {
				c.String(httpError.Code, s)
				return
			}
		}
	}
	app.LogError(err, &c)
	c.String(http.StatusInternalServerError, "Internal server error")
}

func makeRateLimiter(app *App) echo.MiddlewareFunc {
	requestsPerSecond := rate.Limit(app.Config.RateLimit.RequestsPerSecond)
	return middleware.RateLimiterWithConfig(middleware.RateLimiterConfig{
		Skipper: func(c echo.Context) bool {
			switch c.Path() {
			case "/",
				"/drasl/delete-user",
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

func GetServer(app *App) *echo.Echo {
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
	e.GET("/drasl/admin", FrontAdmin(app))
	e.GET("/drasl/challenge-skin", FrontChallengeSkin(app))
	e.GET("/drasl/profile", FrontProfile(app))
	e.GET("/drasl/registration", FrontRegistration(app))
	e.POST("/drasl/admin/delete-invite", FrontDeleteInvite(app))
	e.POST("/drasl/admin/new-invite", FrontNewInvite(app))
	e.POST("/drasl/admin/update-users", FrontUpdateUsers(app))
	e.POST("/drasl/delete-user", FrontDeleteUser(app))
	e.POST("/drasl/login", FrontLogin(app))
	e.POST("/drasl/logout", FrontLogout(app))
	e.POST("/drasl/register", FrontRegister(app))
	e.POST("/drasl/update", FrontUpdate(app))
	e.Static("/drasl/public", path.Join(app.Config.DataDirectory, "public"))
	e.Static("/drasl/texture/cape", path.Join(app.Config.StateDirectory, "cape"))
	e.Static("/drasl/texture/skin", path.Join(app.Config.StateDirectory, "skin"))

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
	sessionJoin := SessionJoin(app)
	sessionProfile := SessionProfile(app)
	sessionBlockedServers := SessionBlockedServers(app)
	e.GET("/session/minecraft/hasJoined", sessionHasJoined)
	e.POST("/session/minecraft/join", sessionJoin)
	e.GET("/session/minecraft/profile/:id", sessionProfile)
	e.GET("/blockedservers", sessionBlockedServers)

	e.GET("/session/session/minecraft/hasJoined", sessionHasJoined)
	e.POST("/session/session/minecraft/join", sessionJoin)
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

	return e
}

func setup(config *Config) *App {
	_, err := os.Stat(config.StateDirectory)
	if os.IsNotExist(err) {
		log.Println("StateDirectory", config.StateDirectory, "does not exist, creating it.")
		err = os.MkdirAll(config.StateDirectory, 0700)
		Check(err)
	}

	key := ReadOrCreateKey(config)
	keyBytes := Unwrap(x509.MarshalPKCS8PrivateKey(key))
	sum := blake3.Sum512(keyBytes)
	keyB3Sum512 := sum[:]

	db_path := path.Join(config.StateDirectory, "drasl.db")
	db := Unwrap(gorm.Open(sqlite.Open(db_path), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	}))

	err = db.AutoMigrate(&User{})
	Check(err)

	err = db.AutoMigrate(&Client{})
	Check(err)

	err = db.AutoMigrate(&Invite{})
	Check(err)

	cache := Unwrap(ristretto.NewCache(&ristretto.Config{
		NumCounters: 1e7,
		MaxCost:     1 << 30,
		BufferItems: 64,
	}))

	// Precompile regexes
	var transientUsernameRegex *regexp.Regexp
	if config.TransientUsers.Allow {
		transientUsernameRegex = Unwrap(regexp.Compile(config.TransientUsers.UsernameRegex))
	}

	playerCertificateKeys := make([]SerializedKey, 0, 1)
	profilePropertyKeys := make([]SerializedKey, 0, 1)
	publicKeyDer := Unwrap(x509.MarshalPKIXPublicKey(&key.PublicKey))
	serializedKey := SerializedKey{PublicKey: base64.StdEncoding.EncodeToString(publicKeyDer)}
	profilePropertyKeys = append(profilePropertyKeys, serializedKey)
	playerCertificateKeys = append(playerCertificateKeys, serializedKey)
	for _, fallbackAPIServer := range config.FallbackAPIServers {
		reqURL := Unwrap(url.JoinPath(fallbackAPIServer.ServicesURL, "publickeys"))
		res, err := http.Get(reqURL)
		if err != nil {
			log.Printf("Couldn't access fallback API server at %s: %s\n", reqURL, err)
			continue
		}
		defer res.Body.Close()

		if res.StatusCode != http.StatusOK {
			log.Printf("Request to registration server at %s resulted in status code %d\n", reqURL, res.StatusCode)
			continue
		}
		var publicKeysRes PublicKeysResponse
		err = json.NewDecoder(res.Body).Decode(&publicKeysRes)
		if err != nil {
			log.Printf("Received invalid response from registration server at %s\n", reqURL)
			continue
		}
		profilePropertyKeys = append(profilePropertyKeys, publicKeysRes.ProfilePropertyKeys...)
		playerCertificateKeys = append(playerCertificateKeys, publicKeysRes.PlayerCertificateKeys...)
	}

	app := &App{
		RequestCache:           cache,
		Config:                 config,
		TransientUsernameRegex: transientUsernameRegex,
		Constants:              Constants,
		DB:                     db,
		FSMutex:                KeyedMutex{},
		Key:                    key,
		KeyB3Sum512:            keyB3Sum512,
		FrontEndURL:            config.BaseURL,
		PlayerCertificateKeys:  playerCertificateKeys,
		ProfilePropertyKeys:    profilePropertyKeys,
		AccountURL:             Unwrap(url.JoinPath(config.BaseURL, "account")),
		AuthURL:                Unwrap(url.JoinPath(config.BaseURL, "auth")),
		ServicesURL:            Unwrap(url.JoinPath(config.BaseURL, "services")),
		SessionURL:             Unwrap(url.JoinPath(config.BaseURL, "session")),
		AuthlibInjectorURL:     Unwrap(url.JoinPath(config.BaseURL, "authlib-injector")),
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
				log.Println("No users found! Here's an invite URL:", Unwrap(InviteURL(app, &invite)))
			}
		}
	}

	return app
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
