package main

import (
	"context"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/suite"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"time"
)

const TEST_USERNAME = "foo"
const TEST_OTHER_USERNAME = "qux"
const TEST_PASSWORD = "bar"
const TEST_OTHER_PASSWORD = "hunter2"

type TestSuite struct {
	suite.Suite
	App               *App
	Config            *Config
	DataDir           string
	FrontServer       *echo.Echo
	AuthServer        *echo.Echo
	AccountServer     *echo.Echo
	ServicesServer    *echo.Echo
	SessionServer     *echo.Echo
	AuxApp            *App
	AuxConfig         *Config
	AuxDataDir        string
	AuxFrontServer    *echo.Echo
	AuxAuthServer     *echo.Echo
	AuxAccountServer  *echo.Echo
	AuxServicesServer *echo.Echo
	AuxSessionServer  *echo.Echo
}

func (ts *TestSuite) Setup(config *Config) {
	tempDataDir, err := os.MkdirTemp("", "tmp")
	Check(err)
	ts.DataDir = tempDataDir

	config.DataDirectory = tempDataDir

	ts.Config = &(*config)
	ts.App = setup(config)
	ts.FrontServer = GetFrontServer(ts.App)
	ts.AuthServer = GetAuthServer(ts.App)
	ts.AccountServer = GetAccountServer(ts.App)
	ts.SessionServer = GetSessionServer(ts.App)
	ts.ServicesServer = GetServicesServer(ts.App)

	go ts.FrontServer.Start("")
	go ts.AuthServer.Start("")
	go ts.AccountServer.Start("")
	go ts.SessionServer.Start("")
	go ts.ServicesServer.Start("")
}

func (ts *TestSuite) SetupAux(config *Config) {
	tempDataDir, err := os.MkdirTemp("", "tmp")
	Check(err)
	ts.AuxDataDir = tempDataDir

	config.DataDirectory = tempDataDir

	ts.AuxConfig = &(*config)
	ts.AuxApp = setup(config)
	ts.AuxFrontServer = GetFrontServer(ts.AuxApp)
	ts.AuxAuthServer = GetAuthServer(ts.AuxApp)
	ts.AuxAccountServer = GetAccountServer(ts.AuxApp)
	ts.AuxSessionServer = GetSessionServer(ts.AuxApp)
	ts.AuxServicesServer = GetServicesServer(ts.AuxApp)

	go ts.AuxFrontServer.Start("")
	go ts.AuxAuthServer.Start("")
	go ts.AuxAccountServer.Start("")
	go ts.AuxSessionServer.Start("")
	go ts.AuxServicesServer.Start("")

	// There doesn't seem to be another way to wait for the server to start
	// listening
	time.Sleep(1 * time.Second)
}

func (ts *TestSuite) Teardown() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	servers := []*echo.Echo{
		ts.FrontServer,
		ts.AuthServer,
		ts.AccountServer,
		ts.SessionServer,
		ts.ServicesServer,
		ts.AuxFrontServer,
		ts.AuxAuthServer,
		ts.AuxAccountServer,
		ts.AuxSessionServer,
		ts.AuxServicesServer,
	}

	for _, server := range servers {
		if server != nil {
			err := server.Shutdown(ctx)
			Check(err)
		}
	}

	err := os.RemoveAll(ts.DataDir)
	Check(err)
}

func (ts *TestSuite) CreateTestUser(frontServer *echo.Echo) {
	form := url.Values{}
	form.Set("username", TEST_USERNAME)
	form.Set("password", TEST_PASSWORD)
	req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(form.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.ParseForm()
	rec := httptest.NewRecorder()
	frontServer.ServeHTTP(rec, req)
}

func testConfig() *Config {
	config := DefaultConfig()
	config.FallbackAPIServers = []FallbackAPIServer{}
	config.LogRequests = false
	config.HideListenAddress = true
	return &config
}

func getCookie(rec *httptest.ResponseRecorder, cookieName string) *http.Cookie {
	cookies := rec.Result().Cookies()
	for i := range cookies {
		if cookies[i].Name == cookieName {
			return cookies[i]
		}
	}
	return &http.Cookie{}
}
