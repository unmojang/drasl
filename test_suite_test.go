package main

import (
	"context"
	"fmt"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/suite"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"time"
)

const TEST_USERNAME = "username"
const TEST_PASSWORD = "password"

type TestSuite struct {
	suite.Suite
	App               *App
	Config            *Config
	StateDirectory    string
	Server            *echo.Echo
	AuxApp            *App
	AuxConfig         *Config
	AuxStateDirectory string
	AuxServer         *echo.Echo
}

func (ts *TestSuite) Setup(config *Config) {
	tempStateDirectory, err := os.MkdirTemp("", "tmp")
	Check(err)
	ts.StateDirectory = tempStateDirectory

	config.StateDirectory = tempStateDirectory
	config.DataDirectory = "."

	ts.Config = &(*config)
	ts.App = setup(config)
	ts.Server = GetServer(ts.App)

	go ts.Server.Start("")
}

func (ts *TestSuite) SetupAux(config *Config) {
	tempStateDirectory, err := os.MkdirTemp("", "tmp")
	Check(err)
	ts.AuxStateDirectory = tempStateDirectory

	config.StateDirectory = tempStateDirectory
	config.DataDirectory = "."

	ts.AuxConfig = &(*config)
	ts.AuxApp = setup(config)
	ts.AuxServer = GetServer(ts.AuxApp)

	go ts.AuxServer.Start("")

	// There doesn't seem to be another way to wait for the server to start
	// listening
	time.Sleep(1 * time.Second)

	// Hack: patch these after we know the listen address
	baseURL := fmt.Sprintf("http://localhost:%d", ts.AuxServer.Listener.Addr().(*net.TCPAddr).Port)
	ts.AuxApp.Config.BaseURL = baseURL
	ts.AuxApp.FrontEndURL = baseURL
	ts.AuxApp.AccountURL = Unwrap(url.JoinPath(baseURL, "account"))
	ts.AuxApp.AuthURL = Unwrap(url.JoinPath(baseURL, "auth"))
	ts.AuxApp.ServicesURL = Unwrap(url.JoinPath(baseURL, "services"))
	ts.AuxApp.SessionURL = Unwrap(url.JoinPath(baseURL, "session"))
}

func (ts *TestSuite) Teardown() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	servers := []*echo.Echo{
		ts.Server,
		ts.AuxServer,
	}

	for _, server := range servers {
		if server != nil {
			err := server.Shutdown(ctx)
			Check(err)
		}
	}

	err := os.RemoveAll(ts.StateDirectory)
	Check(err)
}

func (ts *TestSuite) CreateTestUser(server *echo.Echo, username string) *http.Cookie {
	form := url.Values{}
	form.Set("username", username)
	form.Set("password", TEST_PASSWORD)
	req := httptest.NewRequest(http.MethodPost, "/drasl/register", strings.NewReader(form.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.ParseForm()
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	return getCookie(rec, "browserToken")
}

func (ts *TestSuite) Get(server *echo.Echo, path string, cookies []http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	for _, cookie := range cookies {
		req.AddCookie(&cookie)
	}
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	return rec
}

func (ts *TestSuite) PostForm(server *echo.Echo, path string, form url.Values, cookies []http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.ParseForm()
	for _, cookie := range cookies {
		req.AddCookie(&cookie)
	}
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	return rec
}

func testConfig() *Config {
	config := DefaultConfig()
	noRateLimit := rateLimitConfig{Enable: false}
	config.RateLimit = noRateLimit
	config.MinPasswordLength = 8
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
