package main

import (
	"context"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/suite"
	"net/http"
	"net/http/httptest"
	"os"
	"time"
)

const TEST_USERNAME = "foo"
const TEST_OTHER_USERNAME = "qux"
const TEST_PASSWORD = "bar"
const TEST_OTHER_PASSWORD = "hunter2"

type TestSuite struct {
	suite.Suite
	App            *App
	Config         *Config
	FrontServer    *echo.Echo
	AuthServer     *echo.Echo
	AccountServer  *echo.Echo
	ServicesServer *echo.Echo
	SessionServer  *echo.Echo
	DataDir        string
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

func (ts *TestSuite) Teardown() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := ts.FrontServer.Shutdown(ctx)
	Check(err)

	err = ts.AuthServer.Shutdown(ctx)
	Check(err)

	err = ts.AccountServer.Shutdown(ctx)
	Check(err)

	err = ts.SessionServer.Shutdown(ctx)
	Check(err)

	err = ts.ServicesServer.Shutdown(ctx)
	Check(err)

	err = os.RemoveAll(ts.DataDir)
	Check(err)
}

func testConfig() *Config {
	config := DefaultConfig()
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
