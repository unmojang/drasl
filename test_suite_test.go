package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"io"
	"io/ioutil"
	"log"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

const TEST_USERNAME = "username"
const TEST_OTHER_USERNAME = "otherUsername"
const TEST_USERNAME_UPPERCASE = "USERNAME"
const TEST_PASSWORD = "password"

const RED_SKIN_BASE64_STRING = "iVBORw0KGgoAAAANSUhEUgAAAEAAAABACAYAAACqaXHeAAAAAXNSR0IArs4c6QAAAARzQklUCAgICHwIZIgAAAE+SURBVHhe7ZtBDoMwDAST/z+6pdcgMXUXCXAn4mY74PV6E0VkDhivMbbn9zHH2J77Dvw4AZABtoAakEiYIugqcPNlMF3mkvb4xF7dIlMAwnVeBoQI2AIXrxJqgCL47yK4ahgxgkQrjSdNPXv+3XlA+oI0XgDCEypi6Dq9DCDKEiVXxGm+qj+9n+zEiHgfUE2o6k8Jkl0AYKcpA6hnqxSj+WyBhZIEGBWA7GqAGnB8JqkIpj1YFbWqP/U42dUANQA0gCjU3Y7/BwhAcwRkQPMCY3oyACFq7iADmhcY05MBCFFzBxnQvMCYngxAiJo7yICzC0xHbHRElcZX8zmdAWkCabwAFBGQAUXAdu5E2XR+iidN+SKeXI7tAvDw3+xiDZABMiC7VZYpUH7hwhZIK6AGqAFqQHSzNG1Bd4LhlZs3vSioQQnlCKsAAAAASUVORK5CYII="

var RED_SKIN []byte = Unwrap(base64.StdEncoding.DecodeString(RED_SKIN_BASE64_STRING))

const BLUE_SKIN_BASE64_STRING = "iVBORw0KGgoAAAANSUhEUgAAAEAAAABACAYAAACqaXHeAAAAAXNSR0IArs4c6QAAAARzQklUCAgICHwIZIgAAAE+SURBVHhe7ZpBDoMwDATJ/x9NK/XUCGVtrVGoO73GDsl6PRTIOOTvPGXIMmAML//e7MDiEAAHeCakBQJt5knsZAcWBwNggGOx43g8A1yLe/LsFujNAAQwexwHmArsZQQtAAOA4N/fBWaGKUEUtNx8xdTa+S+eBdwLuPkIIBSoFRgH+LfBmQnZCql41RJqfM2sgj9CCDC1kapoVjBVYTWOA5ZvvWgBIGg/C2R7OhuvelyNwwAYsPIIEASCQFBRtPd44NsgArRWAAe0Lm9gczggIFLrEBzQuryBzeGAgEitQ3BA6/IGNocDAiK1DsEB9eXNfhmqPp+Q29ENDkAAce5w9wmTb4fggFzHXEUry/tXWM+gHCWy/eUhwE+fNS5gAA7AAT5HnBmAoNXGVvKnbjAABjgd7OfCAKuNreQODHgBFSioQeX4pUIAAAAASUVORK5CYII="

var BLUE_SKIN []byte = Unwrap(base64.StdEncoding.DecodeString(BLUE_SKIN_BASE64_STRING))

const INVALID_SKIN_BASE64_STRING = "iVBORw0KGgoAAAANSUhEUgAAAQAAAAABCAIAAAC+O+cgAAAACXBIWXMAAC4jAAAuIwF4pT92AAAAD0lEQVQoz2NgGAWjYAQDAAMBAAGf4uJmAAAAAElFTkSuQmCC"

var INVALID_SKIN []byte = Unwrap(base64.StdEncoding.DecodeString(INVALID_SKIN_BASE64_STRING))

const RED_CAPE_BASE64_STRING = "iVBORw0KGgoAAAANSUhEUgAAAEAAAAAgCAIAAAAt/+nTAAABcGlDQ1BpY2MAACiRdZG9S8NAGMafthZFK0UUFHHIUEWwhaIgjlqHLkVKrWDVJbkmrZCk4ZIixVVwcSg4iC5+Df4HugquCoKgCCJu7n4tUuJ7TaFF2jsu748n97zcPQf4Uzoz7K44YJgOzyQT0mpuTep+RxADGKY5JTPbWkinU+g4fh7hE/UhJnp13td29OVVmwG+HuJZZnGHeJ44teVYgveIh1hRzhOfEEc5HZD4VuiKx2+CCx5/CebZzCLgFz2lQgsrLcyK3CCeJI4Yepk1ziNuElLNlWWqo7TGYCODJBKQoKCMTehwEKNqUmbtffG6bwkl8jD6WqiAk6OAInmjpJapq0pVI12lqaMicv+fp63NTHvdQwkg+Oq6n+NA9z5Qq7ru76nr1s6AwAtwbTb9Jcpp7pv0alOLHAPhHeDypqkpB8DVLjDybMlcrksBWn5NAz4ugP4cMHgP9K57WTX+4/wJyG7TE90Bh0fABO0Pb/wB/+FoCgeBR+AAAAAJcEhZcwAACxIAAAsSAdLdfvwAAAA0SURBVFjD7c8xDQAACAMw5l8008BJ0jpodn6LgICAgICAgICAgICAgICAgICAgICAgMBVAR+SIAECIeUGAAAAAElFTkSuQmCC"

var RED_CAPE []byte = Unwrap(base64.StdEncoding.DecodeString(RED_CAPE_BASE64_STRING))

const BLUE_CAPE_BASE64_STRING = "iVBORw0KGgoAAAANSUhEUgAAAEAAAAAgCAIAAAAt/+nTAAABcGlDQ1BpY2MAACiRdZG9S8NAGMafthZFK0UUFHHIUEWwhaIgjlqHLkVKrWDVJbkmrZCk4ZIixVVwcSg4iC5+Df4HugquCoKgCCJu7n4tUuJ7TaFF2jsu748n97zcPQf4Uzoz7K44YJgOzyQT0mpuTep+RxADGKY5JTPbWkinU+g4fh7hE/UhJnp13td29OVVmwG+HuJZZnGHeJ44teVYgveIh1hRzhOfEEc5HZD4VuiKx2+CCx5/CebZzCLgFz2lQgsrLcyK3CCeJI4Yepk1ziNuElLNlWWqo7TGYCODJBKQoKCMTehwEKNqUmbtffG6bwkl8jD6WqiAk6OAInmjpJapq0pVI12lqaMicv+fp63NTHvdQwkg+Oq6n+NA9z5Qq7ru76nr1s6AwAtwbTb9Jcpp7pv0alOLHAPhHeDypqkpB8DVLjDybMlcrksBWn5NAz4ugP4cMHgP9K57WTX+4/wJyG7TE90Bh0fABO0Pb/wB/+FoCgeBR+AAAAAJcEhZcwAACxIAAAsSAdLdfvwAAAA0SURBVFjD7c8xDQAACAOwzb9o0MBJ0jpok8lnFRAQEBAQEBAQEBAQEBAQEBAQEBAQEBC4Wt/DIAGQrpeYAAAAAElFTkSuQmCC"

var BLUE_CAPE []byte = Unwrap(base64.StdEncoding.DecodeString(BLUE_CAPE_BASE64_STRING))

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
	log.SetOutput(ioutil.Discard)

	tempStateDirectory := Unwrap(os.MkdirTemp("", "tmp"))
	ts.StateDirectory = tempStateDirectory

	config.StateDirectory = tempStateDirectory
	config.DataDirectory = "."

	ts.Config = &(*config)
	ts.App = setup(config)
	ts.Server = GetServer(ts.App)

	go ts.Server.Start("")
}

func (ts *TestSuite) SetupAux(config *Config) {
	tempStateDirectory := Unwrap(os.MkdirTemp("", "tmp"))
	ts.AuxStateDirectory = tempStateDirectory

	config.StateDirectory = tempStateDirectory
	config.DataDirectory = "."

	ts.AuxConfig = &(*config)
	ts.AuxApp = setup(config)
	ts.AuxServer = GetServer(ts.AuxApp)

	go ts.AuxServer.Start("")

	// Wait until the server has a listen address... polling seems like the
	// easiest way
	timeout := 1000
	for ts.AuxServer.Listener == nil && timeout > 0 {
		time.Sleep(1 * time.Millisecond)
		timeout -= 1
	}

	// Hack: patch these after we know the listen address
	baseURL := fmt.Sprintf("http://localhost:%d/", ts.AuxServer.Listener.Addr().(*net.TCPAddr).Port)
	ts.AuxApp.Config.BaseURL = baseURL
	ts.AuxApp.FrontEndURL = baseURL
	ts.AuxApp.AccountURL = Unwrap(url.JoinPath(baseURL, "account"))
	ts.AuxApp.AuthURL = Unwrap(url.JoinPath(baseURL, "auth"))
	ts.AuxApp.ServicesURL = Unwrap(url.JoinPath(baseURL, "services"))
	ts.AuxApp.SessionURL = Unwrap(url.JoinPath(baseURL, "session"))
}

func (ts *TestSuite) ToFallbackAPIServer(app *App, nickname string) FallbackAPIServer {
	return FallbackAPIServer{
		Nickname:        nickname,
		SessionURL:      app.SessionURL,
		AccountURL:      app.AccountURL,
		ServicesURL:     app.ServicesURL,
		CacheTTLSeconds: 3600,
	}
}

func (ts *TestSuite) CheckAuthlibInjectorHeader(t *testing.T, app *App, rec *httptest.ResponseRecorder) {
	assert.Equal(t, app.AuthlibInjectorURL, rec.Header().Get("X-Authlib-Injector-API-Location"))
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

func (ts *TestSuite) CreateTestUser(server *echo.Echo, username string) (*User, *http.Cookie) {
	form := url.Values{}
	form.Set("username", username)
	form.Set("password", TEST_PASSWORD)
	req := httptest.NewRequest(http.MethodPost, "/web/register", strings.NewReader(form.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.ParseForm()
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)

	var user User
	ts.App.DB.First(&user, "username = ?", username)

	browserToken := getCookie(rec, "browserToken")

	return &user, browserToken
}

func (ts *TestSuite) Get(t *testing.T, server *echo.Echo, path string, cookies []http.Cookie, accessToken *string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	for _, cookie := range cookies {
		req.AddCookie(&cookie)
	}
	if accessToken != nil {
		req.Header.Add("Authorization", "Bearer "+*accessToken)
	}
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	ts.CheckAuthlibInjectorHeader(t, ts.App, rec)
	return rec
}

func (ts *TestSuite) Delete(t *testing.T, server *echo.Echo, path string, cookies []http.Cookie, accessToken *string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodDelete, path, nil)
	for _, cookie := range cookies {
		req.AddCookie(&cookie)
	}
	if accessToken != nil {
		req.Header.Add("Authorization", "Bearer "+*accessToken)
	}
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	ts.CheckAuthlibInjectorHeader(t, ts.App, rec)
	return rec
}

func (ts *TestSuite) PostForm(t *testing.T, server *echo.Echo, path string, form url.Values, cookies []http.Cookie, accessToken *string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.ParseForm()
	for _, cookie := range cookies {
		req.AddCookie(&cookie)
	}
	if accessToken != nil {
		req.Header.Add("Authorization", "Bearer "+*accessToken)
	}
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	ts.CheckAuthlibInjectorHeader(t, ts.App, rec)
	return rec
}

func (ts *TestSuite) PostMultipart(t *testing.T, server *echo.Echo, path string, body io.Reader, writer *multipart.Writer, cookies []http.Cookie, accessToken *string) *httptest.ResponseRecorder {
	assert.Nil(t, writer.Close())
	req := httptest.NewRequest(http.MethodPost, path, body)
	for _, cookie := range cookies {
		req.AddCookie(&cookie)
	}
	if accessToken != nil {
		req.Header.Add("Authorization", "Bearer "+*accessToken)
	}
	req.Header.Add("Content-Type", writer.FormDataContentType())
	rec := httptest.NewRecorder()
	ts.Server.ServeHTTP(rec, req)
	ts.CheckAuthlibInjectorHeader(t, ts.App, rec)
	return rec
}

func (ts *TestSuite) PostJSON(t *testing.T, server *echo.Echo, path string, payload interface{}, cookies []http.Cookie, accessToken *string) *httptest.ResponseRecorder {
	body, err := json.Marshal(payload)
	assert.Nil(t, err)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewBuffer(body))
	for _, cookie := range cookies {
		req.AddCookie(&cookie)
	}
	if accessToken != nil {
		req.Header.Add("Authorization", "Bearer "+*accessToken)
	}
	req.Header.Add("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	ts.CheckAuthlibInjectorHeader(t, ts.App, rec)
	return rec

}

func testConfig() *Config {
	config := DefaultConfig()
	config.BaseURL = "https://drasl.example.com"
	config.Domain = "drasl.example.com"
	noRateLimit := rateLimitConfig{Enable: false}
	config.RateLimit = noRateLimit
	config.FallbackAPIServers = []FallbackAPIServer{}
	config.LogRequests = false
	config.TestMode = true
	config.ServeSwaggerDocs = false
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
