package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"
	"html"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
)

const RED_SKIN_BASE64_STRING = "iVBORw0KGgoAAAANSUhEUgAAAEAAAABACAYAAACqaXHeAAAAAXNSR0IArs4c6QAAAARzQklUCAgICHwIZIgAAAE+SURBVHhe7ZtBDoMwDAST/z+6pdcgMXUXCXAn4mY74PV6E0VkDhivMbbn9zHH2J77Dvw4AZABtoAakEiYIugqcPNlMF3mkvb4xF7dIlMAwnVeBoQI2AIXrxJqgCL47yK4ahgxgkQrjSdNPXv+3XlA+oI0XgDCEypi6Dq9DCDKEiVXxGm+qj+9n+zEiHgfUE2o6k8Jkl0AYKcpA6hnqxSj+WyBhZIEGBWA7GqAGnB8JqkIpj1YFbWqP/U42dUANQA0gCjU3Y7/BwhAcwRkQPMCY3oyACFq7iADmhcY05MBCFFzBxnQvMCYngxAiJo7yICzC0xHbHRElcZX8zmdAWkCabwAFBGQAUXAdu5E2XR+iidN+SKeXI7tAvDw3+xiDZABMiC7VZYpUH7hwhZIK6AGqAFqQHSzNG1Bd4LhlZs3vSioQQnlCKsAAAAASUVORK5CYII="
const BLUE_SKIN_BASE64_STRING = "iVBORw0KGgoAAAANSUhEUgAAAEAAAABACAYAAACqaXHeAAAAAXNSR0IArs4c6QAAAARzQklUCAgICHwIZIgAAAE+SURBVHhe7ZpBDoMwDATJ/x9NK/XUCGVtrVGoO73GDsl6PRTIOOTvPGXIMmAML//e7MDiEAAHeCakBQJt5knsZAcWBwNggGOx43g8A1yLe/LsFujNAAQwexwHmArsZQQtAAOA4N/fBWaGKUEUtNx8xdTa+S+eBdwLuPkIIBSoFRgH+LfBmQnZCql41RJqfM2sgj9CCDC1kapoVjBVYTWOA5ZvvWgBIGg/C2R7OhuvelyNwwAYsPIIEASCQFBRtPd44NsgArRWAAe0Lm9gczggIFLrEBzQuryBzeGAgEitQ3BA6/IGNocDAiK1DsEB9eXNfhmqPp+Q29ENDkAAce5w9wmTb4fggFzHXEUry/tXWM+gHCWy/eUhwE+fNS5gAA7AAT5HnBmAoNXGVvKnbjAABjgd7OfCAKuNreQODHgBFSioQeX4pUIAAAAASUVORK5CYII="
const RED_CAPE_BASE64_STRING = "iVBORw0KGgoAAAANSUhEUgAAAEAAAAAgCAIAAAAt/+nTAAABcGlDQ1BpY2MAACiRdZG9S8NAGMafthZFK0UUFHHIUEWwhaIgjlqHLkVKrWDVJbkmrZCk4ZIixVVwcSg4iC5+Df4HugquCoKgCCJu7n4tUuJ7TaFF2jsu748n97zcPQf4Uzoz7K44YJgOzyQT0mpuTep+RxADGKY5JTPbWkinU+g4fh7hE/UhJnp13td29OVVmwG+HuJZZnGHeJ44teVYgveIh1hRzhOfEEc5HZD4VuiKx2+CCx5/CebZzCLgFz2lQgsrLcyK3CCeJI4Yepk1ziNuElLNlWWqo7TGYCODJBKQoKCMTehwEKNqUmbtffG6bwkl8jD6WqiAk6OAInmjpJapq0pVI12lqaMicv+fp63NTHvdQwkg+Oq6n+NA9z5Qq7ru76nr1s6AwAtwbTb9Jcpp7pv0alOLHAPhHeDypqkpB8DVLjDybMlcrksBWn5NAz4ugP4cMHgP9K57WTX+4/wJyG7TE90Bh0fABO0Pb/wB/+FoCgeBR+AAAAAJcEhZcwAACxIAAAsSAdLdfvwAAAA0SURBVFjD7c8xDQAACAMw5l8008BJ0jpodn6LgICAgICAgICAgICAgICAgICAgICAgMBVAR+SIAECIeUGAAAAAElFTkSuQmCC"
const BLUE_CAPE_BASE64_STRING = "iVBORw0KGgoAAAANSUhEUgAAAEAAAAAgCAIAAAAt/+nTAAABcGlDQ1BpY2MAACiRdZG9S8NAGMafthZFK0UUFHHIUEWwhaIgjlqHLkVKrWDVJbkmrZCk4ZIixVVwcSg4iC5+Df4HugquCoKgCCJu7n4tUuJ7TaFF2jsu748n97zcPQf4Uzoz7K44YJgOzyQT0mpuTep+RxADGKY5JTPbWkinU+g4fh7hE/UhJnp13td29OVVmwG+HuJZZnGHeJ44teVYgveIh1hRzhOfEEc5HZD4VuiKx2+CCx5/CebZzCLgFz2lQgsrLcyK3CCeJI4Yepk1ziNuElLNlWWqo7TGYCODJBKQoKCMTehwEKNqUmbtffG6bwkl8jD6WqiAk6OAInmjpJapq0pVI12lqaMicv+fp63NTHvdQwkg+Oq6n+NA9z5Qq7ru76nr1s6AwAtwbTb9Jcpp7pv0alOLHAPhHeDypqkpB8DVLjDybMlcrksBWn5NAz4ugP4cMHgP9K57WTX+4/wJyG7TE90Bh0fABO0Pb/wB/+FoCgeBR+AAAAAJcEhZcwAACxIAAAsSAdLdfvwAAAA0SURBVFjD7c8xDQAACAOwzb9o0MBJ0jpok8lnFRAQEBAQEBAQEBAQEBAQEBAQEBAQEBC4Wt/DIAGQrpeYAAAAAElFTkSuQmCC"

func setupRegistrationExistingPlayerTS(requireSkinVerification bool) *TestSuite {
	ts := &TestSuite{}

	auxConfig := testConfig()
	ts.SetupAux(auxConfig)

	auxFrontURL := fmt.Sprintf("http://localhost:%d", ts.AuxFrontServer.Listener.Addr().(*net.TCPAddr).Port)
	auxAccountURL := fmt.Sprintf("http://localhost:%d", ts.AuxAccountServer.Listener.Addr().(*net.TCPAddr).Port)
	auxSessionURL := fmt.Sprintf("http://localhost:%d", ts.AuxSessionServer.Listener.Addr().(*net.TCPAddr).Port)

	// Hack: patch this after the fact...
	ts.AuxApp.Config.FrontEndServer.URL = auxFrontURL

	config := testConfig()
	config.RegistrationNewPlayer.Allow = false
	config.RegistrationExistingPlayer = registrationExistingPlayerConfig{
		Allow:                   true,
		Nickname:                "Aux",
		SessionURL:              auxSessionURL,
		AccountURL:              auxAccountURL,
		RequireSkinVerification: requireSkinVerification,
	}
	config.FallbackAPIServers = []FallbackAPIServer{
		{
			Nickname:   "Aux",
			SessionURL: auxSessionURL,
			AccountURL: auxAccountURL,
		},
	}
	ts.Setup(config)

	ts.CreateTestUser(ts.AuxFrontServer)

	return ts
}

func TestFront(t *testing.T) {
	{
		ts := &TestSuite{}

		config := testConfig()
		config.RegistrationExistingPlayer.Allow = false
		ts.Setup(config)
		defer ts.Teardown()

		t.Run("Test public pages and assets", ts.testPublic)
		t.Run("Test registration as new player", ts.testRegistrationNewPlayer)
		t.Run("Test registration as new player, chosen UUID, chosen UUID not allowed", ts.testRegistrationNewPlayerChosenUUIDNotAllowed)
		t.Run("Test login, logout", ts.testLoginLogout)
		t.Run("Test delete account", ts.testDeleteAccount)
	}
	{
		ts := &TestSuite{}

		config := testConfig()
		config.RegistrationNewPlayer.AllowChoosingUUID = true
		ts.Setup(config)
		defer ts.Teardown()

		t.Run("Test registration as new player, chosen UUID, chosen UUID allowed", ts.testRegistrationNewPlayerChosenUUID)
	}
	{
		ts := setupRegistrationExistingPlayerTS(false)
		defer ts.Teardown()

		t.Run("Test registration as existing player, no skin verification", ts.testRegistrationExistingPlayerNoVerification)
	}
	{
		ts := setupRegistrationExistingPlayerTS(true)
		defer ts.Teardown()

		t.Run("Test registration as existing player, with skin verification", ts.testRegistrationExistingPlayerWithVerification)
	}
}

func (ts *TestSuite) testStatusOK(t *testing.T, path string) {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rec := httptest.NewRecorder()

	ts.FrontServer.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func (ts *TestSuite) testPublic(t *testing.T) {
	ts.testStatusOK(t, "/")
	ts.testStatusOK(t, "/drasl/registration")
	ts.testStatusOK(t, "/drasl/public/bundle.js")
	ts.testStatusOK(t, "/drasl/public/style.css")
}

func (ts *TestSuite) registrationShouldFail(t *testing.T, rec *httptest.ResponseRecorder, errorMessage string) {
	assert.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, errorMessage, getCookie(rec, "errorMessage").Value)
	assert.Equal(t, "", getCookie(rec, "browserToken").Value)
	assert.Equal(t, ts.App.Config.FrontEndServer.URL+"/drasl/registration", rec.Header().Get("Location"))
}

func (ts *TestSuite) registrationShouldSucceed(t *testing.T, rec *httptest.ResponseRecorder) {
	assert.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, "", getCookie(rec, "errorMessage").Value)
	assert.NotEqual(t, "", getCookie(rec, "browserToken").Value)
	assert.Equal(t, ts.App.Config.FrontEndServer.URL+"/drasl/profile", rec.Header().Get("Location"))
}

func (ts *TestSuite) testRegistrationNewPlayer(t *testing.T) {
	{
		// Register
		form := url.Values{}
		form.Set("username", TEST_USERNAME)
		form.Set("password", TEST_PASSWORD)
		req := httptest.NewRequest(http.MethodPost, "/drasl/register", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		req.ParseForm()
		rec := httptest.NewRecorder()
		ts.FrontServer.ServeHTTP(rec, req)
		ts.registrationShouldSucceed(t, rec)

		// Check that the user has been created with a correct password hash/salt
		var user User
		result := ts.App.DB.First(&user, "username = ?", TEST_USERNAME)
		assert.Nil(t, result.Error)
		passwordHash, err := HashPassword(TEST_PASSWORD, user.PasswordSalt)
		assert.Nil(t, err)
		assert.Equal(t, passwordHash, user.PasswordHash)

		// Get the profile
		req = httptest.NewRequest(http.MethodGet, "/drasl/profile", nil)
		browserTokenCookie := getCookie(rec, "browserToken")
		req.AddCookie(browserTokenCookie)
		rec = httptest.NewRecorder()
		ts.FrontServer.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "", getCookie(rec, "errorMessage").Value)
	}
	{
		// Try registering again with the same username
		form := url.Values{}
		form.Set("username", TEST_USERNAME)
		form.Set("password", TEST_PASSWORD)
		req := httptest.NewRequest(http.MethodPost, "/drasl/register", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		req.ParseForm()
		rec := httptest.NewRecorder()
		ts.FrontServer.ServeHTTP(rec, req)

		ts.registrationShouldFail(t, rec, "That username is taken.")
	}
	{
		// Registration with a too-long username should fail
		form := url.Values{}
		form.Set("username", "AReallyReallyReallyLongUsername")
		form.Set("password", TEST_PASSWORD)
		req := httptest.NewRequest(http.MethodPost, "/drasl/register", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		req.ParseForm()
		rec := httptest.NewRecorder()
		ts.FrontServer.ServeHTTP(rec, req)

		ts.registrationShouldFail(t, rec, "Invalid username: can't be longer than 16 characters")
	}
	{
		// Registration with a too-short password should fail
		form := url.Values{}
		form.Set("username", TEST_OTHER_USERNAME)
		form.Set("password", "")
		req := httptest.NewRequest(http.MethodPost, "/drasl/register", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		req.ParseForm()
		rec := httptest.NewRecorder()
		ts.FrontServer.ServeHTTP(rec, req)

		ts.registrationShouldFail(t, rec, "Invalid password: can't be blank")
	}
	{
		// Registration from an existing account should fail
		form := url.Values{}
		form.Set("username", TEST_OTHER_USERNAME)
		form.Set("password", TEST_OTHER_PASSWORD)
		form.Set("existingPlayer", "on")
		form.Set("challengeToken", "This is not a valid challenge token.")
		req := httptest.NewRequest(http.MethodPost, "/drasl/register", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		req.ParseForm()
		rec := httptest.NewRecorder()
		ts.FrontServer.ServeHTTP(rec, req)
		ts.registrationShouldFail(t, rec, "Registration from an existing account is not allowed.")
	}
}

func (ts *TestSuite) testRegistrationNewPlayerChosenUUIDNotAllowed(t *testing.T) {
	uuid := "11111111-2222-3333-4444-555555555555"

	ts.App.Config.RegistrationNewPlayer.AllowChoosingUUID = false

	form := url.Values{}
	form.Set("username", TEST_USERNAME)
	form.Set("password", TEST_PASSWORD)
	form.Set("uuid", uuid)
	req := httptest.NewRequest(http.MethodPost, "/drasl/register", strings.NewReader(form.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.ParseForm()
	rec := httptest.NewRecorder()
	ts.FrontServer.ServeHTTP(rec, req)

	ts.registrationShouldFail(t, rec, "Choosing a UUID is not allowed.")
}

func (ts *TestSuite) testRegistrationNewPlayerChosenUUID(t *testing.T) {
	uuid := "11111111-2222-3333-4444-555555555555"

	{
		// Register
		form := url.Values{}
		form.Set("username", TEST_USERNAME)
		form.Set("password", TEST_PASSWORD)
		form.Set("uuid", uuid)
		req := httptest.NewRequest(http.MethodPost, "/drasl/register", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		req.ParseForm()
		rec := httptest.NewRecorder()
		ts.FrontServer.ServeHTTP(rec, req)

		// Registration should succeed, grant a browserToken, and redirect to profile
		assert.NotEqual(t, "", getCookie(rec, "browserToken"))
		ts.registrationShouldSucceed(t, rec)

		// Check that the user has been created with the UUID
		var user User
		result := ts.App.DB.First(&user, "uuid = ?", uuid)
		assert.Nil(t, result.Error)
	}
	{
		// Try registering again with the same UUID
		form := url.Values{}
		form.Set("username", TEST_OTHER_USERNAME)
		form.Set("password", TEST_PASSWORD)
		form.Set("uuid", uuid)
		req := httptest.NewRequest(http.MethodPost, "/drasl/register", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		req.ParseForm()
		rec := httptest.NewRecorder()
		ts.FrontServer.ServeHTTP(rec, req)

		ts.registrationShouldFail(t, rec, "That UUID is taken.")
	}
	{
		// Try registering with a garbage UUID
		form := url.Values{}
		form.Set("username", TEST_OTHER_USERNAME)
		form.Set("password", TEST_PASSWORD)
		form.Set("uuid", "This is not a UUID.")
		req := httptest.NewRequest(http.MethodPost, "/drasl/register", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		req.ParseForm()
		rec := httptest.NewRecorder()
		ts.FrontServer.ServeHTTP(rec, req)

		ts.registrationShouldFail(t, rec, "Invalid UUID: invalid UUID length: 19")
	}
}

func (ts *TestSuite) testLoginLogout(t *testing.T) {
	{
		// Login
		form := url.Values{}
		form.Set("username", TEST_USERNAME)
		form.Set("password", TEST_PASSWORD)
		req := httptest.NewRequest(http.MethodPost, "/drasl/login", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		req.ParseForm()
		rec := httptest.NewRecorder()
		ts.FrontServer.ServeHTTP(rec, req)

		// Login should succeed and redirect to profile
		browserTokenCookie := getCookie(rec, "browserToken")
		assert.Equal(t, http.StatusSeeOther, rec.Code)
		assert.Equal(t, "", getCookie(rec, "errorMessage").Value)
		assert.NotEqual(t, "", browserTokenCookie.Value)
		assert.Equal(t, ts.App.Config.FrontEndServer.URL+"/drasl/profile", rec.Header().Get("Location"))

		// The BrowserToken we get should match the one in the database
		var user User
		result := ts.App.DB.First(&user, "username = ?", TEST_USERNAME)
		assert.Nil(t, result.Error)
		assert.Equal(t, *UnmakeNullString(&user.BrowserToken), browserTokenCookie.Value)

		// Get profile
		req = httptest.NewRequest(http.MethodGet, "/drasl/profile", nil)
		req.AddCookie(browserTokenCookie)
		rec = httptest.NewRecorder()
		ts.FrontServer.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "", getCookie(rec, "errorMessage").Value)

		// Logout should redirect to / and clear the browserToken
		req = httptest.NewRequest(http.MethodPost, "/drasl/logout", nil)
		req.AddCookie(browserTokenCookie)
		rec = httptest.NewRecorder()
		ts.FrontServer.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusSeeOther, rec.Code)
		assert.Equal(t, ts.App.Config.FrontEndServer.URL, rec.Header().Get("Location"))
		result = ts.App.DB.First(&user, "username = ?", TEST_USERNAME)
		assert.Nil(t, result.Error)
		assert.Nil(t, UnmakeNullString(&user.BrowserToken))
	}
	{
		// Login with incorrect password should fail
		form := url.Values{}
		form.Set("username", TEST_USERNAME)
		form.Set("password", TEST_OTHER_PASSWORD)
		req := httptest.NewRequest(http.MethodPost, "/drasl/login", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		req.ParseForm()
		rec := httptest.NewRecorder()
		ts.FrontServer.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusSeeOther, rec.Code)
		assert.Equal(t, "Incorrect password!", getCookie(rec, "errorMessage").Value)
		assert.Equal(t, "", getCookie(rec, "browserToken").Value)
		assert.Equal(t, ts.App.Config.FrontEndServer.URL, rec.Header().Get("Location"))
	}
	{
		// GET /profile without valid BrowserToken should fail
		req := httptest.NewRequest(http.MethodGet, "/drasl/profile", nil)
		rec := httptest.NewRecorder()
		ts.FrontServer.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusSeeOther, rec.Code)
		assert.Equal(t, ts.App.Config.FrontEndServer.URL, rec.Header().Get("Location"))
		assert.Equal(t, "You are not logged in.", getCookie(rec, "errorMessage").Value)

		// Logout without valid BrowserToken should fail
		req = httptest.NewRequest(http.MethodPost, "/drasl/logout", nil)
		rec = httptest.NewRecorder()
		ts.FrontServer.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusSeeOther, rec.Code)
		assert.Equal(t, ts.App.Config.FrontEndServer.URL, rec.Header().Get("Location"))
		assert.Equal(t, "You are not logged in.", getCookie(rec, "errorMessage").Value)
	}
}

func (ts *TestSuite) testRegistrationExistingPlayerNoVerification(t *testing.T) {
	// Register from the existing account
	form := url.Values{}
	form.Set("username", TEST_USERNAME)
	form.Set("password", TEST_PASSWORD)
	form.Set("existingPlayer", "on")
	req := httptest.NewRequest(http.MethodPost, "/drasl/register", strings.NewReader(form.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.ParseForm()
	rec := httptest.NewRecorder()
	ts.FrontServer.ServeHTTP(rec, req)
	ts.registrationShouldSucceed(t, rec)

	// Check that the user has been created with the same UUID
	var auxUser User
	result := ts.AuxApp.DB.First(&auxUser, "username = ?", TEST_USERNAME)
	assert.Nil(t, result.Error)
	var user User
	result = ts.App.DB.First(&user, "username = ?", TEST_USERNAME)
	assert.Nil(t, result.Error)
	assert.Equal(t, auxUser.UUID, user.UUID)

	{
		// Registration as a new user should fail
		form := url.Values{}
		form.Set("username", TEST_USERNAME)
		form.Set("password", TEST_PASSWORD)
		req := httptest.NewRequest(http.MethodPost, "/drasl/register", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		req.ParseForm()
		rec := httptest.NewRecorder()
		ts.FrontServer.ServeHTTP(rec, req)
		ts.registrationShouldFail(t, rec, "Registration without some existing account is not allowed.")
	}
	{
		// Registration with a missing existing account should fail
		form := url.Values{}
		form.Set("username", TEST_OTHER_USERNAME)
		form.Set("password", TEST_PASSWORD)
		form.Set("existingPlayer", "on")
		req := httptest.NewRequest(http.MethodPost, "/drasl/register", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		req.ParseForm()
		rec := httptest.NewRecorder()
		ts.FrontServer.ServeHTTP(rec, req)
		ts.registrationShouldFail(t, rec, "Couldn't find your account, maybe try again: registration server returned error")
	}
}

func (ts *TestSuite) testRegistrationExistingPlayerWithVerification(t *testing.T) {
	{
		// Registration without setting a skin should fail
		form := url.Values{}
		form.Set("username", TEST_USERNAME)
		form.Set("password", TEST_PASSWORD)
		form.Set("existingPlayer", "on")
		req := httptest.NewRequest(http.MethodPost, "/drasl/register", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		req.ParseForm()
		rec := httptest.NewRecorder()
		ts.FrontServer.ServeHTTP(rec, req)
		ts.registrationShouldFail(t, rec, "Couldn't verify your skin, maybe try again: player does not have a skin")
	}
	{
		// Get challenge skin with invalid username should fail
		req := httptest.NewRequest(http.MethodGet, "/drasl/challenge-skin?username=AReallyReallyReallyLongUsername", nil)
		rec := httptest.NewRecorder()
		ts.FrontServer.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusSeeOther, rec.Code)
		assert.Equal(t, "Invalid username: can't be longer than 16 characters", getCookie(rec, "errorMessage").Value)
		assert.Equal(t, ts.App.Config.FrontEndServer.URL+"/drasl/registration", rec.Header().Get("Location"))
	}
	{
		// Get challenge skin
		req := httptest.NewRequest(http.MethodGet, "/drasl/challenge-skin?username="+TEST_USERNAME, nil)
		rec := httptest.NewRecorder()
		ts.FrontServer.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
		challengeToken := getCookie(rec, "challengeToken")
		assert.NotEqual(t, "", challengeToken.Value)

		base64Exp, err := regexp.Compile("src=\"data:image\\/png;base64,([A-Za-z0-9+/&#;]*={0,2})\"")
		match := base64Exp.FindStringSubmatch(rec.Body.String())
		assert.Equal(t, 2, len(match))
		// The base64 will come back HTML-escaped...
		base64String := html.UnescapeString(match[1])

		challengeSkin, err := base64.StdEncoding.DecodeString(base64String)
		assert.Nil(t, err)

		// Bypass the controller for setting the skin here, we can test that with the rest of /update
		validSkinHandle, err := ValidateSkin(ts.AuxApp, bytes.NewReader(challengeSkin))
		assert.Nil(t, err)

		var auxUser User
		result := ts.AuxApp.DB.First(&auxUser, "username = ?", TEST_USERNAME)
		assert.Nil(t, result.Error)

		err = SetSkin(ts.AuxApp, &auxUser, validSkinHandle)
		assert.Nil(t, err)

		{
			// Registration should fail if we give the wrong challenge token
			form := url.Values{}
			form.Set("username", TEST_USERNAME)
			form.Set("password", TEST_PASSWORD)
			form.Set("existingPlayer", "on")
			form.Set("challengeToken", "This is not a valid challenge token.")
			req = httptest.NewRequest(http.MethodPost, "/drasl/register", strings.NewReader(form.Encode()))
			req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
			req.ParseForm()
			rec = httptest.NewRecorder()
			ts.FrontServer.ServeHTTP(rec, req)

			ts.registrationShouldFail(t, rec, "Couldn't verify your skin, maybe try again: skin does not match")
		}
		{
			// Registration should succeed if everything is correct
			form := url.Values{}
			form.Set("username", TEST_USERNAME)
			form.Set("password", TEST_PASSWORD)
			form.Set("existingPlayer", "on")
			form.Set("challengeToken", challengeToken.Value)
			req = httptest.NewRequest(http.MethodPost, "/drasl/register", strings.NewReader(form.Encode()))
			req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
			req.ParseForm()
			rec = httptest.NewRecorder()
			ts.FrontServer.ServeHTTP(rec, req)

			ts.registrationShouldSucceed(t, rec)

			// Check that the user has been created with the same UUID
			var user User
			result = ts.App.DB.First(&user, "username = ?", TEST_USERNAME)
			assert.Nil(t, result.Error)
			assert.Equal(t, auxUser.UUID, user.UUID)
		}
	}
}

func (ts *TestSuite) testDeleteAccount(t *testing.T) {
	redSkin, err := base64.StdEncoding.DecodeString(RED_SKIN_BASE64_STRING)
	assert.Nil(t, err)

	blueSkin, err := base64.StdEncoding.DecodeString(BLUE_SKIN_BASE64_STRING)
	assert.Nil(t, err)

	redCape, err := base64.StdEncoding.DecodeString(RED_CAPE_BASE64_STRING)
	assert.Nil(t, err)

	blueCape, err := base64.StdEncoding.DecodeString(BLUE_CAPE_BASE64_STRING)
	assert.Nil(t, err)
	{
		var user User
		result := ts.App.DB.First(&user, "username = ?", TEST_USERNAME)
		assert.Nil(t, result.Error)

		// Set red skin and cape on TEST_USERNAME
		validSkinHandle, err := ValidateSkin(ts.App, bytes.NewReader(redSkin))
		assert.Nil(t, err)
		err = SetSkin(ts.App, &user, validSkinHandle)
		assert.Nil(t, err)
		validCapeHandle, err := ValidateCape(ts.App, bytes.NewReader(redCape))
		assert.Nil(t, err)
		err = SetCape(ts.App, &user, validCapeHandle)
		assert.Nil(t, err)

		// Register TEST_OTHER_USERNAME
		form := url.Values{}
		form.Set("username", TEST_OTHER_USERNAME)
		form.Set("password", TEST_OTHER_PASSWORD)
		req := httptest.NewRequest(http.MethodPost, "/drasl/register", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		req.ParseForm()
		rec := httptest.NewRecorder()
		ts.FrontServer.ServeHTTP(rec, req)
		ts.registrationShouldSucceed(t, rec)
		browserTokenCookie := getCookie(rec, "browserToken")

		// Check that TEST_OTHER_USERNAME has been created
		var otherUser User
		result = ts.App.DB.First(&otherUser, "username = ?", TEST_OTHER_USERNAME)
		assert.Nil(t, result.Error)

		// Set red skin and cape on TEST_OTHER_USERNAME
		validSkinHandle, err = ValidateSkin(ts.App, bytes.NewReader(redSkin))
		assert.Nil(t, err)
		err = SetSkin(ts.App, &otherUser, validSkinHandle)
		assert.Nil(t, err)
		validCapeHandle, err = ValidateCape(ts.App, bytes.NewReader(redCape))
		assert.Nil(t, err)
		err = SetCape(ts.App, &otherUser, validCapeHandle)
		assert.Nil(t, err)

		// Delete account TEST_OTHER_USERNAME
		req = httptest.NewRequest(http.MethodPost, "/drasl/delete-account", nil)
		req.AddCookie(browserTokenCookie)
		rec = httptest.NewRecorder()
		ts.FrontServer.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusSeeOther, rec.Code)
		assert.Equal(t, "", getCookie(rec, "errorMessage").Value)
		assert.Equal(t, ts.App.Config.FrontEndServer.URL, rec.Header().Get("Location"))

		// Check that TEST_OTHER_USERNAME has been deleted
		result = ts.App.DB.First(&otherUser, "username = ?", TEST_OTHER_USERNAME)
		assert.True(t, errors.Is(result.Error, gorm.ErrRecordNotFound))

		// Check that the red skin and cape still exist in the filesystem
		_, err = os.Stat(GetSkinPath(ts.App, *UnmakeNullString(&user.SkinHash)))
		assert.Nil(t, err)
		_, err = os.Stat(GetCapePath(ts.App, *UnmakeNullString(&user.CapeHash)))
		assert.Nil(t, err)
	}
	{
		// Register TEST_OTHER_USERNAME again
		form := url.Values{}
		form.Set("username", TEST_OTHER_USERNAME)
		form.Set("password", TEST_OTHER_PASSWORD)
		req := httptest.NewRequest(http.MethodPost, "/drasl/register", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		req.ParseForm()
		rec := httptest.NewRecorder()
		ts.FrontServer.ServeHTTP(rec, req)
		ts.registrationShouldSucceed(t, rec)
		browserTokenCookie := getCookie(rec, "browserToken")

		// Check that TEST_OTHER_USERNAME has been created
		var otherUser User
		result := ts.App.DB.First(&otherUser, "username = ?", TEST_OTHER_USERNAME)
		assert.Nil(t, result.Error)

		// Set blue skin and cape on TEST_OTHER_USERNAME
		validSkinHandle, err := ValidateSkin(ts.App, bytes.NewReader(blueSkin))
		assert.Nil(t, err)
		err = SetSkin(ts.App, &otherUser, validSkinHandle)
		assert.Nil(t, err)
		validCapeHandle, err := ValidateCape(ts.App, bytes.NewReader(blueCape))
		assert.Nil(t, err)
		err = SetCape(ts.App, &otherUser, validCapeHandle)
		assert.Nil(t, err)

		blueSkinHash := *UnmakeNullString(&otherUser.SkinHash)
		blueCapeHash := *UnmakeNullString(&otherUser.CapeHash)

		// Delete account TEST_OTHER_USERNAME
		req = httptest.NewRequest(http.MethodPost, "/drasl/delete-account", nil)
		req.AddCookie(browserTokenCookie)
		rec = httptest.NewRecorder()
		ts.FrontServer.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusSeeOther, rec.Code)
		assert.Equal(t, "", getCookie(rec, "errorMessage").Value)
		assert.Equal(t, ts.App.Config.FrontEndServer.URL, rec.Header().Get("Location"))

		// Check that the blue skin and cape no longer exist in the filesystem
		_, err = os.Stat(GetSkinPath(ts.App, blueSkinHash))
		assert.True(t, os.IsNotExist(err))
		_, err = os.Stat(GetCapePath(ts.App, blueCapeHash))
		assert.True(t, os.IsNotExist(err))
	}
	{
		// Delete account without valid BrowserToken should fail
		req := httptest.NewRequest(http.MethodPost, "/drasl/delete-account", nil)
		rec := httptest.NewRecorder()
		ts.FrontServer.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusSeeOther, rec.Code)
		assert.Equal(t, ts.App.Config.FrontEndServer.URL, rec.Header().Get("Location"))
		assert.Equal(t, "You are not logged in.", getCookie(rec, "errorMessage").Value)
	}
}
