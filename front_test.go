package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"
	"html"
	"io"
	"lukechampine.com/blake3"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"testing"
)

const RED_SKIN_BASE64_STRING = "iVBORw0KGgoAAAANSUhEUgAAAEAAAABACAYAAACqaXHeAAAAAXNSR0IArs4c6QAAAARzQklUCAgICHwIZIgAAAE+SURBVHhe7ZtBDoMwDAST/z+6pdcgMXUXCXAn4mY74PV6E0VkDhivMbbn9zHH2J77Dvw4AZABtoAakEiYIugqcPNlMF3mkvb4xF7dIlMAwnVeBoQI2AIXrxJqgCL47yK4ahgxgkQrjSdNPXv+3XlA+oI0XgDCEypi6Dq9DCDKEiVXxGm+qj+9n+zEiHgfUE2o6k8Jkl0AYKcpA6hnqxSj+WyBhZIEGBWA7GqAGnB8JqkIpj1YFbWqP/U42dUANQA0gCjU3Y7/BwhAcwRkQPMCY3oyACFq7iADmhcY05MBCFFzBxnQvMCYngxAiJo7yICzC0xHbHRElcZX8zmdAWkCabwAFBGQAUXAdu5E2XR+iidN+SKeXI7tAvDw3+xiDZABMiC7VZYpUH7hwhZIK6AGqAFqQHSzNG1Bd4LhlZs3vSioQQnlCKsAAAAASUVORK5CYII="
const BLUE_SKIN_BASE64_STRING = "iVBORw0KGgoAAAANSUhEUgAAAEAAAABACAYAAACqaXHeAAAAAXNSR0IArs4c6QAAAARzQklUCAgICHwIZIgAAAE+SURBVHhe7ZpBDoMwDATJ/x9NK/XUCGVtrVGoO73GDsl6PRTIOOTvPGXIMmAML//e7MDiEAAHeCakBQJt5knsZAcWBwNggGOx43g8A1yLe/LsFujNAAQwexwHmArsZQQtAAOA4N/fBWaGKUEUtNx8xdTa+S+eBdwLuPkIIBSoFRgH+LfBmQnZCql41RJqfM2sgj9CCDC1kapoVjBVYTWOA5ZvvWgBIGg/C2R7OhuvelyNwwAYsPIIEASCQFBRtPd44NsgArRWAAe0Lm9gczggIFLrEBzQuryBzeGAgEitQ3BA6/IGNocDAiK1DsEB9eXNfhmqPp+Q29ENDkAAce5w9wmTb4fggFzHXEUry/tXWM+gHCWy/eUhwE+fNS5gAA7AAT5HnBmAoNXGVvKnbjAABjgd7OfCAKuNreQODHgBFSioQeX4pUIAAAAASUVORK5CYII="
const RED_CAPE_BASE64_STRING = "iVBORw0KGgoAAAANSUhEUgAAAEAAAAAgCAIAAAAt/+nTAAABcGlDQ1BpY2MAACiRdZG9S8NAGMafthZFK0UUFHHIUEWwhaIgjlqHLkVKrWDVJbkmrZCk4ZIixVVwcSg4iC5+Df4HugquCoKgCCJu7n4tUuJ7TaFF2jsu748n97zcPQf4Uzoz7K44YJgOzyQT0mpuTep+RxADGKY5JTPbWkinU+g4fh7hE/UhJnp13td29OVVmwG+HuJZZnGHeJ44teVYgveIh1hRzhOfEEc5HZD4VuiKx2+CCx5/CebZzCLgFz2lQgsrLcyK3CCeJI4Yepk1ziNuElLNlWWqo7TGYCODJBKQoKCMTehwEKNqUmbtffG6bwkl8jD6WqiAk6OAInmjpJapq0pVI12lqaMicv+fp63NTHvdQwkg+Oq6n+NA9z5Qq7ru76nr1s6AwAtwbTb9Jcpp7pv0alOLHAPhHeDypqkpB8DVLjDybMlcrksBWn5NAz4ugP4cMHgP9K57WTX+4/wJyG7TE90Bh0fABO0Pb/wB/+FoCgeBR+AAAAAJcEhZcwAACxIAAAsSAdLdfvwAAAA0SURBVFjD7c8xDQAACAMw5l8008BJ0jpodn6LgICAgICAgICAgICAgICAgICAgICAgMBVAR+SIAECIeUGAAAAAElFTkSuQmCC"
const BLUE_CAPE_BASE64_STRING = "iVBORw0KGgoAAAANSUhEUgAAAEAAAAAgCAIAAAAt/+nTAAABcGlDQ1BpY2MAACiRdZG9S8NAGMafthZFK0UUFHHIUEWwhaIgjlqHLkVKrWDVJbkmrZCk4ZIixVVwcSg4iC5+Df4HugquCoKgCCJu7n4tUuJ7TaFF2jsu748n97zcPQf4Uzoz7K44YJgOzyQT0mpuTep+RxADGKY5JTPbWkinU+g4fh7hE/UhJnp13td29OVVmwG+HuJZZnGHeJ44teVYgveIh1hRzhOfEEc5HZD4VuiKx2+CCx5/CebZzCLgFz2lQgsrLcyK3CCeJI4Yepk1ziNuElLNlWWqo7TGYCODJBKQoKCMTehwEKNqUmbtffG6bwkl8jD6WqiAk6OAInmjpJapq0pVI12lqaMicv+fp63NTHvdQwkg+Oq6n+NA9z5Qq7ru76nr1s6AwAtwbTb9Jcpp7pv0alOLHAPhHeDypqkpB8DVLjDybMlcrksBWn5NAz4ugP4cMHgP9K57WTX+4/wJyG7TE90Bh0fABO0Pb/wB/+FoCgeBR+AAAAAJcEhZcwAACxIAAAsSAdLdfvwAAAA0SURBVFjD7c8xDQAACAOwzb9o0MBJ0jpok8lnFRAQEBAQEBAQEBAQEBAQEBAQEBAQEBC4Wt/DIAGQrpeYAAAAAElFTkSuQmCC"

var FAKE_BROWSER_TOKEN = "deadbeef"

var EXISTING_USERNAME = "existing"

func setupRegistrationExistingPlayerTS(requireSkinVerification bool) *TestSuite {
	ts := &TestSuite{}

	auxConfig := testConfig()
	ts.SetupAux(auxConfig)

	config := testConfig()
	config.RegistrationNewPlayer.Allow = false
	config.RegistrationExistingPlayer = registrationExistingPlayerConfig{
		Allow:                   true,
		Nickname:                "Aux",
		SessionURL:              ts.AuxApp.SessionURL,
		AccountURL:              ts.AuxApp.AccountURL,
		RequireSkinVerification: requireSkinVerification,
	}
	config.FallbackAPIServers = []FallbackAPIServer{
		{
			Nickname:   "Aux",
			SessionURL: ts.AuxApp.SessionURL,
			AccountURL: ts.AuxApp.AccountURL,
		},
	}
	ts.Setup(config)

	ts.CreateTestUser(ts.AuxServer, EXISTING_USERNAME)

	return ts
}

func (ts *TestSuite) testStatusOK(t *testing.T, path string) {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rec := httptest.NewRecorder()

	ts.Server.ServeHTTP(rec, req)

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
	assert.Equal(t, ts.App.FrontEndURL+"/drasl/registration", rec.Header().Get("Location"))
}

func (ts *TestSuite) registrationShouldSucceed(t *testing.T, rec *httptest.ResponseRecorder) {
	assert.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, "", getCookie(rec, "errorMessage").Value)
	assert.NotEqual(t, "", getCookie(rec, "browserToken").Value)
	assert.Equal(t, ts.App.FrontEndURL+"/drasl/profile", rec.Header().Get("Location"))
}

func (ts *TestSuite) updateShouldFail(t *testing.T, rec *httptest.ResponseRecorder, errorMessage string) {
	assert.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, errorMessage, getCookie(rec, "errorMessage").Value)
	assert.Equal(t, "", getCookie(rec, "browserToken").Value)
	assert.Equal(t, ts.App.FrontEndURL+"/drasl/profile", rec.Header().Get("Location"))
}

func (ts *TestSuite) updateShouldSucceed(t *testing.T, rec *httptest.ResponseRecorder) {
	assert.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, "", getCookie(rec, "errorMessage").Value)
	assert.Equal(t, "", getCookie(rec, "browserToken").Value)
	assert.Equal(t, ts.App.FrontEndURL+"/drasl/profile", rec.Header().Get("Location"))
}

func (ts *TestSuite) loginShouldSucceed(t *testing.T, rec *httptest.ResponseRecorder) {
	assert.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, "", getCookie(rec, "errorMessage").Value)
	assert.NotEqual(t, "", getCookie(rec, "browserToken").Value)
	assert.Equal(t, ts.App.FrontEndURL+"/drasl/profile", rec.Header().Get("Location"))
}

func (ts *TestSuite) loginShouldFail(t *testing.T, rec *httptest.ResponseRecorder, errorMessage string) {
	assert.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, errorMessage, getCookie(rec, "errorMessage").Value)
	assert.Equal(t, "", getCookie(rec, "browserToken").Value)
	assert.Equal(t, ts.App.FrontEndURL, rec.Header().Get("Location"))
}

func TestFront(t *testing.T) {
	{
		// Registration as existing player not allowed
		ts := &TestSuite{}

		config := testConfig()
		config.RegistrationExistingPlayer.Allow = false
		ts.Setup(config)
		defer ts.Teardown()

		t.Run("Test public pages and assets", ts.testPublic)
		t.Run("Test registration as new player", ts.testRegistrationNewPlayer)
		t.Run("Test registration as new player, chosen UUID, chosen UUID not allowed", ts.testRegistrationNewPlayerChosenUUIDNotAllowed)
		t.Run("Test profile update", ts.testUpdate)
		t.Run("Test login, logout", ts.testLoginLogout)
		t.Run("Test delete account", ts.testDeleteAccount)
	}
	{
		// Choosing UUID allowed
		ts := &TestSuite{}

		config := testConfig()
		config.RegistrationNewPlayer.AllowChoosingUUID = true
		ts.Setup(config)
		defer ts.Teardown()

		t.Run("Test registration as new player, chosen UUID, chosen UUID allowed", ts.testRegistrationNewPlayerChosenUUID)
	}
	{
		// Low rate limit
		ts := &TestSuite{}

		config := testConfig()
		config.RateLimit = rateLimitConfig{
			Enable:            true,
			RequestsPerSecond: 2,
		}
		ts.Setup(config)
		defer ts.Teardown()

		t.Run("Test rate limiting", ts.testRateLimit)
	}
	{
		// Registration as existing player allowed, skin verification not required
		ts := setupRegistrationExistingPlayerTS(false)
		defer ts.Teardown()

		t.Run("Test registration as existing player, no skin verification", ts.testRegistrationExistingPlayerNoVerification)
	}
	{
		// Registration as existing player allowed, skin verification required
		ts := setupRegistrationExistingPlayerTS(true)
		defer ts.Teardown()

		t.Run("Test registration as existing player, with skin verification", ts.testRegistrationExistingPlayerWithVerification)
	}
}

func (ts *TestSuite) testRateLimit(t *testing.T) {
	form := url.Values{}
	form.Set("username", "")
	form.Set("password", "")

	// Login should fail the first time due to missing account, then
	// soon get rate-limited
	rec := ts.PostForm(ts.Server, "/drasl/login", form, nil)
	ts.loginShouldFail(t, rec, "User not found!")
	rec = ts.PostForm(ts.Server, "/drasl/login", form, nil)
	ts.loginShouldFail(t, rec, "User not found!")
	rec = ts.PostForm(ts.Server, "/drasl/login", form, nil)
	ts.loginShouldFail(t, rec, "Too many requests. Try again later.")

	// Static paths should not be rate-limited
	rec = ts.Get(ts.Server, "/drasl/registration", nil)
	assert.Equal(t, http.StatusOK, rec.Code)
	rec = ts.Get(ts.Server, "/drasl/registration", nil)
	assert.Equal(t, http.StatusOK, rec.Code)
	rec = ts.Get(ts.Server, "/drasl/registration", nil)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func (ts *TestSuite) testRegistrationNewPlayer(t *testing.T) {
	usernameA := "registrationNewA"
	usernameB := "registrationNewB"
	{
		// Register
		form := url.Values{}
		form.Set("username", usernameA)
		form.Set("password", TEST_PASSWORD)
		rec := ts.PostForm(ts.Server, "/drasl/register", form, nil)
		ts.registrationShouldSucceed(t, rec)

		// Check that the user has been created with a correct password hash/salt
		var user User
		result := ts.App.DB.First(&user, "username = ?", usernameA)
		assert.Nil(t, result.Error)
		passwordHash, err := HashPassword(TEST_PASSWORD, user.PasswordSalt)
		assert.Nil(t, err)
		assert.Equal(t, passwordHash, user.PasswordHash)

		// Get the profile
		req := httptest.NewRequest(http.MethodGet, "/drasl/profile", nil)
		browserTokenCookie := getCookie(rec, "browserToken")
		req.AddCookie(browserTokenCookie)
		rec = httptest.NewRecorder()
		ts.Server.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "", getCookie(rec, "errorMessage").Value)
	}
	{
		// Try registering again with the same username
		form := url.Values{}
		form.Set("username", usernameA)
		form.Set("password", TEST_PASSWORD)
		rec := ts.PostForm(ts.Server, "/drasl/register", form, nil)

		ts.registrationShouldFail(t, rec, "That username is taken.")
	}
	{
		// Registration with a too-long username should fail
		form := url.Values{}
		form.Set("username", "AReallyReallyReallyLongUsername")
		form.Set("password", TEST_PASSWORD)
		rec := ts.PostForm(ts.Server, "/drasl/register", form, nil)

		ts.registrationShouldFail(t, rec, "Invalid username: can't be longer than 16 characters")
	}
	{
		// Registration with a too-short password should fail
		form := url.Values{}
		form.Set("username", usernameB)
		form.Set("password", "")
		rec := ts.PostForm(ts.Server, "/drasl/register", form, nil)

		ts.registrationShouldFail(t, rec, "Invalid password: can't be blank")
	}
	{
		// Registration from an existing account should fail
		form := url.Values{}
		form.Set("username", usernameB)
		form.Set("password", TEST_PASSWORD)
		form.Set("existingPlayer", "on")
		form.Set("challengeToken", "This is not a valid challenge token.")
		rec := ts.PostForm(ts.Server, "/drasl/register", form, nil)

		ts.registrationShouldFail(t, rec, "Registration from an existing account is not allowed.")
	}
}

func (ts *TestSuite) testRegistrationNewPlayerChosenUUIDNotAllowed(t *testing.T) {
	username := "noChosenUUID"
	ts.CreateTestUser(ts.Server, username)

	uuid := "11111111-2222-3333-4444-555555555555"

	ts.App.Config.RegistrationNewPlayer.AllowChoosingUUID = false

	form := url.Values{}
	form.Set("username", username)
	form.Set("password", TEST_PASSWORD)
	form.Set("uuid", uuid)
	rec := ts.PostForm(ts.Server, "/drasl/register", form, nil)

	ts.registrationShouldFail(t, rec, "Choosing a UUID is not allowed.")
}

func (ts *TestSuite) testRegistrationNewPlayerChosenUUID(t *testing.T) {
	username_a := "chosenUUIDA"
	username_b := "chosenUUIDB"
	uuid := "11111111-2222-3333-4444-555555555555"
	{
		// Register
		form := url.Values{}
		form.Set("username", username_a)
		form.Set("password", TEST_PASSWORD)
		form.Set("uuid", uuid)
		rec := ts.PostForm(ts.Server, "/drasl/register", form, nil)

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
		form.Set("username", username_b)
		form.Set("password", TEST_PASSWORD)
		form.Set("uuid", uuid)
		rec := ts.PostForm(ts.Server, "/drasl/register", form, nil)

		ts.registrationShouldFail(t, rec, "That UUID is taken.")
	}
	{
		// Try registering with a garbage UUID
		form := url.Values{}
		form.Set("username", username_b)
		form.Set("password", TEST_PASSWORD)
		form.Set("uuid", "This is not a UUID.")
		rec := ts.PostForm(ts.Server, "/drasl/register", form, nil)

		ts.registrationShouldFail(t, rec, "Invalid UUID: invalid UUID length: 19")
	}
}

func (ts *TestSuite) testLoginLogout(t *testing.T) {
	username := "loginLogout"
	ts.CreateTestUser(ts.Server, username)

	{
		// Login
		form := url.Values{}
		form.Set("username", username)
		form.Set("password", TEST_PASSWORD)
		rec := ts.PostForm(ts.Server, "/drasl/login", form, nil)
		ts.loginShouldSucceed(t, rec)
		browserTokenCookie := getCookie(rec, "browserToken")

		// The BrowserToken we get should match the one in the database
		var user User
		result := ts.App.DB.First(&user, "username = ?", username)
		assert.Nil(t, result.Error)
		assert.Equal(t, *UnmakeNullString(&user.BrowserToken), browserTokenCookie.Value)

		// Get profile
		req := httptest.NewRequest(http.MethodGet, "/drasl/profile", nil)
		req.AddCookie(browserTokenCookie)
		rec = httptest.NewRecorder()
		ts.Server.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "", getCookie(rec, "errorMessage").Value)

		// Logout should redirect to / and clear the browserToken
		rec = ts.PostForm(ts.Server, "/drasl/logout", url.Values{}, []http.Cookie{*browserTokenCookie})
		assert.Equal(t, http.StatusSeeOther, rec.Code)
		assert.Equal(t, ts.App.FrontEndURL, rec.Header().Get("Location"))
		result = ts.App.DB.First(&user, "username = ?", username)
		assert.Nil(t, result.Error)
		assert.Nil(t, UnmakeNullString(&user.BrowserToken))
	}
	{
		// Login with incorrect password should fail
		form := url.Values{}
		form.Set("username", username)
		form.Set("password", "wrong password")
		rec := ts.PostForm(ts.Server, "/drasl/login", form, nil)
		ts.loginShouldFail(t, rec, "Incorrect password!")
	}
	{
		// GET /profile without valid BrowserToken should fail
		req := httptest.NewRequest(http.MethodGet, "/drasl/profile", nil)
		rec := httptest.NewRecorder()
		ts.Server.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusSeeOther, rec.Code)
		assert.Equal(t, ts.App.FrontEndURL, rec.Header().Get("Location"))
		assert.Equal(t, "You are not logged in.", getCookie(rec, "errorMessage").Value)

		// Logout without valid BrowserToken should fail
		rec = ts.PostForm(ts.Server, "/drasl/logout", url.Values{}, nil)
		assert.Equal(t, http.StatusSeeOther, rec.Code)
		assert.Equal(t, ts.App.FrontEndURL, rec.Header().Get("Location"))
		assert.Equal(t, "You are not logged in.", getCookie(rec, "errorMessage").Value)
	}
}

func (ts *TestSuite) testRegistrationExistingPlayerNoVerification(t *testing.T) {
	username := EXISTING_USERNAME

	// Register from the existing account
	form := url.Values{}
	form.Set("username", username)
	form.Set("password", TEST_PASSWORD)
	form.Set("existingPlayer", "on")
	rec := ts.PostForm(ts.Server, "/drasl/register", form, nil)
	ts.registrationShouldSucceed(t, rec)

	// Check that the user has been created with the same UUID
	var auxUser User
	result := ts.AuxApp.DB.First(&auxUser, "username = ?", username)
	assert.Nil(t, result.Error)
	var user User
	result = ts.App.DB.First(&user, "username = ?", username)
	assert.Nil(t, result.Error)
	assert.Equal(t, auxUser.UUID, user.UUID)

	{
		// Registration as a new user should fail
		form := url.Values{}
		form.Set("username", username)
		form.Set("password", TEST_PASSWORD)
		rec := ts.PostForm(ts.Server, "/drasl/register", form, nil)
		ts.registrationShouldFail(t, rec, "Registration without some existing account is not allowed.")
	}
	{
		// Registration with a missing existing account should fail
		form := url.Values{}
		form.Set("username", "nonexistent")
		form.Set("password", TEST_PASSWORD)
		form.Set("existingPlayer", "on")
		rec := ts.PostForm(ts.Server, "/drasl/register", form, nil)
		ts.registrationShouldFail(t, rec, "Couldn't find your account, maybe try again: registration server returned error")
	}
}

func (ts *TestSuite) testRegistrationExistingPlayerWithVerification(t *testing.T) {
	username := EXISTING_USERNAME

	{
		// Registration without setting a skin should fail
		form := url.Values{}
		form.Set("username", username)
		form.Set("password", TEST_PASSWORD)
		form.Set("existingPlayer", "on")
		rec := ts.PostForm(ts.Server, "/drasl/register", form, nil)
		ts.registrationShouldFail(t, rec, "Couldn't verify your skin, maybe try again: player does not have a skin")
	}
	{
		// Get challenge skin with invalid username should fail
		req := httptest.NewRequest(http.MethodGet, "/drasl/challenge-skin?username=AReallyReallyReallyLongUsername", nil)
		rec := httptest.NewRecorder()
		ts.Server.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusSeeOther, rec.Code)
		assert.Equal(t, "Invalid username: can't be longer than 16 characters", getCookie(rec, "errorMessage").Value)
		assert.Equal(t, ts.App.FrontEndURL+"/drasl/registration", rec.Header().Get("Location"))
	}
	{
		// Get challenge skin
		req := httptest.NewRequest(http.MethodGet, "/drasl/challenge-skin?username="+username, nil)
		rec := httptest.NewRecorder()
		ts.Server.ServeHTTP(rec, req)
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
		result := ts.AuxApp.DB.First(&auxUser, "username = ?", username)
		assert.Nil(t, result.Error)

		err = SetSkin(ts.AuxApp, &auxUser, validSkinHandle)
		assert.Nil(t, err)

		{
			// Registration should fail if we give the wrong challenge token
			form := url.Values{}
			form.Set("username", username)
			form.Set("password", TEST_PASSWORD)
			form.Set("existingPlayer", "on")
			form.Set("challengeToken", "This is not a valid challenge token.")
			rec := ts.PostForm(ts.Server, "/drasl/register", form, nil)

			ts.registrationShouldFail(t, rec, "Couldn't verify your skin, maybe try again: skin does not match")
		}
		{
			// Registration should succeed if everything is correct
			form := url.Values{}
			form.Set("username", username)
			form.Set("password", TEST_PASSWORD)
			form.Set("existingPlayer", "on")
			form.Set("challengeToken", challengeToken.Value)
			rec := ts.PostForm(ts.Server, "/drasl/register", form, nil)

			ts.registrationShouldSucceed(t, rec)

			// Check that the user has been created with the same UUID
			var user User
			result = ts.App.DB.First(&user, "username = ?", username)
			assert.Nil(t, result.Error)
			assert.Equal(t, auxUser.UUID, user.UUID)
		}
	}
}

func (ts *TestSuite) testUpdate(t *testing.T) {
	username := "testUpdate"
	takenUsername := "testUpdateTaken"
	ts.CreateTestUser(ts.Server, username)
	ts.CreateTestUser(ts.Server, takenUsername)

	redSkin, err := base64.StdEncoding.DecodeString(RED_SKIN_BASE64_STRING)
	assert.Nil(t, err)
	sum := blake3.Sum256(redSkin)
	redSkinHash := hex.EncodeToString(sum[:])

	redCape, err := base64.StdEncoding.DecodeString(RED_CAPE_BASE64_STRING)
	assert.Nil(t, err)
	sum = blake3.Sum256(redCape)
	redCapeHash := hex.EncodeToString(sum[:])

	var user User
	result := ts.App.DB.First(&user, "username = ?", username)
	assert.Nil(t, result.Error)
	assert.Equal(t, "en", user.PreferredLanguage)

	user.BrowserToken = MakeNullString(&FAKE_BROWSER_TOKEN)
	ts.App.DB.Save(user)

	browserTokenCookie := &http.Cookie{
		Name:  "browserToken",
		Value: FAKE_BROWSER_TOKEN,
	}

	update := func(body io.Reader, writer *multipart.Writer) *httptest.ResponseRecorder {
		assert.Nil(t, writer.Close())
		req := httptest.NewRequest(http.MethodPost, "/drasl/update", body)
		req.AddCookie(browserTokenCookie)
		req.Header.Add("Content-Type", writer.FormDataContentType())
		rec := httptest.NewRecorder()
		ts.Server.ServeHTTP(rec, req)
		return rec
	}
	{
		// Successful update
		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)

		writer.WriteField("playerName", "newTestUpdate")
		writer.WriteField("preferredLanguage", "es")
		writer.WriteField("password", "newpassword")
		writer.WriteField("skinModel", "slim")
		skinFileField, err := writer.CreateFormFile("skinFile", "redSkin.png")
		assert.Nil(t, err)
		_, err = skinFileField.Write(redSkin)
		assert.Nil(t, err)

		capeFileField, err := writer.CreateFormFile("capeFile", "redCape.png")
		assert.Nil(t, err)
		_, err = capeFileField.Write(redCape)
		assert.Nil(t, err)

		rec := update(body, writer)
		ts.updateShouldSucceed(t, rec)

		var newUser User
		result := ts.App.DB.First(&newUser, "player_name = ?", "newTestUpdate")
		assert.Nil(t, result.Error)
		assert.Equal(t, "es", newUser.PreferredLanguage)
		assert.Equal(t, "slim", newUser.SkinModel)
		assert.Equal(t, redSkinHash, *UnmakeNullString(&newUser.SkinHash))
		assert.Equal(t, redCapeHash, *UnmakeNullString(&newUser.CapeHash))

		// Make sure we can log in with the new password
	}
	{
		// TODO test set skin/cape by URL
	}
	{
		// TODO test skin/cape delete
	}
	{
		// Invalid player name should fail
		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)
		writer.WriteField("playerName", "AReallyReallyReallyLongUsername")
		assert.Nil(t, writer.Close())
		rec := update(body, writer)
		ts.updateShouldFail(t, rec, "Invalid player name: can't be longer than 16 characters")
	}
	{
		// Invalid preferred language should fail
		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)
		writer.WriteField("preferredLanguage", "xx")
		assert.Nil(t, writer.Close())
		rec := update(body, writer)
		ts.updateShouldFail(t, rec, "Invalid preferred language.")
	}
	{
		// Changing to a taken username should fail
		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)
		writer.WriteField("playerName", takenUsername)
		assert.Nil(t, writer.Close())
		rec := update(body, writer)
		ts.updateShouldFail(t, rec, "That player name is taken.")
	}
	{
		// Setting an invalid password should fail
		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)
		writer.WriteField("password", "short")
		assert.Nil(t, writer.Close())
		rec := update(body, writer)
		ts.updateShouldFail(t, rec, "Invalid password: password must be longer than 8 characters")
	}
}

func (ts *TestSuite) testDeleteAccount(t *testing.T) {
	usernameA := "deleteA"
	usernameB := "deleteB"

	ts.CreateTestUser(ts.Server, usernameA)

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
		result := ts.App.DB.First(&user, "username = ?", usernameA)
		assert.Nil(t, result.Error)

		// Set red skin and cape on usernameA
		validSkinHandle, err := ValidateSkin(ts.App, bytes.NewReader(redSkin))
		assert.Nil(t, err)
		err = SetSkin(ts.App, &user, validSkinHandle)
		assert.Nil(t, err)
		validCapeHandle, err := ValidateCape(ts.App, bytes.NewReader(redCape))
		assert.Nil(t, err)
		err = SetCape(ts.App, &user, validCapeHandle)
		assert.Nil(t, err)

		// Register usernameB
		browserTokenCookie := ts.CreateTestUser(ts.Server, usernameB)

		// Check that usernameB has been created
		var otherUser User
		result = ts.App.DB.First(&otherUser, "username = ?", usernameB)
		assert.Nil(t, result.Error)

		// Set red skin and cape on usernameB
		validSkinHandle, err = ValidateSkin(ts.App, bytes.NewReader(redSkin))
		assert.Nil(t, err)
		err = SetSkin(ts.App, &otherUser, validSkinHandle)
		assert.Nil(t, err)
		validCapeHandle, err = ValidateCape(ts.App, bytes.NewReader(redCape))
		assert.Nil(t, err)
		err = SetCape(ts.App, &otherUser, validCapeHandle)
		assert.Nil(t, err)

		// Delete account usernameB
		rec := ts.PostForm(ts.Server, "/drasl/delete-account", url.Values{}, []http.Cookie{*browserTokenCookie})
		assert.Equal(t, http.StatusSeeOther, rec.Code)
		assert.Equal(t, "", getCookie(rec, "errorMessage").Value)
		assert.Equal(t, ts.App.FrontEndURL, rec.Header().Get("Location"))

		// Check that usernameB has been deleted
		result = ts.App.DB.First(&otherUser, "username = ?", usernameB)
		assert.True(t, errors.Is(result.Error, gorm.ErrRecordNotFound))

		// Check that the red skin and cape still exist in the filesystem
		_, err = os.Stat(GetSkinPath(ts.App, *UnmakeNullString(&user.SkinHash)))
		assert.Nil(t, err)
		_, err = os.Stat(GetCapePath(ts.App, *UnmakeNullString(&user.CapeHash)))
		assert.Nil(t, err)
	}
	{
		// Register usernameB again
		form := url.Values{}
		form.Set("username", usernameB)
		form.Set("password", TEST_PASSWORD)
		rec := ts.PostForm(ts.Server, "/drasl/register", form, nil)
		ts.registrationShouldSucceed(t, rec)
		browserTokenCookie := getCookie(rec, "browserToken")

		// Check that TEST_OTHER_USERNAME has been created
		var otherUser User
		result := ts.App.DB.First(&otherUser, "username = ?", usernameB)
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

		// Delete account usernameB
		rec = ts.PostForm(ts.Server, "/drasl/delete-account", url.Values{}, []http.Cookie{*browserTokenCookie})
		assert.Equal(t, http.StatusSeeOther, rec.Code)
		assert.Equal(t, "", getCookie(rec, "errorMessage").Value)
		assert.Equal(t, ts.App.FrontEndURL, rec.Header().Get("Location"))

		// Check that the blue skin and cape no longer exist in the filesystem
		_, err = os.Stat(GetSkinPath(ts.App, blueSkinHash))
		assert.True(t, os.IsNotExist(err))
		_, err = os.Stat(GetCapePath(ts.App, blueCapeHash))
		assert.True(t, os.IsNotExist(err))
	}
	{
		// Delete account without valid BrowserToken should fail
		rec := ts.PostForm(ts.Server, "/drasl/delete-account", url.Values{}, nil)
		assert.Equal(t, http.StatusSeeOther, rec.Code)
		assert.Equal(t, ts.App.FrontEndURL, rec.Header().Get("Location"))
		assert.Equal(t, "You are not logged in.", getCookie(rec, "errorMessage").Value)
	}
}
