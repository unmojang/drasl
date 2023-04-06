package main

import (
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

const username = "foo"
const password = "bar"

func TestFront(t *testing.T) {
	{
		ts := &TestSuite{}

		config := testConfig()
		ts.Setup(config)
		defer ts.Teardown()

		t.Run("Test public pages and assets", ts.testPublic)
		t.Run("Test registration as new player", ts.testRegistrationNewPlayer)
		t.Run("Test registration as new player, chosen UUID but not allowed", ts.testRegistrationNewPlayerChosenUUIDNotAllowed)
		t.Run("Test login", ts.testLoginLogout)
	}
	{
		ts := &TestSuite{}

		config := testConfig()
		ts.Setup(config)
		defer ts.Teardown()

		t.Run("Test registration from existing player", ts.testRegistrationExistingPlayer)
	}
	{
		ts := &TestSuite{}

		config := testConfig()
		config.RegistrationNewPlayer.AllowChoosingUUID = true
		ts.Setup(config)
		defer ts.Teardown()

		t.Run("Test registration as new player, chosen UUID allowed", ts.testRegistrationNewPlayerChosenUUID)
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
	ts.testStatusOK(t, "/registration")
	ts.testStatusOK(t, "/public/bundle.js")
	ts.testStatusOK(t, "/public/style.css")
}

func (ts *TestSuite) testRegistrationNewPlayerChosenUUIDNotAllowed(t *testing.T) {
	ts.App.Config.RegistrationNewPlayer.AllowChoosingUUID = false

	form := url.Values{}
	form.Set("username", username)
	form.Set("password", password)
	form.Set("uuid", "11111111-2222-3333-4444-555555555555")
	req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(form.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.ParseForm()
	rec := httptest.NewRecorder()
	ts.FrontServer.ServeHTTP(rec, req)

	// Registration should fail and redirect back to registration page
	assert.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, "Choosing a UUID is not allowed.", getCookie(rec, "errorMessage").Value)
	assert.Equal(t, "", getCookie(rec, "browserToken").Value)
	assert.Equal(t, ts.App.Config.FrontEndServer.URL+"/registration", rec.Header().Get("Location"))
}

func (ts *TestSuite) testRegistrationNewPlayer(t *testing.T) {
	form := url.Values{}
	form.Set("username", username)
	form.Set("password", password)
	req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(form.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.ParseForm()
	rec := httptest.NewRecorder()
	ts.FrontServer.ServeHTTP(rec, req)

	// Registration should succeed and redirect to profile
	browserTokenCookie := getCookie(rec, "browserToken")
	assert.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, "", getCookie(rec, "errorMessage").Value)
	assert.NotEqual(t, "", browserTokenCookie.Value)
	assert.Equal(t, ts.App.Config.FrontEndServer.URL+"/profile", rec.Header().Get("Location"))

	// Check that the user has been created with a correct password hash/salt
	var user User
	result := ts.App.DB.First(&user, "username = ?", username)
	assert.Nil(t, result.Error)
	passwordHash, err := HashPassword(password, user.PasswordSalt)
	assert.Nil(t, err)
	assert.Equal(t, passwordHash, user.PasswordHash)

	// Get the profile
	req = httptest.NewRequest(http.MethodGet, "/profile", nil)
	req.AddCookie(browserTokenCookie)
	rec = httptest.NewRecorder()
	ts.FrontServer.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "", getCookie(rec, "errorMessage").Value)
}

func (ts *TestSuite) testRegistrationNewPlayerChosenUUID(t *testing.T) {
	uuid := "11111111-2222-3333-4444-555555555555"

	form := url.Values{}
	form.Set("username", username)
	form.Set("password", password)
	form.Set("uuid", uuid)
	req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(form.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.ParseForm()
	rec := httptest.NewRecorder()
	ts.FrontServer.ServeHTTP(rec, req)

	// Registration should succeed and redirect to profile
	assert.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, "", getCookie(rec, "errorMessage").Value)
	assert.NotEqual(t, "", getCookie(rec, "browserToken").Value)
	assert.Equal(t, ts.App.Config.FrontEndServer.URL+"/profile", rec.Header().Get("Location"))

	var user User
	result := ts.App.DB.First(&user, "uuid = ?", uuid)
	assert.Nil(t, result.Error)
}

func (ts *TestSuite) testLoginLogout(t *testing.T) {
	form := url.Values{}
	form.Set("username", username)
	form.Set("password", password)
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.ParseForm()
	rec := httptest.NewRecorder()
	ts.FrontServer.ServeHTTP(rec, req)

	// Login should succeed and redirect to profile
	assert.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, "", getCookie(rec, "errorMessage").Value)
	assert.NotEqual(t, "", getCookie(rec, "browserToken").Value)
	assert.Equal(t, ts.App.Config.FrontEndServer.URL+"/profile", rec.Header().Get("Location"))

	var user User
	result := ts.App.DB.First(&user, "username = ?", username)
	assert.Nil(t, result.Error)
	assert.Equal(t, *UnmakeNullString(&user.BrowserToken), getCookie(rec, "browserToken").Value)

	// Logout
	req = httptest.NewRequest(http.MethodPost, "/logout", nil)
	rec = httptest.NewRecorder()
	ts.FrontServer.ServeHTTP(rec, req)

	// Logout should redirect to / and clear the browserToken
	assert.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, ts.App.Config.FrontEndServer.URL, rec.Header().Get("Location"))
	assert.Equal(t, "", getCookie(rec, "browserToken").Value)

	result = ts.App.DB.First(&user, "username = ?", username)
	assert.Nil(t, result.Error)
}

func (ts *TestSuite) testRegistrationExistingPlayer(t *testing.T) {
	// TODO
}
