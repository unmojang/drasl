package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"
	"html"
	"lukechampine.com/blake3"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"testing"
)

var FAKE_BROWSER_TOKEN = "deadbeef"

var EXISTING_USERNAME = "existing"

func setupRegistrationExistingPlayerTS(requireSkinVerification bool, requireInvite bool) *TestSuite {
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
		RequireInvite:           requireInvite,
	}
	config.FallbackAPIServers = []FallbackAPIServer{
		{
			Nickname:    "Aux",
			SessionURL:  ts.AuxApp.SessionURL,
			AccountURL:  ts.AuxApp.AccountURL,
			ServicesURL: ts.AuxApp.ServicesURL,
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

func (ts *TestSuite) testWebManifest(t *testing.T) {
	ts.testStatusOK(t, "/drasl/manifest.webmanifest")
}

func (ts *TestSuite) testPublic(t *testing.T) {
	ts.testStatusOK(t, "/")
	ts.testStatusOK(t, "/drasl/registration")
	ts.testStatusOK(t, "/drasl/public/bundle.js")
	ts.testStatusOK(t, "/drasl/public/style.css")
	ts.testStatusOK(t, "/drasl/public/logo.svg")
	ts.testStatusOK(t, "/drasl/public/icon.png")
}

func getErrorMessage(rec *httptest.ResponseRecorder) string {
	return Unwrap(url.QueryUnescape(getCookie(rec, "errorMessage").Value))
}

func (ts *TestSuite) registrationShouldFail(t *testing.T, rec *httptest.ResponseRecorder, errorMessage string, returnURL string) {
	assert.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, errorMessage, getErrorMessage(rec))
	assert.Equal(t, "", getCookie(rec, "browserToken").Value)
	assert.Equal(t, returnURL, rec.Header().Get("Location"))
}

func (ts *TestSuite) registrationShouldSucceed(t *testing.T, rec *httptest.ResponseRecorder) {
	assert.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, "", getErrorMessage(rec))
	assert.NotEqual(t, "", getCookie(rec, "browserToken").Value)
	assert.Equal(t, ts.App.FrontEndURL+"/drasl/profile", rec.Header().Get("Location"))
}

func (ts *TestSuite) updateShouldFail(t *testing.T, rec *httptest.ResponseRecorder, errorMessage string, returnURL string) {
	assert.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, errorMessage, getErrorMessage(rec))
	assert.Equal(t, returnURL, rec.Header().Get("Location"))
}

func (ts *TestSuite) updateShouldSucceed(t *testing.T, rec *httptest.ResponseRecorder) {
	assert.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, "", getErrorMessage(rec))
	assert.Equal(t, ts.App.FrontEndURL+"/drasl/profile", rec.Header().Get("Location"))
}

func (ts *TestSuite) loginShouldSucceed(t *testing.T, rec *httptest.ResponseRecorder) {
	assert.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, "", getErrorMessage(rec))
	assert.NotEqual(t, "", getCookie(rec, "browserToken").Value)
	assert.Equal(t, ts.App.FrontEndURL+"/drasl/profile", rec.Header().Get("Location"))
}

func (ts *TestSuite) loginShouldFail(t *testing.T, rec *httptest.ResponseRecorder, errorMessage string) {
	assert.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, errorMessage, getErrorMessage(rec))
	assert.Equal(t, "", getCookie(rec, "browserToken").Value)
	assert.Equal(t, ts.App.FrontEndURL, rec.Header().Get("Location"))
}

func TestFront(t *testing.T) {
	{
		// Registration as existing player not allowed
		ts := &TestSuite{}

		config := testConfig()
		config.RegistrationExistingPlayer.Allow = false
		config.DefaultAdmins = []string{"registrationNewA"}
		ts.Setup(config)
		defer ts.Teardown()

		t.Run("Test public pages and assets", ts.testPublic)
		t.Run("Test web app manifest", ts.testWebManifest)
		t.Run("Test registration as new player", ts.testRegistrationNewPlayer)
		t.Run("Test registration as new player, chosen UUID, chosen UUID not allowed", ts.testRegistrationNewPlayerChosenUUIDNotAllowed)
		t.Run("Test profile update", ts.testUpdate)
		t.Run("Test creating/deleting invites", ts.testNewInviteDeleteInvite)
		t.Run("Test login, logout", ts.testLoginLogout)
		t.Run("Test delete account", ts.testDeleteAccount)
	}
	{
		ts := &TestSuite{}

		config := testConfig()
		config.RegistrationExistingPlayer.Allow = false
		config.AllowSkins = false
		config.AllowCapes = false
		ts.Setup(config)
		defer ts.Teardown()

		t.Run("Test profile update, skins and capes not allowed", ts.testUpdateSkinsCapesNotAllowed)
	}
	{
		ts := &TestSuite{}
		config := testConfig()
		ts.Setup(config)
		defer ts.Teardown()
		t.Run("Test admin", ts.testAdmin)
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
		// Low body limit
		ts := &TestSuite{}

		config := testConfig()
		config.BodyLimit = bodyLimitConfig{
			Enable:       true,
			SizeLimitKiB: 1,
		}
		ts.Setup(config)
		defer ts.Teardown()

		t.Run("Test body size limiting", ts.testBodyLimit)
	}
	{
		// Registration as existing player allowed, skin verification not required
		ts := setupRegistrationExistingPlayerTS(false, false)
		defer ts.Teardown()

		t.Run("Test registration as existing player, no skin verification", ts.testRegistrationExistingPlayerNoVerification)
	}
	{
		// Registration as existing player allowed, skin verification required
		ts := setupRegistrationExistingPlayerTS(true, false)
		defer ts.Teardown()

		t.Run("Test registration as existing player, with skin verification", ts.testRegistrationExistingPlayerWithVerification)
	}
	{
		// Invite required, new player
		ts := &TestSuite{}

		config := testConfig()
		config.RegistrationNewPlayer.RequireInvite = true
		ts.Setup(config)
		defer ts.Teardown()

		t.Run("Test registration as new player, invite only", ts.testRegistrationNewPlayerInvite)
	}
	{
		// Invite required, existing player, skin verification
		ts := setupRegistrationExistingPlayerTS(true, true)
		defer ts.Teardown()

		t.Run("Test registration as existing player, with skin verification, invite only", ts.testRegistrationExistingPlayerInvite)
	}
}

func (ts *TestSuite) testRateLimit(t *testing.T) {
	form := url.Values{}
	form.Set("username", "")
	form.Set("password", "")

	// Login should fail the first time due to missing account, then
	// soon get rate-limited
	rec := ts.PostForm(t, ts.Server, "/drasl/login", form, nil, nil)
	ts.loginShouldFail(t, rec, "User not found!")
	rec = ts.PostForm(t, ts.Server, "/drasl/login", form, nil, nil)
	ts.loginShouldFail(t, rec, "User not found!")
	rec = ts.PostForm(t, ts.Server, "/drasl/login", form, nil, nil)
	ts.loginShouldFail(t, rec, "Too many requests. Try again later.")

	// Static paths should not be rate-limited
	rec = ts.Get(t, ts.Server, "/drasl/registration", nil, nil)
	assert.Equal(t, http.StatusOK, rec.Code)
	rec = ts.Get(t, ts.Server, "/drasl/registration", nil, nil)
	assert.Equal(t, http.StatusOK, rec.Code)
	rec = ts.Get(t, ts.Server, "/drasl/registration", nil, nil)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func (ts *TestSuite) testBodyLimit(t *testing.T) {
	form := url.Values{}
	form.Set("bogus", Unwrap(RandomHex(2048)))
	rec := ts.PostForm(t, ts.Server, "/drasl/login", form, nil, nil)
	assert.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)
}

func (ts *TestSuite) testRegistrationNewPlayer(t *testing.T) {
	usernameA := "registrationNewA"
	usernameAUppercase := "REGISTRATIONNEWA"
	usernameB := "registrationNewB"
	usernameC := "registrationNewC"
	returnURL := ts.App.FrontEndURL + "/drasl/registration"
	{
		// Tripping the honeypot should fail
		form := url.Values{}
		form.Set("username", usernameA)
		form.Set("password", TEST_PASSWORD)
		form.Set("email", "mail@example.com")
		form.Set("returnUrl", ts.App.FrontEndURL+"/drasl/registration")
		rec := ts.PostForm(t, ts.Server, "/drasl/register", form, nil, nil)
		ts.registrationShouldFail(t, rec, "You are now covered in bee stings.", returnURL)
	}
	{
		// Register
		form := url.Values{}
		form.Set("username", usernameA)
		form.Set("password", TEST_PASSWORD)
		rec := ts.PostForm(t, ts.Server, "/drasl/register", form, nil, nil)
		ts.registrationShouldSucceed(t, rec)
		browserTokenCookie := getCookie(rec, "browserToken")

		// Check that the user has been created with a correct password hash/salt
		var user User
		result := ts.App.DB.First(&user, "username = ?", usernameA)
		assert.Nil(t, result.Error)
		passwordHash, err := HashPassword(TEST_PASSWORD, user.PasswordSalt)
		assert.Nil(t, err)
		assert.Equal(t, passwordHash, user.PasswordHash)

		// Users in the DefaultAdmins list should be admins
		assert.True(t, ts.App.IsDefaultAdmin(&user))
		assert.True(t, user.IsAdmin)

		// Get the profile
		{
			// TODO use ts.Get here
			req := httptest.NewRequest(http.MethodGet, "/drasl/profile", nil)
			req.AddCookie(browserTokenCookie)
			rec = httptest.NewRecorder()
			ts.Server.ServeHTTP(rec, req)
			assert.Equal(t, http.StatusOK, rec.Code)
			assert.Equal(t, "", getErrorMessage(rec))
		}

		// Get admin page
		{
			req := httptest.NewRequest(http.MethodGet, "/drasl/admin", nil)
			req.AddCookie(browserTokenCookie)
			rec = httptest.NewRecorder()
			ts.Server.ServeHTTP(rec, req)
			assert.Equal(t, http.StatusOK, rec.Code)
			assert.Equal(t, "", getErrorMessage(rec))
		}
	}
	{
		// Register
		form := url.Values{}
		form.Set("username", usernameB)
		form.Set("password", TEST_PASSWORD)
		form.Set("returnUrl", ts.App.FrontEndURL+"/drasl/registration")
		rec := ts.PostForm(t, ts.Server, "/drasl/register", form, nil, nil)
		ts.registrationShouldSucceed(t, rec)
		browserTokenCookie := getCookie(rec, "browserToken")

		// Users not in the DefaultAdmins list should not be admins
		var user User
		result := ts.App.DB.First(&user, "username = ?", usernameB)
		assert.Nil(t, result.Error)
		assert.False(t, ts.App.IsDefaultAdmin(&user))
		assert.False(t, user.IsAdmin)

		// Getting admin page should fail and redirect back to /
		req := httptest.NewRequest(http.MethodGet, "/drasl/admin", nil)
		req.AddCookie(browserTokenCookie)
		rec = httptest.NewRecorder()
		ts.Server.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusSeeOther, rec.Code)
		assert.Equal(t, "You are not an admin.", getErrorMessage(rec))
		assert.Equal(t, ts.App.FrontEndURL, rec.Header().Get("Location"))
	}
	{
		// Try registering again with the same username
		form := url.Values{}
		form.Set("username", usernameA)
		form.Set("password", TEST_PASSWORD)
		form.Set("returnUrl", ts.App.FrontEndURL+"/drasl/registration")
		rec := ts.PostForm(t, ts.Server, "/drasl/register", form, nil, nil)

		ts.registrationShouldFail(t, rec, "That username is taken.", returnURL)
	}
	{
		// Test case insensitivity: try registering again with the "same"
		// username, but uppercase
		form := url.Values{}
		form.Set("username", usernameAUppercase)
		form.Set("password", TEST_PASSWORD)
		form.Set("returnUrl", ts.App.FrontEndURL+"/drasl/registration")
		rec := ts.PostForm(t, ts.Server, "/drasl/register", form, nil, nil)

		ts.registrationShouldFail(t, rec, "That username is taken.", returnURL)
	}
	{
		// Registration with a too-long username should fail
		form := url.Values{}
		form.Set("username", "AReallyReallyReallyLongUsername")
		form.Set("password", TEST_PASSWORD)
		form.Set("returnUrl", returnURL)
		rec := ts.PostForm(t, ts.Server, "/drasl/register", form, nil, nil)

		ts.registrationShouldFail(t, rec, "Invalid username: can't be longer than 16 characters", returnURL)
	}
	{
		// Registration with a too-short password should fail
		form := url.Values{}
		form.Set("username", usernameC)
		form.Set("password", "")
		form.Set("returnUrl", returnURL)
		rec := ts.PostForm(t, ts.Server, "/drasl/register", form, nil, nil)

		ts.registrationShouldFail(t, rec, "Invalid password: can't be blank", returnURL)
	}
	{
		// Registration from an existing account should fail
		form := url.Values{}
		form.Set("username", usernameC)
		form.Set("password", TEST_PASSWORD)
		form.Set("existingPlayer", "on")
		form.Set("challengeToken", "This is not a valid challenge token.")
		form.Set("returnUrl", returnURL)
		rec := ts.PostForm(t, ts.Server, "/drasl/register", form, nil, nil)

		ts.registrationShouldFail(t, rec, "Registration from an existing account is not allowed.", returnURL)
	}
}

func (ts *TestSuite) testRegistrationNewPlayerChosenUUIDNotAllowed(t *testing.T) {
	username := "noChosenUUID"
	ts.CreateTestUser(ts.Server, username)

	uuid := "11111111-2222-3333-4444-555555555555"

	ts.App.Config.RegistrationNewPlayer.AllowChoosingUUID = false

	returnURL := ts.App.FrontEndURL + "/drasl/registration"
	form := url.Values{}
	form.Set("username", username)
	form.Set("password", TEST_PASSWORD)
	form.Set("uuid", uuid)
	form.Set("returnUrl", returnURL)
	rec := ts.PostForm(t, ts.Server, "/drasl/register", form, nil, nil)

	ts.registrationShouldFail(t, rec, "Choosing a UUID is not allowed.", returnURL)
}

func (ts *TestSuite) testRegistrationNewPlayerChosenUUID(t *testing.T) {
	usernameA := "chosenUUIDA"
	usernameB := "chosenUUIDB"
	uuid := "11111111-2222-3333-4444-555555555555"
	returnURL := ts.App.FrontEndURL + "/drasl/registration"
	{
		// Register
		form := url.Values{}
		form.Set("username", usernameA)
		form.Set("password", TEST_PASSWORD)
		form.Set("uuid", uuid)
		form.Set("returnUrl", ts.App.FrontEndURL+"/drasl/registration")
		rec := ts.PostForm(t, ts.Server, "/drasl/register", form, nil, nil)

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
		form.Set("username", usernameB)
		form.Set("password", TEST_PASSWORD)
		form.Set("uuid", uuid)
		form.Set("returnUrl", ts.App.FrontEndURL+"/drasl/registration")
		rec := ts.PostForm(t, ts.Server, "/drasl/register", form, nil, nil)

		ts.registrationShouldFail(t, rec, "That UUID is taken.", returnURL)
	}
	{
		// Try registering with a garbage UUID
		form := url.Values{}
		form.Set("username", usernameB)
		form.Set("password", TEST_PASSWORD)
		form.Set("uuid", "This is not a UUID.")
		form.Set("returnUrl", ts.App.FrontEndURL+"/drasl/registration")
		rec := ts.PostForm(t, ts.Server, "/drasl/register", form, nil, nil)

		ts.registrationShouldFail(t, rec, "Invalid UUID: invalid UUID length: 19", returnURL)
	}
}

func (ts *TestSuite) testRegistrationNewPlayerInvite(t *testing.T) {
	usernameA := "inviteA"
	{
		// Registration without an invite should fail
		returnURL := ts.App.FrontEndURL + "/drasl/registration"
		form := url.Values{}
		form.Set("username", usernameA)
		form.Set("password", TEST_PASSWORD)
		form.Set("returnUrl", ts.App.FrontEndURL+"/drasl/registration")
		rec := ts.PostForm(t, ts.Server, "/drasl/register", form, nil, nil)
		ts.registrationShouldFail(t, rec, "Registration requires an invite.", returnURL)
	}
	{
		// Registration with an invalid invite should fail, and redirect to
		// registration page without ?invite
		returnURL := ts.App.FrontEndURL + "/drasl/registration"
		form := url.Values{}
		form.Set("username", usernameA)
		form.Set("password", TEST_PASSWORD)
		form.Set("inviteCode", "invalid")
		form.Set("returnUrl", ts.App.FrontEndURL+"/drasl/registration?invite=invalid")
		rec := ts.PostForm(t, ts.Server, "/drasl/register", form, nil, nil)
		ts.registrationShouldFail(t, rec, InviteNotFoundError.Error(), returnURL)
	}
	{
		// Registration with an invite

		// Create an invite
		invite, err := ts.App.CreateInvite()
		assert.Nil(t, err)

		var invites []Invite
		result := ts.App.DB.Find(&invites)
		assert.Nil(t, result.Error)
		inviteCount := len(invites)

		// Registration with an invalid username should redirect to the
		// registration page with the same unused invite code
		returnURL := ts.App.FrontEndURL + "/drasl/registration?invite=" + invite.Code
		form := url.Values{}
		form.Set("username", "")
		form.Set("password", TEST_PASSWORD)
		form.Set("inviteCode", invite.Code)
		form.Set("returnUrl", returnURL)
		rec := ts.PostForm(t, ts.Server, "/drasl/register", form, nil, nil)
		ts.registrationShouldFail(t, rec, "Invalid username: can't be blank", returnURL)

		// Then, set a valid username and continnue
		form.Set("username", usernameA)
		rec = ts.PostForm(t, ts.Server, "/drasl/register", form, nil, nil)
		ts.registrationShouldSucceed(t, rec)

		// Invite should be deleted
		result = ts.App.DB.Find(&invites)
		assert.Nil(t, result.Error)
		assert.Equal(t, inviteCount-1, len(invites))
	}
}

func (ts *TestSuite) solveSkinChallenge(t *testing.T, username string) *http.Cookie {
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

	var auxUser User
	result := ts.AuxApp.DB.First(&auxUser, "username = ?", username)
	assert.Nil(t, result.Error)

	// Bypass the controller for setting the skin here, we can test that with the rest of /update
	err = ts.AuxApp.SetSkinAndSave(&auxUser, bytes.NewReader(challengeSkin))
	assert.Nil(t, err)

	return challengeToken
}

func (ts *TestSuite) testRegistrationExistingPlayerInvite(t *testing.T) {
	username := EXISTING_USERNAME
	{
		// Registration without an invite should fail
		returnURL := ts.App.FrontEndURL + "/drasl/registration"
		form := url.Values{}
		form.Set("username", username)
		form.Set("password", TEST_PASSWORD)
		form.Set("existingPlayer", "on")
		form.Set("returnUrl", ts.App.FrontEndURL+"/drasl/registration")
		rec := ts.PostForm(t, ts.Server, "/drasl/register", form, nil, nil)
		ts.registrationShouldFail(t, rec, InviteMissingError.Error(), returnURL)
	}
	{
		// Registration with an invalid invite should fail, and redirect to
		// registration page without ?invite
		returnURL := ts.App.FrontEndURL + "/drasl/registration"
		form := url.Values{}
		form.Set("username", username)
		form.Set("password", TEST_PASSWORD)
		form.Set("existingPlayer", "on")
		form.Set("inviteCode", "invalid")
		form.Set("returnUrl", ts.App.FrontEndURL+"/drasl/registration?invite=invalid")
		rec := ts.PostForm(t, ts.Server, "/drasl/register", form, nil, nil)
		ts.registrationShouldFail(t, rec, InviteNotFoundError.Error(), returnURL)
	}
	{
		// Registration with an invite

		// Create an invite
		invite, err := ts.App.CreateInvite()
		assert.Nil(t, err)

		var invites []Invite
		result := ts.App.DB.Find(&invites)
		assert.Nil(t, result.Error)
		inviteCount := len(invites)

		challengeToken := ts.solveSkinChallenge(t, username)
		returnURL := ts.App.FrontEndURL + "/drasl/registration?invite=" + invite.Code
		{
			// Registration with an invalid username should redirect to the
			// registration page with the same unused invite code
			form := url.Values{}
			form.Set("username", "")
			form.Set("password", TEST_PASSWORD)
			form.Set("existingPlayer", "on")
			form.Set("inviteCode", invite.Code)
			form.Set("returnUrl", returnURL)
			rec := ts.PostForm(t, ts.Server, "/drasl/register", form, nil, nil)
			ts.registrationShouldFail(t, rec, "Invalid username: can't be blank", returnURL)
		}
		{
			// Registration should fail if we give the wrong challenge token, and the invite should not be used
			form := url.Values{}
			form.Set("username", username)
			form.Set("password", TEST_PASSWORD)
			form.Set("existingPlayer", "on")
			form.Set("inviteCode", invite.Code)
			form.Set("challengeToken", "This is not a valid challenge token.")
			form.Set("returnUrl", returnURL)
			rec := ts.PostForm(t, ts.Server, "/drasl/register", form, nil, nil)

			ts.registrationShouldFail(t, rec, "Couldn't verify your skin, maybe try again: skin does not match", returnURL)
		}
		{
			// Registration should succeed if everything is correct
			form := url.Values{}
			form.Set("username", username)
			form.Set("password", TEST_PASSWORD)
			form.Set("existingPlayer", "on")
			form.Set("inviteCode", invite.Code)
			form.Set("challengeToken", challengeToken.Value)
			form.Set("returnUrl", returnURL)
			rec := ts.PostForm(t, ts.Server, "/drasl/register", form, nil, nil)

			ts.registrationShouldSucceed(t, rec)

			// Check that the user has been created with the same UUID
			var user User
			result = ts.App.DB.First(&user, "username = ?", username)
			assert.Nil(t, result.Error)
			var auxUser User
			result = ts.AuxApp.DB.First(&auxUser, "username = ?", username)
			assert.Nil(t, result.Error)
			assert.Equal(t, auxUser.UUID, user.UUID)

			// Invite should be deleted
			result = ts.App.DB.Find(&invites)
			assert.Nil(t, result.Error)
			assert.Equal(t, inviteCount-1, len(invites))
		}
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
		form.Set("returnUrl", ts.App.FrontEndURL+"/drasl/registration")
		rec := ts.PostForm(t, ts.Server, "/drasl/login", form, nil, nil)
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
		assert.Equal(t, "", getErrorMessage(rec))

		// Logout should redirect to / and clear the browserToken
		rec = ts.PostForm(t, ts.Server, "/drasl/logout", url.Values{}, []http.Cookie{*browserTokenCookie}, nil)
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
		rec := ts.PostForm(t, ts.Server, "/drasl/login", form, nil, nil)
		ts.loginShouldFail(t, rec, "Incorrect password!")
	}
	{
		// GET /profile without valid BrowserToken should fail
		req := httptest.NewRequest(http.MethodGet, "/drasl/profile", nil)
		rec := httptest.NewRecorder()
		ts.Server.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusSeeOther, rec.Code)
		assert.Equal(t, ts.App.FrontEndURL, rec.Header().Get("Location"))
		assert.Equal(t, "You are not logged in.", getErrorMessage(rec))

		// Logout without valid BrowserToken should fail
		rec = ts.PostForm(t, ts.Server, "/drasl/logout", url.Values{}, nil, nil)
		assert.Equal(t, http.StatusSeeOther, rec.Code)
		assert.Equal(t, ts.App.FrontEndURL, rec.Header().Get("Location"))
		assert.Equal(t, "You are not logged in.", getErrorMessage(rec))
	}
}

func (ts *TestSuite) testRegistrationExistingPlayerNoVerification(t *testing.T) {
	username := EXISTING_USERNAME
	returnURL := ts.App.FrontEndURL + "/drasl/registration"

	// Register from the existing account
	form := url.Values{}
	form.Set("username", username)
	form.Set("password", TEST_PASSWORD)
	form.Set("existingPlayer", "on")
	form.Set("returnUrl", returnURL)
	rec := ts.PostForm(t, ts.Server, "/drasl/register", form, nil, nil)
	ts.registrationShouldSucceed(t, rec)
	browserTokenCookie := getCookie(rec, "browserToken")

	// Check that the user has been created with the same UUID
	var auxUser User
	result := ts.AuxApp.DB.First(&auxUser, "username = ?", username)
	assert.Nil(t, result.Error)
	var user User
	result = ts.App.DB.First(&user, "username = ?", username)
	assert.Nil(t, result.Error)
	assert.Equal(t, auxUser.UUID, user.UUID)
	{
		// Test setting skin from URL
		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)

		// Set a skin on the existing account
		assert.Nil(t, ts.AuxApp.SetSkinAndSave(&auxUser, bytes.NewReader(BLUE_SKIN)))
		skinHash := *UnmakeNullString(&auxUser.SkinHash)
		skinURL, err := ts.AuxApp.SkinURL(skinHash)
		assert.Nil(t, err)

		writer.WriteField("skinUrl", skinURL)
		writer.WriteField("returnUrl", ts.App.FrontEndURL+"/drasl/profile")
		assert.Nil(t, writer.Close())
		rec := ts.PostMultipart(t, ts.Server, "/drasl/update", body, writer, []http.Cookie{*browserTokenCookie}, nil)
		ts.updateShouldSucceed(t, rec)

		assert.Nil(t, ts.App.DB.First(&user, "username = ?", username).Error)
		assert.Equal(t, skinHash, *UnmakeNullString(&user.SkinHash))
	}
	{
		// Registration as a new user should fail
		form := url.Values{}
		form.Set("username", username)
		form.Set("password", TEST_PASSWORD)
		form.Set("returnUrl", returnURL)
		rec := ts.PostForm(t, ts.Server, "/drasl/register", form, nil, nil)
		ts.registrationShouldFail(t, rec, "Registration without some existing account is not allowed.", returnURL)
	}
	{
		// Registration with a missing existing account should fail
		returnURL := ts.App.FrontEndURL + "/drasl/registration"
		form := url.Values{}
		form.Set("username", "nonexistent")
		form.Set("password", TEST_PASSWORD)
		form.Set("existingPlayer", "on")
		form.Set("returnUrl", returnURL)
		rec := ts.PostForm(t, ts.Server, "/drasl/register", form, nil, nil)
		ts.registrationShouldFail(t, rec, "Couldn't find your account, maybe try again: registration server returned error", returnURL)
	}
}

func (ts *TestSuite) testRegistrationExistingPlayerWithVerification(t *testing.T) {
	username := EXISTING_USERNAME
	returnURL := ts.App.FrontEndURL + "/drasl/registration"
	{
		// Registration without setting a skin should fail
		form := url.Values{}
		form.Set("username", username)
		form.Set("password", TEST_PASSWORD)
		form.Set("existingPlayer", "on")
		form.Set("returnUrl", ts.App.FrontEndURL+"/drasl/registration")
		rec := ts.PostForm(t, ts.Server, "/drasl/register", form, nil, nil)
		ts.registrationShouldFail(t, rec, "Couldn't verify your skin, maybe try again: player does not have a skin", returnURL)
	}
	{
		// Get challenge skin with invalid username should fail
		req := httptest.NewRequest(http.MethodGet, "/drasl/challenge-skin?username=AReallyReallyReallyLongUsername&returnUrl="+ts.App.FrontEndURL+"/drasl/registration", nil)
		rec := httptest.NewRecorder()
		ts.Server.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusSeeOther, rec.Code)
		assert.Equal(t, "Invalid username: can't be longer than 16 characters", getErrorMessage(rec))
		assert.Equal(t, returnURL, rec.Header().Get("Location"))
	}
	{
		challengeToken := ts.solveSkinChallenge(t, username)
		{
			// Registration should fail if we give the wrong challenge token
			form := url.Values{}
			form.Set("username", username)
			form.Set("password", TEST_PASSWORD)
			form.Set("existingPlayer", "on")
			form.Set("challengeToken", "This is not a valid challenge token.")
			form.Set("returnUrl", returnURL)
			rec := ts.PostForm(t, ts.Server, "/drasl/register", form, nil, nil)

			ts.registrationShouldFail(t, rec, "Couldn't verify your skin, maybe try again: skin does not match", returnURL)
		}
		{
			// Registration should succeed if everything is correct
			form := url.Values{}
			form.Set("username", username)
			form.Set("password", TEST_PASSWORD)
			form.Set("existingPlayer", "on")
			form.Set("challengeToken", challengeToken.Value)
			form.Set("returnUrl", returnURL)
			rec := ts.PostForm(t, ts.Server, "/drasl/register", form, nil, nil)

			ts.registrationShouldSucceed(t, rec)

			// Check that the user has been created with the same UUID
			var user User
			result := ts.App.DB.First(&user, "username = ?", username)
			assert.Nil(t, result.Error)
			var auxUser User
			result = ts.AuxApp.DB.First(&auxUser, "username = ?", username)
			assert.Nil(t, result.Error)
			assert.Equal(t, auxUser.UUID, user.UUID)
		}
	}
}

func (ts *TestSuite) testNewInviteDeleteInvite(t *testing.T) {
	username := "inviteAdmin"
	user, browserTokenCookie := ts.CreateTestUser(ts.Server, username)

	user.IsAdmin = true
	result := ts.App.DB.Save(&user)
	assert.Nil(t, result.Error)

	// Create an invite
	returnURL := ts.App.FrontEndURL + "/drasl/admin"
	form := url.Values{}
	form.Set("returnUrl", returnURL)
	rec := ts.PostForm(t, ts.Server, "/drasl/admin/new-invite", form, []http.Cookie{*browserTokenCookie}, nil)

	assert.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, "", getErrorMessage(rec))
	assert.Equal(t, returnURL, rec.Header().Get("Location"))

	// Check that invite was created
	var invites []Invite
	result = ts.App.DB.Find(&invites)
	assert.Nil(t, result.Error)
	assert.Equal(t, 1, len(invites))

	// Delete the invite
	form = url.Values{}
	form.Set("inviteCode", invites[0].Code)
	form.Set("returnUrl", returnURL)
	rec = ts.PostForm(t, ts.Server, "/drasl/admin/delete-invite", form, []http.Cookie{*browserTokenCookie}, nil)

	assert.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, "", getErrorMessage(rec))
	assert.Equal(t, returnURL, rec.Header().Get("Location"))

	// Check that invite was deleted
	result = ts.App.DB.Find(&invites)
	assert.Nil(t, result.Error)
	assert.Equal(t, 0, len(invites))
}

func (ts *TestSuite) testUpdate(t *testing.T) {
	username := "testUpdate"
	takenUsername := "testUpdateTaken"
	user, browserTokenCookie := ts.CreateTestUser(ts.Server, username)
	_, takenBrowserTokenCookie := ts.CreateTestUser(ts.Server, takenUsername)

	sum := blake3.Sum256(RED_SKIN)
	redSkinHash := hex.EncodeToString(sum[:])

	sum = blake3.Sum256(RED_CAPE)
	redCapeHash := hex.EncodeToString(sum[:])

	assert.Equal(t, "en", user.PreferredLanguage)
	user.IsAdmin = true
	assert.Nil(t, ts.App.DB.Save(&user).Error)

	{
		// Successful update
		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)

		writer.WriteField("playerName", "newTestUpdate")
		writer.WriteField("fallbackPlayer", "newTestUpdate")
		writer.WriteField("preferredLanguage", "es")
		writer.WriteField("password", "newpassword")
		writer.WriteField("skinModel", "slim")
		skinFileField, err := writer.CreateFormFile("skinFile", "redSkin.png")
		assert.Nil(t, err)
		_, err = skinFileField.Write(RED_SKIN)
		assert.Nil(t, err)

		capeFileField, err := writer.CreateFormFile("capeFile", "redCape.png")
		assert.Nil(t, err)
		_, err = capeFileField.Write(RED_CAPE)
		assert.Nil(t, err)

		writer.WriteField("returnUrl", ts.App.FrontEndURL+"/drasl/profile")

		rec := ts.PostMultipart(t, ts.Server, "/drasl/update", body, writer, []http.Cookie{*browserTokenCookie}, nil)
		ts.updateShouldSucceed(t, rec)

		var updatedUser User
		result := ts.App.DB.First(&updatedUser, "player_name = ?", "newTestUpdate")
		assert.Nil(t, result.Error)
		assert.Equal(t, "es", updatedUser.PreferredLanguage)
		assert.Equal(t, "slim", updatedUser.SkinModel)
		assert.Equal(t, redSkinHash, *UnmakeNullString(&updatedUser.SkinHash))
		assert.Equal(t, redCapeHash, *UnmakeNullString(&updatedUser.CapeHash))

		// Make sure we can log in with the new password
		form := url.Values{}
		form.Set("username", username)
		form.Set("password", "newpassword")
		form.Set("returnUrl", ts.App.FrontEndURL+"/drasl/registration")
		rec = ts.PostForm(t, ts.Server, "/drasl/login", form, nil, nil)
		ts.loginShouldSucceed(t, rec)
		browserTokenCookie = getCookie(rec, "browserToken")
	}
	{
		// As an admin, test updating another user's profile
		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)
		writer.WriteField("username", takenUsername)
		writer.WriteField("preferredLanguage", "es")
		writer.WriteField("returnUrl", ts.App.FrontEndURL+"/drasl/profile")
		assert.Nil(t, writer.Close())
		rec := ts.PostMultipart(t, ts.Server, "/drasl/update", body, writer, []http.Cookie{*browserTokenCookie}, nil)
		ts.updateShouldSucceed(t, rec)
	}
	{
		// Non-admin should not be able to edit another user's profile
		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)
		writer.WriteField("username", username)
		writer.WriteField("preferredLanguage", "es")
		writer.WriteField("returnUrl", ts.App.FrontEndURL+"/drasl/profile")
		assert.Nil(t, writer.Close())
		rec := ts.PostMultipart(t, ts.Server, "/drasl/update", body, writer, []http.Cookie{*takenBrowserTokenCookie}, nil)
		ts.updateShouldFail(t, rec, "You are not an admin.", ts.App.FrontEndURL)
	}
	{
		// Deleting skin should succeed
		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)
		writer.WriteField("deleteSkin", "on")
		writer.WriteField("returnUrl", ts.App.FrontEndURL+"/drasl/profile")
		assert.Nil(t, writer.Close())
		rec := ts.PostMultipart(t, ts.Server, "/drasl/update", body, writer, []http.Cookie{*browserTokenCookie}, nil)
		ts.updateShouldSucceed(t, rec)
		var updatedUser User
		result := ts.App.DB.First(&updatedUser, "username = ?", username)
		assert.Nil(t, result.Error)
		assert.Nil(t, UnmakeNullString(&updatedUser.SkinHash))
		assert.NotNil(t, UnmakeNullString(&updatedUser.CapeHash))
		assert.Nil(t, ts.App.SetSkinAndSave(&updatedUser, bytes.NewReader(RED_SKIN)))
	}
	{
		// Deleting cape should succeed
		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)
		writer.WriteField("deleteCape", "on")
		writer.WriteField("returnUrl", ts.App.FrontEndURL+"/drasl/profile")
		assert.Nil(t, writer.Close())
		rec := ts.PostMultipart(t, ts.Server, "/drasl/update", body, writer, []http.Cookie{*browserTokenCookie}, nil)
		ts.updateShouldSucceed(t, rec)
		var updatedUser User
		result := ts.App.DB.First(&updatedUser, "username = ?", username)
		assert.Nil(t, result.Error)
		assert.Nil(t, UnmakeNullString(&updatedUser.CapeHash))
		assert.NotNil(t, UnmakeNullString(&updatedUser.SkinHash))
		assert.Nil(t, ts.App.SetCapeAndSave(&updatedUser, bytes.NewReader(RED_CAPE)))
	}
	{
		// Invalid player name should fail
		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)
		writer.WriteField("playerName", "AReallyReallyReallyLongUsername")
		writer.WriteField("returnUrl", ts.App.FrontEndURL+"/drasl/profile")
		assert.Nil(t, writer.Close())
		rec := ts.PostMultipart(t, ts.Server, "/drasl/update", body, writer, []http.Cookie{*browserTokenCookie}, nil)
		ts.updateShouldFail(t, rec, "Invalid player name: can't be longer than 16 characters", ts.App.FrontEndURL+"/drasl/profile")
	}
	{
		// Invalid fallback player should fail
		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)
		writer.WriteField("fallbackPlayer", "521759201-invalid-uuid-057219")
		writer.WriteField("returnUrl", ts.App.FrontEndURL+"/drasl/profile")
		assert.Nil(t, writer.Close())
		rec := ts.PostMultipart(t, ts.Server, "/drasl/update", body, writer, []http.Cookie{*browserTokenCookie}, nil)
		ts.updateShouldFail(t, rec, "Invalid fallback player: not a valid player name or UUID", ts.App.FrontEndURL+"/drasl/profile")
	}
	{
		// Invalid preferred language should fail
		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)
		writer.WriteField("preferredLanguage", "xx")
		writer.WriteField("returnUrl", ts.App.FrontEndURL+"/drasl/profile")
		assert.Nil(t, writer.Close())
		rec := ts.PostMultipart(t, ts.Server, "/drasl/update", body, writer, []http.Cookie{*browserTokenCookie}, nil)
		ts.updateShouldFail(t, rec, "Invalid preferred language.", ts.App.FrontEndURL+"/drasl/profile")
	}
	{
		// Changing to a taken username should fail
		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)
		writer.WriteField("playerName", takenUsername)
		writer.WriteField("returnUrl", ts.App.FrontEndURL+"/drasl/profile")
		assert.Nil(t, writer.Close())
		rec := ts.PostMultipart(t, ts.Server, "/drasl/update", body, writer, []http.Cookie{*browserTokenCookie}, nil)
		ts.updateShouldFail(t, rec, "That player name is taken.", ts.App.FrontEndURL+"/drasl/profile")
	}
	{
		// Setting an invalid password should fail
		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)
		writer.WriteField("password", "short")
		writer.WriteField("returnUrl", ts.App.FrontEndURL+"/drasl/profile")
		assert.Nil(t, writer.Close())
		rec := ts.PostMultipart(t, ts.Server, "/drasl/update", body, writer, []http.Cookie{*browserTokenCookie}, nil)
		ts.updateShouldFail(t, rec, "Invalid password: password must be longer than 8 characters", ts.App.FrontEndURL+"/drasl/profile")
	}
}

func (ts *TestSuite) testUpdateSkinsCapesNotAllowed(t *testing.T) {
	username := "updateNoSkinCape"
	_, browserTokenCookie := ts.CreateTestUser(ts.Server, username)
	{
		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)
		writer.WriteField("returnUrl", ts.App.FrontEndURL+"/drasl/profile")
		writer.WriteField("skinModel", "classic")
		skinFileField, err := writer.CreateFormFile("skinFile", "redSkin.png")
		assert.Nil(t, err)
		_, err = skinFileField.Write(RED_SKIN)
		assert.Nil(t, err)

		assert.Nil(t, writer.Close())
		rec := ts.PostMultipart(t, ts.Server, "/drasl/update", body, writer, []http.Cookie{*browserTokenCookie}, nil)
		ts.updateShouldFail(t, rec, "Setting a skin is not allowed.", ts.App.FrontEndURL+"/drasl/profile")

		// The user should not have a skin set
		var user User
		result := ts.App.DB.First(&user, "username = ?", username)
		assert.Nil(t, result.Error)
		assert.Nil(t, UnmakeNullString(&user.SkinHash))
	}
	{
		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)
		writer.WriteField("returnUrl", ts.App.FrontEndURL+"/drasl/profile")
		capeFileField, err := writer.CreateFormFile("capeFile", "redCape.png")
		assert.Nil(t, err)
		_, err = capeFileField.Write(RED_CAPE)
		assert.Nil(t, err)

		assert.Nil(t, writer.Close())
		rec := ts.PostMultipart(t, ts.Server, "/drasl/update", body, writer, []http.Cookie{*browserTokenCookie}, nil)
		ts.updateShouldFail(t, rec, "Setting a cape is not allowed.", ts.App.FrontEndURL+"/drasl/profile")

		// The user should not have a cape set
		var user User
		result := ts.App.DB.First(&user, "username = ?", username)
		assert.Nil(t, result.Error)
		assert.Nil(t, UnmakeNullString(&user.CapeHash))
	}
}

func (ts *TestSuite) testDeleteAccount(t *testing.T) {
	usernameA := "deleteA"
	usernameB := "deleteB"

	ts.CreateTestUser(ts.Server, usernameA)
	{
		var user User
		result := ts.App.DB.First(&user, "username = ?", usernameA)
		assert.Nil(t, result.Error)

		// Set red skin and cape on usernameA
		err := ts.App.SetSkinAndSave(&user, bytes.NewReader(RED_SKIN))
		assert.Nil(t, err)
		validCapeHandle, err := ts.App.ValidateCape(bytes.NewReader(RED_CAPE))
		assert.Nil(t, err)
		err = ts.App.SetCapeAndSave(&user, validCapeHandle)
		assert.Nil(t, err)

		// Register usernameB
		_, browserTokenCookie := ts.CreateTestUser(ts.Server, usernameB)

		// Check that usernameB has been created
		var otherUser User
		result = ts.App.DB.First(&otherUser, "username = ?", usernameB)
		assert.Nil(t, result.Error)

		// Set red skin and cape on usernameB
		err = ts.App.SetSkinAndSave(&otherUser, bytes.NewReader(RED_SKIN))
		assert.Nil(t, err)
		validCapeHandle, err = ts.App.ValidateCape(bytes.NewReader(RED_CAPE))
		assert.Nil(t, err)
		err = ts.App.SetCapeAndSave(&otherUser, validCapeHandle)
		assert.Nil(t, err)

		// Delete account usernameB
		rec := ts.PostForm(t, ts.Server, "/drasl/delete-user", url.Values{}, []http.Cookie{*browserTokenCookie}, nil)
		assert.Equal(t, http.StatusSeeOther, rec.Code)
		assert.Equal(t, "", getErrorMessage(rec))
		assert.Equal(t, ts.App.FrontEndURL, rec.Header().Get("Location"))

		// Check that usernameB has been deleted
		result = ts.App.DB.First(&otherUser, "username = ?", usernameB)
		assert.True(t, errors.Is(result.Error, gorm.ErrRecordNotFound))

		// Check that the red skin and cape still exist in the filesystem
		_, err = os.Stat(ts.App.GetSkinPath(*UnmakeNullString(&user.SkinHash)))
		assert.Nil(t, err)
		_, err = os.Stat(ts.App.GetCapePath(*UnmakeNullString(&user.CapeHash)))
		assert.Nil(t, err)
	}
	{
		// Register usernameB again
		form := url.Values{}
		form.Set("username", usernameB)
		form.Set("password", TEST_PASSWORD)
		rec := ts.PostForm(t, ts.Server, "/drasl/register", form, nil, nil)
		ts.registrationShouldSucceed(t, rec)
		browserTokenCookie := getCookie(rec, "browserToken")

		// Check that usernameB has been created
		var otherUser User
		result := ts.App.DB.First(&otherUser, "username = ?", usernameB)
		assert.Nil(t, result.Error)

		// Set blue skin and cape on usernameB
		err := ts.App.SetSkinAndSave(&otherUser, bytes.NewReader(BLUE_SKIN))
		assert.Nil(t, err)
		validCapeHandle, err := ts.App.ValidateCape(bytes.NewReader(BLUE_CAPE))
		assert.Nil(t, err)
		err = ts.App.SetCapeAndSave(&otherUser, validCapeHandle)
		assert.Nil(t, err)

		blueSkinHash := *UnmakeNullString(&otherUser.SkinHash)
		blueCapeHash := *UnmakeNullString(&otherUser.CapeHash)

		// Delete account usernameB
		rec = ts.PostForm(t, ts.Server, "/drasl/delete-user", url.Values{}, []http.Cookie{*browserTokenCookie}, nil)
		assert.Equal(t, http.StatusSeeOther, rec.Code)
		assert.Equal(t, "", getErrorMessage(rec))
		assert.Equal(t, ts.App.FrontEndURL, rec.Header().Get("Location"))

		// Check that the blue skin and cape no longer exist in the filesystem
		_, err = os.Stat(ts.App.GetSkinPath(blueSkinHash))
		assert.True(t, os.IsNotExist(err))
		_, err = os.Stat(ts.App.GetCapePath(blueCapeHash))
		assert.True(t, os.IsNotExist(err))
	}
	{
		// Delete account without valid BrowserToken should fail
		rec := ts.PostForm(t, ts.Server, "/drasl/delete-user", url.Values{}, nil, nil)
		assert.Equal(t, http.StatusSeeOther, rec.Code)
		assert.Equal(t, ts.App.FrontEndURL, rec.Header().Get("Location"))
		assert.Equal(t, "You are not logged in.", getErrorMessage(rec))
	}
}

// Admin
func (ts *TestSuite) testAdmin(t *testing.T) {
	returnURL := ts.App.FrontEndURL + "/drasl/admin"

	username := "admin"
	user, browserTokenCookie := ts.CreateTestUser(ts.Server, username)

	otherUsername := "adminOther"
	_, otherBrowserTokenCookie := ts.CreateTestUser(ts.Server, otherUsername)

	// Make `username` an admin
	user.IsAdmin = true
	result := ts.App.DB.Save(&user)
	assert.Nil(t, result.Error)

	{
		// Revoke admin from `username` should fail
		form := url.Values{}
		form.Set("returnUrl", returnURL)
		rec := ts.PostForm(t, ts.Server, "/drasl/admin/update-users", form, []http.Cookie{*browserTokenCookie}, nil)

		assert.Equal(t, http.StatusSeeOther, rec.Code)
		assert.Equal(t, "There must be at least one unlocked admin account.", getErrorMessage(rec))
		assert.Equal(t, returnURL, rec.Header().Get("Location"))
	}

	// Make `otherUsername` an admin and lock their account
	form := url.Values{}
	form.Set("returnUrl", returnURL)
	form.Set("admin-"+username, "on")
	form.Set("admin-"+otherUsername, "on")
	form.Set("locked-"+otherUsername, "on")
	rec := ts.PostForm(t, ts.Server, "/drasl/admin/update-users", form, []http.Cookie{*browserTokenCookie}, nil)

	assert.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, "", getErrorMessage(rec))
	assert.Equal(t, returnURL, rec.Header().Get("Location"))

	// Check that their account was locked and they were made an admin
	var other User
	result = ts.App.DB.First(&other, "username = ?", otherUsername)
	assert.Nil(t, result.Error)
	assert.True(t, other.IsAdmin)
	assert.True(t, other.IsLocked)
	// `otherUser` should be logged out of the web interface
	assert.NotEqual(t, "", otherBrowserTokenCookie.Value)
	assert.Nil(t, UnmakeNullString(&other.BrowserToken))

	// Delete `otherUser`
	form = url.Values{}
	form.Set("returnUrl", returnURL)
	form.Set("username", otherUsername)
	rec = ts.PostForm(t, ts.Server, "/drasl/delete-user", form, []http.Cookie{*browserTokenCookie}, nil)

	assert.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, "", getErrorMessage(rec))
	assert.Equal(t, returnURL, rec.Header().Get("Location"))
}
