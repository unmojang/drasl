package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"github.com/google/uuid"
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

var EXISTING_PLAYER_NAME = "Existing"
var EXISTING_OTHER_PLAYER_NAME = "ExistingOther"

func setupRegistrationExistingPlayerTS(t *testing.T, requireSkinVerification bool, requireInvite bool) *TestSuite {
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

	ts.CreateTestUser(t, ts.AuxApp, ts.AuxServer, EXISTING_PLAYER_NAME)
	ts.CreateTestUser(t, ts.AuxApp, ts.AuxServer, EXISTING_OTHER_PLAYER_NAME)

	return ts
}

func (ts *TestSuite) testStatusOK(t *testing.T, path string) {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rec := httptest.NewRecorder()

	ts.Server.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func (ts *TestSuite) testWebManifest(t *testing.T) {
	ts.testStatusOK(t, "/web/manifest.webmanifest")
}

func (ts *TestSuite) testPublic(t *testing.T) {
	ts.testStatusOK(t, "/")
	ts.testStatusOK(t, "/web/registration")
	ts.testStatusOK(t, "/web/public/bundle.js")
	ts.testStatusOK(t, "/web/public/style.css")
	ts.testStatusOK(t, "/web/public/logo.svg")
	ts.testStatusOK(t, "/web/public/icon.png")
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
	assert.Equal(t, ts.App.FrontEndURL+"/web/user", rec.Header().Get("Location"))
}

func (ts *TestSuite) createPlayerShouldFail(t *testing.T, rec *httptest.ResponseRecorder, errorMessage string, returnURL string) {
	assert.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, errorMessage, getErrorMessage(rec))
	assert.Equal(t, returnURL, rec.Header().Get("Location"))
}

func (ts *TestSuite) createPlayerShouldSucceed(t *testing.T, rec *httptest.ResponseRecorder) string {
	assert.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, "", getErrorMessage(rec))

	returnURLExp := regexp.MustCompile("^" + regexp.QuoteMeta(ts.App.FrontEndURL+"/web/player/") + "(.+)$")
	uuidMatch := returnURLExp.FindStringSubmatch(rec.Header().Get("Location"))
	assert.True(t, uuidMatch != nil && len(uuidMatch) == 2)
	uuid_ := uuidMatch[1]
	_, err := uuid.Parse(uuid_)
	assert.Nil(t, err)
	return uuid_
}

func (ts *TestSuite) updateUserShouldFail(t *testing.T, rec *httptest.ResponseRecorder, errorMessage string, returnURL string) {
	assert.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, errorMessage, getErrorMessage(rec))
	assert.Equal(t, returnURL, rec.Header().Get("Location"))
}

func (ts *TestSuite) updateUserShouldSucceed(t *testing.T, rec *httptest.ResponseRecorder) {
	assert.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, "", getErrorMessage(rec))
	assert.Equal(t, ts.App.FrontEndURL+"/web/user", rec.Header().Get("Location"))
}

func (ts *TestSuite) updatePlayerShouldFail(t *testing.T, rec *httptest.ResponseRecorder, errorMessage string, returnURL string) {
	assert.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, errorMessage, getErrorMessage(rec))
	assert.Equal(t, returnURL, rec.Header().Get("Location"))
}

func (ts *TestSuite) updatePlayerShouldSucceed(t *testing.T, rec *httptest.ResponseRecorder, playerUUID string) {
	assert.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, "", getErrorMessage(rec))
	assert.Equal(t, ts.App.FrontEndURL+"/web/player/"+playerUUID, rec.Header().Get("Location"))
}

func (ts *TestSuite) loginShouldSucceed(t *testing.T, rec *httptest.ResponseRecorder) {
	assert.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, "", getErrorMessage(rec))
	assert.NotEqual(t, "", getCookie(rec, "browserToken").Value)
	assert.Equal(t, ts.App.FrontEndURL+"/web/user", rec.Header().Get("Location"))
}

func (ts *TestSuite) loginShouldFail(t *testing.T, rec *httptest.ResponseRecorder, errorMessage string) {
	assert.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, errorMessage, getErrorMessage(rec))
	assert.Equal(t, "", getCookie(rec, "browserToken").Value)
	assert.Equal(t, ts.App.FrontEndURL, rec.Header().Get("Location"))
}

func TestFront(t *testing.T) {
	t.Parallel()
	{
		// Registration as existing player not allowed
		ts := &TestSuite{}

		config := testConfig()
		config.DefaultAdmins = []string{"registrationNewA"}
		ts.Setup(config)
		defer ts.Teardown()

		t.Run("Test public pages and assets", ts.testPublic)
		t.Run("Test web app manifest", ts.testWebManifest)
		t.Run("Test registration as new player", ts.testRegistrationNewPlayer)
		t.Run("Test registration as new player, chosen UUID, chosen UUID not allowed", ts.testRegistrationNewPlayerChosenUUIDNotAllowed)
		t.Run("Test user update", ts.testUserUpdate)
		t.Run("Test player update", ts.testPlayerUpdate)
		t.Run("Test creating/deleting invites", ts.testNewInviteDeleteInvite)
		t.Run("Test login, logout", ts.testLoginLogout)
		t.Run("Test delete account", ts.testDeleteAccount)
	}
	{
		ts := &TestSuite{}

		config := testConfig()
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
		t.Run("Test create new player, chosen UUID, chosen UUID allowed", ts.testCreateNewPlayer)
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
		// Set skin texture from URL
		ts := &TestSuite{}

		auxConfig := testConfig()
		ts.SetupAux(auxConfig)
		ts.CreateTestUser(t, ts.AuxApp, ts.AuxServer, EXISTING_PLAYER_NAME)

		config := testConfig()
		config.AllowTextureFromURL = true
		ts.Setup(config)
		defer ts.Teardown()

		t.Run("Test setting texture from URL", ts.testTextureFromURL)
	}
	{
		// Registration as existing player allowed, skin verification not required
		ts := setupRegistrationExistingPlayerTS(
			t,
			false, // requireSkinVerification
			false, // requireInvite
		)
		defer ts.Teardown()

		t.Run("Test registration as existing player, no skin verification", ts.testRegistrationExistingPlayerNoVerification)
		t.Run("Test import player, no skin verification", ts.testImportPlayerNoVerification)
	}
	{
		// Registration as existing player allowed, skin verification required
		ts := setupRegistrationExistingPlayerTS(
			t,
			true,  // requireSkinVerification
			false, // requireInvite
		)
		defer ts.Teardown()

		t.Run("Test registration as existing player, with skin verification", ts.testRegistrationExistingPlayerVerification)
		t.Run("Test import player, with skin verification", ts.testImportPlayerVerification)
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
		ts := setupRegistrationExistingPlayerTS(t, true, true)
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
	rec := ts.PostForm(t, ts.Server, "/web/login", form, nil, nil)
	ts.loginShouldFail(t, rec, "User not found!")
	rec = ts.PostForm(t, ts.Server, "/web/login", form, nil, nil)
	ts.loginShouldFail(t, rec, "User not found!")
	rec = ts.PostForm(t, ts.Server, "/web/login", form, nil, nil)
	ts.loginShouldFail(t, rec, "Too many requests. Try again later.")

	// Static paths should not be rate-limited
	rec = ts.Get(t, ts.Server, "/web/registration", nil, nil)
	assert.Equal(t, http.StatusOK, rec.Code)
	rec = ts.Get(t, ts.Server, "/web/registration", nil, nil)
	assert.Equal(t, http.StatusOK, rec.Code)
	rec = ts.Get(t, ts.Server, "/web/registration", nil, nil)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func (ts *TestSuite) testBodyLimit(t *testing.T) {
	form := url.Values{}
	form.Set("bogus", Unwrap(RandomHex(2048)))
	rec := ts.PostForm(t, ts.Server, "/web/login", form, nil, nil)
	assert.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)
}

func (ts *TestSuite) testRegistrationNewPlayer(t *testing.T) {
	usernameA := "registrationNewA"
	usernameAUppercase := "REGISTRATIONNEWA"
	usernameB := "registrationNewB"
	usernameC := "registrationNewC"
	returnURL := ts.App.FrontEndURL + "/web/registration"
	{
		// Tripping the honeypot should fail
		form := url.Values{}
		form.Set("username", usernameA)
		form.Set("password", TEST_PASSWORD)
		form.Set("email", "mail@example.com")
		form.Set("returnUrl", ts.App.FrontEndURL+"/web/registration")
		rec := ts.PostForm(t, ts.Server, "/web/register", form, nil, nil)
		ts.registrationShouldFail(t, rec, "You are now covered in bee stings.", returnURL)
	}
	{
		// Register
		form := url.Values{}
		form.Set("username", usernameA)
		form.Set("password", TEST_PASSWORD)
		rec := ts.PostForm(t, ts.Server, "/web/register", form, nil, nil)
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
			rec := ts.Get(t, ts.Server, "/web/user", []http.Cookie{*browserTokenCookie}, nil)
			assert.Equal(t, http.StatusOK, rec.Code)
			assert.Equal(t, "", getErrorMessage(rec))
		}

		// Get admin page
		{
			rec := ts.Get(t, ts.Server, "/web/admin", []http.Cookie{*browserTokenCookie}, nil)
			assert.Equal(t, http.StatusOK, rec.Code)
			assert.Equal(t, "", getErrorMessage(rec))
		}
	}
	{
		// Register
		form := url.Values{}
		form.Set("username", usernameB)
		form.Set("password", TEST_PASSWORD)
		form.Set("returnUrl", ts.App.FrontEndURL+"/web/registration")
		rec := ts.PostForm(t, ts.Server, "/web/register", form, nil, nil)
		ts.registrationShouldSucceed(t, rec)
		browserTokenCookie := getCookie(rec, "browserToken")

		// Users not in the DefaultAdmins list should not be admins
		var user User
		result := ts.App.DB.First(&user, "username = ?", usernameB)
		assert.Nil(t, result.Error)
		assert.False(t, ts.App.IsDefaultAdmin(&user))
		assert.False(t, user.IsAdmin)

		// Getting admin page should fail and redirect back to /
		rec = ts.Get(t, ts.Server, "/web/admin", []http.Cookie{*browserTokenCookie}, nil)
		assert.Equal(t, http.StatusSeeOther, rec.Code)
		assert.Equal(t, "You are not an admin.", getErrorMessage(rec))
		assert.Equal(t, ts.App.FrontEndURL, rec.Header().Get("Location"))
	}
	{
		// Try registering again with the same username
		form := url.Values{}
		form.Set("username", usernameA)
		form.Set("password", TEST_PASSWORD)
		form.Set("returnUrl", ts.App.FrontEndURL+"/web/registration")
		rec := ts.PostForm(t, ts.Server, "/web/register", form, nil, nil)

		ts.registrationShouldFail(t, rec, "That username is taken.", returnURL)
	}
	{
		// Test case insensitivity: try registering again with the "same"
		// username, but uppercase. Usernames are case-sensitive, but player
		// names are.
		form := url.Values{}
		form.Set("username", usernameAUppercase)
		form.Set("password", TEST_PASSWORD)
		form.Set("returnUrl", ts.App.FrontEndURL+"/web/registration")
		rec := ts.PostForm(t, ts.Server, "/web/register", form, nil, nil)

		ts.registrationShouldFail(t, rec, "That username is in use as the name of another user's player.", returnURL)
	}
	{
		// Registration with a too-long username should fail
		form := url.Values{}
		form.Set("username", "AReallyReallyReallyLongUsername")
		form.Set("password", TEST_PASSWORD)
		form.Set("returnUrl", returnURL)
		rec := ts.PostForm(t, ts.Server, "/web/register", form, nil, nil)

		ts.registrationShouldFail(t, rec, "Invalid username: can't be longer than 16 characters", returnURL)
	}
	{
		// Registration with a too-short password should fail
		form := url.Values{}
		form.Set("username", usernameC)
		form.Set("password", "")
		form.Set("returnUrl", returnURL)
		rec := ts.PostForm(t, ts.Server, "/web/register", form, nil, nil)

		ts.registrationShouldFail(t, rec, "Invalid password: can't be blank", returnURL)
	}
	{
		// Registration from an existing player should fail
		form := url.Values{}
		form.Set("username", usernameC)
		form.Set("password", TEST_PASSWORD)
		form.Set("existingPlayer", "on")
		form.Set("challengeToken", "This is not a valid challenge token.")
		form.Set("returnUrl", returnURL)
		rec := ts.PostForm(t, ts.Server, "/web/register", form, nil, nil)

		ts.registrationShouldFail(t, rec, "Registration from an existing player is not allowed.", returnURL)
	}
}

func (ts *TestSuite) testRegistrationNewPlayerChosenUUIDNotAllowed(t *testing.T) {
	username := "noChosenUUID"
	ts.CreateTestUser(t, ts.App, ts.Server, username)

	uuid := "11111111-2222-3333-4444-555555555555"

	ts.App.Config.RegistrationNewPlayer.AllowChoosingUUID = false

	returnURL := ts.App.FrontEndURL + "/web/registration"
	form := url.Values{}
	form.Set("username", username)
	form.Set("password", TEST_PASSWORD)
	form.Set("uuid", uuid)
	form.Set("returnUrl", returnURL)
	rec := ts.PostForm(t, ts.Server, "/web/register", form, nil, nil)

	ts.registrationShouldFail(t, rec, "Choosing a UUID is not allowed.", returnURL)
}

func (ts *TestSuite) testRegistrationNewPlayerChosenUUID(t *testing.T) {
	usernameA := "chosenUUIDA"
	usernameB := "chosenUUIDB"
	uuid := "11111111-2222-3333-4444-555555555555"
	returnURL := ts.App.FrontEndURL + "/web/registration"
	{
		// Register
		form := url.Values{}
		form.Set("username", usernameA)
		form.Set("password", TEST_PASSWORD)
		form.Set("uuid", uuid)
		form.Set("returnUrl", ts.App.FrontEndURL+"/web/registration")
		rec := ts.PostForm(t, ts.Server, "/web/register", form, nil, nil)

		// Registration should succeed, grant a browserToken, and redirect to user page
		assert.NotEqual(t, "", getCookie(rec, "browserToken"))
		ts.registrationShouldSucceed(t, rec)

		// Check that the user has been created and has a player with the chosen UUID
		var user User
		result := ts.App.DB.First(&user, "username = ?", usernameA)
		assert.Nil(t, result.Error)
		assert.Equal(t, 1, len(user.Players))
		assert.Equal(t, uuid, user.Players[0].UUID)
	}
	{
		// Try registering again with the same UUID
		form := url.Values{}
		form.Set("username", usernameB)
		form.Set("password", TEST_PASSWORD)
		form.Set("uuid", uuid)
		form.Set("returnUrl", ts.App.FrontEndURL+"/web/registration")
		rec := ts.PostForm(t, ts.Server, "/web/register", form, nil, nil)

		ts.registrationShouldFail(t, rec, "That UUID is taken.", returnURL)
	}
	{
		// Try registering with a garbage UUID
		form := url.Values{}
		form.Set("username", usernameB)
		form.Set("password", TEST_PASSWORD)
		form.Set("uuid", "This is not a UUID.")
		form.Set("returnUrl", ts.App.FrontEndURL+"/web/registration")
		rec := ts.PostForm(t, ts.Server, "/web/register", form, nil, nil)

		ts.registrationShouldFail(t, rec, "Invalid UUID: invalid UUID length: 19", returnURL)
	}
}

func (ts *TestSuite) testRegistrationNewPlayerInvite(t *testing.T) {
	usernameA := "inviteA"
	{
		// Registration without an invite should fail
		returnURL := ts.App.FrontEndURL + "/web/registration"
		form := url.Values{}
		form.Set("username", usernameA)
		form.Set("password", TEST_PASSWORD)
		form.Set("returnUrl", ts.App.FrontEndURL+"/web/registration")
		rec := ts.PostForm(t, ts.Server, "/web/register", form, nil, nil)
		ts.registrationShouldFail(t, rec, "Registration requires an invite.", returnURL)
	}
	{
		// Registration with an invalid invite should fail, and redirect to
		// registration page without ?invite
		returnURL := ts.App.FrontEndURL + "/web/registration"
		form := url.Values{}
		form.Set("username", usernameA)
		form.Set("password", TEST_PASSWORD)
		form.Set("inviteCode", "invalid")
		form.Set("returnUrl", ts.App.FrontEndURL+"/web/registration?invite=invalid")
		rec := ts.PostForm(t, ts.Server, "/web/register", form, nil, nil)
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
		returnURL := ts.App.FrontEndURL + "/web/registration?invite=" + invite.Code
		form := url.Values{}
		form.Set("username", "")
		form.Set("password", TEST_PASSWORD)
		form.Set("inviteCode", invite.Code)
		form.Set("returnUrl", returnURL)
		rec := ts.PostForm(t, ts.Server, "/web/register", form, nil, nil)
		ts.registrationShouldFail(t, rec, "Invalid username: can't be blank", returnURL)

		// Then, set a valid username and continnue
		form.Set("username", usernameA)
		rec = ts.PostForm(t, ts.Server, "/web/register", form, nil, nil)
		ts.registrationShouldSucceed(t, rec)

		// Invite should be deleted
		result = ts.App.DB.Find(&invites)
		assert.Nil(t, result.Error)
		assert.Equal(t, inviteCount-1, len(invites))
	}
}

func (ts *TestSuite) solveRegisterChallenge(t *testing.T, username string) *http.Cookie {
	// Get challenge skin
	req := httptest.NewRequest(http.MethodGet, "/web/register-challenge?username="+username, nil)
	rec := httptest.NewRecorder()
	ts.Server.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	challengeToken := getCookie(rec, "challengeToken")
	assert.NotEqual(t, "", challengeToken.Value)

	base64Exp, err := regexp.Compile("src=\"data:image\\/png;base64,([A-Za-z0-9+/&#;]*={0,2})\"")
	assert.Nil(t, err)
	match := base64Exp.FindStringSubmatch(rec.Body.String())
	assert.Equal(t, 2, len(match))
	// The base64 will come back HTML-escaped...
	base64String := html.UnescapeString(match[1])

	challengeSkin, err := base64.StdEncoding.DecodeString(base64String)
	assert.Nil(t, err)

	var auxPlayer Player
	result := ts.AuxApp.DB.First(&auxPlayer, "name = ?", username)
	assert.Nil(t, result.Error)

	// Bypass the controller for setting the skin here, we can test that with the rest of /update
	err = ts.AuxApp.SetSkinAndSave(&auxPlayer, bytes.NewReader(challengeSkin))
	assert.Nil(t, err)

	return challengeToken
}

func (ts *TestSuite) solveCreatePlayerChallenge(t *testing.T, playerName string) *http.Cookie {
	// Get challenge skin
	req := httptest.NewRequest(http.MethodGet, "/web/create-player-challenge?playerName="+playerName, nil)
	rec := httptest.NewRecorder()
	ts.Server.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	challengeToken := getCookie(rec, "challengeToken")
	assert.NotEqual(t, "", challengeToken.Value)

	base64Exp, err := regexp.Compile("src=\"data:image\\/png;base64,([A-Za-z0-9+/&#;]*={0,2})\"")
	assert.Nil(t, err)
	match := base64Exp.FindStringSubmatch(rec.Body.String())
	assert.Equal(t, 2, len(match))
	// The base64 will come back HTML-escaped...
	base64String := html.UnescapeString(match[1])

	challengeSkin, err := base64.StdEncoding.DecodeString(base64String)
	assert.Nil(t, err)

	var auxPlayer Player
	result := ts.AuxApp.DB.First(&auxPlayer, "name = ?", playerName)
	assert.Nil(t, result.Error)

	// Bypass the controller for setting the skin here, we can test that with the rest of /update
	err = ts.AuxApp.SetSkinAndSave(&auxPlayer, bytes.NewReader(challengeSkin))
	assert.Nil(t, err)

	return challengeToken
}

func (ts *TestSuite) testRegistrationExistingPlayerInvite(t *testing.T) {
	username := EXISTING_PLAYER_NAME
	{
		// Registration without an invite should fail
		returnURL := ts.App.FrontEndURL + "/web/registration"
		form := url.Values{}
		form.Set("username", username)
		form.Set("password", TEST_PASSWORD)
		form.Set("existingPlayer", "on")
		form.Set("returnUrl", ts.App.FrontEndURL+"/web/registration")
		rec := ts.PostForm(t, ts.Server, "/web/register", form, nil, nil)
		ts.registrationShouldFail(t, rec, InviteMissingError.Error(), returnURL)
	}
	{
		// Registration with an invalid invite should fail, and redirect to
		// registration page without ?invite
		returnURL := ts.App.FrontEndURL + "/web/registration"
		form := url.Values{}
		form.Set("username", username)
		form.Set("password", TEST_PASSWORD)
		form.Set("existingPlayer", "on")
		form.Set("inviteCode", "invalid")
		form.Set("returnUrl", ts.App.FrontEndURL+"/web/registration?invite=invalid")
		rec := ts.PostForm(t, ts.Server, "/web/register", form, nil, nil)
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

		challengeToken := ts.solveRegisterChallenge(t, username)
		returnURL := ts.App.FrontEndURL + "/web/registration?invite=" + invite.Code
		{
			// Registration with an invalid username should redirect to the
			// registration page with the same unused invite code
			form := url.Values{}
			form.Set("username", "")
			form.Set("password", TEST_PASSWORD)
			form.Set("existingPlayer", "on")
			form.Set("inviteCode", invite.Code)
			form.Set("returnUrl", returnURL)
			rec := ts.PostForm(t, ts.Server, "/web/register", form, nil, nil)
			ts.registrationShouldFail(t, rec, "Invalid username: can't be blank", returnURL)
		}
		{
			// Registration should fail if we give the wrong challenge token, and the invite should not be used
			form := url.Values{}
			form.Set("username", username)
			form.Set("password", TEST_PASSWORD)
			form.Set("existingPlayer", "on")
			form.Set("inviteCode", invite.Code)
			form.Set("challengeToken", "invalid-challenge-token")
			form.Set("returnUrl", returnURL)
			rec := ts.PostForm(t, ts.Server, "/web/register", form, nil, nil)

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
			rec := ts.PostForm(t, ts.Server, "/web/register", form, nil, nil)

			ts.registrationShouldSucceed(t, rec)

			// Check that the created user has a player with the same UUID
			var user User
			result = ts.App.DB.First(&user, "username = ?", username)
			assert.Nil(t, result.Error)
			player := user.Players[0]

			var auxPlayer Player
			result = ts.AuxApp.DB.First(&auxPlayer, "name = ?", username)
			assert.Nil(t, result.Error)
			assert.Equal(t, auxPlayer.UUID, player.UUID)

			// Invite should be deleted
			result = ts.App.DB.Find(&invites)
			assert.Nil(t, result.Error)
			assert.Equal(t, inviteCount-1, len(invites))
		}
	}
}

func (ts *TestSuite) testLoginLogout(t *testing.T) {
	username := "loginLogout"
	ts.CreateTestUser(t, ts.App, ts.Server, username)

	{
		// Login
		form := url.Values{}
		form.Set("username", username)
		form.Set("password", TEST_PASSWORD)
		form.Set("returnUrl", ts.App.FrontEndURL+"/web/registration")
		rec := ts.PostForm(t, ts.Server, "/web/login", form, nil, nil)
		ts.loginShouldSucceed(t, rec)
		browserTokenCookie := getCookie(rec, "browserToken")

		// The BrowserToken we get should match the one in the database
		var user User
		result := ts.App.DB.First(&user, "username = ?", username)
		assert.Nil(t, result.Error)
		assert.Equal(t, *UnmakeNullString(&user.BrowserToken), browserTokenCookie.Value)

		// Get user page
		req := httptest.NewRequest(http.MethodGet, "/web/user", nil)
		req.AddCookie(browserTokenCookie)
		rec = httptest.NewRecorder()
		ts.Server.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "", getErrorMessage(rec))

		// Logout should redirect to / and clear the browserToken
		rec = ts.PostForm(t, ts.Server, "/web/logout", url.Values{}, []http.Cookie{*browserTokenCookie}, nil)
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
		rec := ts.PostForm(t, ts.Server, "/web/login", form, nil, nil)
		ts.loginShouldFail(t, rec, "Incorrect password!")
	}
	{
		// GET /web/user without valid BrowserToken should fail
		req := httptest.NewRequest(http.MethodGet, "/web/user", nil)
		rec := httptest.NewRecorder()
		ts.Server.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusSeeOther, rec.Code)
		assert.Equal(t, ts.App.FrontEndURL+"?destination=%2Fweb%2Fuser", rec.Header().Get("Location"))
		assert.Equal(t, "You are not logged in.", getErrorMessage(rec))

		// Logout without valid BrowserToken should fail
		rec = ts.PostForm(t, ts.Server, "/web/logout", url.Values{}, nil, nil)
		assert.Equal(t, http.StatusSeeOther, rec.Code)
		assert.Equal(t, ts.App.FrontEndURL, rec.Header().Get("Location"))
		assert.Equal(t, "You are not logged in.", getErrorMessage(rec))
	}
}

func (ts *TestSuite) testRegistrationExistingPlayerNoVerification(t *testing.T) {
	username := EXISTING_PLAYER_NAME
	returnURL := ts.App.FrontEndURL + "/web/registration"

	// Register from the existing account
	form := url.Values{}
	form.Set("username", username)
	form.Set("password", TEST_PASSWORD)
	form.Set("existingPlayer", "on")
	form.Set("returnUrl", returnURL)
	rec := ts.PostForm(t, ts.Server, "/web/register", form, nil, nil)
	ts.registrationShouldSucceed(t, rec)

	// Check that the new user was created and has a player with the same UUID
	// as the player on the auxiliary server
	var auxPlayer Player
	result := ts.AuxApp.DB.First(&auxPlayer, "name = ?", username)
	assert.Nil(t, result.Error)

	var user User
	result = ts.App.DB.First(&user, "username = ?", username)
	assert.Nil(t, result.Error)
	assert.Equal(t, 1, len(user.Players))
	player := user.Players[0]
	assert.Equal(t, auxPlayer.UUID, player.UUID)

	{
		// Registration as a new user should fail
		form := url.Values{}
		form.Set("username", username)
		form.Set("password", TEST_PASSWORD)
		form.Set("returnUrl", returnURL)
		rec := ts.PostForm(t, ts.Server, "/web/register", form, nil, nil)
		ts.registrationShouldFail(t, rec, "Registration without some existing player is not allowed.", returnURL)
	}
	{
		// Registration with a missing existing account should fail
		returnURL := ts.App.FrontEndURL + "/web/registration"
		form := url.Values{}
		form.Set("username", "nonexistent")
		form.Set("password", TEST_PASSWORD)
		form.Set("existingPlayer", "on")
		form.Set("returnUrl", returnURL)
		rec := ts.PostForm(t, ts.Server, "/web/register", form, nil, nil)
		ts.registrationShouldFail(t, rec, "Couldn't find your account, maybe try again: registration server returned error", returnURL)
	}
}

func (ts *TestSuite) testImportPlayerNoVerification(t *testing.T) {
	user, browserTokenCookie := ts.CreateTestUser(t, ts.App, ts.Server, "ImportPlayer")
	user.MaxPlayerCount = ts.App.Constants.MaxPlayerCountUnlimited
	assert.Nil(t, ts.App.DB.Save(&user).Error)

	returnURL := ts.App.FrontEndURL + "/web/user"

	form := url.Values{}
	form.Set("userUuid", user.UUID)
	form.Set("playerName", EXISTING_OTHER_PLAYER_NAME)
	form.Set("existingPlayer", "on")
	form.Set("returnUrl", returnURL)
	rec := ts.PostForm(t, ts.Server, "/web/create-player", form, []http.Cookie{*browserTokenCookie}, nil)
	createdUUID := ts.createPlayerShouldSucceed(t, rec)

	// Check that the new player was created with the same UUID as the player
	// on the auxiliary server
	var auxPlayer Player
	result := ts.AuxApp.DB.First(&auxPlayer, "name = ?", EXISTING_OTHER_PLAYER_NAME)
	assert.Nil(t, result.Error)

	var player Player
	assert.Nil(t, ts.App.DB.First(&player, "uuid = ?", auxPlayer.UUID).Error)
	assert.Equal(t, user.UUID, player.UserUUID)
	assert.Equal(t, createdUUID, player.UUID)

	assert.Nil(t, ts.App.DB.First(&user, "uuid = ?", user.UUID).Error)
	assert.Equal(t, 2, len(user.Players))

	{
		// Creating a new player should fail
		form := url.Values{}
		form.Set("userUuid", user.UUID)
		form.Set("playerName", "SomeJunk")
		form.Set("returnUrl", returnURL)
		rec := ts.PostForm(t, ts.Server, "/web/create-player", form, []http.Cookie{*browserTokenCookie}, nil)
		ts.createPlayerShouldFail(t, rec, "Creating a new player is not allowed.", returnURL)
	}
	{
		// Creating a player with a missing existing player should fail
		form := url.Values{}
		form.Set("userUuid", user.UUID)
		form.Set("playerName", "Nonexistent")
		form.Set("existingPlayer", "on")
		form.Set("returnUrl", returnURL)
		rec := ts.PostForm(t, ts.Server, "/web/create-player", form, []http.Cookie{*browserTokenCookie}, nil)
		ts.createPlayerShouldFail(t, rec, "Couldn't find your account, maybe try again: registration server returned error", returnURL)
	}
}

func (ts *TestSuite) testImportPlayerVerification(t *testing.T) {
	user, browserTokenCookie := ts.CreateTestUser(t, ts.App, ts.Server, "ImportPlayer")
	user.MaxPlayerCount = ts.App.Constants.MaxPlayerCountUnlimited
	assert.Nil(t, ts.App.DB.Save(&user).Error)

	returnURL := ts.App.FrontEndURL + "/web/user"

	challengeToken := ts.solveCreatePlayerChallenge(t, EXISTING_OTHER_PLAYER_NAME)

	{
		// Importing player should fail if we give the wrong challenge token
		form := url.Values{}
		form.Set("userUuid", user.UUID)
		form.Set("playerName", EXISTING_OTHER_PLAYER_NAME)
		form.Set("existingPlayer", "on")
		form.Set("challengeToken", "invalid-challenge-token")
		form.Set("returnUrl", returnURL)
		rec := ts.PostForm(t, ts.Server, "/web/create-player", form, []http.Cookie{*browserTokenCookie}, nil)
		ts.createPlayerShouldFail(t, rec, "Couldn't verify your skin, maybe try again: skin does not match", returnURL)
	}
	{
		// Import should succeed when we give the correct challenge token
		form := url.Values{}
		form.Set("userUuid", user.UUID)
		form.Set("playerName", EXISTING_OTHER_PLAYER_NAME)
		form.Set("existingPlayer", "on")
		form.Set("challengeToken", challengeToken.Value)
		form.Set("returnUrl", returnURL)
		rec := ts.PostForm(t, ts.Server, "/web/create-player", form, []http.Cookie{*browserTokenCookie}, nil)
		createdUUID := ts.createPlayerShouldSucceed(t, rec)

		// Check that the new player was created with the same UUID as the player
		// on the auxiliary server
		var auxPlayer Player
		result := ts.AuxApp.DB.First(&auxPlayer, "name = ?", EXISTING_OTHER_PLAYER_NAME)
		assert.Nil(t, result.Error)

		var player Player
		assert.Nil(t, ts.App.DB.First(&player, "uuid = ?", auxPlayer.UUID).Error)
		assert.Equal(t, user.UUID, player.UserUUID)
		assert.Equal(t, createdUUID, player.UUID)

		assert.Nil(t, ts.App.DB.First(&user, "uuid = ?", user.UUID).Error)
		assert.Equal(t, 2, len(user.Players))
	}
}

func (ts *TestSuite) testRegistrationExistingPlayerVerification(t *testing.T) {
	username := EXISTING_PLAYER_NAME
	returnURL := ts.App.FrontEndURL + "/web/registration"
	{
		// Registration without setting a skin should fail
		form := url.Values{}
		form.Set("username", username)
		form.Set("password", TEST_PASSWORD)
		form.Set("existingPlayer", "on")
		form.Set("returnUrl", ts.App.FrontEndURL+"/web/registration")
		rec := ts.PostForm(t, ts.Server, "/web/register", form, nil, nil)
		ts.registrationShouldFail(t, rec, "Couldn't verify your skin, maybe try again: player does not have a skin", returnURL)
	}
	{
		// Get challenge skin with invalid username should fail
		req := httptest.NewRequest(http.MethodGet, "/web/register-challenge?username=AReallyReallyReallyLongUsername&returnUrl="+ts.App.FrontEndURL+"/web/registration", nil)
		rec := httptest.NewRecorder()
		ts.Server.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusSeeOther, rec.Code)
		assert.Equal(t, "Invalid username: can't be longer than 16 characters", getErrorMessage(rec))
		assert.Equal(t, returnURL, rec.Header().Get("Location"))
	}
	{
		challengeToken := ts.solveRegisterChallenge(t, username)
		{
			// Registration should fail if we give the wrong challenge token
			form := url.Values{}
			form.Set("username", username)
			form.Set("password", TEST_PASSWORD)
			form.Set("existingPlayer", "on")
			form.Set("challengeToken", "invalid-challenge-token")
			form.Set("returnUrl", returnURL)
			rec := ts.PostForm(t, ts.Server, "/web/register", form, nil, nil)

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
			rec := ts.PostForm(t, ts.Server, "/web/register", form, nil, nil)

			ts.registrationShouldSucceed(t, rec)

			// Check that the user has been created with the same UUID
			var auxPlayer Player
			result := ts.AuxApp.DB.First(&auxPlayer, "name = ?", username)
			assert.Nil(t, result.Error)

			var user User
			result = ts.App.DB.First(&user, "username = ?", username)
			assert.Nil(t, result.Error)
			assert.Equal(t, 1, len(user.Players))
			player := user.Players[0]
			assert.Equal(t, auxPlayer.UUID, player.UUID)
		}
	}
}

func (ts *TestSuite) testNewInviteDeleteInvite(t *testing.T) {
	username := "inviteAdmin"
	user, browserTokenCookie := ts.CreateTestUser(t, ts.App, ts.Server, username)

	user.IsAdmin = true
	result := ts.App.DB.Save(&user)
	assert.Nil(t, result.Error)

	// Create an invite
	returnURL := ts.App.FrontEndURL + "/web/admin"
	form := url.Values{}
	form.Set("returnUrl", returnURL)
	rec := ts.PostForm(t, ts.Server, "/web/admin/new-invite", form, []http.Cookie{*browserTokenCookie}, nil)

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
	rec = ts.PostForm(t, ts.Server, "/web/admin/delete-invite", form, []http.Cookie{*browserTokenCookie}, nil)

	assert.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, "", getErrorMessage(rec))
	assert.Equal(t, returnURL, rec.Header().Get("Location"))

	// Check that invite was deleted
	result = ts.App.DB.Find(&invites)
	assert.Nil(t, result.Error)
	assert.Equal(t, 0, len(invites))
}

func (ts *TestSuite) testUserUpdate(t *testing.T) {
	username := "userUpdate"
	takenUsername := "userUpdateTaken"
	user, browserTokenCookie := ts.CreateTestUser(t, ts.App, ts.Server, username)
	takenUser, takenBrowserTokenCookie := ts.CreateTestUser(t, ts.App, ts.Server, takenUsername)

	assert.Equal(t, "en", user.PreferredLanguage)
	user.IsAdmin = true
	assert.Nil(t, ts.App.DB.Save(&user).Error)

	{
		// Successful update
		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)

		assert.Nil(t, writer.WriteField("preferredLanguage", "es"))
		assert.Nil(t, writer.WriteField("password", "newpassword"))
		assert.Nil(t, writer.WriteField("returnUrl", ts.App.FrontEndURL+"/web/user"))

		rec := ts.PostMultipart(t, ts.Server, "/web/update-user", body, writer, []http.Cookie{*browserTokenCookie}, nil)
		ts.updateUserShouldSucceed(t, rec)

		var updatedUser User
		result := ts.App.DB.First(&updatedUser, "uuid = ?", user.UUID)
		assert.Nil(t, result.Error)
		assert.Equal(t, "es", updatedUser.PreferredLanguage)

		// Make sure we can log in with the new password
		form := url.Values{}
		form.Set("username", username)
		form.Set("password", "newpassword")
		form.Set("returnUrl", ts.App.FrontEndURL+"/web/registration")
		rec = ts.PostForm(t, ts.Server, "/web/login", form, nil, nil)
		ts.loginShouldSucceed(t, rec)
		browserTokenCookie = getCookie(rec, "browserToken")
	}
	{
		// As an admin, test updating another user's account
		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)
		assert.Nil(t, writer.WriteField("uuid", takenUser.UUID))
		assert.Nil(t, writer.WriteField("maxPlayerCount", "3"))
		assert.Nil(t, writer.WriteField("preferredLanguage", "es"))
		assert.Nil(t, writer.WriteField("returnUrl", ts.App.FrontEndURL+"/web/user"))
		assert.Nil(t, writer.Close())
		rec := ts.PostMultipart(t, ts.Server, "/web/update-user", body, writer, []http.Cookie{*browserTokenCookie}, nil)
		ts.updateUserShouldSucceed(t, rec)
	}
	{
		// Non-admin should not be able to edit another user
		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)
		assert.Nil(t, writer.WriteField("uuid", user.UUID))
		assert.Nil(t, writer.WriteField("preferredLanguage", "es"))
		assert.Nil(t, writer.WriteField("returnUrl", ts.App.FrontEndURL+"/web/user"))
		assert.Nil(t, writer.Close())
		rec := ts.PostMultipart(t, ts.Server, "/web/update-user", body, writer, []http.Cookie{*takenBrowserTokenCookie}, nil)
		ts.updateUserShouldFail(t, rec, "You are not an admin.", ts.App.FrontEndURL)
	}
	{
		// Non-admin should not be able to increase their max player count
		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)
		assert.Nil(t, writer.WriteField("uuid", takenUser.UUID))
		assert.Nil(t, writer.WriteField("maxPlayerCount", "-1"))
		assert.Nil(t, writer.WriteField("returnUrl", ts.App.FrontEndURL+"/web/user"))
		assert.Nil(t, writer.Close())
		rec := ts.PostMultipart(t, ts.Server, "/web/update-user", body, writer, []http.Cookie{*takenBrowserTokenCookie}, nil)
		ts.updateUserShouldFail(t, rec, "Cannot set a max player count without admin privileges.", ts.App.FrontEndURL+"/web/user")
	}
	{
		// Non-admin should be able to change other settings
		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)
		assert.Nil(t, writer.WriteField("preferredLanguage", "ar"))
		assert.Nil(t, writer.WriteField("returnUrl", ts.App.FrontEndURL+"/web/user"))
		assert.Nil(t, writer.Close())
		rec := ts.PostMultipart(t, ts.Server, "/web/update-user", body, writer, []http.Cookie{*takenBrowserTokenCookie}, nil)
		ts.updateUserShouldSucceed(t, rec)
	}
	{
		// Invalid preferred language should fail
		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)
		assert.Nil(t, writer.WriteField("preferredLanguage", "xx"))
		assert.Nil(t, writer.WriteField("returnUrl", ts.App.FrontEndURL+"/web/user"))
		assert.Nil(t, writer.Close())
		rec := ts.PostMultipart(t, ts.Server, "/web/update-user", body, writer, []http.Cookie{*browserTokenCookie}, nil)
		ts.updateUserShouldFail(t, rec, "Invalid preferred language.", ts.App.FrontEndURL+"/web/user")
	}
	{
		// Setting an invalid password should fail
		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)
		assert.Nil(t, writer.WriteField("password", "short"))
		assert.Nil(t, writer.WriteField("returnUrl", ts.App.FrontEndURL+"/web/user"))
		assert.Nil(t, writer.Close())
		rec := ts.PostMultipart(t, ts.Server, "/web/update-user", body, writer, []http.Cookie{*browserTokenCookie}, nil)
		ts.updateUserShouldFail(t, rec, "Invalid password: password must be longer than 8 characters", ts.App.FrontEndURL+"/web/user")
	}
}

func (ts *TestSuite) testPlayerUpdate(t *testing.T) {
	playerName := "playerUpdate"
	takenPlayerName := "pUpdateTaken"
	user, browserTokenCookie := ts.CreateTestUser(t, ts.App, ts.Server, playerName)
	player := user.Players[0]
	takenUser, takenBrowserTokenCookie := ts.CreateTestUser(t, ts.App, ts.Server, takenPlayerName)
	takenPlayer := takenUser.Players[0]

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

		newPlayerName := "newPlayerUpdate"

		assert.Nil(t, writer.WriteField("uuid", player.UUID))
		assert.Nil(t, writer.WriteField("playerName", newPlayerName))
		assert.Nil(t, writer.WriteField("fallbackPlayer", newPlayerName))
		assert.Nil(t, writer.WriteField("skinModel", "slim"))
		skinFileField, err := writer.CreateFormFile("skinFile", "redSkin.png")
		assert.Nil(t, err)
		_, err = skinFileField.Write(RED_SKIN)
		assert.Nil(t, err)

		capeFileField, err := writer.CreateFormFile("capeFile", "redCape.png")
		assert.Nil(t, err)
		_, err = capeFileField.Write(RED_CAPE)
		assert.Nil(t, err)

		assert.Nil(t, writer.WriteField("returnUrl", ts.App.FrontEndURL+"/web/player/"+player.UUID))

		rec := ts.PostMultipart(t, ts.Server, "/web/update-player", body, writer, []http.Cookie{*browserTokenCookie}, nil)
		ts.updatePlayerShouldSucceed(t, rec, player.UUID)

		var updatedPlayer Player
		result := ts.App.DB.First(&updatedPlayer, "name = ?", newPlayerName)
		assert.Nil(t, result.Error)
		assert.Equal(t, "slim", updatedPlayer.SkinModel)
		assert.Equal(t, redSkinHash, *UnmakeNullString(&updatedPlayer.SkinHash))
		assert.Equal(t, redCapeHash, *UnmakeNullString(&updatedPlayer.CapeHash))
	}
	{
		// As an admin, test updating another user's player
		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)
		assert.Nil(t, writer.WriteField("uuid", takenPlayer.UUID))
		assert.Nil(t, writer.WriteField("skinModel", "slim"))
		assert.Nil(t, writer.WriteField("returnUrl", ts.App.FrontEndURL+"/web/player/"+takenPlayer.UUID))
		assert.Nil(t, writer.Close())
		rec := ts.PostMultipart(t, ts.Server, "/web/update-player", body, writer, []http.Cookie{*browserTokenCookie}, nil)
		ts.updatePlayerShouldSucceed(t, rec, takenPlayer.UUID)
	}
	{
		// Non-admin should not be able to edit another user's player
		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)
		assert.Nil(t, writer.WriteField("uuid", player.UUID))
		assert.Nil(t, writer.WriteField("preferredLanguage", "es"))
		assert.Nil(t, writer.WriteField("returnUrl", ts.App.FrontEndURL+"/web/player/"+player.UUID))
		assert.Nil(t, writer.Close())
		rec := ts.PostMultipart(t, ts.Server, "/web/update-player", body, writer, []http.Cookie{*takenBrowserTokenCookie}, nil)
		ts.updatePlayerShouldFail(t, rec, "Can't update a player belonging to another user unless you're an admin.", ts.App.FrontEndURL+"/web/player/"+player.UUID)
	}
	{
		// Deleting skin should succeed
		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)
		assert.Nil(t, writer.WriteField("uuid", player.UUID))
		assert.Nil(t, writer.WriteField("deleteSkin", "on"))
		assert.Nil(t, writer.WriteField("returnUrl", ts.App.FrontEndURL+"/web/player/"+player.UUID))
		assert.Nil(t, writer.Close())
		rec := ts.PostMultipart(t, ts.Server, "/web/update-player", body, writer, []http.Cookie{*browserTokenCookie}, nil)
		ts.updatePlayerShouldSucceed(t, rec, player.UUID)

		var updatedPlayer Player
		result := ts.App.DB.First(&updatedPlayer, "uuid = ?", player.UUID)
		assert.Nil(t, result.Error)
		assert.Nil(t, UnmakeNullString(&updatedPlayer.SkinHash))
		assert.NotNil(t, UnmakeNullString(&updatedPlayer.CapeHash))
		assert.Nil(t, ts.App.SetSkinAndSave(&updatedPlayer, bytes.NewReader(RED_SKIN)))
	}
	{
		// Deleting cape should succeed
		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)
		assert.Nil(t, writer.WriteField("uuid", player.UUID))
		assert.Nil(t, writer.WriteField("deleteCape", "on"))
		assert.Nil(t, writer.WriteField("returnUrl", ts.App.FrontEndURL+"/web/player/"+player.UUID))
		assert.Nil(t, writer.Close())
		rec := ts.PostMultipart(t, ts.Server, "/web/update-player", body, writer, []http.Cookie{*browserTokenCookie}, nil)
		ts.updatePlayerShouldSucceed(t, rec, player.UUID)

		var updatedPlayer Player
		result := ts.App.DB.First(&updatedPlayer, "uuid = ?", player.UUID)
		assert.Nil(t, result.Error)
		assert.Nil(t, UnmakeNullString(&updatedPlayer.CapeHash))
		assert.NotNil(t, UnmakeNullString(&updatedPlayer.SkinHash))
		assert.Nil(t, ts.App.SetCapeAndSave(&updatedPlayer, bytes.NewReader(RED_CAPE)))
	}
	{
		// Invalid player name should fail
		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)
		assert.Nil(t, writer.WriteField("uuid", player.UUID))
		assert.Nil(t, writer.WriteField("playerName", "AReallyReallyReallyLongUsername"))
		assert.Nil(t, writer.WriteField("returnUrl", ts.App.FrontEndURL+"/web/player/"+player.UUID))
		assert.Nil(t, writer.Close())
		rec := ts.PostMultipart(t, ts.Server, "/web/update-player", body, writer, []http.Cookie{*browserTokenCookie}, nil)
		ts.updatePlayerShouldFail(t, rec, "Invalid player name: can't be longer than 16 characters", ts.App.FrontEndURL+"/web/player/"+player.UUID)
	}
	{
		// Setting a skin from URL should fail for non-admin (config.AllowTextureFromURL is false by default)
		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)

		assert.Nil(t, writer.WriteField("uuid", takenPlayer.UUID))
		assert.Nil(t, writer.WriteField("skinUrl", "https://example.com/skin.png"))
		assert.Nil(t, writer.WriteField("returnUrl", ts.App.FrontEndURL+"/web/profile"))
		assert.Nil(t, writer.Close())
		rec := ts.PostMultipart(t, ts.Server, "/web/update-player", body, writer, []http.Cookie{*takenBrowserTokenCookie}, nil)
		ts.updatePlayerShouldFail(t, rec, "Setting a skin from a URL is not allowed.", ts.App.FrontEndURL+"/web/profile")
	}
	{
		// Invalid fallback player should fail
		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)
		assert.Nil(t, writer.WriteField("uuid", player.UUID))
		assert.Nil(t, writer.WriteField("fallbackPlayer", "521759201-invalid-uuid-057219"))
		assert.Nil(t, writer.WriteField("returnUrl", ts.App.FrontEndURL+"/web/player/"+player.UUID))
		assert.Nil(t, writer.Close())
		rec := ts.PostMultipart(t, ts.Server, "/web/update-player", body, writer, []http.Cookie{*browserTokenCookie}, nil)
		ts.updatePlayerShouldFail(t, rec, "Invalid fallback player: not a valid player name or UUID", ts.App.FrontEndURL+"/web/player/"+player.UUID)
	}
	{
		// Changing to a taken player name should fail
		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)
		assert.Nil(t, writer.WriteField("uuid", player.UUID))
		assert.Nil(t, writer.WriteField("playerName", takenPlayerName))
		assert.Nil(t, writer.WriteField("returnUrl", ts.App.FrontEndURL+"/web/player/"+player.UUID))
		assert.Nil(t, writer.Close())
		rec := ts.PostMultipart(t, ts.Server, "/web/update-player", body, writer, []http.Cookie{*browserTokenCookie}, nil)
		ts.updatePlayerShouldFail(t, rec, "That player name is taken.", ts.App.FrontEndURL+"/web/player/"+player.UUID)
	}
}

func (ts *TestSuite) testCreateNewPlayer(t *testing.T) {
	username := "createNewPlayer1"
	user, browserTokenCookie := ts.CreateTestUser(t, ts.App, ts.Server, username)
	user.MaxPlayerCount = ts.App.Constants.MaxPlayerCountUnlimited
	assert.Nil(t, ts.App.DB.Save(&user).Error)

	chosenUUID := "2f7b0267-2502-49f9-ba05-8f9c958df02c"

	form := url.Values{}
	form.Set("userUuid", user.UUID)
	form.Set("playerName", "createNewPlayer2")
	form.Set("playerUuid", chosenUUID)
	form.Set("returnUrl", ts.App.FrontEndURL+"/web/user")
	rec := ts.PostForm(t, ts.Server, "/web/create-player", form, []http.Cookie{*browserTokenCookie}, nil)
	createdUUID := ts.createPlayerShouldSucceed(t, rec)
	assert.Equal(t, chosenUUID, createdUUID)
}

func (ts *TestSuite) testUpdateSkinsCapesNotAllowed(t *testing.T) {
	playerName := "updateNoSkinCape"
	user, browserTokenCookie := ts.CreateTestUser(t, ts.App, ts.Server, playerName)
	player := user.Players[0]

	{
		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)
		assert.Nil(t, writer.WriteField("uuid", player.UUID))
		assert.Nil(t, writer.WriteField("returnUrl", ts.App.FrontEndURL+"/web/player/"+player.UUID))
		assert.Nil(t, writer.WriteField("skinModel", "classic"))
		skinFileField, err := writer.CreateFormFile("skinFile", "redSkin.png")
		assert.Nil(t, err)
		_, err = skinFileField.Write(RED_SKIN)
		assert.Nil(t, err)

		assert.Nil(t, writer.Close())
		rec := ts.PostMultipart(t, ts.Server, "/web/update-player", body, writer, []http.Cookie{*browserTokenCookie}, nil)
		ts.updateUserShouldFail(t, rec, "Setting a skin texture is not allowed.", ts.App.FrontEndURL+"/web/player/"+player.UUID)

		// The player should not have a skin set
		result := ts.App.DB.First(&player, "uuid = ?", player.UUID)
		assert.Nil(t, result.Error)
		assert.Nil(t, UnmakeNullString(&user.Players[0].SkinHash))
	}
	{
		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)
		assert.Nil(t, writer.WriteField("uuid", player.UUID))
		assert.Nil(t, writer.WriteField("returnUrl", ts.App.FrontEndURL+"/web/player/"+player.UUID))
		capeFileField, err := writer.CreateFormFile("capeFile", "redCape.png")
		assert.Nil(t, err)
		_, err = capeFileField.Write(RED_CAPE)
		assert.Nil(t, err)

		assert.Nil(t, writer.Close())
		rec := ts.PostMultipart(t, ts.Server, "/web/update-player", body, writer, []http.Cookie{*browserTokenCookie}, nil)
		ts.updateUserShouldFail(t, rec, "Setting a cape texture is not allowed.", ts.App.FrontEndURL+"/web/player/"+player.UUID)

		// The player should not have a cape set
		result := ts.App.DB.First(&player, "uuid = ?", player.UUID)
		assert.Nil(t, result.Error)
		assert.Nil(t, UnmakeNullString(&player.CapeHash))
	}
}

func (ts *TestSuite) testTextureFromURL(t *testing.T) {
	// Test setting skin from URL
	username := "textureFromURL"
	user, browserTokenCookie := ts.CreateTestUser(t, ts.App, ts.Server, username)
	player := user.Players[0]

	var auxPlayer Player
	result := ts.AuxApp.DB.First(&auxPlayer, "name = ?", EXISTING_PLAYER_NAME)
	assert.Nil(t, result.Error)

	// Set a skin on the existing account
	assert.Nil(t, ts.AuxApp.SetSkinAndSave(&auxPlayer, bytes.NewReader(BLUE_SKIN)))
	skinHash := *UnmakeNullString(&auxPlayer.SkinHash)
	skinURL, err := ts.AuxApp.SkinURL(skinHash)
	assert.Nil(t, err)

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	assert.Nil(t, writer.WriteField("uuid", player.UUID))
	assert.Nil(t, writer.WriteField("skinUrl", skinURL))
	assert.Nil(t, writer.WriteField("returnUrl", ts.App.FrontEndURL+"/web/player/"+player.UUID))
	assert.Nil(t, writer.Close())
	rec := ts.PostMultipart(t, ts.Server, "/web/update-player", body, writer, []http.Cookie{*browserTokenCookie}, nil)
	ts.updatePlayerShouldSucceed(t, rec, player.UUID)

	assert.Nil(t, ts.App.DB.First(&player, "uuid = ?", player.UUID).Error)
	assert.Equal(t, skinHash, *UnmakeNullString(&player.SkinHash))
}

func (ts *TestSuite) testDeleteAccount(t *testing.T) {
	usernameA := "deleteA"
	usernameB := "deleteB"

	ts.CreateTestUser(t, ts.App, ts.Server, usernameA)
	{
		var user User
		result := ts.App.DB.First(&user, "username = ?", usernameA)
		assert.Nil(t, result.Error)
		player := user.Players[0]

		// Set red skin and cape on usernameA
		err := ts.App.SetSkinAndSave(&player, bytes.NewReader(RED_SKIN))
		assert.Nil(t, err)
		err = ts.App.SetCapeAndSave(&player, bytes.NewReader(RED_CAPE))
		assert.Nil(t, err)

		// Register usernameB
		_, browserTokenCookie := ts.CreateTestUser(t, ts.App, ts.Server, usernameB)

		// Check that usernameB has been created
		var otherUser User
		result = ts.App.DB.First(&otherUser, "username = ?", usernameB)
		assert.Nil(t, result.Error)
		otherPlayer := user.Players[0]

		// Set red skin and cape on usernameB
		err = ts.App.SetSkinAndSave(&otherPlayer, bytes.NewReader(RED_SKIN))
		assert.Nil(t, err)
		err = ts.App.SetCapeAndSave(&otherPlayer, bytes.NewReader(RED_CAPE))
		assert.Nil(t, err)

		// Delete account usernameB
		rec := ts.PostForm(t, ts.Server, "/web/delete-user", url.Values{}, []http.Cookie{*browserTokenCookie}, nil)
		assert.Equal(t, http.StatusSeeOther, rec.Code)
		assert.Equal(t, "", getErrorMessage(rec))
		assert.Equal(t, ts.App.FrontEndURL, rec.Header().Get("Location"))

		// Check that usernameB has been deleted
		result = ts.App.DB.First(&otherUser, "username = ?", usernameB)
		assert.True(t, errors.Is(result.Error, gorm.ErrRecordNotFound))

		// Check that the red skin and cape still exist in the filesystem
		_, err = os.Stat(ts.App.GetSkinPath(*UnmakeNullString(&player.SkinHash)))
		assert.Nil(t, err)
		_, err = os.Stat(ts.App.GetCapePath(*UnmakeNullString(&player.CapeHash)))
		assert.Nil(t, err)
	}
	{
		// Register usernameB again
		form := url.Values{}
		form.Set("username", usernameB)
		form.Set("password", TEST_PASSWORD)
		rec := ts.PostForm(t, ts.Server, "/web/register", form, nil, nil)
		ts.registrationShouldSucceed(t, rec)
		browserTokenCookie := getCookie(rec, "browserToken")

		// Check that usernameB has been created
		var otherUser User
		result := ts.App.DB.First(&otherUser, "username = ?", usernameB)
		assert.Nil(t, result.Error)
		otherPlayer := otherUser.Players[0]

		// Set blue skin and cape on usernameB
		err := ts.App.SetSkinAndSave(&otherPlayer, bytes.NewReader(BLUE_SKIN))
		assert.Nil(t, err)
		err = ts.App.SetCapeAndSave(&otherPlayer, bytes.NewReader(BLUE_CAPE))
		assert.Nil(t, err)

		blueSkinHash := *UnmakeNullString(&otherPlayer.SkinHash)
		blueCapeHash := *UnmakeNullString(&otherPlayer.CapeHash)

		// Delete account usernameB
		rec = ts.PostForm(t, ts.Server, "/web/delete-user", url.Values{}, []http.Cookie{*browserTokenCookie}, nil)
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
		rec := ts.PostForm(t, ts.Server, "/web/delete-user", url.Values{}, nil, nil)
		assert.Equal(t, http.StatusSeeOther, rec.Code)
		assert.Equal(t, ts.App.FrontEndURL, rec.Header().Get("Location"))
		assert.Equal(t, "You are not logged in.", getErrorMessage(rec))
	}
}

// Admin
func (ts *TestSuite) testAdmin(t *testing.T) {
	returnURL := ts.App.FrontEndURL + "/web/admin"

	username := "admin"
	user, browserTokenCookie := ts.CreateTestUser(t, ts.App, ts.Server, username)

	otherUsername := "adminOther"
	otherUser, otherBrowserTokenCookie := ts.CreateTestUser(t, ts.App, ts.Server, otherUsername)

	anotherUsername := "adminAnother"
	anotherUser, anotherBrowserTokenCookie := ts.CreateTestUser(t, ts.App, ts.Server, anotherUsername)

	// Make `username` an admin
	user.IsAdmin = true
	result := ts.App.DB.Save(&user)
	assert.Nil(t, result.Error)

	{
		// Revoke admin from `username` should fail
		form := url.Values{}
		form.Set("returnUrl", returnURL)
		rec := ts.PostForm(t, ts.Server, "/web/admin/update-users", form, []http.Cookie{*browserTokenCookie}, nil)

		assert.Equal(t, http.StatusSeeOther, rec.Code)
		assert.Equal(t, "There must be at least one unlocked admin account.", getErrorMessage(rec))
		assert.Equal(t, returnURL, rec.Header().Get("Location"))
	}

	// Make `otherUser` and `anotherUser` admins, lock their accounts, and set max player counts
	form := url.Values{}
	form.Set("returnUrl", returnURL)
	form.Set("admin-"+user.UUID, "on")
	form.Set("admin-"+otherUser.UUID, "on")
	form.Set("locked-"+otherUser.UUID, "on")
	form.Set("admin-"+anotherUser.UUID, "on")
	form.Set("locked-"+anotherUser.UUID, "on")
	form.Set("max-player-count-"+otherUser.UUID, "3")
	form.Set("max-player-count-"+anotherUser.UUID, "-1")
	rec := ts.PostForm(t, ts.Server, "/web/admin/update-users", form, []http.Cookie{*browserTokenCookie}, nil)

	assert.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, "", getErrorMessage(rec))
	assert.Equal(t, returnURL, rec.Header().Get("Location"))

	result = ts.App.DB.First(&otherUser, "uuid = ?", otherUser.UUID)
	assert.Nil(t, result.Error)
	assert.True(t, otherUser.IsAdmin)
	assert.True(t, otherUser.IsLocked)
	assert.Equal(t, 3, otherUser.MaxPlayerCount)
	// `otherUser` should be logged out of the web interface
	assert.NotEqual(t, "", otherBrowserTokenCookie.Value)
	assert.Nil(t, UnmakeNullString(&otherUser.BrowserToken))

	result = ts.App.DB.First(&anotherUser, "uuid = ?", anotherUser.UUID)
	assert.Nil(t, result.Error)
	assert.True(t, anotherUser.IsAdmin)
	assert.True(t, anotherUser.IsLocked)
	assert.Equal(t, -1, anotherUser.MaxPlayerCount)
	// `anotherUser` should be logged out of the web interface
	assert.NotEqual(t, "", anotherBrowserTokenCookie.Value)
	assert.Nil(t, UnmakeNullString(&anotherUser.BrowserToken))

	// Delete `otherUser`
	form = url.Values{}
	form.Set("returnUrl", returnURL)
	form.Set("uuid", otherUser.UUID)
	rec = ts.PostForm(t, ts.Server, "/web/delete-user", form, []http.Cookie{*browserTokenCookie}, nil)

	assert.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, "", getErrorMessage(rec))
	assert.Equal(t, returnURL, rec.Header().Get("Location"))

	err := ts.App.DB.First(&otherUser, "uuid = ?", otherUser.UUID).Error
	assert.NotNil(t, err)
	assert.True(t, errors.Is(err, gorm.ErrRecordNotFound))
}
