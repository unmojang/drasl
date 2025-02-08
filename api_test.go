package main

import (
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestAPI(t *testing.T) {
	t.Parallel()
	{
		// Registration as existing player not allowed
		ts := &TestSuite{}

		config := testConfig()
		config.RegistrationExistingPlayer.Allow = false
		config.DefaultAdmins = []string{"admin"}
		ts.Setup(config)
		defer ts.Teardown()

		t.Run("Test GET /drasl/api/vX/challenge-skin", ts.testAPIGetChallengeSkin)
		t.Run("Test GET /drasl/api/vX/user", ts.testAPIGetSelf)
		t.Run("Test DELETE /drasl/api/vX/user", ts.testAPIDeleteSelf)
		t.Run("Test PATCH /drasl/api/vX/user", ts.testAPIUpdateSelf)
		t.Run("Test GET /drasl/api/vX/users", ts.testAPIGetUsers)
		t.Run("Test POST /drasl/api/vX/users", ts.testAPICreateUser)
		t.Run("Test GET /drasl/api/vX/users/{uuid}", ts.testAPIGetUser)
		t.Run("Test DELETE /drasl/api/vX/users/{uuid}", ts.testAPIDeleteUser)
		t.Run("Test PATCH /drasl/api/vX/users/{uuid}", ts.testAPIUpdateUser)

		t.Run("Test GET /drasl/api/vX/players", ts.testAPIGetPlayers)
		t.Run("Test GET /drasl/api/vX/players/{uuid}", ts.testAPIGetPlayer)
		t.Run("Test POST /drasl/api/vX/players", ts.testAPICreatePlayer)
		t.Run("Test DELETE /drasl/api/vX/players/{uuid}", ts.testAPIDeletePlayer)
		t.Run("Test PATCH /drasl/api/vX/players/{uuid}", ts.testAPIUpdatePlayer)

		t.Run("Test DELETE /drasl/api/vX/invites/{code}", ts.testAPIDeleteInvite)
		t.Run("Test GET /drasl/api/vX/invites", ts.testAPIGetInvites)
		t.Run("Test POST /drasl/api/vX/invites", ts.testAPICreateInvite)
	}
}

func (ts *TestSuite) testAPIGetSelf(t *testing.T) {
	adminUsername := "admin"
	admin, _ := ts.CreateTestUser(t, ts.App, ts.Server, adminUsername)
	assert.True(t, admin.IsAdmin)
	username := "user"
	user, _ := ts.CreateTestUser(t, ts.App, ts.Server, username)

	// admin (admin) should get a response
	rec := ts.Get(t, ts.Server, DRASL_API_PREFIX+"/user", nil, &admin.APIToken)
	assert.Equal(t, http.StatusOK, rec.Code)
	var response APIUser
	assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))
	assert.Equal(t, admin.UUID, response.UUID)

	// user2 (not admin) should also get a response
	rec = ts.Get(t, ts.Server, DRASL_API_PREFIX+"/user", nil, &user.APIToken)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))
	assert.Equal(t, user.UUID, response.UUID)

	assert.Nil(t, ts.App.DeleteUser(&GOD, admin))
	assert.Nil(t, ts.App.DeleteUser(&GOD, user))
}

func (ts *TestSuite) testAPIGetUsers(t *testing.T) {
	adminUsername := "admin"
	admin, _ := ts.CreateTestUser(t, ts.App, ts.Server, adminUsername)
	nonAdminUsername := "nonAdmin"
	nonAdmin, _ := ts.CreateTestUser(t, ts.App, ts.Server, nonAdminUsername)

	// admin should get a response
	rec := ts.Get(t, ts.Server, DRASL_API_PREFIX+"/users", nil, &admin.APIToken)
	assert.Equal(t, http.StatusOK, rec.Code)
	var response []APIUser
	assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))
	assert.Equal(t, 2, len(response))

	// non-admin should get a StatusForbidden
	rec = ts.Get(t, ts.Server, DRASL_API_PREFIX+"/users", nil, &nonAdmin.APIToken)
	assert.Equal(t, http.StatusForbidden, rec.Code)
	var err APIError
	assert.Nil(t, json.NewDecoder(rec.Body).Decode(&err))

	assert.Nil(t, ts.App.DeleteUser(&GOD, admin))
	assert.Nil(t, ts.App.DeleteUser(&GOD, nonAdmin))
}

func (ts *TestSuite) testAPIGetUser(t *testing.T) {
	adminUsername := "admin"
	admin, _ := ts.CreateTestUser(t, ts.App, ts.Server, adminUsername)
	nonAdminUsername := "nonAdmin"
	nonAdmin, _ := ts.CreateTestUser(t, ts.App, ts.Server, nonAdminUsername)

	// admin should get a response
	rec := ts.Get(t, ts.Server, DRASL_API_PREFIX+"/users/"+nonAdmin.UUID, nil, &admin.APIToken)
	assert.Equal(t, http.StatusOK, rec.Code)
	var response APIUser
	assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))
	assert.Equal(t, nonAdmin.UUID, response.UUID)

	// user2 (not admin) should get a StatusForbidden
	rec = ts.Get(t, ts.Server, DRASL_API_PREFIX+"/users/"+admin.UUID, nil, &nonAdmin.APIToken)
	assert.Equal(t, http.StatusForbidden, rec.Code)
	var err APIError
	assert.Nil(t, json.NewDecoder(rec.Body).Decode(&err))

	assert.Nil(t, ts.App.DeleteUser(&GOD, admin))
	assert.Nil(t, ts.App.DeleteUser(&GOD, nonAdmin))
}

func (ts *TestSuite) testAPIDeleteUser(t *testing.T) {
	username1 := "admin"
	admin, _ := ts.CreateTestUser(t, ts.App, ts.Server, username1)
	username2 := "user2"
	user2, _ := ts.CreateTestUser(t, ts.App, ts.Server, username2)

	// user2 (not admin) should get a StatusForbidden
	rec := ts.Delete(t, ts.Server, DRASL_API_PREFIX+"/users/"+admin.UUID, nil, &user2.APIToken)
	assert.Equal(t, http.StatusForbidden, rec.Code)
	var err APIError
	assert.Nil(t, json.NewDecoder(rec.Body).Decode(&err))

	// admin should get a response
	rec = ts.Delete(t, ts.Server, DRASL_API_PREFIX+"/users/"+user2.UUID, nil, &admin.APIToken)
	assert.Equal(t, http.StatusNoContent, rec.Code)

	// user2 should no longer exist in the database
	var count int64
	assert.Nil(t, ts.App.DB.Model(&User{}).Where("uuid = ?", user2.UUID).Count(&count).Error)
	assert.Equal(t, int64(0), count)

	assert.Nil(t, ts.App.DeleteUser(&GOD, admin))
}

func (ts *TestSuite) testAPIDeleteSelf(t *testing.T) {
	username := "user"
	user, _ := ts.CreateTestUser(t, ts.App, ts.Server, username)

	rec := ts.Delete(t, ts.Server, DRASL_API_PREFIX+"/user", nil, &user.APIToken)
	assert.Equal(t, http.StatusNoContent, rec.Code)

	// user should no longer exist in the database
	var count int64
	assert.Nil(t, ts.App.DB.Model(&User{}).Where("uuid = ?", user.UUID).Count(&count).Error)
	assert.Equal(t, int64(0), count)
}

func (ts *TestSuite) testAPIUpdateSelf(t *testing.T) {
	username := "user"
	user, _ := ts.CreateTestUser(t, ts.App, ts.Server, username)

	assert.Equal(t, "en", user.PreferredLanguage)

	oldAPIToken := user.APIToken
	newPreferredLanguage := "es"
	payload := APIUpdateUserRequest{
		PreferredLanguage: &newPreferredLanguage,
		ResetAPIToken:     true,
	}

	rec := ts.PatchJSON(t, ts.Server, DRASL_API_PREFIX+"/user", payload, nil, &user.APIToken)
	assert.Equal(t, http.StatusOK, rec.Code)
	var updatedAPIUser APIUser
	assert.Nil(t, json.NewDecoder(rec.Body).Decode(&updatedAPIUser))
	assert.Equal(t, user.UUID, updatedAPIUser.UUID)
	assert.Equal(t, user.Username, updatedAPIUser.Username)
	assert.Equal(t, newPreferredLanguage, updatedAPIUser.PreferredLanguage)

	assert.Nil(t, ts.App.DB.First(&user, "uuid = ?", user.UUID).Error)
	assert.Equal(t, newPreferredLanguage, user.PreferredLanguage)
	assert.NotEqual(t, oldAPIToken, user.APIToken)

	assert.Nil(t, ts.App.DeleteUser(&GOD, user))
}

func (ts *TestSuite) testAPIUpdateUser(t *testing.T) {
	adminUsername := "admin"
	admin, _ := ts.CreateTestUser(t, ts.App, ts.Server, adminUsername)

	username := "user"
	user, _ := ts.CreateTestUser(t, ts.App, ts.Server, username)

	assert.Equal(t, ts.App.Constants.MaxPlayerCountUseDefault, user.MaxPlayerCount)

	newMaxPlayerCount := 3
	payload := APIUpdateUserRequest{
		MaxPlayerCount: &newMaxPlayerCount,
	}

	rec := ts.PatchJSON(t, ts.Server, DRASL_API_PREFIX+"/users/"+user.UUID, payload, nil, &admin.APIToken)
	assert.Equal(t, http.StatusOK, rec.Code)
	var updatedAPIUser APIUser
	assert.Nil(t, json.NewDecoder(rec.Body).Decode(&updatedAPIUser))
	assert.Equal(t, user.UUID, updatedAPIUser.UUID)
	assert.Equal(t, user.Username, updatedAPIUser.Username)
	assert.Equal(t, newMaxPlayerCount, updatedAPIUser.MaxPlayerCount)

	assert.Nil(t, ts.App.DB.First(&user, "uuid = ?", user.UUID).Error)
	assert.Equal(t, newMaxPlayerCount, user.MaxPlayerCount)

	assert.Nil(t, ts.App.DeleteUser(&GOD, admin))
	assert.Nil(t, ts.App.DeleteUser(&GOD, user))
}

func (ts *TestSuite) testAPICreateUser(t *testing.T) {
	adminUsername := "admin"
	adminPlayerName := "AdminPlayer"
	admin, _ := ts.CreateTestUser(t, ts.App, ts.Server, adminUsername)
	admin.Players[0].Name = adminPlayerName
	assert.Nil(t, ts.App.DB.Session(&gorm.Session{FullSaveAssociations: true}).Save(&admin).Error)

	createdUsername := "created"

	{
		// Simple case
		payload := APICreateUserRequest{
			Username: createdUsername,
			Password: TEST_PASSWORD,
		}

		rec := ts.PostJSON(t, ts.Server, DRASL_API_PREFIX+"/users", payload, nil, &admin.APIToken)
		assert.Equal(t, http.StatusOK, rec.Code)
		var apiCreateUserResponse APICreateUserResponse
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&apiCreateUserResponse))
		createdAPIUser := apiCreateUserResponse.User
		assert.Equal(t, createdUsername, createdAPIUser.Username)
		assert.Equal(t, 1, len(createdAPIUser.Players))
		assert.Nil(t, createdAPIUser.Players[0].SkinURL)

		var createdUser User
		ts.App.DB.First(&createdUser, "uuid = ?", createdAPIUser.UUID)
		assert.Nil(t, ts.App.DeleteUser(&GOD, &createdUser))
	}
	{
		// With skin and cape
		payload := APICreateUserRequest{
			Username:   createdUsername,
			Password:   TEST_PASSWORD,
			SkinBase64: Ptr(RED_SKIN_BASE64_STRING),
			CapeBase64: Ptr(RED_CAPE_BASE64_STRING),
		}

		rec := ts.PostJSON(t, ts.Server, DRASL_API_PREFIX+"/users", payload, nil, &admin.APIToken)
		assert.Equal(t, http.StatusOK, rec.Code)
		var apiCreateUserResponse APICreateUserResponse
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&apiCreateUserResponse))
		createdAPIUser := apiCreateUserResponse.User
		assert.Equal(t, createdUsername, createdAPIUser.Username)
		assert.Equal(t, 1, len(createdAPIUser.Players))
		assert.NotEqual(t, "", createdAPIUser.Players[0].SkinURL)
		assert.NotEqual(t, "", createdAPIUser.Players[0].CapeURL)

		var createdUser User
		ts.App.DB.First(&createdUser, "uuid = ?", createdAPIUser.UUID)
		assert.Nil(t, ts.App.DeleteUser(&GOD, &createdUser))
	}
	{
		// Username in use as another user's player name
		payload := APICreateUserRequest{
			Username: adminPlayerName,
			Password: TEST_PASSWORD,
		}

		rec := ts.PostJSON(t, ts.Server, DRASL_API_PREFIX+"/users", payload, nil, &admin.APIToken)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		var apiError APIError
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&apiError))
		assert.Equal(t, "That username is in use as the name of another user's player.", apiError.Message)
	}
	assert.Nil(t, ts.App.DeleteUser(&GOD, admin))
}

func (ts *TestSuite) testAPIGetChallengeSkin(t *testing.T) {
	username := "user"
	user, _ := ts.CreateTestUser(t, ts.App, ts.Server, username)

	ts.Get(t, ts.Server, DRASL_API_PREFIX+"/challenge-skin", nil, &user.APIToken)
	req := httptest.NewRequest(http.MethodGet, DRASL_API_PREFIX+"/challenge-skin", nil)
	req.Header.Add("Authorization", "Bearer "+user.APIToken)
	req.URL.RawQuery = url.Values{
		"username": {"foo"},
	}.Encode()
	rec := httptest.NewRecorder()
	ts.Server.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)

	var challenge APIChallenge
	assert.Nil(t, json.NewDecoder(rec.Body).Decode(&challenge))

	assert.Nil(t, ts.App.DeleteUser(&GOD, user))
}

func (ts *TestSuite) testAPIGetPlayers(t *testing.T) {
	adminUsername := "admin"
	admin, _ := ts.CreateTestUser(t, ts.App, ts.Server, adminUsername)
	nonAdminUsername := "nonAdmin"
	nonAdmin, _ := ts.CreateTestUser(t, ts.App, ts.Server, nonAdminUsername)

	// admin should get a response
	rec := ts.Get(t, ts.Server, DRASL_API_PREFIX+"/players", nil, &admin.APIToken)
	assert.Equal(t, http.StatusOK, rec.Code)
	var response []APIPlayer
	assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))
	assert.Equal(t, 2, len(response))

	// non-admin should get a StatusForbidden
	rec = ts.Get(t, ts.Server, DRASL_API_PREFIX+"/players", nil, &nonAdmin.APIToken)
	assert.Equal(t, http.StatusForbidden, rec.Code)
	var err APIError
	assert.Nil(t, json.NewDecoder(rec.Body).Decode(&err))

	assert.Nil(t, ts.App.DeleteUser(&GOD, admin))
	assert.Nil(t, ts.App.DeleteUser(&GOD, nonAdmin))
}

func (ts *TestSuite) testAPIGetPlayer(t *testing.T) {
	adminUsername := "admin"
	admin, _ := ts.CreateTestUser(t, ts.App, ts.Server, adminUsername)
	username := "user2"
	user, _ := ts.CreateTestUser(t, ts.App, ts.Server, username)

	adminPlayer := admin.Players[0]
	player := user.Players[0]

	// admin should get a response for both players
	{
		rec := ts.Get(t, ts.Server, DRASL_API_PREFIX+"/players/"+adminPlayer.UUID, nil, &admin.APIToken)
		assert.Equal(t, http.StatusOK, rec.Code)
		var response APIPlayer
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))
		assert.Equal(t, adminPlayer.UUID, response.UUID)
	}
	{
		rec := ts.Get(t, ts.Server, DRASL_API_PREFIX+"/players/"+player.UUID, nil, &admin.APIToken)
		assert.Equal(t, http.StatusOK, rec.Code)
		var response APIPlayer
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))
		assert.Equal(t, player.UUID, response.UUID)
	}

	// user (not admin) should get a StatusForbidden for admin player
	{
		rec := ts.Get(t, ts.Server, DRASL_API_PREFIX+"/players/"+adminPlayer.UUID, nil, &user.APIToken)
		assert.Equal(t, http.StatusForbidden, rec.Code)
		var err APIError
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&err))
	}
	// user should get a response for their own player
	{
		rec := ts.Get(t, ts.Server, DRASL_API_PREFIX+"/players/"+player.UUID, nil, &admin.APIToken)
		assert.Equal(t, http.StatusOK, rec.Code)
		var response APIPlayer
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))
		assert.Equal(t, player.UUID, response.UUID)
	}

	assert.Nil(t, ts.App.DeleteUser(&GOD, admin))
	assert.Nil(t, ts.App.DeleteUser(&GOD, user))
}

func (ts *TestSuite) testAPICreatePlayer(t *testing.T) {
	adminUsername := "admin"
	adminPlayerName := "AdminPlayer"
	admin, _ := ts.CreateTestUser(t, ts.App, ts.Server, adminUsername)
	admin.Players[0].Name = adminPlayerName
	assert.Nil(t, ts.App.DB.Session(&gorm.Session{FullSaveAssociations: true}).Save(&admin).Error)

	username := "user"
	user, _ := ts.CreateTestUser(t, ts.App, ts.Server, username)
	assert.Equal(t, 1, len(user.Players))
	assert.Equal(t, ts.App.Constants.MaxPlayerCountUseDefault, user.MaxPlayerCount)
	assert.Equal(t, 1, ts.Config.DefaultMaxPlayerCount)

	newName := "newPlayer"

	{
		payload := APICreatePlayerRequest{
			Name:       newName,
			UserUUID:   Ptr(user.UUID),
			SkinBase64: Ptr(RED_SKIN_BASE64_STRING),
			CapeBase64: Ptr(RED_CAPE_BASE64_STRING),
		}

		// Should fail since the user already has one player
		rec := ts.PostJSON(t, ts.Server, DRASL_API_PREFIX+"/players", payload, nil, &user.APIToken)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		var apiError APIError
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&apiError))
		assert.Equal(t, "You are only allowed to own 1 player(s).", apiError.Message)

		// Admins should be able to override the MaxPlayerCount limit
		rec = ts.PostJSON(t, ts.Server, DRASL_API_PREFIX+"/players", payload, nil, &admin.APIToken)
		assert.Equal(t, http.StatusOK, rec.Code)
		var createdAPIPlayer APIPlayer
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&createdAPIPlayer))
		assert.Equal(t, newName, createdAPIPlayer.Name)
		assert.NotEqual(t, "", createdAPIPlayer.SkinURL)
		assert.NotEqual(t, "", createdAPIPlayer.CapeURL)

		assert.Nil(t, ts.App.DB.First(&user, "uuid = ?", user.UUID).Error)
		assert.Equal(t, 2, len(user.Players))

		var player Player
		assert.Nil(t, ts.App.DB.First(&player, "uuid = ?", createdAPIPlayer.UUID).Error)
		assert.Equal(t, newName, player.Name)
	}
	{
		// Player name is already in use by another player
		payload := APICreatePlayerRequest{
			Name:     adminPlayerName,
			UserUUID: Ptr(user.UUID),
		}

		rec := ts.PostJSON(t, ts.Server, DRASL_API_PREFIX+"/players", payload, nil, &admin.APIToken)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		var apiError APIError
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&apiError))
		assert.Equal(t, "That player name is taken.", apiError.Message)
	}
	{
		// Player name is already in use as another user's username
		payload := APICreatePlayerRequest{
			Name:     adminUsername,
			UserUUID: Ptr(user.UUID),
		}

		rec := ts.PostJSON(t, ts.Server, DRASL_API_PREFIX+"/players", payload, nil, &admin.APIToken)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		var apiError APIError
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&apiError))
		assert.Equal(t, "That player name is in use as another user's username.", apiError.Message)
	}

	assert.Nil(t, ts.App.DeleteUser(&GOD, user))
	assert.Nil(t, ts.App.DeleteUser(&GOD, admin))
}

func (ts *TestSuite) testAPIUpdatePlayer(t *testing.T) {
	adminUsername := "admin"
	admin, _ := ts.CreateTestUser(t, ts.App, ts.Server, adminUsername)
	assert.Equal(t, 1, len(admin.Players))
	adminPlayer := admin.Players[0]
	assert.Equal(t, adminUsername, adminPlayer.Name)

	username := "user"
	user, _ := ts.CreateTestUser(t, ts.App, ts.Server, username)
	assert.Equal(t, 1, len(user.Players))
	player := user.Players[0]
	assert.Equal(t, username, player.Name)

	{
		// Admins should be able to update any user's player
		newName := "newAdminPlayer"
		payload := APIUpdatePlayerRequest{Name: &newName}
		rec := ts.PatchJSON(t, ts.Server, DRASL_API_PREFIX+"/players/"+player.UUID, payload, nil, &admin.APIToken)
		assert.Equal(t, http.StatusOK, rec.Code)

		var updatedAPIPlayer APIPlayer
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&updatedAPIPlayer))
		assert.Equal(t, player.UUID, updatedAPIPlayer.UUID)
		assert.Equal(t, newName, updatedAPIPlayer.Name)

		assert.Nil(t, ts.App.DB.First(&player, "uuid = ?", player.UUID).Error)
		assert.Equal(t, newName, player.Name)
	}
	{
		// Non-admin user should not be able to update admin's player
		newName := "bad"
		payload := APIUpdatePlayerRequest{Name: &newName}
		rec := ts.PatchJSON(t, ts.Server, DRASL_API_PREFIX+"/players/"+adminPlayer.UUID, payload, nil, &user.APIToken)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		var err APIError
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&err))

		assert.Nil(t, ts.App.DB.First(&adminPlayer, "uuid = ?", adminPlayer.UUID).Error)
		assert.Equal(t, adminUsername, adminPlayer.Name)
	}
	{
		// Non-admin user should be able to update their own player
		newName := "newPlayer"
		payload := APIUpdatePlayerRequest{Name: &newName}
		rec := ts.PatchJSON(t, ts.Server, DRASL_API_PREFIX+"/players/"+player.UUID, payload, nil, &user.APIToken)
		assert.Equal(t, http.StatusOK, rec.Code)

		var updatedAPIPlayer APIPlayer
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&updatedAPIPlayer))
		assert.Equal(t, player.UUID, updatedAPIPlayer.UUID)
		assert.Equal(t, newName, updatedAPIPlayer.Name)

		assert.Nil(t, ts.App.DB.First(&player, "uuid = ?", player.UUID).Error)
		assert.Equal(t, newName, player.Name)
	}

	assert.Nil(t, ts.App.DeleteUser(&GOD, user))
	assert.Nil(t, ts.App.DeleteUser(&GOD, admin))
}

func (ts *TestSuite) testAPIDeletePlayer(t *testing.T) {
	adminUsername := "admin"
	admin, _ := ts.CreateTestUser(t, ts.App, ts.Server, adminUsername)
	username := "user2"
	user, _ := ts.CreateTestUser(t, ts.App, ts.Server, username)
	adminPlayer := admin.Players[0]
	player := user.Players[0]
	secondPlayer, err := ts.App.CreatePlayer(
		admin,
		user.UUID,
		"player1",
		nil,
		false,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
	)
	assert.Nil(t, err)

	// user (not admin) should get a StatusForbidden when deleting admin's player
	rec := ts.Delete(t, ts.Server, DRASL_API_PREFIX+"/players/"+adminPlayer.UUID, nil, &user.APIToken)
	assert.Equal(t, http.StatusForbidden, rec.Code)
	var apiError APIError
	assert.Nil(t, json.NewDecoder(rec.Body).Decode(&apiError))

	// admin should get a response
	rec = ts.Delete(t, ts.Server, DRASL_API_PREFIX+"/players/"+adminPlayer.UUID, nil, &admin.APIToken)
	assert.Equal(t, http.StatusNoContent, rec.Code)

	// adminPlayer should no longer exist in the database
	var count int64
	assert.Nil(t, ts.App.DB.Model(&Player{}).Where("uuid = ?", adminPlayer.UUID).Count(&count).Error)
	assert.Equal(t, int64(0), count)

	// user should be able to delete its own player
	rec = ts.Delete(t, ts.Server, DRASL_API_PREFIX+"/players/"+player.UUID, nil, &user.APIToken)
	assert.Equal(t, http.StatusNoContent, rec.Code)

	// player should no longer exist in the database
	assert.Nil(t, ts.App.DB.Model(&Player{}).Where("uuid = ?", player.UUID).Count(&count).Error)
	assert.Equal(t, int64(0), count)

	// admin should be able to delete any user's player
	rec = ts.Delete(t, ts.Server, DRASL_API_PREFIX+"/players/"+secondPlayer.UUID, nil, &admin.APIToken)
	assert.Equal(t, http.StatusNoContent, rec.Code)

	// secondPlayer should no longer exist in the database
	assert.Nil(t, ts.App.DB.Model(&Player{}).Where("uuid = ?", secondPlayer.UUID).Count(&count).Error)
	assert.Equal(t, int64(0), count)

	assert.Nil(t, ts.App.DeleteUser(&GOD, admin))
	assert.Nil(t, ts.App.DeleteUser(&GOD, user))
}

func (ts *TestSuite) testAPIGetInvites(t *testing.T) {
	username1 := "admin"
	admin, _ := ts.CreateTestUser(t, ts.App, ts.Server, username1)
	username2 := "user2"
	user2, _ := ts.CreateTestUser(t, ts.App, ts.Server, username2)

	_, err := ts.App.CreateInvite()
	assert.Nil(t, err)
	_, err = ts.App.CreateInvite()
	assert.Nil(t, err)

	var invites []Invite
	result := ts.App.DB.Find(&invites)
	assert.Nil(t, result.Error)
	inviteCount := len(invites)

	assert.Equal(t, 2, inviteCount)

	// admin should get a response
	rec := ts.Get(t, ts.Server, DRASL_API_PREFIX+"/invites", nil, &admin.APIToken)
	assert.Equal(t, http.StatusOK, rec.Code)
	var response []APIUser
	assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))
	assert.Equal(t, inviteCount, len(response))

	// user2 (not admin) should get a StatusForbidden
	rec = ts.Get(t, ts.Server, DRASL_API_PREFIX+"/invites", nil, &user2.APIToken)
	assert.Equal(t, http.StatusForbidden, rec.Code)
	var apiErr APIError
	assert.Nil(t, json.NewDecoder(rec.Body).Decode(&apiErr))

	assert.Nil(t, ts.App.DeleteUser(&GOD, admin))
	assert.Nil(t, ts.App.DeleteUser(&GOD, user2))

	for _, invite := range invites {
		assert.Nil(t, ts.App.DB.Delete(invite).Error)
	}
}

func (ts *TestSuite) testAPIDeleteInvite(t *testing.T) {
	adminUsername := "admin"
	admin, _ := ts.CreateTestUser(t, ts.App, ts.Server, adminUsername)
	username := "user"
	user, _ := ts.CreateTestUser(t, ts.App, ts.Server, username)

	invite, err := ts.App.CreateInvite()
	assert.Nil(t, err)

	// user (not admin) should get a StatusForbidden
	rec := ts.Delete(t, ts.Server, DRASL_API_PREFIX+"/invites/"+invite.Code, nil, &user.APIToken)
	assert.Equal(t, http.StatusForbidden, rec.Code)
	var apiError APIError
	assert.Nil(t, json.NewDecoder(rec.Body).Decode(&apiError))

	// admin should get a response
	rec = ts.Delete(t, ts.Server, DRASL_API_PREFIX+"/invites/"+invite.Code, nil, &admin.APIToken)
	assert.Equal(t, http.StatusNoContent, rec.Code)

	// invite should no longer exist in the database
	var count int64
	assert.Nil(t, ts.App.DB.Model(&Invite{}).Where("code = ?", invite.Code).Count(&count).Error)
	assert.Equal(t, int64(0), count)

	assert.Nil(t, ts.App.DeleteUser(&GOD, admin))
	assert.Nil(t, ts.App.DeleteUser(&GOD, user))
}

func (ts *TestSuite) testAPICreateInvite(t *testing.T) {
	username1 := "admin"
	admin, _ := ts.CreateTestUser(t, ts.App, ts.Server, username1)
	username2 := "user2"
	user2, _ := ts.CreateTestUser(t, ts.App, ts.Server, username2)

	var invites []Invite
	result := ts.App.DB.Find(&invites)
	assert.Nil(t, result.Error)
	assert.Equal(t, 0, len(invites))

	// admin should get a response
	rec := ts.PostJSON(t, ts.Server, DRASL_API_PREFIX+"/invites", nil, nil, &admin.APIToken)
	assert.Equal(t, http.StatusOK, rec.Code)
	var response APIInvite
	assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))

	// user2 (not admin) should get a StatusForbidden
	rec = ts.Get(t, ts.Server, DRASL_API_PREFIX+"/invites", nil, &user2.APIToken)
	assert.Equal(t, http.StatusForbidden, rec.Code)
	var apiErr APIError
	assert.Nil(t, json.NewDecoder(rec.Body).Decode(&apiErr))

	assert.Nil(t, ts.App.DeleteUser(&GOD, admin))
	assert.Nil(t, ts.App.DeleteUser(&GOD, user2))

	result = ts.App.DB.Find(&invites)
	assert.Nil(t, result.Error)
	assert.Equal(t, 1, len(invites))

	for _, invite := range invites {
		assert.Nil(t, ts.App.DB.Delete(invite).Error)
	}
}
