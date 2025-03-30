package main

import (
	"bytes"
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAPI(t *testing.T) {
	t.Parallel()
	{
		// Registration as existing player not allowed
		ts := &TestSuite{}

		config := testConfig()
		config.AllowAddingDeletingPlayers = true
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

		t.Run("Test POST/DELETE /drasl/api/vX/oidc-identities", ts.testAPICreateDeleteOIDCIdentity)

		t.Run("Test DELETE /drasl/api/vX/invites/{code}", ts.testAPIDeleteInvite)
		t.Run("Test GET /drasl/api/vX/invites", ts.testAPIGetInvites)
		t.Run("Test POST /drasl/api/vX/invites", ts.testAPICreateInvite)
		t.Run("Test POST /drasl/api/vX/login", ts.testAPILogin)
	}
	{
		ts := &TestSuite{}
		config := testConfig()
		config.RateLimit = rateLimitConfig{
			Enable:            true,
			RequestsPerSecond: 2,
		}
		config.DefaultAdmins = []string{"admin"}
		ts.Setup(config)
		defer ts.Teardown()

		t.Run("Test API rate limiting", ts.testAPIRateLimit)
	}
}

func (ts *TestSuite) testAPIGetSelf(t *testing.T) {
	adminUsername := "admin"
	admin, _ := ts.CreateTestUser(t, ts.App, ts.Server, adminUsername)
	assert.True(t, admin.IsAdmin)
	username := "user"
	user, _ := ts.CreateTestUser(t, ts.App, ts.Server, username)

	// admin should get a response
	rec := ts.Get(t, ts.Server, DRASL_API_PREFIX+"/user", nil, &admin.APIToken)
	assert.Equal(t, http.StatusOK, rec.Code)
	var response APIUser
	assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))
	assert.Equal(t, admin.UUID, response.UUID)

	// user (not admin) should also get a response
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

	// nonexistent user should get StatusNotFound
	var err APIError
	rec = ts.Get(t, ts.Server, DRASL_API_PREFIX+"/users/00000000-0000-0000-0000-000000000000", nil, &admin.APIToken)
	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.Nil(t, json.NewDecoder(rec.Body).Decode(&err))
	assert.Equal(t, "Unknown UUID", err.Message)

	// user2 (not admin) should get a StatusForbidden
	rec = ts.Get(t, ts.Server, DRASL_API_PREFIX+"/users/"+admin.UUID, nil, &nonAdmin.APIToken)
	assert.Equal(t, http.StatusForbidden, rec.Code)
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
	rec := ts.Delete(t, ts.Server, DRASL_API_PREFIX+"/users/"+admin.UUID, nil, nil, &user2.APIToken)
	assert.Equal(t, http.StatusForbidden, rec.Code)
	var err APIError
	assert.Nil(t, json.NewDecoder(rec.Body).Decode(&err))

	// admin should get a response
	rec = ts.Delete(t, ts.Server, DRASL_API_PREFIX+"/users/"+user2.UUID, nil, nil, &admin.APIToken)
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

	rec := ts.Delete(t, ts.Server, DRASL_API_PREFIX+"/user", nil, nil, &user.APIToken)
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
			Password: Ptr(TEST_PASSWORD),
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
			Password:   Ptr(TEST_PASSWORD),
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
			Password: Ptr(TEST_PASSWORD),
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

	payload := APIGetChallengeSkinRequest{
		PlayerName: "foo",
	}
	body, err := json.Marshal(payload)
	assert.Nil(t, err)
	req := httptest.NewRequest(http.MethodGet, DRASL_API_PREFIX+"/challenge-skin", bytes.NewBuffer(body))
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", "Bearer "+user.APIToken)
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
	rec := ts.Delete(t, ts.Server, DRASL_API_PREFIX+"/players/"+adminPlayer.UUID, nil, nil, &user.APIToken)
	assert.Equal(t, http.StatusForbidden, rec.Code)
	var apiError APIError
	assert.Nil(t, json.NewDecoder(rec.Body).Decode(&apiError))

	// admin should get a response
	rec = ts.Delete(t, ts.Server, DRASL_API_PREFIX+"/players/"+adminPlayer.UUID, nil, nil, &admin.APIToken)
	assert.Equal(t, http.StatusNoContent, rec.Code)

	// adminPlayer should no longer exist in the database
	var count int64
	assert.Nil(t, ts.App.DB.Model(&Player{}).Where("uuid = ?", adminPlayer.UUID).Count(&count).Error)
	assert.Equal(t, int64(0), count)

	// user should be able to delete its own player
	rec = ts.Delete(t, ts.Server, DRASL_API_PREFIX+"/players/"+player.UUID, nil, nil, &user.APIToken)
	assert.Equal(t, http.StatusNoContent, rec.Code)

	// player should no longer exist in the database
	assert.Nil(t, ts.App.DB.Model(&Player{}).Where("uuid = ?", player.UUID).Count(&count).Error)
	assert.Equal(t, int64(0), count)

	// admin should be able to delete any user's player
	rec = ts.Delete(t, ts.Server, DRASL_API_PREFIX+"/players/"+secondPlayer.UUID, nil, nil, &admin.APIToken)
	assert.Equal(t, http.StatusNoContent, rec.Code)

	// secondPlayer should no longer exist in the database
	assert.Nil(t, ts.App.DB.Model(&Player{}).Where("uuid = ?", secondPlayer.UUID).Count(&count).Error)
	assert.Equal(t, int64(0), count)

	assert.Nil(t, ts.App.DeleteUser(&GOD, admin))
	assert.Nil(t, ts.App.DeleteUser(&GOD, user))
}

func (ts *TestSuite) testAPICreateDeleteOIDCIdentity(t *testing.T) {
	adminUsername := "admin"
	admin, _ := ts.CreateTestUser(t, ts.App, ts.Server, adminUsername)
	assert.True(t, admin.IsAdmin)
	username := "user"
	user, _ := ts.CreateTestUser(t, ts.App, ts.Server, username)

	fakeOIDCProvider1 := OIDCProvider{
		Config: RegistrationOIDCConfig{
			Name:   "Fake IDP 1",
			Issuer: "https://idm.example.com/oauth2/openid/drasl1",
		},
	}
	fakeOIDCProvider2 := OIDCProvider{
		Config: RegistrationOIDCConfig{
			Name:   "Fake IDP 2",
			Issuer: "https://idm.example.com/oauth2/openid/drasl2",
		},
	}
	provider1Subject1 := "11111111-1111-1111-1111-111111111111"
	provider1Subject2 := "11111111-1111-1111-1111-222222222222"
	provider1Subject3 := "11111111-1111-1111-1111-333333333333"

	provider2Subject1 := "22222222-2222-2222-2222-111111111111"
	provider2Subject2 := "22222222-2222-2222-2222-222222222222"
	provider2Subject3 := "22222222-2222-2222-2222-333333333333"
	// Monkey-patch these until we can properly mock an OIDC IDP in the test environment...
	ts.App.OIDCProvidersByName[fakeOIDCProvider1.Config.Name] = &fakeOIDCProvider1
	ts.App.OIDCProvidersByName[fakeOIDCProvider2.Config.Name] = &fakeOIDCProvider2
	ts.App.OIDCProvidersByIssuer[fakeOIDCProvider1.Config.Issuer] = &fakeOIDCProvider1
	ts.App.OIDCProvidersByIssuer[fakeOIDCProvider2.Config.Issuer] = &fakeOIDCProvider2

	{
		// admin should be able to create OIDC identities for themself
		payload := APICreateOIDCIdentityRequest{
			Issuer:  fakeOIDCProvider1.Config.Issuer,
			Subject: provider1Subject1,
		}
		rec := ts.PostJSON(t, ts.Server, DRASL_API_PREFIX+"/users/"+admin.UUID+"/oidc-identities", payload, nil, &admin.APIToken)
		assert.Equal(t, http.StatusOK, rec.Code)
		var apiOIDCIdentity APIOIDCIdentity
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&apiOIDCIdentity))
		assert.Equal(t, provider1Subject1, apiOIDCIdentity.Subject)
		assert.Equal(t, fakeOIDCProvider1.Config.Issuer, apiOIDCIdentity.Issuer)

		assert.Nil(t, ts.App.DB.First(&admin, "uuid = ?", admin.UUID).Error)
		assert.Equal(t, 1, len(admin.OIDCIdentities))
		assert.Equal(t, fakeOIDCProvider1.Config.Issuer, admin.OIDCIdentities[0].Issuer)
		assert.Equal(t, provider1Subject1, admin.OIDCIdentities[0].Subject)
	}
	{
		// If UserUUID is ommitted, default to the caller's UUID
		payload := APICreateOIDCIdentityRequest{
			Issuer:  fakeOIDCProvider2.Config.Issuer,
			Subject: provider2Subject1,
		}
		rec := ts.PostJSON(t, ts.Server, DRASL_API_PREFIX+"/users/"+admin.UUID+"/oidc-identities", payload, nil, &admin.APIToken)
		assert.Equal(t, http.StatusOK, rec.Code)
		var apiOIDCIdentity APIOIDCIdentity
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&apiOIDCIdentity))
		assert.Equal(t, provider2Subject1, apiOIDCIdentity.Subject)
		assert.Equal(t, fakeOIDCProvider2.Config.Issuer, apiOIDCIdentity.Issuer)
	}
	{
		// admin should be able to create OIDC identities for other users
		payload := APICreateOIDCIdentityRequest{
			Issuer:  fakeOIDCProvider1.Config.Issuer,
			Subject: provider1Subject2,
		}
		rec := ts.PostJSON(t, ts.Server, DRASL_API_PREFIX+"/users/"+user.UUID+"/oidc-identities", payload, nil, &admin.APIToken)
		assert.Equal(t, http.StatusOK, rec.Code)
		var apiOIDCIdentity APIOIDCIdentity
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&apiOIDCIdentity))
		assert.Equal(t, provider1Subject2, apiOIDCIdentity.Subject)
		assert.Equal(t, fakeOIDCProvider1.Config.Issuer, apiOIDCIdentity.Issuer)
	}
	{
		// Duplicate issuer and subject should fail
		payload := APICreateOIDCIdentityRequest{
			Issuer:  fakeOIDCProvider1.Config.Issuer,
			Subject: provider1Subject1,
		}
		rec := ts.PostJSON(t, ts.Server, DRASL_API_PREFIX+"/users/"+admin.UUID+"/oidc-identities", payload, nil, &admin.APIToken)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		var apiError APIError
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&apiError))
		assert.Equal(t, "That Fake IDP 1 account is already linked to another user.", apiError.Message)
	}
	{
		// Duplicate issuer on the same user should fail
		payload := APICreateOIDCIdentityRequest{
			Issuer:  fakeOIDCProvider1.Config.Issuer,
			Subject: provider1Subject3,
		}
		rec := ts.PostJSON(t, ts.Server, DRASL_API_PREFIX+"/users/"+admin.UUID+"/oidc-identities", payload, nil, &admin.APIToken)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		var apiError APIError
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&apiError))
		assert.Equal(t, "That user is already linked to a Fake IDP 1 account.", apiError.Message)
	}
	{
		// Non-admin should not be able to link an OIDC identity for another user
		payload := APICreateOIDCIdentityRequest{
			Issuer:  fakeOIDCProvider2.Config.Issuer,
			Subject: provider2Subject3,
		}
		rec := ts.PostJSON(t, ts.Server, DRASL_API_PREFIX+"/users/"+admin.UUID+"/oidc-identities", payload, nil, &user.APIToken)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		var apiError APIError
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&apiError))
		assert.Equal(t, "Can't link an OIDC account for another user unless you're an admin.", apiError.Message)
	}
	{
		// Non-admin should be able to link an OIDC identity for themself
		payload := APICreateOIDCIdentityRequest{
			Issuer:  fakeOIDCProvider2.Config.Issuer,
			Subject: provider2Subject2,
		}
		rec := ts.PostJSON(t, ts.Server, DRASL_API_PREFIX+"/users/"+user.UUID+"/oidc-identities", payload, nil, &user.APIToken)
		assert.Equal(t, http.StatusOK, rec.Code)
		var apiOIDCIdentity APIOIDCIdentity
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&apiOIDCIdentity))
		assert.Equal(t, provider2Subject2, apiOIDCIdentity.Subject)
		assert.Equal(t, fakeOIDCProvider2.Config.Issuer, apiOIDCIdentity.Issuer)
	}
	{
		// admin should be able to delete OIDC identity for other users
		payload := APIDeleteOIDCIdentityRequest{
			Issuer: fakeOIDCProvider1.Config.Issuer,
		}
		rec := ts.Delete(t, ts.Server, DRASL_API_PREFIX+"/users/"+user.UUID+"/oidc-identities", payload, nil, &admin.APIToken)
		assert.Equal(t, http.StatusNoContent, rec.Code)
	}
	{
		// Add the identity back for future tests...
		payload := APICreateOIDCIdentityRequest{
			Issuer:  fakeOIDCProvider1.Config.Issuer,
			Subject: provider1Subject2,
		}
		rec := ts.PostJSON(t, ts.Server, DRASL_API_PREFIX+"/users/"+user.UUID+"/oidc-identities", payload, nil, &admin.APIToken)
		assert.Equal(t, http.StatusOK, rec.Code)
	}
	{
		// Non-admin user should not be able to delete OIDC identity for other users
		payload := APIDeleteOIDCIdentityRequest{
			Issuer: fakeOIDCProvider1.Config.Issuer,
		}
		rec := ts.Delete(t, ts.Server, DRASL_API_PREFIX+"/users/"+admin.UUID+"/oidc-identities", payload, nil, &user.APIToken)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		var apiError APIError
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&apiError))
		assert.Equal(t, "Can't unlink an OIDC account for another user unless you're an admin.", apiError.Message)
	}
	{
		// Non-admin user should be able to delete OIDC identity for themself
		payload := APIDeleteOIDCIdentityRequest{
			Issuer: fakeOIDCProvider2.Config.Issuer,
		}
		rec := ts.Delete(t, ts.Server, DRASL_API_PREFIX+"/users/"+user.UUID+"/oidc-identities", payload, nil, &user.APIToken)
		assert.Equal(t, http.StatusNoContent, rec.Code)
	}
	{
		// Can't delete nonexistent OIDC identity
		payload := APIDeleteOIDCIdentityRequest{
			Issuer: fakeOIDCProvider2.Config.Issuer,
		}
		rec := ts.Delete(t, ts.Server, DRASL_API_PREFIX+"/users/"+user.UUID+"/oidc-identities", payload, nil, &user.APIToken)
		assert.Equal(t, http.StatusNotFound, rec.Code)
		var apiError APIError
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&apiError))
		assert.Equal(t, "No linked Fake IDP 2 account found.", apiError.Message)
	}
	{
		// Can't delete last OIDC identity
		payload := APIDeleteOIDCIdentityRequest{
			Issuer: fakeOIDCProvider1.Config.Issuer,
		}
		rec := ts.Delete(t, ts.Server, DRASL_API_PREFIX+"/users/"+user.UUID+"/oidc-identities", payload, nil, &user.APIToken)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		var apiError APIError
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&apiError))
		assert.Equal(t, "Can't remove the last linked OIDC account.", apiError.Message)
	}
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
	rec := ts.Delete(t, ts.Server, DRASL_API_PREFIX+"/invites/"+invite.Code, nil, nil, &user.APIToken)
	assert.Equal(t, http.StatusForbidden, rec.Code)
	var apiError APIError
	assert.Nil(t, json.NewDecoder(rec.Body).Decode(&apiError))

	// admin should get a response
	rec = ts.Delete(t, ts.Server, DRASL_API_PREFIX+"/invites/"+invite.Code, nil, nil, &admin.APIToken)
	assert.Equal(t, http.StatusNoContent, rec.Code)

	// invite should no longer exist in the database
	var count int64
	assert.Nil(t, ts.App.DB.Model(&Invite{}).Where("code = ?", invite.Code).Count(&count).Error)
	assert.Equal(t, int64(0), count)

	// should not be able to delete the same invite twice
	rec = ts.Delete(t, ts.Server, DRASL_API_PREFIX+"/invites/"+invite.Code, nil, nil, &admin.APIToken)
	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.Nil(t, json.NewDecoder(rec.Body).Decode(&apiError))

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

func (ts *TestSuite) testAPILogin(t *testing.T) {
	username := "user"
	user, _ := ts.CreateTestUser(t, ts.App, ts.Server, username)

	{
		// Correct credentials should get an HTTP 200 and an API token
		rec := ts.PostJSON(t, ts.Server, DRASL_API_PREFIX+"/login", APILoginRequest{
			Username: username,
			Password: TEST_PASSWORD,
		}, nil, nil)
		assert.Equal(t, http.StatusOK, rec.Code)
		var jsonRec APILoginResponse
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&jsonRec))
		assert.NotNil(t, jsonRec.APIToken)
	}
	{
		// Username of nonexistent user should return HTTP 401 and "User not found." message
		rec := ts.PostJSON(t, ts.Server, DRASL_API_PREFIX+"/login", APILoginRequest{
			Username: "user1",
			Password: TEST_PASSWORD,
		}, nil, nil)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		var apiErr APIError
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&apiErr))
		assert.Equal(t, "User not found.", apiErr.Message)
	}
	{
		// Incorrect password should return HTTP 401 and "Incorrect password." message
		rec := ts.PostJSON(t, ts.Server, DRASL_API_PREFIX+"/login", APILoginRequest{
			Username: username,
			Password: "password1",
		}, nil, nil)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		var apiErr APIError
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&apiErr))
		assert.Equal(t, "Incorrect password.", apiErr.Message)
	}
	{
		// Locked user should return HTTP 403 and "User is locked." message
		assert.Nil(t, ts.App.SetIsLocked(ts.App.DB, user, true))
		rec := ts.PostJSON(t, ts.Server, DRASL_API_PREFIX+"/login", APILoginRequest{
			Username: username,
			Password: TEST_PASSWORD,
		}, nil, nil)
		assert.Equal(t, http.StatusForbidden, rec.Code)
		var apiErr APIError
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&apiErr))
		assert.Equal(t, "User is locked.", apiErr.Message)
	}

	assert.Nil(t, ts.App.DeleteUser(&GOD, user))
}

func (ts *TestSuite) testAPIRateLimit(t *testing.T) {
	payload := APILoginRequest{
		Username: "nonexistent",
		Password: "password",
	}
	// First two requests should get StatusUnauthorized
	rec := ts.PostJSON(t, ts.Server, DRASL_API_PREFIX+"/login", payload, nil, nil)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	rec = ts.PostJSON(t, ts.Server, DRASL_API_PREFIX+"/login", payload, nil, nil)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	// After rate limit exceeded, unauthenticated request should get StatusTooManyRequests
	rec = ts.PostJSON(t, ts.Server, DRASL_API_PREFIX+"/login", payload, nil, nil)
	assert.Equal(t, http.StatusTooManyRequests, rec.Code)

	// We have to create the users down here since CreateTestUser hits the
	// rate-limit counter...
	admin, _ := ts.CreateTestUser(t, ts.App, ts.Server, "admin")
	assert.True(t, admin.IsAdmin)
	user, _ := ts.CreateTestUser(t, ts.App, ts.Server, "user")

	// Admins should not be rate-limited
	rec = ts.PostJSON(t, ts.Server, DRASL_API_PREFIX+"/login", payload, nil, &admin.APIToken)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	// Regular users should be rate-limited
	rec = ts.PostJSON(t, ts.Server, DRASL_API_PREFIX+"/login", payload, nil, &user.APIToken)
	assert.Equal(t, http.StatusTooManyRequests, rec.Code)

	assert.Nil(t, ts.App.DeleteUser(&GOD, admin))
	assert.Nil(t, ts.App.DeleteUser(&GOD, user))
}
