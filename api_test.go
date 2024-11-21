package main

import (
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestAPI(t *testing.T) {
	{
		// Registration as existing player not allowed
		ts := &TestSuite{}

		config := testConfig()
		config.RegistrationExistingPlayer.Allow = false
		config.DefaultAdmins = []string{"admin"}
		ts.Setup(config)
		defer ts.Teardown()

		t.Run("Test GET /drasl/api/vX/user", ts.testAPIGetSelf)
		t.Run("Test GET /drasl/api/vX/users", ts.testAPIGetUsers)
		t.Run("Test GET /drasl/api/vX/users/{uuid}", ts.testAPIGetUser)
		t.Run("Test POST /drasl/api/vX/users", ts.testAPICreateUser)
		t.Run("Test DELETE /drasl/api/vX/users/{uuid}", ts.testAPIDeleteUser)
		t.Run("Test DELETE /drasl/api/vX/user", ts.testAPIDeleteSelf)
		t.Run("Test GET /drasl/api/vX/challenge-skin", ts.testAPIGetChallengeSkin)
		t.Run("Test GET /drasl/api/vX/invites", ts.testAPIGetInvites)
		t.Run("Test POST /drasl/api/vX/invites", ts.testAPICreateInvite)
	}
}

func (ts *TestSuite) testAPIGetSelf(t *testing.T) {
	adminUsername := "admin"
	admin, _ := ts.CreateTestUser(ts.App, ts.Server, adminUsername)
	assert.True(t, admin.IsAdmin)
	username2 := "user2"
	user2, _ := ts.CreateTestUser(ts.App, ts.Server, username2)

	// admin (admin) should get a response
	rec := ts.Get(t, ts.Server, DRASL_API_PREFIX+"/user", nil, &admin.APIToken)
	assert.Equal(t, http.StatusOK, rec.Code)
	var response APIUser
	assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))
	assert.Equal(t, admin.UUID, response.UUID)

	// user2 (not admin) should also get a response
	rec = ts.Get(t, ts.Server, DRASL_API_PREFIX+"/user", nil, &user2.APIToken)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))
	assert.Equal(t, user2.UUID, response.UUID)

	assert.Nil(t, ts.App.DeleteUser(admin))
	assert.Nil(t, ts.App.DeleteUser(user2))
}

func (ts *TestSuite) testAPIGetUsers(t *testing.T) {
	adminUsername := "admin"
	admin, _ := ts.CreateTestUser(ts.App, ts.Server, adminUsername)
	nonAdminUsername := "nonAdmin"
	nonAdmin, _ := ts.CreateTestUser(ts.App, ts.Server, nonAdminUsername)

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

	assert.Nil(t, ts.App.DeleteUser(admin))
	assert.Nil(t, ts.App.DeleteUser(nonAdmin))
}

func (ts *TestSuite) testAPIGetUser(t *testing.T) {
	username1 := "admin"
	admin, _ := ts.CreateTestUser(ts.App, ts.Server, username1)
	username2 := "user2"
	user2, _ := ts.CreateTestUser(ts.App, ts.Server, username2)

	// admin should get a response
	rec := ts.Get(t, ts.Server, DRASL_API_PREFIX+"/users/"+user2.UUID, nil, &admin.APIToken)
	assert.Equal(t, http.StatusOK, rec.Code)
	var response APIUser
	assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))
	assert.Equal(t, user2.UUID, response.UUID)

	// user2 (not admin) should get a StatusForbidden
	rec = ts.Get(t, ts.Server, DRASL_API_PREFIX+"/users/"+admin.UUID, nil, &user2.APIToken)
	assert.Equal(t, http.StatusForbidden, rec.Code)
	var err APIError
	assert.Nil(t, json.NewDecoder(rec.Body).Decode(&err))

	assert.Nil(t, ts.App.DeleteUser(admin))
	assert.Nil(t, ts.App.DeleteUser(user2))
}

func (ts *TestSuite) testAPIDeleteUser(t *testing.T) {
	username1 := "admin"
	admin, _ := ts.CreateTestUser(ts.App, ts.Server, username1)
	username2 := "user2"
	user2, _ := ts.CreateTestUser(ts.App, ts.Server, username2)

	// user2 (not admin) should get a StatusForbidden
	rec := ts.Get(t, ts.Server, DRASL_API_PREFIX+"/users/"+admin.UUID, nil, &user2.APIToken)
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

	assert.Nil(t, ts.App.DeleteUser(admin))
}

func (ts *TestSuite) testAPIDeleteSelf(t *testing.T) {
	username := "user"
	user, _ := ts.CreateTestUser(ts.App, ts.Server, username)

	rec := ts.Delete(t, ts.Server, DRASL_API_PREFIX+"/user", nil, &user.APIToken)
	assert.Equal(t, http.StatusNoContent, rec.Code)

	// user should no longer exist in the database
	var count int64
	assert.Nil(t, ts.App.DB.Model(&User{}).Where("uuid = ?", user.UUID).Count(&count).Error)
	assert.Equal(t, int64(0), count)
}

func (ts *TestSuite) testAPICreateUser(t *testing.T) {
	adminUsername := "admin"
	admin, _ := ts.CreateTestUser(ts.App, ts.Server, adminUsername)

	createdUsername := "user2"

	{
		// Simple case
		payload := APICreateUserRequest{
			Username: createdUsername,
			Password: TEST_PASSWORD,
		}

		rec := ts.PostJSON(t, ts.Server, DRASL_API_PREFIX+"/users", payload, nil, &admin.APIToken)
		assert.Equal(t, http.StatusOK, rec.Code)
		var createdAPIUser APIUser
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&createdAPIUser))
		assert.Equal(t, createdUsername, createdAPIUser.Username)
		assert.Equal(t, 1, len(createdAPIUser.Players))
		assert.Nil(t, createdAPIUser.Players[0].SkinURL)

		var createdUser User
		ts.App.DB.First(&createdUser, "uuid = ?", createdAPIUser.UUID)
		assert.Nil(t, ts.App.DeleteUser(&createdUser))
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
		var createdAPIUser APIUser
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&createdAPIUser))
		assert.Equal(t, createdUsername, createdAPIUser.Username)
		assert.Equal(t, 1, len(createdAPIUser.Players))
		assert.NotEqual(t, "", createdAPIUser.Players[0].SkinURL)
		assert.NotEqual(t, "", createdAPIUser.Players[0].CapeURL)

		var createdUser User
		ts.App.DB.First(&createdUser, "uuid = ?", createdAPIUser.UUID)
		assert.Nil(t, ts.App.DeleteUser(&createdUser))
	}
	assert.Nil(t, ts.App.DeleteUser(admin))
}

func (ts *TestSuite) testAPIGetChallengeSkin(t *testing.T) {
	username := "user"
	user, _ := ts.CreateTestUser(ts.App, ts.Server, username)

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
}

func (ts *TestSuite) testAPIGetInvites(t *testing.T) {
	username1 := "admin"
	admin, _ := ts.CreateTestUser(ts.App, ts.Server, username1)
	username2 := "user2"
	user2, _ := ts.CreateTestUser(ts.App, ts.Server, username2)

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

	assert.Nil(t, ts.App.DeleteUser(admin))
	assert.Nil(t, ts.App.DeleteUser(user2))

	for _, invite := range invites {
		assert.Nil(t, ts.App.DB.Delete(invite).Error)
	}
}

func (ts *TestSuite) testAPICreateInvite(t *testing.T) {
	username1 := "admin"
	admin, _ := ts.CreateTestUser(ts.App, ts.Server, username1)
	username2 := "user2"
	user2, _ := ts.CreateTestUser(ts.App, ts.Server, username2)

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

	assert.Nil(t, ts.App.DeleteUser(admin))
	assert.Nil(t, ts.App.DeleteUser(user2))

	result = ts.App.DB.Find(&invites)
	assert.Nil(t, result.Error)
	assert.Equal(t, 1, len(invites))

	for _, invite := range invites {
		assert.Nil(t, ts.App.DB.Delete(invite).Error)
	}
}
