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

		t.Run("Test GET /drasl/api/v1/user", ts.testAPIGetSelf)
		t.Run("Test GET /drasl/api/v1/users", ts.testAPIGetUsers)
		t.Run("Test GET /drasl/api/v1/users/{uuid}", ts.testAPIGetUser)
		t.Run("Test POST /drasl/api/v1/users", ts.testAPICreateUser)
		t.Run("Test DELETE /drasl/api/v1/users/{uuid}", ts.testAPIDeleteUser)
		t.Run("Test DELETE /drasl/api/v1/user", ts.testAPIDeleteSelf)
		t.Run("Test GET /drasl/api/v1/challenge-skin", ts.testAPIGetChallengeSkin)
		t.Run("Test GET /drasl/api/v1/invites", ts.testAPIGetInvites)
		t.Run("Test POST /drasl/api/v1/invites", ts.testAPICreateInvite)
	}
}

func (ts *TestSuite) testAPIGetUsers(t *testing.T) {
	username1 := "admin"
	admin, _ := ts.CreateTestUser(ts.App, ts.Server, username1)
	username2 := "user2"
	user2, _ := ts.CreateTestUser(ts.App, ts.Server, username2)

	// admin should get a response
	rec := ts.Get(t, ts.Server, "/drasl/api/v1/users", nil, &admin.APIToken)
	assert.Equal(t, http.StatusOK, rec.Code)
	var response []APIUser
	assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))
	assert.Equal(t, 2, len(response))

	// user2 (not admin) should get a StatusForbidden
	rec = ts.Get(t, ts.Server, "/drasl/api/v1/users", nil, &user2.APIToken)
	assert.Equal(t, http.StatusForbidden, rec.Code)
	var err APIError
	assert.Nil(t, json.NewDecoder(rec.Body).Decode(&err))

	assert.Nil(t, ts.App.DB.Delete(&admin).Error)
	assert.Nil(t, ts.App.DB.Delete(&user2).Error)
}

func (ts *TestSuite) testAPIGetUser(t *testing.T) {
	username1 := "admin"
	admin, _ := ts.CreateTestUser(ts.App, ts.Server, username1)
	username2 := "user2"
	user2, _ := ts.CreateTestUser(ts.App, ts.Server, username2)

	// admin should get a response
	rec := ts.Get(t, ts.Server, "/drasl/api/v1/users/"+user2.UUID, nil, &admin.APIToken)
	assert.Equal(t, http.StatusOK, rec.Code)
	var response APIUser
	assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))
	assert.Equal(t, user2.UUID, response.UUID)

	// user2 (not admin) should get a StatusForbidden
	rec = ts.Get(t, ts.Server, "/drasl/api/v1/users/"+admin.UUID, nil, &user2.APIToken)
	assert.Equal(t, http.StatusForbidden, rec.Code)
	var err APIError
	assert.Nil(t, json.NewDecoder(rec.Body).Decode(&err))

	assert.Nil(t, ts.App.DB.Delete(&admin).Error)
	assert.Nil(t, ts.App.DB.Delete(&user2).Error)
}

func (ts *TestSuite) testAPIDeleteUser(t *testing.T) {
	username1 := "admin"
	admin, _ := ts.CreateTestUser(ts.App, ts.Server, username1)
	username2 := "user2"
	user2, _ := ts.CreateTestUser(ts.App, ts.Server, username2)

	// user2 (not admin) should get a StatusForbidden
	rec := ts.Get(t, ts.Server, "/drasl/api/v1/users/"+admin.UUID, nil, &user2.APIToken)
	assert.Equal(t, http.StatusForbidden, rec.Code)
	var err APIError
	assert.Nil(t, json.NewDecoder(rec.Body).Decode(&err))

	// admin should get a response
	rec = ts.Delete(t, ts.Server, "/drasl/api/v1/users/"+user2.UUID, nil, &admin.APIToken)
	assert.Equal(t, http.StatusNoContent, rec.Code)

	// user2 should no longer exist in the database
	var count int64
	assert.Nil(t, ts.App.DB.Model(&User{}).Where("uuid = ?", user2.UUID).Count(&count).Error)
	assert.Equal(t, int64(0), count)

	assert.Nil(t, ts.App.DB.Delete(&admin).Error)
}

func (ts *TestSuite) testAPIDeleteSelf(t *testing.T) {
	username := "user"
	user, _ := ts.CreateTestUser(ts.App, ts.Server, username)

	rec := ts.Delete(t, ts.Server, "/drasl/api/v1/user", nil, &user.APIToken)
	assert.Equal(t, http.StatusNoContent, rec.Code)

	// user should no longer exist in the database
	var count int64
	assert.Nil(t, ts.App.DB.Model(&User{}).Where("uuid = ?", user.UUID).Count(&count).Error)
	assert.Equal(t, int64(0), count)
}

func (ts *TestSuite) testAPIGetSelf(t *testing.T) {
	adminUsername := "admin"
	admin, _ := ts.CreateTestUser(ts.App, ts.Server, adminUsername)
	assert.True(t, admin.IsAdmin)
	username2 := "user2"
	user2, _ := ts.CreateTestUser(ts.App, ts.Server, username2)

	// admin (admin) should get a response
	rec := ts.Get(t, ts.Server, "/drasl/api/v1/user", nil, &admin.APIToken)
	assert.Equal(t, http.StatusOK, rec.Code)
	var response APIUser
	assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))
	assert.Equal(t, admin.UUID, response.UUID)

	// user2 (not admin) should also get a response
	rec = ts.Get(t, ts.Server, "/drasl/api/v1/user", nil, &user2.APIToken)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))
	assert.Equal(t, user2.UUID, response.UUID)

	assert.Nil(t, ts.App.DB.Delete(&admin).Error)
	assert.Nil(t, ts.App.DB.Delete(&user2).Error)
}

func (ts *TestSuite) testAPICreateUser(t *testing.T) {
	adminUsername := "admin"
	admin, _ := ts.CreateTestUser(ts.App, ts.Server, adminUsername)

	user2Username := "user2"

	{
		// Simple case
		payload := APICreateUserRequest{
			Username: user2Username,
			Password: TEST_PASSWORD,
		}

		rec := ts.PostJSON(t, ts.Server, "/drasl/api/v1/users", payload, nil, &admin.APIToken)
		assert.Equal(t, http.StatusOK, rec.Code)
		var user2 APIUser
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&user2))
		assert.Equal(t, user2Username, user2.Username)
		assert.Nil(t, user2.SkinURL)

		assert.Nil(t, ts.App.DB.Where("uuid = ?", user2.UUID).Delete(&User{}).Error)
	}
	{
		// With skin and cape
		payload := APICreateUserRequest{
			Username:   user2Username,
			Password:   TEST_PASSWORD,
			SkinBase64: Ptr(RED_SKIN_BASE64_STRING),
			CapeBase64: Ptr(RED_CAPE_BASE64_STRING),
		}

		rec := ts.PostJSON(t, ts.Server, "/drasl/api/v1/users", payload, nil, &admin.APIToken)
		assert.Equal(t, http.StatusOK, rec.Code)
		var user2 APIUser
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&user2))
		assert.Equal(t, user2Username, user2.Username)
		assert.NotEqual(t, "", user2.SkinURL)
		assert.NotEqual(t, "", user2.CapeURL)

		assert.Nil(t, ts.App.DB.Where("uuid = ?", user2.UUID).Delete(&User{}).Error)
	}
	assert.Nil(t, ts.App.DB.Delete(&admin).Error)
}

func (ts *TestSuite) testAPIGetChallengeSkin(t *testing.T) {
	username := "user"
	user, _ := ts.CreateTestUser(ts.App, ts.Server, username)

	ts.Get(t, ts.Server, "/drasl/api/v1/challenge-skin", nil, &user.APIToken)
	req := httptest.NewRequest(http.MethodGet, "/drasl/api/v1/challenge-skin", nil)
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
	rec := ts.Get(t, ts.Server, "/drasl/api/v1/invites", nil, &admin.APIToken)
	assert.Equal(t, http.StatusOK, rec.Code)
	var response []APIUser
	assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))
	assert.Equal(t, inviteCount, len(response))

	// user2 (not admin) should get a StatusForbidden
	rec = ts.Get(t, ts.Server, "/drasl/api/v1/invites", nil, &user2.APIToken)
	assert.Equal(t, http.StatusForbidden, rec.Code)
	var apiErr APIError
	assert.Nil(t, json.NewDecoder(rec.Body).Decode(&apiErr))

	assert.Nil(t, ts.App.DB.Delete(&admin).Error)
	assert.Nil(t, ts.App.DB.Delete(&user2).Error)

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
	rec := ts.PostJSON(t, ts.Server, "/drasl/api/v1/invites", nil, nil, &admin.APIToken)
	assert.Equal(t, http.StatusOK, rec.Code)
	var response APIInvite
	assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))

	// user2 (not admin) should get a StatusForbidden
	rec = ts.Get(t, ts.Server, "/drasl/api/v1/invites", nil, &user2.APIToken)
	assert.Equal(t, http.StatusForbidden, rec.Code)
	var apiErr APIError
	assert.Nil(t, json.NewDecoder(rec.Body).Decode(&apiErr))

	assert.Nil(t, ts.App.DB.Delete(&admin).Error)
	assert.Nil(t, ts.App.DB.Delete(&user2).Error)

	result = ts.App.DB.Find(&invites)
	assert.Nil(t, result.Error)
	assert.Equal(t, 1, len(invites))

	for _, invite := range invites {
		assert.Nil(t, ts.App.DB.Delete(invite).Error)
	}
}
