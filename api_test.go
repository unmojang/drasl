package main

import (
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"net/http"
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
	}
}

func (ts *TestSuite) testAPIGetUsers(t *testing.T) {
	username1 := "admin"
	admin, _ := ts.CreateTestUser(ts.Server, username1)
	username2 := "user2"
	user2, _ := ts.CreateTestUser(ts.Server, username2)

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
	admin, _ := ts.CreateTestUser(ts.Server, username1)
	username2 := "user2"
	user2, _ := ts.CreateTestUser(ts.Server, username2)

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

func (ts *TestSuite) testAPIGetSelf(t *testing.T) {
	adminUsername := "admin"
	admin, _ := ts.CreateTestUser(ts.Server, adminUsername)
	assert.True(t, admin.IsAdmin)
	username2 := "user2"
	user2, _ := ts.CreateTestUser(ts.Server, username2)

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
	// Simple case
	adminUsername := "admin"
	admin, _ := ts.CreateTestUser(ts.Server, adminUsername)

	user2Username := "user2"

	payload := createUserRequest{
		Username: user2Username,
		Password: TEST_PASSWORD,
	}

	rec := ts.PostJSON(t, ts.Server, "/drasl/api/v1/users", payload, nil, &admin.APIToken)
	assert.Equal(t, http.StatusOK, rec.Code)
	var user2 APIUser
	assert.Nil(t, json.NewDecoder(rec.Body).Decode(&user2))
	assert.Equal(t, user2Username, user2.Username)

	assert.Nil(t, ts.App.DB.Delete(&admin).Error)
	assert.Nil(t, ts.App.DB.Where("uuid = ?", user2.UUID).Delete(&User{}).Error)
}
