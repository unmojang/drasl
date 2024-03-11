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
		config.DefaultAdmins = []string{"user1"}
		ts.Setup(config)
		defer ts.Teardown()

		t.Run("Test GET /drasl/api/v1/user", ts.testAPIGetSelf)
		t.Run("Test GET /drasl/api/v1/users", ts.testAPIGetUsers)
		t.Run("Test GET /drasl/api/v1/users/{uuid}", ts.testAPIGetUser)
	}
}

func (ts *TestSuite) testAPIGetUsers(t *testing.T) {
	username1 := "user1"
	user1, _ := ts.CreateTestUser(ts.Server, username1)
	username2 := "user2"
	user2, _ := ts.CreateTestUser(ts.Server, username2)

	// user1 (admin) should get a response
	rec := ts.Get(t, ts.Server, "/drasl/api/v1/users", nil, &user1.APIToken)
	assert.Equal(t, http.StatusOK, rec.Code)
	var response []APIUser
	assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))
	assert.Equal(t, 2, len(response))

	// user2 (not admin) should get a StatusForbidden
	rec = ts.Get(t, ts.Server, "/drasl/api/v1/users", nil, &user2.APIToken)
	assert.Equal(t, http.StatusForbidden, rec.Code)
	var err APIError
	assert.Nil(t, json.NewDecoder(rec.Body).Decode(&err))

	assert.Nil(t, ts.App.DB.Delete(&user1).Error)
	assert.Nil(t, ts.App.DB.Delete(&user2).Error)
}

func (ts *TestSuite) testAPIGetUser(t *testing.T) {
	username1 := "user1"
	user1, _ := ts.CreateTestUser(ts.Server, username1)
	username2 := "user2"
	user2, _ := ts.CreateTestUser(ts.Server, username2)

	// user1 (admin) should get a response
	rec := ts.Get(t, ts.Server, "/drasl/api/v1/users/"+user2.UUID, nil, &user1.APIToken)
	assert.Equal(t, http.StatusOK, rec.Code)
	var response APIUser
	assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))
	assert.Equal(t, user2.UUID, response.UUID)

	// user2 (not admin) should get a StatusForbidden
	rec = ts.Get(t, ts.Server, "/drasl/api/v1/users/"+user1.UUID, nil, &user2.APIToken)
	assert.Equal(t, http.StatusForbidden, rec.Code)
	var err APIError
	assert.Nil(t, json.NewDecoder(rec.Body).Decode(&err))

	assert.Nil(t, ts.App.DB.Delete(&user1).Error)
	assert.Nil(t, ts.App.DB.Delete(&user2).Error)
}

func (ts *TestSuite) testAPIGetSelf(t *testing.T) {
	username1 := "user1"
	user1, _ := ts.CreateTestUser(ts.Server, username1)
	username2 := "user2"
	user2, _ := ts.CreateTestUser(ts.Server, username2)

	// user1 (admin) should get a response
	rec := ts.Get(t, ts.Server, "/drasl/api/v1/user", nil, &user1.APIToken)
	assert.Equal(t, http.StatusOK, rec.Code)
	var response APIUser
	assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))
	assert.Equal(t, user1.UUID, response.UUID)

	// user2 (not admin) should also get a response
	rec = ts.Get(t, ts.Server, "/drasl/api/v1/user", nil, &user2.APIToken)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))
	assert.Equal(t, user2.UUID, response.UUID)

	assert.Nil(t, ts.App.DB.Delete(&user1).Error)
	assert.Nil(t, ts.App.DB.Delete(&user2).Error)
}
