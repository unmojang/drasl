package main

import (
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAccount(t *testing.T) {
	{
		ts := &TestSuite{}

		config := testConfig()
		ts.Setup(config)
		defer ts.Teardown()

		ts.CreateTestUser()

		t.Run("Test /users/profiles/minecraft/:playerName", ts.testAccountPlayerNameToUUID)
	}
}

func (ts *TestSuite) testAccountPlayerNameToUUID(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/users/profiles/minecraft/"+TEST_USERNAME, nil)
	rec := httptest.NewRecorder()
	ts.AccountServer.ServeHTTP(rec, req)

	// Authentication should succeed and we should get a valid clientToken and
	// accessToken
	assert.Equal(t, http.StatusOK, rec.Code)
	var response playerNameToUUIDResponse
	assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))

	// Check that the player name is correct
	assert.Equal(t, response.Name, TEST_USERNAME)

	// Get the real UUID
	var user User
	result := ts.App.DB.First(&user, "username = ?", TEST_USERNAME)
	assert.Nil(t, result.Error)

	// Check that the UUID is correct
	uuid, err := IDToUUID(response.ID)
	assert.Nil(t, err)
	assert.Equal(t, uuid, user.UUID)
}
