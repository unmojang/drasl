package main

import (
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"net/http"
	"testing"
)

func TestSession(t *testing.T) {
	{
		ts := &TestSuite{}

		config := testConfig()
		ts.Setup(config)
		defer ts.Teardown()

		ts.CreateTestUser(ts.Server, TEST_USERNAME)

		t.Run("Test /session/minecraft/hasJoined", ts.testSessionHasJoined)
		t.Run("Test /session/minecraft/join", ts.testSessionJoin)
		t.Run("Test /session/minecraft/profile/:id", ts.testSessionProfile)
		t.Run("Test /blockedservers", ts.testSessionBlockedServers)
	}
}

func (ts *TestSuite) testSessionJoin(t *testing.T) {
	// First, authenticate to get a token pair
	authenticateRes := ts.authenticate(t, TEST_USERNAME, TEST_PASSWORD)
	accessToken := authenticateRes.AccessToken

	var user User
	result := ts.App.DB.First(&user, "username = ?", TEST_USERNAME)
	assert.Nil(t, result.Error)

	selectedProfile := Unwrap(UUIDToID(user.UUID))
	serverID := "0000000000000000000000000000000000000000"
	{
		// Successful join
		payload := sessionJoinRequest{
			AccessToken:     accessToken,
			SelectedProfile: selectedProfile,
			ServerID:        serverID,
		}
		rec := ts.PostJSON(t, ts.Server, "/session/minecraft/join", payload, nil, nil)
		assert.Equal(t, http.StatusNoContent, rec.Code)

		// User ServerID should be set
		result = ts.App.DB.First(&user, "username = ?", TEST_USERNAME)
		assert.Nil(t, result.Error)

		assert.Equal(t, serverID, *UnmakeNullString(&user.ServerID))
	}
	{
		// Join should fail if we send an invalid access token

		// Start with an invalid ServerID
		assert.Nil(t, ts.App.DB.First(&user, "username = ?", TEST_USERNAME).Error)
		user.ServerID = MakeNullString(nil)
		assert.Nil(t, ts.App.DB.Save(&user).Error)

		payload := sessionJoinRequest{
			AccessToken:     "invalid",
			SelectedProfile: selectedProfile,
			ServerID:        serverID,
		}
		rec := ts.PostJSON(t, ts.Server, "/session/minecraft/join", payload, nil, nil)
		assert.Equal(t, http.StatusForbidden, rec.Code)

		var response ErrorResponse
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))
		assert.Equal(t, "ForbiddenOperationException", *response.Error)
		assert.Equal(t, "Invalid token.", *response.ErrorMessage)

		// User ServerID should be invalid
		assert.Nil(t, ts.App.DB.First(&user, "username = ?", TEST_USERNAME).Error)

		assert.False(t, user.ServerID.Valid)
	}
}

func (ts *TestSuite) testSessionHasJoined(t *testing.T) {
	var user User
	result := ts.App.DB.First(&user, "username = ?", TEST_USERNAME)
	assert.Nil(t, result.Error)

	serverID := "0000000000000000000000000000000000000000"
	{
		// Successful hasJoined

		// Start with a valid ServerID
		assert.Nil(t, ts.App.DB.First(&user, "username = ?", TEST_USERNAME).Error)
		user.ServerID = MakeNullString(&serverID)
		assert.Nil(t, ts.App.DB.Save(&user).Error)

		url := "/session/minecraft/hasJoined?username=" + user.PlayerName + "&serverId=" + serverID + "&ip=" + "127.0.0.1"
		rec := ts.Get(t, ts.Server, url, nil, nil)
		assert.Equal(t, http.StatusOK, rec.Code)

		var response SessionProfileResponse
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))

		assert.Equal(t, Unwrap(UUIDToID(user.UUID)), response.ID)
		assert.Equal(t, user.PlayerName, response.Name)
	}
	{
		// hasJoined should fail if we send an invalid server ID

		// Start with a valid ServerID
		assert.Nil(t, ts.App.DB.First(&user, "username = ?", TEST_USERNAME).Error)
		user.ServerID = MakeNullString(&serverID)
		assert.Nil(t, ts.App.DB.Save(&user).Error)

		url := "/session/minecraft/hasJoined?username=" + user.PlayerName + "&serverId=" + "invalid" + "&ip=" + "127.0.0.1"
		rec := ts.Get(t, ts.Server, url, nil, nil)
		assert.Equal(t, http.StatusForbidden, rec.Code)
	}
}

func (ts *TestSuite) testSessionProfile(t *testing.T) {
	var user User
	result := ts.App.DB.First(&user, "username = ?", TEST_USERNAME)
	assert.Nil(t, result.Error)
	{
		// Successfully get profile

		url := "/session/minecraft/profile/" + Unwrap(UUIDToID(user.UUID))
		rec := ts.Get(t, ts.Server, url, nil, nil)
		assert.Equal(t, http.StatusOK, rec.Code)

		var response SessionProfileResponse
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))

		assert.Equal(t, Unwrap(UUIDToID(user.UUID)), response.ID)
		assert.Equal(t, user.PlayerName, response.Name)
	}
	{
		// If the UUID doesn't exist, we should get a StatusNoContent
		url := "/session/minecraft/profile/" + "00000000000000000000000000000000"
		rec := ts.Get(t, ts.Server, url, nil, nil)
		assert.Equal(t, http.StatusNoContent, rec.Code)
	}
	{
		// If the UUID is invalid, we should get a StatusBadRequest with an error message
		url := "/session/minecraft/profile/" + "invalid"
		rec := ts.Get(t, ts.Server, url, nil, nil)
		assert.Equal(t, http.StatusBadRequest, rec.Code)

		var response ErrorResponse
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))
		assert.Equal(t, "Not a valid UUID: "+"invalid", *response.ErrorMessage)
	}
}

func (ts *TestSuite) testSessionBlockedServers(t *testing.T) {
	rec := ts.Get(t, ts.Server, "/blockedservers", nil, nil)
	assert.Equal(t, http.StatusOK, rec.Code)
}
