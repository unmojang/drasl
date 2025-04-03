package main

import (
	"encoding/json"
	"fmt"
	"github.com/stretchr/testify/assert"
	"net/http"
	"testing"
)

func TestAccount(t *testing.T) {
	t.Parallel()
	{
		ts := &TestSuite{}

		config := testConfig()
		ts.Setup(config)
		defer ts.Teardown()

		ts.CreateTestUser(t, ts.App, ts.Server, TEST_USERNAME)

		t.Run("Test /users/profiles/minecraft/:playerName", ts.testAccountPlayerNameToID)
		t.Run("Test /profiles/minecraft", ts.makeTestAccountPlayerNamesToIDs("/profiles/minecraft"))
		t.Run("Test /users/security/location", ts.testAccountVerifySecurityLocation)
	}
	{
		ts := &TestSuite{}

		auxConfig := testConfig()
		ts.SetupAux(auxConfig)

		config := testConfig()
		config.FallbackAPIServers = []FallbackAPIServerConfig{ts.ToFallbackAPIServer(ts.AuxApp, "Aux")}
		ts.Setup(config)
		defer ts.Teardown()

		ts.CreateTestUser(t, ts.AuxApp, ts.AuxServer, TEST_USERNAME)
		for i := 1; i <= 20; i += 1 {
			ts.CreateTestUser(t, ts.AuxApp, ts.AuxServer, fmt.Sprintf("%s%d", TEST_USERNAME, i))
		}

		t.Run("Test /users/profiles/minecraft/:playerName, fallback API server", ts.testAccountPlayerNameToIDFallback)
		t.Run("Test /profile/minecraft, fallback API server", ts.testAccountPlayerNamesToIDsFallback)
	}
}

func (ts *TestSuite) testAccountPlayerNameToID(t *testing.T) {
	rec := ts.Get(t, ts.Server, "/users/profiles/minecraft/"+TEST_PLAYER_NAME, nil, nil)

	assert.Equal(t, http.StatusOK, rec.Code)
	var response PlayerNameToIDResponse
	assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))

	// Check that the player name is correct
	assert.Equal(t, response.Name, TEST_PLAYER_NAME)

	// Get the real UUID
	var player Player
	result := ts.App.DB.First(&player, "name = ?", TEST_PLAYER_NAME)
	assert.Nil(t, result.Error)

	// Check that the UUID is correct
	uuid, err := IDToUUID(response.ID)
	assert.Nil(t, err)
	assert.Equal(t, uuid, player.UUID)

	// Any case variations of the username should return the same user
	rec = ts.Get(t, ts.Server, "/users/profiles/minecraft/"+TEST_PLAYER_NAME_UPPERCASE, nil, nil)
	assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))
	uuid, err = IDToUUID(response.ID)
	assert.Nil(t, err)
	assert.Equal(t, player.UUID, uuid)
}

func (ts *TestSuite) testAccountPlayerNameToIDFallback(t *testing.T) {
	{
		rec := ts.Get(t, ts.Server, "/users/profiles/minecraft/"+TEST_PLAYER_NAME, nil, nil)
		assert.Equal(t, http.StatusOK, rec.Code)
		var response PlayerNameToIDResponse
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))

		// Check that the player name is correct
		assert.Equal(t, response.Name, TEST_PLAYER_NAME)

		// Get the real UUID
		var player Player
		result := ts.AuxApp.DB.First(&player, "name = ?", TEST_PLAYER_NAME)
		assert.Nil(t, result.Error)

		// Check that the UUID is correct
		uuid, err := IDToUUID(response.ID)
		assert.Nil(t, err)
		assert.Equal(t, uuid, player.UUID)

		// This test is unreliable
		// // Test that fallback requests are correctly cached: change the aux
		// // user's player name and make sure the main server finds the old
		// // profile in the cache
		// player.Name = "testcache"
		// assert.Nil(t, ts.AuxApp.DB.Save(&player).Error)
		//
		// rec = ts.Get(t, ts.Server, "/users/profiles/minecraft/"+TEST_PLAYER_NAME, nil, nil)
		// assert.Equal(t, http.StatusOK, rec.Code)
		// assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))
		//
		// uuid, err = IDToUUID(response.ID)
		// assert.Nil(t, err)
		// assert.Equal(t, uuid, player.UUID)
		//
		// // Change the aux user's player name back
		// player.Name = TEST_PLAYER_NAME
		// assert.Nil(t, ts.AuxApp.DB.Save(&player).Error)
	}

	// Test a non-existent user
	{
		rec := ts.Get(t, ts.Server, "/users/profiles/minecraft/nonexistent", nil, nil)
		assert.Equal(t, http.StatusNotFound, rec.Code)
	}
}

func (ts *TestSuite) testAccountPlayerNamesToIDsFallback(t *testing.T) {
	{
		payload := []string{TEST_PLAYER_NAME, "nonexistent"}
		rec := ts.PostJSON(t, ts.Server, "/profiles/minecraft", payload, nil, nil)

		assert.Equal(t, http.StatusOK, rec.Code)
		var response []PlayerNameToIDResponse
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))

		// Get the real UUID
		var player Player
		result := ts.AuxApp.DB.First(&player, "name = ?", TEST_PLAYER_NAME)
		assert.Nil(t, result.Error)

		// There should only be one player, the nonexistent player should not be present
		id, err := UUIDToID(player.UUID)
		assert.Nil(t, err)
		assert.Equal(t, []PlayerNameToIDResponse{{Name: TEST_PLAYER_NAME, ID: id}}, response)
	}
	{
		payload := []string{"1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11"}
		rec := ts.PostJSON(t, ts.Server, "/profiles/minecraft", payload, nil, nil)

		assert.Equal(t, http.StatusBadRequest, rec.Code)

		var response YggdrasilErrorResponse
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))
		assert.Equal(t, "CONSTRAINT_VIOLATION", *response.Error)
	}
	{
		// Test multiple batches
		{
			payload := make([]string, 0)
			for i := 1; i <= 10; i += 1 {
				payload = append(payload, fmt.Sprintf("%s%d", TEST_PLAYER_NAME, i))
			}
			rec := ts.PostJSON(t, ts.Server, "/profiles/minecraft", payload, nil, nil)
			assert.Equal(t, http.StatusOK, rec.Code)
			var response []PlayerNameToIDResponse
			assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))
		}
		{
			payload := make([]string, 0)
			for i := 11; i <= 15; i += 1 {
				payload = append(payload, fmt.Sprintf("%s%d", TEST_PLAYER_NAME, i))
			}
			rec := ts.PostJSON(t, ts.Server, "/profiles/minecraft", payload, nil, nil)
			assert.Equal(t, http.StatusOK, rec.Code)
			var response []PlayerNameToIDResponse
			assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))
		}
		{
			payload := make([]string, 0)
			for i := 16; i <= 20; i += 1 {
				payload = append(payload, fmt.Sprintf("%s%d", TEST_PLAYER_NAME, i))
			}
			rec := ts.PostJSON(t, ts.Server, "/profiles/minecraft", payload, nil, nil)
			assert.Equal(t, http.StatusOK, rec.Code)
			var response []PlayerNameToIDResponse
			assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))
		}
	}
}

func (ts *TestSuite) testAccountVerifySecurityLocation(t *testing.T) {
	rec := ts.Get(t, ts.Server, "/user/security/location", nil, nil)
	assert.Equal(t, http.StatusNoContent, rec.Code)
}
