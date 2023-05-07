package main

import (
	"bytes"
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAuth(t *testing.T) {
	{
		ts := &TestSuite{}

		config := testConfig()
		ts.Setup(config)
		defer ts.Teardown()

		ts.CreateTestUser(ts.FrontServer)

		t.Run("Test /authenticate", ts.testAuthenticate)
	}
}

func (ts *TestSuite) testAuthenticate(t *testing.T) {
	payload := authenticateRequest{
		Username:    TEST_USERNAME,
		Password:    TEST_PASSWORD,
		ClientToken: nil,
		RequestUser: false,
	}
	body, err := json.Marshal(payload)
	assert.Nil(t, err)

	req := httptest.NewRequest(http.MethodPost, "/authenticate", bytes.NewBuffer(body))
	req.Header.Add("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	ts.AuthServer.ServeHTTP(rec, req)

	// Authentication should succeed and we should get a valid clientToken and
	// accessToken
	assert.Equal(t, http.StatusOK, rec.Code)
	var response authenticateResponse
	assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))
	assert.Equal(t, 32, len(response.ClientToken))
	assert.Equal(t, 32, len(response.AccessToken))

	// Check that the database was updated
	var tokenPair TokenPair
	result := ts.App.DB.Preload("User").First(&tokenPair, "client_token = ?", response.ClientToken)
	assert.Nil(t, result.Error)
	assert.Equal(t, response.AccessToken, tokenPair.AccessToken)
	assert.Equal(t, TEST_USERNAME, tokenPair.User.Username)

	// We did not pass an agent
	assert.Nil(t, response.SelectedProfile)
	assert.Nil(t, response.AvailableProfiles)

	// We did not pass requestUser
	assert.Nil(t, response.User)
}
