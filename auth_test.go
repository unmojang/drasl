package main

import (
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"net/http"
	"testing"
)

func TestAuth(t *testing.T) {
	{
		ts := &TestSuite{}

		config := testConfig()
		ts.Setup(config)
		defer ts.Teardown()

		ts.CreateTestUser(ts.Server, TEST_USERNAME)
		ts.CreateTestUser(ts.Server, TEST_OTHER_USERNAME)

		t.Run("Test /", ts.testGetServerInfo)
		t.Run("Test /authenticate", ts.testAuthenticate)
		t.Run("Test /invalidate", ts.testInvalidate)
		t.Run("Test /refresh", ts.testRefresh)
		t.Run("Test /signout", ts.testSignout)
		t.Run("Test /validate", ts.testValidate)

		t.Run("Test authenticate with duplicate client token", ts.testDuplicateClientToken)
	}
}

func (ts *TestSuite) testGetServerInfo(t *testing.T) {
	rec := ts.Get(t, ts.Server, "/auth", nil, nil)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func (ts *TestSuite) authenticate(t *testing.T, username string, password string) *authenticateResponse {
	authenticatePayload := authenticateRequest{
		Username:    username,
		Password:    password,
		RequestUser: false,
	}

	rec := ts.PostJSON(t, ts.Server, "/authenticate", authenticatePayload, nil, nil)

	// Authentication should succeed and we should get a valid clientToken and
	// accessToken
	assert.Equal(t, http.StatusOK, rec.Code)
	var authenticateRes authenticateResponse
	assert.Nil(t, json.NewDecoder(rec.Body).Decode(&authenticateRes))
	assert.Equal(t, 32, len(authenticateRes.ClientToken))

	clientToken := authenticateRes.ClientToken
	accessToken := authenticateRes.AccessToken

	// Check that the access token is valid
	client := ts.App.GetClient(accessToken, StalePolicyDeny)
	assert.NotNil(t, client)
	assert.Equal(t, client.ClientToken, clientToken)

	return &authenticateRes
}

func (ts *TestSuite) testAuthenticate(t *testing.T) {
	{
		// Successful authentication
		response := ts.authenticate(t, TEST_USERNAME, TEST_PASSWORD)

		// We did not pass an agent
		assert.Nil(t, response.SelectedProfile)
		assert.Nil(t, response.AvailableProfiles)

		// We did not pass requestUser
		assert.Nil(t, response.User)
	}
	{
		// If we send our own clientToken, the server should use it
		clientToken := "12345678901234567890123456789012"
		payload := authenticateRequest{
			Username:    TEST_USERNAME,
			Password:    TEST_PASSWORD,
			ClientToken: &clientToken,
			RequestUser: false,
		}
		rec := ts.PostJSON(t, ts.Server, "/authenticate", payload, nil, nil)

		// Authentication should succeed and we should get a valid clientToken and
		// accessToken
		assert.Equal(t, http.StatusOK, rec.Code)
		var response authenticateResponse
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))
		assert.Equal(t, clientToken, response.ClientToken)

		// Check that the database was updated
		var client Client
		result := ts.App.DB.Preload("User").First(&client, "client_token = ?", response.ClientToken)
		assert.Nil(t, result.Error)
		assert.Equal(t, TEST_USERNAME, client.User.Username)

		accessTokenClient := ts.App.GetClient(response.AccessToken, StalePolicyDeny)
		assert.NotNil(t, accessTokenClient)
		assert.Equal(t, client, *accessTokenClient)

		// The accessToken should be valid
		validatePayload := validateRequest{
			ClientToken: response.ClientToken,
			AccessToken: response.AccessToken,
		}
		rec = ts.PostJSON(t, ts.Server, "/validate", validatePayload, nil, nil)
		assert.Equal(t, http.StatusNoContent, rec.Code)

		// Authentication should succeed if we POST /authenticate again with
		// the same clientToken
		payload = authenticateRequest{
			Username:    TEST_USERNAME,
			Password:    TEST_PASSWORD,
			ClientToken: &clientToken,
			RequestUser: false,
		}
		rec = ts.PostJSON(t, ts.Server, "/authenticate", payload, nil, nil)
		assert.Equal(t, http.StatusOK, rec.Code)

		var newResponse authenticateResponse
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&newResponse))
		assert.Equal(t, clientToken, newResponse.ClientToken)

		result = ts.App.DB.Preload("User").First(&client, "client_token = ?", clientToken)
		assert.Nil(t, result.Error)

		// The old accessToken should be invalid
		validatePayload = validateRequest{
			ClientToken: response.ClientToken,
			AccessToken: response.AccessToken,
		}
		rec = ts.PostJSON(t, ts.Server, "/validate", validatePayload, nil, nil)
		assert.Equal(t, http.StatusForbidden, rec.Code)

		// The new accessToken should be valid
		validatePayload = validateRequest{
			ClientToken: newResponse.ClientToken,
			AccessToken: newResponse.AccessToken,
		}
		rec = ts.PostJSON(t, ts.Server, "/validate", validatePayload, nil, nil)
		assert.Equal(t, http.StatusNoContent, rec.Code)
	}
	{
		// Should fail when incorrect password is sent
		payload := authenticateRequest{
			Username:    TEST_USERNAME,
			Password:    "incorrect",
			ClientToken: nil,
			RequestUser: false,
		}
		rec := ts.PostJSON(t, ts.Server, "/authenticate", payload, nil, nil)

		// Authentication should fail
		var response ErrorResponse
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))
		assert.Equal(t, "ForbiddenOperationException", *response.Error)
		assert.Equal(t, "Invalid credentials. Invalid username or password.", *response.ErrorMessage)
	}
	{
		// Should return a profile when the `agent` field is included in the request
		payload := authenticateRequest{
			Username:    TEST_USERNAME,
			Password:    TEST_PASSWORD,
			ClientToken: nil,
			RequestUser: false,
			Agent: &Agent{
				Name:    "Minecraft",
				Version: 1,
			},
		}
		rec := ts.PostJSON(t, ts.Server, "/authenticate", payload, nil, nil)

		// Authentication should succeed
		assert.Equal(t, http.StatusOK, rec.Code)
		var response authenticateResponse
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))

		var user User
		assert.Nil(t, ts.App.DB.First(&user, "username = ?", TEST_USERNAME).Error)

		expectedProfile := Profile{
			ID:   Unwrap(UUIDToID(user.UUID)),
			Name: user.PlayerName,
		}
		assert.Equal(t, expectedProfile, *response.SelectedProfile)
		assert.Equal(t, 1, len(*response.AvailableProfiles))
		assert.Equal(t, expectedProfile, (*response.AvailableProfiles)[0])
	}
	{
		// Should return a user when `requestUser` is true
		payload := authenticateRequest{
			Username:    TEST_USERNAME,
			Password:    TEST_PASSWORD,
			ClientToken: nil,
			RequestUser: true,
		}
		rec := ts.PostJSON(t, ts.Server, "/authenticate", payload, nil, nil)

		// Authentication should succeed
		assert.Equal(t, http.StatusOK, rec.Code)
		var response authenticateResponse
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))

		var user User
		assert.Nil(t, ts.App.DB.First(&user, "username = ?", TEST_USERNAME).Error)

		expectedUser := UserResponse{
			ID: Unwrap(UUIDToID(user.UUID)),
			Properties: []UserProperty{UserProperty{
				Name:  "preferredLanguage",
				Value: user.PreferredLanguage,
			}},
		}
		assert.Equal(t, expectedUser, *response.User)
	}
}

func (ts *TestSuite) testInvalidate(t *testing.T) {
	// First, authenticate to get a token pair
	authenticateRes := ts.authenticate(t, TEST_USERNAME, TEST_PASSWORD)
	clientToken := authenticateRes.ClientToken
	accessToken := authenticateRes.AccessToken
	{
		// Successful invalidate
		// We should start with valid clients in the database
		client := ts.App.GetClient(accessToken, StalePolicyDeny)
		assert.NotNil(t, client)
		var clients []Client
		result := ts.App.DB.Model(Client{}).Where("user_uuid = ?", client.User.UUID).Find(&clients)
		assert.Nil(t, result.Error)
		assert.True(t, len(clients) > 0)
		oldVersions := make(map[string]int)
		for _, client := range clients {
			oldVersions[client.ClientToken] = client.Version
		}

		payload := invalidateRequest{
			ClientToken: clientToken,
			AccessToken: accessToken,
		}
		rec := ts.PostJSON(t, ts.Server, "/invalidate", payload, nil, nil)

		// Invalidate should succeed
		assert.Equal(t, http.StatusNoContent, rec.Code)

		// The token version of each client should have been incremented,
		// invalidating all previously-issued JWTs
		assert.Nil(t, ts.App.GetClient(accessToken, StalePolicyDeny))
		result = ts.App.DB.Model(Client{}).Where("user_uuid = ?", client.User.UUID).Find(&clients)
		assert.Nil(t, result.Error)
		for _, client := range clients {
			assert.Equal(t, oldVersions[client.ClientToken]+1, client.Version)
		}
	}

	// Re-authenticate
	authenticateRes = ts.authenticate(t, TEST_USERNAME, TEST_PASSWORD)
	clientToken = authenticateRes.ClientToken
	accessToken = authenticateRes.AccessToken
	{
		// Invalidation should fail when client token is invalid
		payload := refreshRequest{
			ClientToken: "invalid",
			AccessToken: accessToken,
		}
		rec := ts.PostJSON(t, ts.Server, "/invalidate", payload, nil, nil)

		// Invalidate should fail
		var response ErrorResponse
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))
		assert.Equal(t, "ForbiddenOperationException", *response.Error)
	}
	{
		// Invalidate should fail if we send an invalid access token
		payload := refreshRequest{
			ClientToken: clientToken,
			AccessToken: "invalid",
		}
		rec := ts.PostJSON(t, ts.Server, "/invalidate", payload, nil, nil)

		// Invalidate should fail
		var response ErrorResponse
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))
		assert.Equal(t, "ForbiddenOperationException", *response.Error)
		assert.Equal(t, "Invalid token.", *response.ErrorMessage)
	}
}

func (ts *TestSuite) testRefresh(t *testing.T) {
	// First, authenticate to get a token pair
	authenticateRes := ts.authenticate(t, TEST_USERNAME, TEST_PASSWORD)
	clientToken := authenticateRes.ClientToken
	accessToken := authenticateRes.AccessToken

	{
		// Successful refresh
		payload := refreshRequest{
			ClientToken: clientToken,
			AccessToken: accessToken,
			RequestUser: false,
		}
		rec := ts.PostJSON(t, ts.Server, "/refresh", payload, nil, nil)

		// Refresh should succeed and we should get a new accessToken
		assert.Equal(t, http.StatusOK, rec.Code)
		var refreshRes refreshResponse
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&refreshRes))
		assert.Equal(t, clientToken, refreshRes.ClientToken)
		assert.NotEqual(t, accessToken, refreshRes.AccessToken)

		// The old accessToken should be invalid
		client := ts.App.GetClient(accessToken, StalePolicyDeny)
		assert.Nil(t, client)

		// The new token should be valid
		client = ts.App.GetClient(refreshRes.AccessToken, StalePolicyDeny)
		assert.NotNil(t, client)

		// The response should include a profile
		var user User
		assert.Nil(t, ts.App.DB.First(&user, "username = ?", TEST_USERNAME).Error)
		expectedProfile := Profile{
			ID:   Unwrap(UUIDToID(user.UUID)),
			Name: user.PlayerName,
		}
		assert.Equal(t, expectedProfile, refreshRes.SelectedProfile)
		assert.Equal(t, []Profile{expectedProfile}, refreshRes.AvailableProfiles)

		// We did not pass requestUser
		assert.Nil(t, refreshRes.User)

		// For future tests
		accessToken = refreshRes.AccessToken
	}
	{
		// Should return a user when `requestUser` is true
		payload := refreshRequest{
			ClientToken: clientToken,
			AccessToken: accessToken,
			RequestUser: true,
		}
		rec := ts.PostJSON(t, ts.Server, "/refresh", payload, nil, nil)

		var refreshRes refreshResponse
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&refreshRes))

		var user User
		assert.Nil(t, ts.App.DB.First(&user, "username = ?", TEST_USERNAME).Error)

		expectedUser := UserResponse{
			ID: Unwrap(UUIDToID(user.UUID)),
			Properties: []UserProperty{UserProperty{
				Name:  "preferredLanguage",
				Value: user.PreferredLanguage,
			}},
		}
		assert.Equal(t, expectedUser, *refreshRes.User)

		accessToken = refreshRes.AccessToken
	}
	{
		// Refresh should fail if we send an invalid client token
		payload := refreshRequest{
			ClientToken: "invalid",
			AccessToken: accessToken,
			RequestUser: false,
		}
		rec := ts.PostJSON(t, ts.Server, "/refresh", payload, nil, nil)

		// Refresh should fail
		var response ErrorResponse
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))
		assert.Equal(t, "ForbiddenOperationException", *response.Error)
	}
	{
		// Refresh should fail if we send an invalid access token
		payload := refreshRequest{
			ClientToken: clientToken,
			AccessToken: "invalid",
			RequestUser: false,
		}
		rec := ts.PostJSON(t, ts.Server, "/refresh", payload, nil, nil)

		// Refresh should fail
		var response ErrorResponse
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))
		assert.Equal(t, "ForbiddenOperationException", *response.Error)
		assert.Equal(t, "Invalid token.", *response.ErrorMessage)
	}
}

func (ts *TestSuite) testSignout(t *testing.T) {
	// First, authenticate so we have a valid client to test that it gets
	// invalidated
	authenticateRes := ts.authenticate(t, TEST_USERNAME, TEST_PASSWORD)
	accessToken := authenticateRes.AccessToken
	{
		// Successful signout
		var user User
		result := ts.App.DB.First(&user, "username = ?", TEST_USERNAME)
		assert.Nil(t, result.Error)

		// We should start with valid clients in the database
		client := ts.App.GetClient(accessToken, StalePolicyDeny)
		assert.NotNil(t, client)
		var clients []Client
		result = ts.App.DB.Model(Client{}).Where("user_uuid = ?", client.User.UUID).Find(&clients)
		assert.Nil(t, result.Error)
		assert.True(t, len(clients) > 0)
		oldVersions := make(map[string]int)
		for _, client := range clients {
			oldVersions[client.ClientToken] = client.Version
		}

		payload := signoutRequest{
			Username: TEST_USERNAME,
			Password: TEST_PASSWORD,
		}
		rec := ts.PostJSON(t, ts.Server, "/signout", payload, nil, nil)

		// Signout should succeed
		assert.Equal(t, http.StatusNoContent, rec.Code)

		// The token version of each client should have been incremented,
		// invalidating all previously-issued JWTs
		assert.Nil(t, ts.App.GetClient(accessToken, StalePolicyDeny))
		result = ts.App.DB.Model(Client{}).Where("user_uuid = ?", client.User.UUID).Find(&clients)
		assert.Nil(t, result.Error)
		assert.True(t, len(clients) > 0)
		for _, client := range clients {
			assert.Equal(t, oldVersions[client.ClientToken]+1, client.Version)
		}
	}
	{
		// Should fail when incorrect password is sent
		payload := signoutRequest{
			Username: TEST_USERNAME,
			Password: "incorrect",
		}
		rec := ts.PostJSON(t, ts.Server, "/signout", payload, nil, nil)

		// Signout should fail
		var response ErrorResponse
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))
		assert.Equal(t, "ForbiddenOperationException", *response.Error)
		assert.Equal(t, "Invalid credentials. Invalid username or password.", *response.ErrorMessage)
	}
}

func (ts *TestSuite) testValidate(t *testing.T) {
	// First, authenticate to get a token pair
	authenticateRes := ts.authenticate(t, TEST_USERNAME, TEST_PASSWORD)
	clientToken := authenticateRes.ClientToken
	accessToken := authenticateRes.AccessToken
	{
		// Successful validate
		payload := validateRequest{
			ClientToken: clientToken,
			AccessToken: accessToken,
		}
		rec := ts.PostJSON(t, ts.Server, "/validate", payload, nil, nil)
		assert.Equal(t, http.StatusNoContent, rec.Code)
	}
	{
		// Validate should fail if we send an invalid client token
		payload := refreshRequest{
			ClientToken: "invalid",
			AccessToken: accessToken,
		}
		rec := ts.PostJSON(t, ts.Server, "/validate", payload, nil, nil)
		assert.Equal(t, http.StatusForbidden, rec.Code)
	}
	{
		// Validate should fail if we send an invalid client token
		payload := refreshRequest{
			ClientToken: clientToken,
			AccessToken: "invalid",
		}
		rec := ts.PostJSON(t, ts.Server, "/validate", payload, nil, nil)
		assert.Equal(t, http.StatusForbidden, rec.Code)
	}
	{
		// Validate should fail if the token pair is invalid
		var client Client
		result := ts.App.DB.First(&client, "client_token = ?", clientToken)
		assert.Nil(t, result.Error)

		client.Version += 1
		assert.Nil(t, ts.App.DB.Save(&client).Error)

		payload := refreshRequest{
			ClientToken: clientToken,
			AccessToken: accessToken,
		}
		rec := ts.PostJSON(t, ts.Server, "/validate", payload, nil, nil)
		assert.Equal(t, http.StatusForbidden, rec.Code)
	}
}

func (ts *TestSuite) testDuplicateClientToken(t *testing.T) {
	// Two users should be able to use the same clientToken

	authenticateRes := ts.authenticate(t, TEST_USERNAME, TEST_PASSWORD)
	clientToken := authenticateRes.ClientToken

	payload := authenticateRequest{
		Username:    TEST_OTHER_USERNAME,
		Password:    TEST_PASSWORD,
		ClientToken: &clientToken,
		RequestUser: false,
	}
	rec := ts.PostJSON(t, ts.Server, "/authenticate", payload, nil, nil)

	assert.Equal(t, http.StatusOK, rec.Code)
	var response authenticateResponse
	assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))
	assert.Equal(t, clientToken, response.ClientToken)

	var user User
	result := ts.App.DB.First(&user, "username = ?", TEST_USERNAME)
	assert.Nil(t, result.Error)

	var otherUser User
	result = ts.App.DB.First(&otherUser, "username = ?", TEST_OTHER_USERNAME)
	assert.Nil(t, result.Error)

	var client Client
	result = ts.App.DB.Preload("User").First(&client, "client_token = ? AND user_uuid = ?", clientToken, user.UUID)
	assert.Nil(t, result.Error)
	assert.Equal(t, TEST_USERNAME, client.User.Username)

	var otherClient Client
	result = ts.App.DB.Preload("User").First(&otherClient, "client_token = ? AND user_uuid = ?", clientToken, otherUser.UUID)
	assert.Nil(t, result.Error)
	assert.Equal(t, TEST_OTHER_USERNAME, otherClient.User.Username)
}
