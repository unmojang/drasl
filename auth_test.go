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

		t.Run("Test /", ts.testGetServerInfo)
		t.Run("Test /authenticate", ts.testAuthenticate)
		t.Run("Test /invalidate", ts.testInvalidate)
		t.Run("Test /refresh", ts.testRefresh)
		t.Run("Test /signout", ts.testSignout)
		t.Run("Test /validate", ts.testValidate)
	}
}

func (ts *TestSuite) testGetServerInfo(t *testing.T) {
	rec := ts.Get(ts.Server, "/auth", nil)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func (ts *TestSuite) authenticate(t *testing.T, username string, password string) *authenticateResponse {
	authenticatePayload := authenticateRequest{
		Username:    username,
		Password:    password,
		RequestUser: false,
	}

	rec := ts.PostJSON(t, ts.Server, "/authenticate", authenticatePayload)

	// Authentication should succeed and we should get a valid clientToken and
	// accessToken
	assert.Equal(t, http.StatusOK, rec.Code)
	var authenticateRes authenticateResponse
	assert.Nil(t, json.NewDecoder(rec.Body).Decode(&authenticateRes))
	assert.Equal(t, 32, len(authenticateRes.ClientToken))
	assert.Equal(t, 32, len(authenticateRes.AccessToken))

	clientToken := authenticateRes.ClientToken
	accessToken := authenticateRes.AccessToken

	// Check that the database has the token pair
	var tokenPair TokenPair
	result := ts.App.DB.Preload("User").First(&tokenPair, "client_token = ?", clientToken)
	assert.Nil(t, result.Error)
	assert.Equal(t, accessToken, tokenPair.AccessToken)
	assert.Equal(t, TEST_USERNAME, tokenPair.User.Username)

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
		rec := ts.PostJSON(t, ts.Server, "/authenticate", payload)

		// Authentication should succeed and we should get a valid clientToken and
		// accessToken
		assert.Equal(t, http.StatusOK, rec.Code)
		var response authenticateResponse
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))
		assert.Equal(t, clientToken, response.ClientToken)
		assert.Equal(t, 32, len(response.AccessToken))

		// Check that the database was updated
		var tokenPair TokenPair
		result := ts.App.DB.Preload("User").First(&tokenPair, "client_token = ?", response.ClientToken)
		assert.Nil(t, result.Error)
		assert.Equal(t, response.AccessToken, tokenPair.AccessToken)
		assert.Equal(t, TEST_USERNAME, tokenPair.User.Username)
	}
	{
		// Should fail when incorrect password is sent
		payload := authenticateRequest{
			Username:    TEST_USERNAME,
			Password:    "incorrect",
			ClientToken: nil,
			RequestUser: false,
		}
		rec := ts.PostJSON(t, ts.Server, "/authenticate", payload)

		// Authentication should fail
		var response ErrorResponse
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))
		assert.Equal(t, "ForbiddenOperationException", response.Error)
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
		rec := ts.PostJSON(t, ts.Server, "/authenticate", payload)

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
		rec := ts.PostJSON(t, ts.Server, "/authenticate", payload)

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
		// We should start with some valid token pairs
		var count int64
		result := ts.App.DB.Model(&TokenPair{}).Where("client_token = ?", clientToken).Where("valid = ?", true).Count(&count)
		assert.True(t, count > 0)

		payload := invalidateRequest{
			ClientToken: clientToken,
			AccessToken: accessToken,
		}
		rec := ts.PostJSON(t, ts.Server, "/invalidate", payload)

		// Invalidate should succeed
		assert.Equal(t, http.StatusNoContent, rec.Code)

		// The database should now have no valid token pairs
		result = ts.App.DB.Model(&TokenPair{}).Where("client_token = ?", clientToken).Where("valid = ?", true).Count(&count)
		assert.Nil(t, result.Error)

		assert.Equal(t, int64(0), count)
	}

	// Re-authenticate
	authenticateRes = ts.authenticate(t, TEST_USERNAME, TEST_PASSWORD)
	clientToken = authenticateRes.ClientToken
	accessToken = authenticateRes.AccessToken
	{
		// Invalidation should fail when client token is invalid
		payload := refreshRequest{
			ClientToken: "invalid",
			AccessToken: "invalid",
		}
		rec := ts.PostJSON(t, ts.Server, "/invalidate", payload)

		// Invalidate should fail
		var response ErrorResponse
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))
		assert.Equal(t, ErrorResponse{
			Error: "ForbiddenOperationException",
		}, response)
	}
	{
		// Invalidate should fail if we send an invalid access token
		payload := refreshRequest{
			ClientToken: clientToken,
			AccessToken: "invalid",
		}
		rec := ts.PostJSON(t, ts.Server, "/invalidate", payload)

		// Invalidate should fail
		var response ErrorResponse
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))
		assert.Equal(t, "ForbiddenOperationException", response.Error)
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
		rec := ts.PostJSON(t, ts.Server, "/refresh", payload)

		// Refresh should succeed and we should get a new accessToken
		assert.Equal(t, http.StatusOK, rec.Code)
		var refreshRes refreshResponse
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&refreshRes))
		assert.Equal(t, clientToken, refreshRes.ClientToken)
		assert.NotEqual(t, accessToken, refreshRes.AccessToken)
		assert.Equal(t, 32, len(refreshRes.AccessToken))

		// The database should have the new token pair
		var tokenPair TokenPair
		result := ts.App.DB.Preload("User").First(&tokenPair, "client_token = ?", clientToken)
		assert.Nil(t, result.Error)
		assert.Equal(t, refreshRes.AccessToken, tokenPair.AccessToken)
		assert.Equal(t, TEST_USERNAME, tokenPair.User.Username)

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
		rec := ts.PostJSON(t, ts.Server, "/refresh", payload)

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
			AccessToken: "invalid",
			RequestUser: false,
		}
		rec := ts.PostJSON(t, ts.Server, "/refresh", payload)

		// Refresh should fail
		var response ErrorResponse
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))
		assert.Equal(t, ErrorResponse{
			Error: "ForbiddenOperationException",
		}, response)
	}
	{
		// Refresh should fail if we send an invalid access token
		payload := refreshRequest{
			ClientToken: clientToken,
			AccessToken: "invalid",
			RequestUser: false,
		}
		rec := ts.PostJSON(t, ts.Server, "/refresh", payload)

		// Refresh should fail
		var response ErrorResponse
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))
		assert.Equal(t, "ForbiddenOperationException", response.Error)
		assert.Equal(t, "Invalid token.", *response.ErrorMessage)
	}
}

func (ts *TestSuite) testSignout(t *testing.T) {
	// First, authenticate to get a token pair
	ts.authenticate(t, TEST_USERNAME, TEST_PASSWORD)
	{
		// Successful signout
		var user User
		result := ts.App.DB.First(&user, "username = ?", TEST_USERNAME)
		assert.Nil(t, result.Error)

		// We should start with some valid token pairs
		var count int64
		result = ts.App.DB.Model(&TokenPair{}).Where("user_uuid = ?", user.UUID).Where("valid = ?", true).Count(&count)
		assert.Nil(t, result.Error)
		assert.True(t, count > 0)

		payload := signoutRequest{
			Username: TEST_USERNAME,
			Password: TEST_PASSWORD,
		}
		rec := ts.PostJSON(t, ts.Server, "/signout", payload)

		// Signout should succeed
		assert.Equal(t, http.StatusNoContent, rec.Code)

		// The database should now have no valid token pairs
		result = ts.App.DB.Model(&TokenPair{}).Where("user_uuid = ?", user.UUID).Where("valid = ?", true).Count(&count)
		assert.Nil(t, result.Error)
		assert.Equal(t, int64(0), count)
	}
	{
		// Should fail when incorrect password is sent
		payload := signoutRequest{
			Username: TEST_USERNAME,
			Password: "incorrect",
		}
		rec := ts.PostJSON(t, ts.Server, "/signout", payload)

		// Signout should fail
		var response ErrorResponse
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))
		assert.Equal(t, "ForbiddenOperationException", response.Error)
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
		rec := ts.PostJSON(t, ts.Server, "/validate", payload)
		assert.Equal(t, http.StatusNoContent, rec.Code)
	}
	{
		// Validate should fail if we send an invalid client token
		payload := refreshRequest{
			ClientToken: "invalid",
			AccessToken: "invalid",
		}
		rec := ts.PostJSON(t, ts.Server, "/validate", payload)
		assert.Equal(t, http.StatusForbidden, rec.Code)
	}
	{
		// Validate should fail if we send an invalid client token
		payload := refreshRequest{
			ClientToken: clientToken,
			AccessToken: "invalid",
		}
		rec := ts.PostJSON(t, ts.Server, "/validate", payload)
		assert.Equal(t, http.StatusForbidden, rec.Code)
	}
	{
		// Validate should fail if the token pair is invalid
		var tokenPair TokenPair
		result := ts.App.DB.First(&tokenPair, "client_token = ?", clientToken)
		assert.Nil(t, result.Error)

		tokenPair.Valid = false
		assert.Nil(t, ts.App.DB.Save(&tokenPair).Error)

		payload := refreshRequest{
			ClientToken: clientToken,
			AccessToken: accessToken,
		}
		rec := ts.PostJSON(t, ts.Server, "/validate", payload)
		assert.Equal(t, http.StatusForbidden, rec.Code)
	}
}
