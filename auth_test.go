package main

import (
	"encoding/json"
	"github.com/samber/mo"
	"github.com/stretchr/testify/assert"
	"net/http"
	"testing"
)

func TestAuth(t *testing.T) {
	t.Parallel()
	{
		ts := &TestSuite{}

		config := testConfig()
		ts.Setup(config)
		defer ts.Teardown()

		ts.CreateTestUser(t, ts.App, ts.Server, TEST_USERNAME)
		ts.CreateTestUser(t, ts.App, ts.Server, TEST_OTHER_USERNAME)

		t.Run("Test /", ts.testGetServerInfo)
		t.Run("Test /authenticate", ts.testAuthenticate)
		t.Run("Test /authenticate, multiple profiles", ts.testAuthenticateMultipleProfiles)
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
		response := ts.authenticate(t, TEST_PLAYER_NAME, TEST_PASSWORD)

		// We did not pass an agent
		assert.Nil(t, response.SelectedProfile)
		assert.Nil(t, response.AvailableProfiles)

		// We did not pass requestUser
		assert.Nil(t, response.User)
	}
	{
		// Authentication should succeed if we use the player's Minecraft token
		// as the password

		var user User
		assert.Nil(t, ts.App.DB.First(&user, "username = ?", TEST_PLAYER_NAME).Error)

		response := ts.authenticate(t, TEST_PLAYER_NAME, user.MinecraftToken)

		// We did not pass an agent
		assert.Nil(t, response.SelectedProfile)
		assert.Nil(t, response.AvailableProfiles)

		// We did not pass requestUser
		assert.Nil(t, response.User)
	}
	{
		// If we send our own clientToken, the server should use it
		clientToken := "11111111111111111111111111111111"
		otherClientToken := "22222222222222222222222222222222"
		payload := authenticateRequest{
			Username:    TEST_PLAYER_NAME,
			Password:    TEST_PASSWORD,
			ClientToken: &clientToken,
			RequestUser: false,
		}
		rec := ts.PostJSON(t, ts.Server, "/authenticate", payload, nil, nil)

		// Authentication should succeed and we should get a valid clientToken and
		// accessToken
		assert.Equal(t, http.StatusOK, rec.Code)
		var response0 authenticateResponse
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response0))
		assert.Equal(t, clientToken, response0.ClientToken)

		// Check that the database was updated
		var client Client
		result := ts.App.DB.Preload("Player").First(&client, "client_token = ?", clientToken)
		assert.Nil(t, result.Error)
		assert.NotNil(t, client.Player)
		assert.Equal(t, TEST_PLAYER_NAME, client.Player.Name)

		accessTokenClient := ts.App.GetClient(response0.AccessToken, StalePolicyDeny)
		assert.NotNil(t, accessTokenClient)
		accessTokenClient.Player = client.Player
		accessTokenClient.User = client.User

		assert.Equal(t, client, *accessTokenClient)

		// The accessToken should be valid
		validatePayload := validateRequest{
			ClientToken: response0.ClientToken,
			AccessToken: response0.AccessToken,
		}
		rec = ts.PostJSON(t, ts.Server, "/validate", validatePayload, nil, nil)
		assert.Equal(t, http.StatusNoContent, rec.Code)

		// Authentication should succeed if we POST /authenticate again with
		// the same clientToken
		payload = authenticateRequest{
			Username:    TEST_PLAYER_NAME,
			Password:    TEST_PASSWORD,
			ClientToken: &clientToken,
			RequestUser: false,
		}
		rec = ts.PostJSON(t, ts.Server, "/authenticate", payload, nil, nil)
		assert.Equal(t, http.StatusOK, rec.Code)

		var response1 authenticateResponse
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response1))
		assert.Equal(t, clientToken, response1.ClientToken)

		result = ts.App.DB.First(&client, "client_token = ?", clientToken)
		assert.Nil(t, result.Error)

		// The old accessToken should be invalid
		validatePayload = validateRequest{
			ClientToken: response0.ClientToken,
			AccessToken: response0.AccessToken,
		}
		rec = ts.PostJSON(t, ts.Server, "/validate", validatePayload, nil, nil)
		assert.Equal(t, http.StatusForbidden, rec.Code)

		// The new accessToken should be valid
		validatePayload = validateRequest{
			ClientToken: response1.ClientToken,
			AccessToken: response1.AccessToken,
		}
		rec = ts.PostJSON(t, ts.Server, "/validate", validatePayload, nil, nil)
		assert.Equal(t, http.StatusNoContent, rec.Code)

		// Authentication should succeed if we POST /authenticate again with a different clientToken
		payload = authenticateRequest{
			Username:    TEST_PLAYER_NAME,
			Password:    TEST_PASSWORD,
			ClientToken: &otherClientToken,
			RequestUser: false,
		}
		rec = ts.PostJSON(t, ts.Server, "/authenticate", payload, nil, nil)
		assert.Equal(t, http.StatusOK, rec.Code)

		var response2 authenticateResponse
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response2))
		assert.Equal(t, otherClientToken, response2.ClientToken)

		var otherClient Client
		result = ts.App.DB.First(&otherClient, "client_token = ?", otherClientToken)
		assert.Nil(t, result.Error)

		// The old accessToken should still be valid
		validatePayload = validateRequest{
			ClientToken: response1.ClientToken,
			AccessToken: response1.AccessToken,
		}
		rec = ts.PostJSON(t, ts.Server, "/validate", validatePayload, nil, nil)
		assert.Equal(t, http.StatusNoContent, rec.Code)

		// The new accessToken should be valid
		validatePayload = validateRequest{
			ClientToken: response2.ClientToken,
			AccessToken: response2.AccessToken,
		}
		rec = ts.PostJSON(t, ts.Server, "/validate", validatePayload, nil, nil)
		assert.Equal(t, http.StatusNoContent, rec.Code)
	}
	{
		// Should fail when incorrect password is sent
		payload := authenticateRequest{
			Username:    TEST_PLAYER_NAME,
			Password:    "incorrect",
			ClientToken: nil,
			RequestUser: false,
		}
		rec := ts.PostJSON(t, ts.Server, "/authenticate", payload, nil, nil)

		// Authentication should fail
		var response YggdrasilErrorResponse
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))
		assert.Equal(t, "ForbiddenOperationException", *response.Error)
		assert.Equal(t, "Invalid credentials. Invalid username or password.", *response.ErrorMessage)
	}
	{
		// Should return a profile when the `agent` field is included in the request
		payload := authenticateRequest{
			Username:    TEST_PLAYER_NAME,
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

		var player Player
		assert.Nil(t, ts.App.DB.First(&player, "name = ?", TEST_PLAYER_NAME).Error)

		expectedProfile := Profile{
			ID:   Unwrap(UUIDToID(player.UUID)),
			Name: player.Name,
		}
		assert.Equal(t, expectedProfile, *response.SelectedProfile)
		assert.Equal(t, 1, len(*response.AvailableProfiles))
		assert.Equal(t, expectedProfile, (*response.AvailableProfiles)[0])
	}
	{
		// Should return a user when `requestUser` is true
		payload := authenticateRequest{
			Username:    TEST_PLAYER_NAME,
			Password:    TEST_PASSWORD,
			ClientToken: nil,
			RequestUser: true,
		}
		rec := ts.PostJSON(t, ts.Server, "/authenticate", payload, nil, nil)

		// Authentication should succeed
		assert.Equal(t, http.StatusOK, rec.Code)
		var response authenticateResponse
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))

		var player Player
		assert.Nil(t, ts.App.DB.Preload("User").First(&player, "name = ?", TEST_PLAYER_NAME).Error)

		expectedUser := UserResponse{
			ID: Unwrap(UUIDToID(player.User.UUID)),
			Properties: []UserProperty{{
				Name:  "preferredLanguage",
				Value: player.User.PreferredLanguage,
			}},
		}
		assert.Equal(t, expectedUser, *response.User)
	}
}

func findProfile(profiles []Profile, playerName string) mo.Option[Profile] {
	for _, profile := range profiles {
		if profile.Name == playerName {
			return mo.Some(profile)
		}
	}
	return mo.None[Profile]()
}

func (ts *TestSuite) testAuthenticateMultipleProfiles(t *testing.T) {
	{
		var user User
		assert.Nil(t, ts.App.DB.First(&user, "username = ?", TEST_USERNAME).Error)

		// Set up two players on the test account, each distrinct from TEST_USERNAME
		firstPlayerName := "FirstPlayer"
		secondPlayerName := "SecondPlayer"

		_, err := ts.App.UpdatePlayer(&GOD, user.Players[0], &firstPlayerName, nil, nil, nil, nil, false, nil, nil, false)
		assert.Nil(t, err)

		secondPlayer, err := ts.App.CreatePlayer(&GOD, user.UUID, secondPlayerName, nil, false, nil, nil, nil, nil, nil, nil, nil)
		assert.Nil(t, err)

		authenticatePayload := authenticateRequest{
			Username:    TEST_USERNAME,
			Password:    TEST_PASSWORD,
			RequestUser: false,
			Agent: &Agent{
				Name:    "Minecraft",
				Version: 1,
			},
		}
		rec := ts.PostJSON(t, ts.Server, "/authenticate", authenticatePayload, nil, nil)

		assert.Equal(t, http.StatusOK, rec.Code)
		var authenticateRes authenticateResponse
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&authenticateRes))

		// We did not pass requestUser
		assert.Nil(t, authenticateRes.User)

		// User has multiple players, selectedProfile should be missing
		assert.Nil(t, authenticateRes.SelectedProfile)

		assert.Equal(t, 2, len(*authenticateRes.AvailableProfiles))

		profile, ok := findProfile(*authenticateRes.AvailableProfiles, secondPlayerName).Get()
		assert.True(t, ok)

		// Now, refresh to select a profile
		refreshPayload := refreshRequest{
			ClientToken:     authenticateRes.ClientToken,
			AccessToken:     authenticateRes.AccessToken,
			RequestUser:     false,
			SelectedProfile: &profile,
		}
		rec = ts.PostJSON(t, ts.Server, "/refresh", refreshPayload, nil, nil)

		// Refresh should succeed and we should get a new accessToken
		assert.Equal(t, http.StatusOK, rec.Code)
		var refreshRes refreshResponse
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&refreshRes))
		assert.Equal(t, authenticateRes.ClientToken, refreshRes.ClientToken)
		assert.NotEqual(t, authenticateRes.AccessToken, refreshRes.AccessToken)

		assert.Equal(t, profile, *refreshRes.SelectedProfile)

		// When the username matches one of the available player names, that
		// player should automatically become the selectedProfile.
		_, err = ts.App.UpdatePlayer(&GOD, user.Players[0], Ptr(TEST_USERNAME), nil, nil, nil, nil, false, nil, nil, false)
		assert.Nil(t, err)

		rec = ts.PostJSON(t, ts.Server, "/authenticate", authenticatePayload, nil, nil)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&authenticateRes))

		usernameProfile, ok := findProfile(*authenticateRes.AvailableProfiles, TEST_USERNAME).Get()
		assert.True(t, ok)

		assert.Equal(t, usernameProfile, *authenticateRes.SelectedProfile)

		assert.Nil(t, ts.App.DeletePlayer(&GOD, &secondPlayer))
	}
}

func (ts *TestSuite) testInvalidate(t *testing.T) {
	{
		authenticateRes := ts.authenticate(t, TEST_PLAYER_NAME, TEST_PASSWORD)
		clientToken := authenticateRes.ClientToken
		accessToken := authenticateRes.AccessToken

		// Successful invalidate
		// We should start with valid clients in the database
		client := ts.App.GetClient(accessToken, StalePolicyDeny)
		assert.NotNil(t, client)
		var clients []Client
		result := ts.App.DB.Model(Client{}).Where("player_uuid = ?", &client.Player.UUID).Find(&clients)
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
		result = ts.App.DB.Model(Client{}).Where("player_uuid = ?", &client.Player.UUID).Find(&clients)
		assert.Nil(t, result.Error)
		for _, client := range clients {
			assert.Equal(t, oldVersions[client.ClientToken]+1, client.Version)
		}
	}
	{
		// Re-authenticate
		authenticateRes := ts.authenticate(t, TEST_PLAYER_NAME, TEST_PASSWORD)
		clientToken := authenticateRes.ClientToken

		// Invalidate should fail if we send an invalid access token
		payload := refreshRequest{
			ClientToken: clientToken,
			AccessToken: "invalid",
		}
		rec := ts.PostJSON(t, ts.Server, "/invalidate", payload, nil, nil)

		// Invalidate should fail
		var response YggdrasilErrorResponse
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))
		assert.Equal(t, http.StatusForbidden, rec.Code)
		assert.Equal(t, "ForbiddenOperationException", *response.Error)
		assert.Equal(t, "Invalid token", *response.ErrorMessage)
	}
}

func (ts *TestSuite) testRefresh(t *testing.T) {
	// First, authenticate to get a token pair
	authenticateRes := ts.authenticate(t, TEST_PLAYER_NAME, TEST_PASSWORD)
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
		var player Player
		assert.Nil(t, ts.App.DB.First(&player, "name = ?", TEST_PLAYER_NAME).Error)
		expectedProfile := Profile{
			ID:   Unwrap(UUIDToID(player.UUID)),
			Name: player.Name,
		}
		assert.Equal(t, expectedProfile, *refreshRes.SelectedProfile)
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

		var player Player
		assert.Nil(t, ts.App.DB.Preload("User").First(&player, "name = ?", TEST_PLAYER_NAME).Error)

		expectedUser := UserResponse{
			ID: Unwrap(UUIDToID(player.UUID)),
			Properties: []UserProperty{{
				Name:  "preferredLanguage",
				Value: player.User.PreferredLanguage,
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
		var response YggdrasilErrorResponse
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
		var response YggdrasilErrorResponse
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))
		assert.Equal(t, "ForbiddenOperationException", *response.Error)
		assert.Equal(t, "Invalid token", *response.ErrorMessage)
	}
}

func (ts *TestSuite) testSignout(t *testing.T) {
	// First, authenticate so we have a valid client to test that it gets
	// invalidated
	authenticateRes := ts.authenticate(t, TEST_PLAYER_NAME, TEST_PASSWORD)
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
		result = ts.App.DB.Model(Client{}).Where("user_uuid = ?", client.UserUUID).Find(&clients)
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
		result = ts.App.DB.Model(Client{}).Where("user_uuid = ?", client.UserUUID).Find(&clients)
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
		var response YggdrasilErrorResponse
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.Equal(t, "ForbiddenOperationException", *response.Error)
		assert.Equal(t, "Invalid credentials. Invalid username or password.", *response.ErrorMessage)
	}
}

func (ts *TestSuite) testValidate(t *testing.T) {
	// First, authenticate to get a token pair
	authenticateRes := ts.authenticate(t, TEST_PLAYER_NAME, TEST_PASSWORD)
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

	authenticateRes := ts.authenticate(t, TEST_PLAYER_NAME, TEST_PASSWORD)
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

	var player Player
	result := ts.App.DB.First(&player, "name = ?", TEST_PLAYER_NAME)
	assert.Nil(t, result.Error)

	var otherPlayer Player
	result = ts.App.DB.First(&otherPlayer, "name = ?", TEST_OTHER_USERNAME)
	assert.Nil(t, result.Error)

	var client Client
	result = ts.App.DB.Preload("Player").First(&client, "client_token = ? AND player_uuid = ?", clientToken, player.UUID)
	assert.Nil(t, result.Error)
	assert.Equal(t, TEST_PLAYER_NAME, client.Player.Name)

	var otherClient Client
	result = ts.App.DB.Preload("Player").First(&otherClient, "client_token = ? AND player_uuid = ?", clientToken, otherPlayer.UUID)
	assert.Nil(t, result.Error)
	assert.Equal(t, TEST_OTHER_USERNAME, otherClient.Player.Name)
}
