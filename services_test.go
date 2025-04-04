package main

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

const SERVICES_EXISTING_USERNAME = "ExistingUser"

func TestServices(t *testing.T) {
	t.Parallel()
	{
		ts := &TestSuite{}

		auxConfig := testConfig()
		ts.SetupAux(auxConfig)

		config := testConfig()
		config.ForwardSkins = false
		config.FallbackAPIServers = []FallbackAPIServerConfig{
			{
				Nickname:    "Aux",
				SessionURL:  ts.AuxApp.SessionURL,
				AccountURL:  ts.AuxApp.AccountURL,
				ServicesURL: ts.AuxApp.ServicesURL,
			},
		}
		ts.Setup(config)
		defer ts.Teardown()

		ts.CreateTestUser(t, ts.App, ts.Server, TEST_USERNAME)
		ts.CreateTestUser(t, ts.App, ts.Server, SERVICES_EXISTING_USERNAME)
		ts.CreateTestUser(t, ts.AuxApp, ts.AuxServer, TEST_USERNAME)
		ts.CreateTestUser(t, ts.AuxApp, ts.AuxServer, TEST_OTHER_USERNAME)

		// Set the red skin on the aux TEST_USERNAME user
		var user User
		assert.Nil(t, ts.AuxApp.DB.First(&user, "username = ?", TEST_USERNAME).Error)
		player := user.Players[0]
		assert.Nil(t, ts.AuxApp.SetSkinAndSave(&player, bytes.NewReader(RED_SKIN)))

		t.Run("Test GET /player/attributes", ts.testServicesPlayerAttributes)
		t.Run("Test POST /player/certificates", ts.testServicesPlayerCertificates)
		t.Run("Test PUT /minecraft/profile/name/:playerName", ts.testServicesChangeName)
		t.Run("Test DELETE /minecraft/profile/skins/active", ts.testServicesResetSkin)
		t.Run("Test DELETE /minecraft/profile/capes/active", ts.testServicesHideCape)
		t.Run("Test GET /minecraft/profile", ts.testServicesProfileInformation)
		t.Run("Test POST /minecraft/profile/skins", ts.testServicesUploadSkin)
		t.Run("Test GET /minecraft/profile/namechange", ts.testServicesNameChange)
		t.Run("Test GET /minecraft/profile/name/:playerName/available", ts.testServicesNameAvailability)
		t.Run("Test GET /privacy/blocklist", ts.testServicesPrivacyBlocklist)
		t.Run("Test GET /rollout/v1/msamigration", ts.testServicesMSAMigration)
		t.Run("Test POST /publickey", ts.testServicesPublicKeys)
		t.Run("Test POST /minecraft/profile/lookup/bulk/byname", ts.makeTestAccountPlayerNamesToIDs("/minecraft/profile/lookup/bulk/byname"))
		t.Run("Test GET /minecraft/profile/lookup/:id", ts.testServicesIDToPlayerName)
	}
	{
		ts := &TestSuite{}

		config := testConfig()
		config.AllowSkins = false
		ts.Setup(config)
		defer ts.Teardown()

		ts.CreateTestUser(t, ts.App, ts.Server, TEST_USERNAME)

		t.Run("Test POST /minecraft/profile/skins, skins not allowed", ts.testServicesUploadSkinSkinsNotAllowed)
	}
}

func (ts *TestSuite) testServicesProfileInformation(t *testing.T) {
	accessToken := ts.authenticate(t, TEST_USERNAME, TEST_PASSWORD).AccessToken

	var player Player
	assert.Nil(t, ts.App.DB.First(&player, "name = ?", TEST_USERNAME).Error)
	{
		rec := ts.Get(t, ts.Server, "/minecraft/profile", nil, &accessToken)
		assert.Equal(t, http.StatusOK, rec.Code)

		var response ServicesProfile
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))

		// Skin should not be forwarded from the AuxServer since ForwardSkins is
		// false
		assert.Equal(t, Unwrap(UUIDToID(player.UUID)), response.ID)
		assert.Equal(t, player.Name, response.Name)
		assert.Equal(t, []ServicesProfileSkin{}, response.Skins)
	}
	{
		// Now, set the skin on the user
		assert.Nil(t, ts.App.SetSkinAndSave(&player, bytes.NewReader(RED_SKIN)))

		// And try again
		rec := ts.Get(t, ts.Server, "/minecraft/profile", nil, &accessToken)
		assert.Equal(t, http.StatusOK, rec.Code)

		var response ServicesProfile
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))

		// The response should have the new skin
		skin := response.Skins[0]
		assert.Equal(t, player.UUID, skin.ID)
		assert.Equal(t, "ACTIVE", skin.State)
		assert.Equal(t, Unwrap(ts.App.SkinURL(*UnmakeNullString(&player.SkinHash))), skin.URL)
		assert.Equal(t, player.SkinModel, strings.ToLower(skin.Variant))

		// Reset the user's skin
		assert.Nil(t, ts.App.SetSkinAndSave(&player, nil))
	}
}

func (ts *TestSuite) testServicesPlayerAttributes(t *testing.T) {
	accessToken := ts.authenticate(t, TEST_USERNAME, TEST_PASSWORD).AccessToken

	{
		rec := ts.Get(t, ts.Server, "/player/attributes", nil, &accessToken)
		assert.Equal(t, http.StatusOK, rec.Code)

		var response playerAttributesResponse
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))

		assert.True(t, response.Privileges.OnlineChat.Enabled)
		assert.True(t, response.Privileges.MultiplayerServer.Enabled)
	}

	{
		// Should fail if we send an invalid access token
		rec := ts.Get(t, ts.Server, "/player/attributes", nil, Ptr("invalid"))
		assert.Equal(t, http.StatusUnauthorized, rec.Code)

		var response YggdrasilErrorResponse
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))
	}
}

func (ts *TestSuite) testServicesPlayerCertificates(t *testing.T) {
	accessToken := ts.authenticate(t, TEST_USERNAME, TEST_PASSWORD).AccessToken

	{
		// Writing this test would be just an exercise in reversing a very
		// linear bit of code... for now we'll just check that the expiry time
		// is correct.
		rec := ts.PostForm(t, ts.Server, "/player/certificates", url.Values{}, nil, &accessToken)
		assert.Equal(t, http.StatusOK, rec.Code)

		var response playerCertificatesResponse
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))

		assert.Equal(t, response.ExpiresAt, DISTANT_FUTURE.Format(time.RFC3339Nano))
	}
	{
		// Should fail if we send an invalid access token
		rec := ts.PostForm(t, ts.Server, "/player/certificates", url.Values{}, nil, Ptr("invalid"))
		assert.Equal(t, http.StatusUnauthorized, rec.Code)

		var response YggdrasilErrorResponse
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))
	}
}

func (ts *TestSuite) testServicesUploadSkin(t *testing.T) {
	accessToken := ts.authenticate(t, TEST_USERNAME, TEST_PASSWORD).AccessToken

	{
		// Successful update
		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)

		assert.Nil(t, writer.WriteField("variant", "slim"))
		skinFileField, err := writer.CreateFormFile("file", "redSkin.png")
		assert.Nil(t, err)
		_, err = skinFileField.Write(RED_SKIN)
		assert.Nil(t, err)

		rec := ts.PostMultipart(t, ts.Server, "/minecraft/profile/skins", body, writer, nil, &accessToken)
		assert.Equal(t, http.StatusOK, rec.Code)
	}
	{
		// Should fail if we submit an empty skin
		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)

		assert.Nil(t, writer.WriteField("variant", "slim"))
		_, err := writer.CreateFormFile("file", "redSkin.png")
		assert.Nil(t, err)

		rec := ts.PostMultipart(t, ts.Server, "/minecraft/profile/skins", body, writer, nil, &accessToken)
		assert.Equal(t, http.StatusBadRequest, rec.Code)

		var response YggdrasilErrorResponse
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))
		assert.Equal(t, "Could not read image data.", *response.ErrorMessage)
	}
	{
		// Should fail if we omit the skin
		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)

		assert.Nil(t, writer.WriteField("variant", "slim"))

		rec := ts.PostMultipart(t, ts.Server, "/minecraft/profile/skins", body, writer, nil, &accessToken)
		assert.Equal(t, http.StatusBadRequest, rec.Code)

		var response YggdrasilErrorResponse
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))
		assert.Equal(t, "content is marked non-null but is null", *response.ErrorMessage)
	}
	{
		// Should fail if we send an invalid skin
		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)

		assert.Nil(t, writer.WriteField("variant", "slim"))
		skinFileField, err := writer.CreateFormFile("file", "invalidSkin.png")
		assert.Nil(t, err)
		_, err = skinFileField.Write(INVALID_SKIN)
		assert.Nil(t, err)

		rec := ts.PostMultipart(t, ts.Server, "/minecraft/profile/skins", body, writer, nil, &accessToken)
		assert.Equal(t, http.StatusBadRequest, rec.Code)

		var response YggdrasilErrorResponse
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))
		assert.Equal(t, "Could not read image data.", *response.ErrorMessage)
	}
}

func (ts *TestSuite) testServicesUploadSkinSkinsNotAllowed(t *testing.T) {
	accessToken := ts.authenticate(t, TEST_USERNAME, TEST_PASSWORD).AccessToken

	// Should fail if skins are not allowed
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	assert.Nil(t, writer.WriteField("variant", "slim"))
	skinFileField, err := writer.CreateFormFile("file", "redSkin.png")
	assert.Nil(t, err)
	_, err = skinFileField.Write(RED_SKIN)
	assert.Nil(t, err)

	rec := ts.PostMultipart(t, ts.Server, "/minecraft/profile/skins", body, writer, nil, &accessToken)
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	var response YggdrasilErrorResponse
	assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))
	assert.Equal(t, "Changing your skin is not allowed.", *response.ErrorMessage)
}

func (ts *TestSuite) testServicesResetSkin(t *testing.T) {
	accessToken := ts.authenticate(t, TEST_USERNAME, TEST_PASSWORD).AccessToken

	var player Player
	assert.Nil(t, ts.App.DB.First(&player, "name = ?", TEST_USERNAME).Error)
	{
		// Successful reset skin
		// Set a skin on the user
		assert.Nil(t, ts.App.SetSkinAndSave(&player, bytes.NewReader(RED_SKIN)))

		req := httptest.NewRequest(http.MethodDelete, "/minecraft/profile/skins/active", nil)
		req.Header.Add("Authorization", "Bearer "+accessToken)
		rec := httptest.NewRecorder()
		ts.Server.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)

		assert.Nil(t, ts.App.DB.First(&player, "name = ?", TEST_USERNAME).Error)
		assert.Nil(t, UnmakeNullString(&player.SkinHash))
	}
	{
		// Should fail if we send an invalid access token

		req := httptest.NewRequest(http.MethodDelete, "/minecraft/profile/skins/active", nil)
		req.Header.Add("Authorization", "Bearer "+"invalid")
		rec := httptest.NewRecorder()
		ts.Server.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	}
}

func (ts *TestSuite) testServicesHideCape(t *testing.T) {
	accessToken := ts.authenticate(t, TEST_USERNAME, TEST_PASSWORD).AccessToken

	var player Player
	assert.Nil(t, ts.App.DB.First(&player, "name = ?", TEST_USERNAME).Error)
	{
		// Successful reset cape
		// Set a cape on the user
		assert.Nil(t, ts.App.SetCapeAndSave(&player, bytes.NewReader(RED_CAPE)))

		req := httptest.NewRequest(http.MethodDelete, "/minecraft/profile/capes/active", nil)
		req.Header.Add("Authorization", "Bearer "+accessToken)
		rec := httptest.NewRecorder()
		ts.Server.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)

		// assert.Nil(t, ts.App.DB.First(&user, "username = ?", TEST_USERNAME).Error)
		// assert.Nil(t, UnmakeNullString(&user.CapeHash))
	}
	{
		// Should fail if we send an invalid access token

		req := httptest.NewRequest(http.MethodDelete, "/minecraft/profile/capes/active", nil)
		req.Header.Add("Authorization", "Bearer "+"invalid")
		rec := httptest.NewRecorder()
		ts.Server.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	}
}

func (ts *TestSuite) testServicesChangeName(t *testing.T) {
	accessToken := ts.authenticate(t, TEST_USERNAME, TEST_PASSWORD).AccessToken

	var player Player
	assert.Nil(t, ts.App.DB.First(&player, "name = ?", TEST_USERNAME).Error)
	{
		// Successful name change
		newName := "NewName"
		req := httptest.NewRequest(http.MethodPut, "/minecraft/profile/name/"+newName, nil)
		req.Header.Add("Authorization", "Bearer "+accessToken)
		rec := httptest.NewRecorder()
		ts.Server.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)

		var response ServicesProfile
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))

		assert.Equal(t, Unwrap(UUIDToID(player.UUID)), response.ID)
		assert.Equal(t, newName, response.Name)

		// New name should be in the database
		assert.Nil(t, ts.App.DB.First(&player, "uuid = ?", player.UUID).Error)
		assert.Equal(t, newName, player.Name)

		// Change it back
		player.Name = TEST_USERNAME
		assert.Nil(t, ts.App.DB.Save(&player).Error)
	}
	{
		// Invalid name should fail
		newName := "AReallyLongAndThusInvalidName"
		req := httptest.NewRequest(http.MethodPut, "/minecraft/profile/name/"+newName, nil)
		req.Header.Add("Authorization", "Bearer "+accessToken)
		rec := httptest.NewRecorder()
		ts.Server.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)

		var response changeNameErrorResponse
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))

		validateNameError := ts.App.ValidatePlayerName(newName)
		assert.Equal(t, validateNameError.Error(), response.ErrorMessage)

		// Database should not be changed
		assert.Nil(t, ts.App.DB.First(&player, "uuid = ?", player.UUID).Error)
		assert.Equal(t, TEST_USERNAME, player.Name)
	}
	{
		// Existing name should fail
		newName := SERVICES_EXISTING_USERNAME
		req := httptest.NewRequest(http.MethodPut, "/minecraft/profile/name/"+newName, nil)
		req.Header.Add("Authorization", "Bearer "+accessToken)
		rec := httptest.NewRecorder()
		ts.Server.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusForbidden, rec.Code)

		var response changeNameErrorResponse
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))

		assert.Equal(t, "That player name is taken.", response.ErrorMessage)
		assert.Equal(t, "DUPLICATE", response.Details.Status)

		// Database should not be changed
		assert.Nil(t, ts.App.DB.First(&player, "uuid = ?", player.UUID).Error)
		assert.Equal(t, TEST_USERNAME, player.Name)
	}
	{
		// Should fail if we send an invalid access token
		newName := "NewName"
		req := httptest.NewRequest(http.MethodPut, "/minecraft/profile/name/"+newName, nil)
		req.Header.Add("Authorization", "Bearer "+"invalid")
		rec := httptest.NewRecorder()
		ts.Server.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	}
}

func (ts *TestSuite) testServicesNameChange(t *testing.T) {
	accessToken := ts.authenticate(t, TEST_USERNAME, TEST_PASSWORD).AccessToken

	rec := ts.Get(t, ts.Server, "/minecraft/profile/namechange", nil, &accessToken)
	assert.Equal(t, http.StatusOK, rec.Code)

	var response nameChangeResponse
	assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))
}

func (ts *TestSuite) testServicesNameAvailability(t *testing.T) {
	accessToken := ts.authenticate(t, TEST_USERNAME, TEST_PASSWORD).AccessToken
	{
		// Available name
		playerName := "NewName"

		rec := ts.Get(t, ts.Server, "/minecraft/profile/name/"+playerName+"/available", nil, &accessToken)
		assert.Equal(t, http.StatusOK, rec.Code)

		var response nameAvailabilityResponse
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))

		assert.Equal(t, "AVAILABLE", response.Status)
	}
	{
		// Invalid player name should fail
		playerName := "AReallyLongAndThusInvalidPlayerName"

		rec := ts.Get(t, ts.Server, "/minecraft/profile/name/"+playerName+"/available", nil, &accessToken)
		assert.Equal(t, http.StatusBadRequest, rec.Code)

		var response YggdrasilErrorResponse
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))

		assert.Equal(t, "CONSTRAINT_VIOLATION", *response.Error)
	}
	{
		// Taken player name
		playerName := SERVICES_EXISTING_USERNAME

		rec := ts.Get(t, ts.Server, "/minecraft/profile/name/"+playerName+"/available", nil, &accessToken)
		assert.Equal(t, http.StatusOK, rec.Code)

		var response nameAvailabilityResponse
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))

		assert.Equal(t, "DUPLICATE", response.Status)
	}
}

func (ts *TestSuite) testServicesPrivacyBlocklist(t *testing.T) {
	accessToken := ts.authenticate(t, TEST_USERNAME, TEST_PASSWORD).AccessToken

	rec := ts.Get(t, ts.Server, "/privacy/blocklist", nil, &accessToken)
	assert.Equal(t, http.StatusOK, rec.Code)

	var response blocklistResponse
	assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))

	assert.Equal(t, 0, len(response.BlockedProfiles))
}

func (ts *TestSuite) testServicesMSAMigration(t *testing.T) {
	accessToken := ts.authenticate(t, TEST_USERNAME, TEST_PASSWORD).AccessToken

	rec := ts.Get(t, ts.Server, "/rollout/v1/msamigration", nil, &accessToken)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func validateSerializedKey(t *testing.T, serializedKey string) {
	pubKeyBytes, err := base64.StdEncoding.DecodeString(serializedKey)
	assert.Nil(t, err)

	_, err = x509.ParsePKIXPublicKey(pubKeyBytes)
	assert.Nil(t, err)
}

func (ts *TestSuite) testServicesPublicKeys(t *testing.T) {
	rec := ts.Get(t, ts.Server, "/publickeys", nil, nil)
	assert.Equal(t, http.StatusOK, rec.Code)

	var response PublicKeysResponse
	assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))

	for _, key := range response.PlayerCertificateKeys {
		validateSerializedKey(t, key.PublicKey)
	}
	for _, key := range response.ProfilePropertyKeys {
		validateSerializedKey(t, key.PublicKey)
	}
}

func (ts *TestSuite) testServicesIDToPlayerName(t *testing.T) {
	{
		// Non-fallback
		var player Player
		assert.Nil(t, ts.App.DB.First(&player, "name = ?", TEST_PLAYER_NAME).Error)

		rec := ts.Get(t, ts.Server, "/minecraft/profile/lookup/"+player.UUID, nil, nil)
		assert.Equal(t, http.StatusOK, rec.Code)
		var response PlayerNameToIDResponse
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))

		assert.Equal(t, response.Name, player.Name)
		assert.Equal(t, response.ID, Unwrap(UUIDToID(player.UUID)))
	}
	{
		// Fallback
		var player Player
		assert.Nil(t, ts.AuxApp.DB.First(&player, "name = ?", TEST_OTHER_PLAYER_NAME).Error)

		rec := ts.Get(t, ts.Server, "/minecraft/profile/lookup/"+player.UUID, nil, nil)
		assert.Equal(t, http.StatusOK, rec.Code)
		var response PlayerNameToIDResponse
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))

		assert.Equal(t, response.Name, player.Name)
		assert.Equal(t, response.ID, Unwrap(UUIDToID(player.UUID)))
	}
}

func (ts *TestSuite) makeTestAccountPlayerNamesToIDs(url string) func(t *testing.T) {
	return func(t *testing.T) {
		payload := []string{TEST_USERNAME, "nonexistent"}
		body, err := json.Marshal(payload)
		assert.Nil(t, err)

		req := httptest.NewRequest(http.MethodPost, url, bytes.NewBuffer(body))
		rec := httptest.NewRecorder()
		ts.Server.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		var response []PlayerNameToIDResponse
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))

		// Get the real UUID
		var player Player
		result := ts.App.DB.First(&player, "name = ?", TEST_USERNAME)
		assert.Nil(t, result.Error)
		id, err := UUIDToID(player.UUID)
		assert.Nil(t, err)

		// There should only be one user, the nonexistent user should not be present
		assert.Equal(t, []PlayerNameToIDResponse{{Name: TEST_USERNAME, ID: id}}, response)
	}
}
