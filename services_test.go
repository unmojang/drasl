package main

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"github.com/google/uuid"
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
		fallback := ts.ToFallbackAPIServerAuthlibInjector(ts.AuxApp, "Aux")
		fallback.ForwardSkins = false
		config.FallbackAPIServers = []FallbackAPIServerConfig{fallback}
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
		t.Run("Test POST /player/report", ts.testServicesPlayerReport)
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

func (ts *TestSuite) testServicesPlayerReport(t *testing.T) {
	accessToken := ts.authenticate(t, TEST_USERNAME, TEST_PASSWORD).AccessToken
	var target User
	assert.Nil(t, ts.App.DB.First(&target, "username = ?", SERVICES_EXISTING_USERNAME).Error)
	assert.NotEmpty(t, target.Players)
	targetPlayer := target.Players[0]
	targetID := Unwrap(UUIDToID(targetPlayer.UUID))

	usernameReportID := uuid.NewString()
	usernameReport := map[string]any{
		"version": 1, "id": strings.ReplaceAll(usernameReportID, "-", ""), "reportType": "USERNAME",
		"report": map[string]any{
			"reportedEntity":  map[string]any{"profileId": targetID},
			"opinionComments": "The current name is abusive.",
		},
	}
	rec := ts.PostJSON(t, ts.Server, "/player/report", usernameReport, nil, &accessToken)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
	assert.Empty(t, rec.Body.String())

	var stored Report
	assert.Nil(t, ts.App.DB.First(&stored, "id = ?", usernameReportID).Error)
	assert.Equal(t, ReportTypeUsername, stored.Type)
	assert.Equal(t, targetPlayer.Name, stored.CapturedName.String)
	assert.Equal(t, ReportStatusOpen, stored.Status)

	// Replaying the exact request is idempotent; changing it under the same ID is not.
	rec = ts.PostJSON(t, ts.Server, "/player/report", usernameReport, nil, &accessToken)
	assert.Equal(t, http.StatusOK, rec.Code)
	usernameReport["report"].(map[string]any)["opinionComments"] = "Different evidence."
	rec = ts.PostJSON(t, ts.Server, "/player/report", usernameReport, nil, &accessToken)
	assert.Equal(t, http.StatusConflict, rec.Code)

	invalidSkinReport := map[string]any{
		"version": 1, "id": strings.ReplaceAll(uuid.NewString(), "-", ""), "reportType": "SKIN",
		"report": map[string]any{
			"reportedEntity": map[string]any{"profileId": targetID},
			"reason":         "IMMINENT_HARM", "skinUrl": "https://example.invalid/skin.png",
		},
	}
	rec = ts.PostJSON(t, ts.Server, "/player/report", invalidSkinReport, nil, &accessToken)
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	assert.NoError(t, ts.App.SetSkinAndSave(&targetPlayer, bytes.NewReader(RED_SKIN)))
	assert.NoError(t, ts.App.SetCapeAndSave(&targetPlayer, bytes.NewReader(RED_CAPE)))
	reportedSkinURL := Unwrap(ts.App.SkinURL(RED_SKIN_HASH))
	skinReportID := uuid.NewString()
	skinReport := map[string]any{
		"version": 1, "id": strings.ReplaceAll(skinReportID, "-", ""), "reportType": "SKIN",
		"report": map[string]any{
			"reportedEntity": map[string]any{"profileId": targetID},
			"reason":         "HATE_SPEECH", "skinUrl": reportedSkinURL,
		},
	}
	rec = ts.PostJSON(t, ts.Server, "/player/report", skinReport, nil, &accessToken)
	assert.Equal(t, http.StatusOK, rec.Code)
	var storedSkin Report
	assert.NoError(t, ts.App.DB.First(&storedSkin, "id = ?", skinReportID).Error)
	assert.Equal(t, RED_SKIN_HASH, storedSkin.CapturedSkinHash.String)
	assert.Equal(t, RED_CAPE_HASH, storedSkin.CapturedCapeHash.String)
	assert.Equal(t, RED_SKIN, storedSkin.CapturedSkinData)
	assert.Equal(t, RED_CAPE, storedSkin.CapturedCapeData)

	// Review evidence remains the reported snapshot even after the profile changes.
	assert.NoError(t, ts.App.SetSkinAndSave(&targetPlayer, bytes.NewReader(BLUE_SKIN)))
	assert.NoError(t, ts.App.DB.First(&storedSkin, "id = ?", skinReportID).Error)
	assert.Equal(t, RED_SKIN_HASH, storedSkin.CapturedSkinHash.String)
	assert.Equal(t, RED_SKIN, storedSkin.CapturedSkinData)

	chatReportID := uuid.NewString()
	chatReport := map[string]any{
		"version": 1, "id": strings.ReplaceAll(chatReportID, "-", ""), "reportType": "CHAT",
		"report": map[string]any{
			"reportedEntity": map[string]any{"profileId": targetID}, "reason": "HATE_SPEECH",
			"evidence": map[string]any{"messages": []any{map[string]any{
				"index": 0, "profileId": targetID, "sessionId": strings.ReplaceAll(uuid.NewString(), "-", ""),
				"timestamp": time.Now().UTC().Format(time.RFC3339Nano), "salt": 1, "lastSeen": []string{},
				"message": "reported text", "signature": "", "messageReported": true,
			}}},
		},
	}
	rec = ts.PostJSON(t, ts.Server, "/player/report", chatReport, nil, &accessToken)
	assert.Equal(t, http.StatusOK, rec.Code)
	var storedChat Report
	assert.Nil(t, ts.App.DB.First(&storedChat, "id = ?", chatReportID).Error)
	assert.Equal(t, ReportAttestationUnattested, storedChat.Attestation)
	var evidence []ReportEvidenceMessage
	assert.Nil(t, json.Unmarshal(storedChat.EvidenceJSON, &evidence))
	if assert.Len(t, evidence, 1) {
		assert.Equal(t, reportMessageMissingSignature, evidence[0].Status)
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
		assert.Equal(t, ChatModeEnabled, response.ChatPreferences.TextCommunication)
		assert.Nil(t, response.BanStatus.BannedScopes.Multiplayer)
	}
	{
		var user User
		assert.Nil(t, ts.App.DB.First(&user, "username = ?", TEST_USERNAME).Error)
		reasonID := 21
		message := "Repeated harassment"
		expiresAt := time.Now().Add(time.Hour)
		ban, err := ts.App.CreateBan(BanTypeUser, user.UUID, &reasonID, &message, &expiresAt)
		assert.Nil(t, err)

		rec := ts.Get(t, ts.Server, "/player/attributes", nil, &accessToken)
		assert.Equal(t, http.StatusOK, rec.Code)
		var response playerAttributesResponse
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))
		assert.False(t, response.Privileges.OnlineChat.Enabled)
		assert.False(t, response.Privileges.MultiplayerServer.Enabled)
		assert.Equal(t, ChatModeDisabled, response.ChatPreferences.TextCommunication)
		assert.Equal(t, ban.ID, response.BanStatus.BannedScopes.Multiplayer.BanID)
		assert.Equal(t, "21", response.BanStatus.BannedScopes.Multiplayer.Reason)
		assert.Equal(t, message, *response.BanStatus.BannedScopes.Multiplayer.ReasonMessage)
		assert.NotNil(t, response.BanStatus.BannedScopes.Multiplayer.Expires)
		assert.Nil(t, ts.App.DB.Delete(&ban).Error)
	}
	{
		var user User
		assert.Nil(t, ts.App.DB.First(&user, "username = ?", TEST_USERNAME).Error)
		user.ChatMode = ChatModeDisabled
		assert.Nil(t, ts.App.DB.Save(&user).Error)

		rec := ts.PostForm(t, ts.Server, "/player/attributes", url.Values{}, nil, &accessToken)
		assert.Equal(t, http.StatusOK, rec.Code)
		var response playerAttributesResponse
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))
		assert.False(t, response.Privileges.OnlineChat.Enabled)
		assert.True(t, response.Privileges.MultiplayerServer.Enabled)
		assert.Equal(t, ChatModeDisabled, response.ChatPreferences.TextCommunication)

		user.ChatMode = ChatModeEnabled
		assert.Nil(t, ts.App.DB.Save(&user).Error)
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
		rec := ts.PostForm(t, ts.Server, "/player/certificates", url.Values{}, nil, &accessToken)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))

		var response playerCertificatesResponse
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))

		expiresAt := Unwrap(time.Parse(time.RFC3339Nano, response.ExpiresAt))
		refreshedAfter := Unwrap(time.Parse(time.RFC3339Nano, response.RefreshedAfter))
		assert.InDelta(t, float64(ts.Config.PlayerCertsLifetime), time.Until(expiresAt).Seconds(), 2)
		assert.InDelta(t, float64(ts.Config.PlayerCertsRefresh), time.Until(refreshedAfter).Seconds(), 2)

		var certificates []PlayerCertificate
		assert.Nil(t, ts.App.DB.Find(&certificates).Error)
		assert.Len(t, certificates, 1)
		assert.NotEmpty(t, certificates[0].PublicKeyDER)

		rec = ts.PostForm(t, ts.Server, "/player/certificates", url.Values{}, nil, &accessToken)
		assert.Equal(t, http.StatusOK, rec.Code)
		var cached playerCertificatesResponse
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&cached))
		assert.Equal(t, response, cached)
		assert.Nil(t, ts.App.DB.Find(&certificates).Error)
		assert.Len(t, certificates, 1)
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

		var resetSkinPlayer Player
		assert.Nil(t, ts.App.DB.First(&resetSkinPlayer, "name = ?", TEST_USERNAME).Error)
		assert.Nil(t, UnmakeNullString(&resetSkinPlayer.SkinHash))
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
		player.ForcedNameChangeBanID = MakeNullString(Ptr("name-ban"))
		player.UsingBannedSkinBanID = MakeNullString(Ptr("skin-ban"))
		assert.Nil(t, ts.App.DB.Save(&player).Error)

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
		var updatedPlayer Player
		assert.Nil(t, ts.App.DB.First(&updatedPlayer, "uuid = ?", player.UUID).Error)
		assert.Equal(t, newName, updatedPlayer.Name)
		assert.False(t, updatedPlayer.ForcedNameChangeBanID.Valid)
		assert.Equal(t, "skin-ban", updatedPlayer.UsingBannedSkinBanID.String)

		// Change it back
		updatedPlayer.Name = TEST_USERNAME
		assert.Nil(t, ts.App.DB.Save(&updatedPlayer).Error)
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
