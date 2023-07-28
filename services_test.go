package main

import (
	"bytes"
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"mime/multipart"
	"net/http"
	"strings"
	"testing"
)

func TestServices(t *testing.T) {
	{
		ts := &TestSuite{}

		auxConfig := testConfig()
		ts.SetupAux(auxConfig)

		config := testConfig()
		config.ForwardSkins = false
		config.FallbackAPIServers = []FallbackAPIServer{
			{
				Nickname:    "Aux",
				SessionURL:  ts.AuxApp.SessionURL,
				AccountURL:  ts.AuxApp.AccountURL,
				ServicesURL: ts.AuxApp.ServicesURL,
			},
		}
		ts.Setup(config)
		defer ts.Teardown()

		ts.CreateTestUser(ts.Server, TEST_USERNAME)
		ts.CreateTestUser(ts.AuxServer, TEST_USERNAME)

		// Set the red skin on the aux user
		var user User
		assert.Nil(t, ts.AuxApp.DB.First(&user, "username = ?", TEST_USERNAME).Error)
		assert.Nil(t, SetSkinAndSave(ts.AuxApp, &user, bytes.NewReader(RED_SKIN)))

		t.Run("Test /player/attributes", ts.testPlayerAttributes)
		t.Run("Test /minecraft/profile", ts.testServicesProfileInformation)
		t.Run("Test POST /minecraft/profile/skins", ts.testServicesUploadSkin)
	}
}

func (ts *TestSuite) testServicesProfileInformation(t *testing.T) {
	accessToken := ts.authenticate(t, TEST_USERNAME, TEST_PASSWORD).AccessToken

	var user User
	assert.Nil(t, ts.App.DB.First(&user, "username = ?", TEST_USERNAME).Error)
	{
		rec := ts.Get(ts.Server, "/minecraft/profile", nil, &accessToken)
		assert.Equal(t, http.StatusOK, rec.Code)

		var response ServicesProfile
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))

		// Skin should not be forwarded from the AuxServer since ForwardSkins is
		// false
		assert.Equal(t, Unwrap(UUIDToID(user.UUID)), response.ID)
		assert.Equal(t, user.PlayerName, response.Name)
		assert.Equal(t, []ServicesProfileSkin{}, response.Skins)
	}
	{
		// Now, set the skin on the user
		assert.Nil(t, SetSkinAndSave(ts.App, &user, bytes.NewReader(RED_SKIN)))

		// And try again
		rec := ts.Get(ts.Server, "/minecraft/profile", nil, &accessToken)
		assert.Equal(t, http.StatusOK, rec.Code)

		var response ServicesProfile
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))

		// The response should have the new skin
		skin := response.Skins[0]
		assert.Equal(t, user.UUID, skin.ID)
		assert.Equal(t, "ACTIVE", skin.State)
		assert.Equal(t, SkinURL(ts.App, *UnmakeNullString(&user.SkinHash)), skin.URL)
		assert.Equal(t, user.SkinModel, strings.ToLower(skin.Variant))

		// Reset the user's skin
		assert.Nil(t, SetSkinAndSave(ts.App, &user, nil))
	}
}

func (ts *TestSuite) testPlayerAttributes(t *testing.T) {
	accessToken := ts.authenticate(t, TEST_USERNAME, TEST_PASSWORD).AccessToken

	{
		rec := ts.Get(ts.Server, "/player/attributes", nil, &accessToken)
		assert.Equal(t, http.StatusOK, rec.Code)

		var response playerAttributesResponse
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))

		assert.True(t, response.Privileges.OnlineChat.Enabled)
		assert.True(t, response.Privileges.MultiplayerServer.Enabled)
	}

	{
		// Should fail if we send an invalid access token
		rec := ts.Get(ts.Server, "/player/attributes", nil, Ptr("invalid"))
		assert.Equal(t, http.StatusUnauthorized, rec.Code)

		var response ErrorResponse
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))
	}
}

func (ts *TestSuite) testServicesUploadSkin(t *testing.T) {
	accessToken := ts.authenticate(t, TEST_USERNAME, TEST_PASSWORD).AccessToken

	{
		// Successful update
		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)

		writer.WriteField("variant", "slim")
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

		writer.WriteField("variant", "slim")
		_, err := writer.CreateFormFile("file", "redSkin.png")
		assert.Nil(t, err)

		rec := ts.PostMultipart(t, ts.Server, "/minecraft/profile/skins", body, writer, nil, &accessToken)
		assert.Equal(t, http.StatusBadRequest, rec.Code)

		var response ErrorResponse
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))
		assert.Equal(t, "Could not read image data.", *response.ErrorMessage)
	}
	{
		// Should fail if we omit the skin
		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)

		writer.WriteField("variant", "slim")

		rec := ts.PostMultipart(t, ts.Server, "/minecraft/profile/skins", body, writer, nil, &accessToken)
		assert.Equal(t, http.StatusBadRequest, rec.Code)

		var response ErrorResponse
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))
		assert.Equal(t, "content is marked non-null but is null", *response.ErrorMessage)
	}
	{
		// Should fail if send an invalid skin
		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)

		writer.WriteField("variant", "slim")
		skinFileField, err := writer.CreateFormFile("file", "invalidSkin.png")
		assert.Nil(t, err)
		_, err = skinFileField.Write(INVALID_SKIN)
		assert.Nil(t, err)

		rec := ts.PostMultipart(t, ts.Server, "/minecraft/profile/skins", body, writer, nil, &accessToken)
		assert.Equal(t, http.StatusBadRequest, rec.Code)

		var response ErrorResponse
		assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))
		assert.Equal(t, "Could not read image data.", *response.ErrorMessage)
	}
}
