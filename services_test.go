package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"net/http"
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
		redSkin, err := base64.StdEncoding.DecodeString(RED_SKIN_BASE64_STRING)
		assert.Nil(t, err)
		assert.Nil(t, SetSkinAndSave(ts.AuxApp, &user, bytes.NewReader(redSkin)))

		t.Run("Test /player/attributes", ts.testPlayerAttributes)
		t.Run("Test /minecraft/profile", ts.testServicesProfileInformation)
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
		redSkin, err := base64.StdEncoding.DecodeString(RED_SKIN_BASE64_STRING)
		assert.Nil(t, err)
		assert.Nil(t, SetSkinAndSave(ts.App, &user, bytes.NewReader(redSkin)))

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
		assert.Equal(t, SkinModelToVariant(user.SkinModel), skin.Variant)

		// Reset the user's skin
		assert.Nil(t, SetSkinAndSave(ts.App, &user, nil))
	}
}

func (ts *TestSuite) testPlayerAttributes(t *testing.T) {
	accessToken := ts.authenticate(t, TEST_USERNAME, TEST_PASSWORD).AccessToken

	rec := ts.Get(ts.Server, "/player/attributes", nil, &accessToken)
	assert.Equal(t, http.StatusOK, rec.Code)

	var response playerAttributesResponse
	assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))

	assert.True(t, response.Privileges.OnlineChat.Enabled)
	assert.True(t, response.Privileges.MultiplayerServer.Enabled)
}
