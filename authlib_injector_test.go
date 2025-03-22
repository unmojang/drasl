package main

import (
	"bytes"
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"mime/multipart"
	"net/http"
	"net/url"
	"testing"
)

const FALLBACK_SKIN_DOMAIN_A = "a.example.com"
const FALLBACK_SKIN_DOMAIN_B = "b.example.com"

func TestAuthlibInjector(t *testing.T) {
	t.Parallel()
	// authlib-injector also expects a X-Authlib-Injector-API-Location header
	// on the authserver and sessionserver routes that it uses; those are
	// tested in auth_test.go and session_test.go.
	{
		ts := &TestSuite{}

		config := testConfig()
		ts.Setup(config)
		defer ts.Teardown()

		ts.CreateTestUser(t, ts.App, ts.Server, TEST_USERNAME)

		t.Run("Test /authlib-injector", ts.testAuthlibInjectorRoot)
		t.Run("Test /authlib-injector/api/user/profile/:playerUUID/:textureType", ts.testAuthlibInjectorTextureUploadDelete)
	}
	{
		ts := &TestSuite{}

		auxConfig := testConfig()
		auxConfig.Domain = "anotherdomain.example.com"
		ts.SetupAux(auxConfig)

		config := testConfig()
		fallback := ts.ToFallbackAPIServer(ts.AuxApp, "Aux")
		fallback.SkinDomains = []string{FALLBACK_SKIN_DOMAIN_A, FALLBACK_SKIN_DOMAIN_B}
		config.FallbackAPIServers = []FallbackAPIServer{fallback}
		ts.Setup(config)
		defer ts.Teardown()

		t.Run("Test /authlib-injector, fallback API server", ts.testAuthlibInjectorRootFallback)
	}
}

func (ts *TestSuite) testAuthlibInjectorRoot(t *testing.T) {
	rec := ts.Get(t, ts.Server, "/authlib-injector", nil, nil)
	ts.CheckAuthlibInjectorHeader(t, ts.App, rec)
	assert.Equal(t, http.StatusOK, rec.Code)

	var response authlibInjectorResponse
	assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))

	// Just check the important stuff here
	assert.Equal(t, ts.App.FrontEndURL, response.Meta.Links.Homepage)
	assert.Equal(t, Unwrap(url.JoinPath(ts.App.FrontEndURL, "web/registration")), response.Meta.Links.Register)
	assert.Equal(t, []string{ts.App.Config.Domain}, response.SkinDomains)
}

func (ts *TestSuite) testAuthlibInjectorRootFallback(t *testing.T) {
	rec := ts.Get(t, ts.Server, "/authlib-injector", nil, nil)
	ts.CheckAuthlibInjectorHeader(t, ts.App, rec)
	assert.Equal(t, http.StatusOK, rec.Code)

	var response authlibInjectorResponse
	assert.Nil(t, json.NewDecoder(rec.Body).Decode(&response))

	assert.Equal(t, []string{ts.App.Config.Domain, FALLBACK_SKIN_DOMAIN_A, FALLBACK_SKIN_DOMAIN_B}, response.SkinDomains)
}

func (ts *TestSuite) testAuthlibInjectorTextureUploadDelete(t *testing.T) {
	accessToken := ts.authenticate(t, TEST_USERNAME, TEST_PASSWORD).AccessToken
	var player Player
	assert.Nil(t, ts.App.DB.First(&player, "name = ?", TEST_USERNAME).Error)
	assert.Nil(t, UnmakeNullString(&player.SkinHash))
	assert.Nil(t, UnmakeNullString(&player.CapeHash))
	assert.Equal(t, SkinModelClassic, player.SkinModel)

	playerID, err := UUIDToID(player.UUID)
	assert.Nil(t, err)
	{
		// Successful skin upload
		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)

		assert.Nil(t, writer.WriteField("model", ""))
		skinFileField, err := writer.CreateFormFile("file", "redSkin.png")
		assert.Nil(t, err)
		_, err = skinFileField.Write(RED_SKIN)
		assert.Nil(t, err)

		rec := ts.PutMultipart(t, ts.Server, "/authlib-injector/api/user/profile/"+playerID+"/skin", body, writer, nil, &accessToken)
		assert.Equal(t, http.StatusNoContent, rec.Code)

		assert.Nil(t, ts.App.DB.First(&player, "name = ?", TEST_USERNAME).Error)
		assert.Equal(t, RED_SKIN_HASH, *UnmakeNullString(&player.SkinHash))
		assert.Equal(t, SkinModelClassic, player.SkinModel)
	}
	{
		// Successful skin upload, slim model
		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)

		assert.Nil(t, writer.WriteField("model", "slim"))
		skinFileField, err := writer.CreateFormFile("file", "blueSkin.png")
		assert.Nil(t, err)
		_, err = skinFileField.Write(BLUE_SKIN)
		assert.Nil(t, err)

		rec := ts.PutMultipart(t, ts.Server, "/authlib-injector/api/user/profile/"+playerID+"/skin", body, writer, nil, &accessToken)
		assert.Equal(t, http.StatusNoContent, rec.Code)

		assert.Nil(t, ts.App.DB.First(&player, "name = ?", TEST_USERNAME).Error)
		assert.Equal(t, BLUE_SKIN_HASH, *UnmakeNullString(&player.SkinHash))
		assert.Equal(t, SkinModelSlim, player.SkinModel)
	}
	{
		// Successful cape upload
		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)

		skinFileField, err := writer.CreateFormFile("file", "redCape.png")
		assert.Nil(t, err)
		_, err = skinFileField.Write(RED_CAPE)
		assert.Nil(t, err)

		rec := ts.PutMultipart(t, ts.Server, "/authlib-injector/api/user/profile/"+playerID+"/cape", body, writer, nil, &accessToken)
		assert.Equal(t, http.StatusNoContent, rec.Code)

		assert.Nil(t, ts.App.DB.First(&player, "name = ?", TEST_USERNAME).Error)
		assert.Equal(t, RED_CAPE_HASH, *UnmakeNullString(&player.CapeHash))
	}
	{
		// Successful skin delete
		rec := ts.Delete(t, ts.Server, "/authlib-injector/api/user/profile/"+playerID+"/skin", nil, nil, &accessToken)
		assert.Equal(t, http.StatusNoContent, rec.Code)

		assert.Nil(t, ts.App.DB.First(&player, "name = ?", TEST_USERNAME).Error)
		assert.Nil(t, UnmakeNullString(&player.SkinHash))
	}
	{
		// Successful cape delete
		rec := ts.Delete(t, ts.Server, "/authlib-injector/api/user/profile/"+playerID+"/cape", nil, nil, &accessToken)
		assert.Equal(t, http.StatusNoContent, rec.Code)

		assert.Nil(t, ts.App.DB.First(&player, "name = ?", TEST_USERNAME).Error)
		assert.Nil(t, UnmakeNullString(&player.CapeHash))
	}
}
