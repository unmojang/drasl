package main

import (
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/url"
	"testing"
)

const FALLBACK_SKIN_DOMAIN_A = "a.example.com"
const FALLBACK_SKIN_DOMAIN_B = "b.example.com"

func TestAuthlibInjector(t *testing.T) {
	// Just check that AuthlibInjectorRoot works.
	// authlib-injector also expects a X-Authlib-Injector-API-Location header
	// on the authserver and sessionserver routes that it uses; those are
	// tested in auth_test.go and session_test.go.
	{
		ts := &TestSuite{}

		config := testConfig()
		ts.Setup(config)
		defer ts.Teardown()

		ts.CreateTestUser(ts.Server, TEST_USERNAME)

		t.Run("Test /authlib-injector", ts.testAuthlibInjectorRoot)
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
	assert.Equal(t, Unwrap(url.JoinPath(ts.App.FrontEndURL, "drasl/registration")), response.Meta.Links.Register)
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
