package main

import (
	"crypto/rsa"
	"net/http"
	"testing"

	"github.com/samber/mo"
	"github.com/stretchr/testify/assert"
)

// fallbackKeyContains checks whether a set of rsa.PublicKey contains a key
// equal to target, using rsa.PublicKey.Equal for value comparison (since
// mapset uses == which compares *big.Int pointers, not values).
func fallbackKeyContains(set interface{ ToSlice() []rsa.PublicKey }, target rsa.PublicKey) bool {
	for _, k := range set.ToSlice() {
		if k.Equal(&target) {
			return true
		}
	}
	return false
}

// TestFallbackAPIServerLegacy verifies that a FallbackAPIServer configured
// with legacy SessionURL/AccountURL/ServicesURL/SkinDomains correctly derives
// its endpoint URLs, public keys, skin domains, and texture valid URIs.
func TestFallbackAPIServerLegacy(t *testing.T) {
	t.Parallel()
	ts := &TestSuite{}

	auxConfig := testConfig()
	ts.SetupAux(auxConfig)

	const legacySkinDomain = "legacy.example.com"
	config := testConfig()
	fallback := ts.ToFallbackAPIServerLegacy(ts.AuxApp, "Aux")
	legacy := fallback.URLs.MustArg3()
	legacy.SkinDomains = []string{legacySkinDomain}
	fallback.URLs = mo.NewEither3Arg3[
		fallbackAPIServerDiscoveryConfig,
		fallbackAPIServerAuthlibInjectorConfig,
		fallbackAPIServerLegacyConfig,
	](legacy)
	config.FallbackAPIServers = []FallbackAPIServerConfig{fallback}
	ts.Setup(config)
	defer ts.Teardown()

	ts.CreateTestUser(t, ts.AuxApp, ts.AuxServer, TEST_USERNAME)

	fb, ok := ts.App.FallbackAPIServers["Aux"]
	assert.True(t, ok, "FallbackAPIServer 'Aux' should be registered")

	assert.Equal(t, ts.AuxApp.SessionURL+"/session/minecraft/profile", fb.SessionGetProfileByIDURL)
	assert.Equal(t, ts.AuxApp.SessionURL+"/session/minecraft/hasJoined", fb.SessionVerifyURL)
	assert.Equal(t, ts.AuxApp.AccountURL+"/profiles/minecraft", fb.ProfilesGetManyByNameURL)

	// The aux's public key should be present in all three key sets, fetched
	// from the aux's /publickeys endpoint.
	assert.Equal(t, 1, fb.ProfilePropertyKeys.Cardinality())
	assert.Equal(t, 1, fb.PlayerCertificateKeys.Cardinality())
	assert.Equal(t, 1, fb.AuthenticationKeys.Cardinality())
	assert.True(t, fallbackKeyContains(fb.ProfilePropertyKeys, ts.AuxApp.PrivateKey.PublicKey))
	assert.True(t, fallbackKeyContains(fb.PlayerCertificateKeys, ts.AuxApp.PrivateKey.PublicKey))
	assert.True(t, fallbackKeyContains(fb.AuthenticationKeys, ts.AuxApp.PrivateKey.PublicKey))

	// Skin domains and texture valid URIs derived from the configured
	// SkinDomains list.
	assert.True(t, fb.SkinDomains.Contains(legacySkinDomain))
	assert.True(t, fb.GetTextureValidURIs.Contains("https://"+legacySkinDomain+"/"))
	assert.True(t, fb.GetTextureValidURIs.Contains("http://"+legacySkinDomain+"/"))

	// Look up an aux player by UUID through the main server.
	{
		var player Player
		assert.Nil(t, ts.AuxApp.DB.First(&player, "name = ?", TEST_USERNAME).Error)

		rec := ts.Get(t, ts.Server, "/minecraft/profile/lookup/"+player.UUID, nil, nil)
		assert.Equal(t, http.StatusOK, rec.Code)
	}
}

// TestFallbackAPIServerDiscovery verifies that a FallbackAPIServer configured
// with a DiscoveryMinecraftClientURL correctly derives its endpoint URLs and
// public keys from the aux server's discovery document.
func TestFallbackAPIServerDiscovery(t *testing.T) {
	t.Parallel()
	ts := &TestSuite{}

	auxConfig := testConfig()
	ts.SetupAux(auxConfig)

	config := testConfig()
	config.FallbackAPIServers = []FallbackAPIServerConfig{
		ts.ToFallbackAPIServerDiscovery(ts.AuxApp, "Aux"),
	}
	ts.Setup(config)
	defer ts.Teardown()

	ts.CreateTestUser(t, ts.AuxApp, ts.AuxServer, TEST_USERNAME)

	fb, ok := ts.App.FallbackAPIServers["Aux"]
	assert.True(t, ok, "FallbackAPIServer 'Aux' should be registered")

	// URLs derived from the aux's discovery document.
	assert.Equal(t, ts.AuxApp.SessionURL+"/session/minecraft/profile", fb.SessionGetProfileByIDURL)
	assert.Equal(t, ts.AuxApp.SessionURL+"/session/minecraft/hasJoined", fb.SessionVerifyURL)
	assert.Equal(t, ts.AuxApp.AccountURL+"/profiles/minecraft", fb.ProfilesGetManyByNameURL)

	// The aux's public key should be present in all three key sets.
	assert.Equal(t, 1, fb.ProfilePropertyKeys.Cardinality())
	assert.Equal(t, 1, fb.PlayerCertificateKeys.Cardinality())
	assert.Equal(t, 1, fb.AuthenticationKeys.Cardinality())
	assert.True(t, fallbackKeyContains(fb.ProfilePropertyKeys, ts.AuxApp.PrivateKey.PublicKey))
	assert.True(t, fallbackKeyContains(fb.PlayerCertificateKeys, ts.AuxApp.PrivateKey.PublicKey))
	assert.True(t, fallbackKeyContains(fb.AuthenticationKeys, ts.AuxApp.PrivateKey.PublicKey))

	// Look up an aux player by UUID through the main server.
	{
		var player Player
		assert.Nil(t, ts.AuxApp.DB.First(&player, "name = ?", TEST_USERNAME).Error)

		rec := ts.Get(t, ts.Server, "/minecraft/profile/lookup/"+player.UUID, nil, nil)
		assert.Equal(t, http.StatusOK, rec.Code)
	}
}

// TestFallbackAPIServerAuthlibInjector verifies that a FallbackAPIServer
// configured with an AuthlibInjectorURL correctly derives its endpoint URLs,
// public keys, skin domains, and texture valid URIs from the aux server's
// authlib-injector root endpoint.
func TestFallbackAPIServerAuthlibInjector(t *testing.T) {
	t.Parallel()
	ts := &TestSuite{}

	auxConfig := testConfig()
	ts.SetupAux(auxConfig)

	config := testConfig()
	config.FallbackAPIServers = []FallbackAPIServerConfig{
		ts.ToFallbackAPIServerAuthlibInjector(ts.AuxApp, "Aux"),
	}
	ts.Setup(config)
	defer ts.Teardown()

	ts.CreateTestUser(t, ts.AuxApp, ts.AuxServer, TEST_USERNAME)

	fb, ok := ts.App.FallbackAPIServers["Aux"]
	assert.True(t, ok, "FallbackAPIServer 'Aux' should be registered")

	// URLs derived from the aux's authlib-injector location.
	assert.Equal(t, ts.AuxApp.AuthlibInjectorURL+"/sessionserver/session/minecraft/profile", fb.SessionGetProfileByIDURL)
	assert.Equal(t, ts.AuxApp.AuthlibInjectorURL+"/sessionserver/session/minecraft/hasJoined", fb.SessionVerifyURL)
	assert.Equal(t, ts.AuxApp.AuthlibInjectorURL+"/api/profiles/minecraft", fb.ProfilesGetManyByNameURL)

	// The aux's public key should be present in all three key sets (ALI form
	// populates all of them from the single SignaturePublickey).
	assert.Equal(t, 1, fb.ProfilePropertyKeys.Cardinality())
	assert.Equal(t, 1, fb.PlayerCertificateKeys.Cardinality())
	assert.Equal(t, 1, fb.AuthenticationKeys.Cardinality())
	assert.True(t, fallbackKeyContains(fb.ProfilePropertyKeys, ts.AuxApp.PrivateKey.PublicKey))
	assert.True(t, fallbackKeyContains(fb.PlayerCertificateKeys, ts.AuxApp.PrivateKey.PublicKey))
	assert.True(t, fallbackKeyContains(fb.AuthenticationKeys, ts.AuxApp.PrivateKey.PublicKey))

	// Skin domains and texture valid URIs derived from the aux's
	// authlib-injector response.
	assert.True(t, fb.SkinDomains.Contains(ts.AuxApp.Config.Domain))
	assert.True(t, fb.GetTextureValidURIs.Contains("https://"+ts.AuxApp.Config.Domain+"/"))
	assert.True(t, fb.GetTextureValidURIs.Contains("http://"+ts.AuxApp.Config.Domain+"/"))

	// Functional: look up an aux player by UUID through the main server.
	{
		var player Player
		assert.Nil(t, ts.AuxApp.DB.First(&player, "name = ?", TEST_USERNAME).Error)

		rec := ts.Get(t, ts.Server, "/minecraft/profile/lookup/"+player.UUID, nil, nil)
		assert.Equal(t, http.StatusOK, rec.Code)
	}
}
