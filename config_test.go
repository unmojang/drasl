package main

import (
	"github.com/BurntSushi/toml"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func configTestRawConfig(stateDirectory string) RawConfig {
	return RawConfig{
		BaseURL:        Ptr("https://drasl.example.com"),
		Domain:         Ptr("drasl.example.com"),
		RateLimit:      &rawRateLimitConfig{Enable: Ptr(false)},
		LogRequests:    Ptr(false),
		StateDirectory: Ptr(stateDirectory),
		DataDirectory:  Ptr("."),
	}
}

func TestConfig(t *testing.T) {
	t.Parallel()
	sd := Unwrap(os.MkdirTemp("", "tmp"))
	defer os.RemoveAll(sd)

	rawConfig := configTestRawConfig(sd)
	assert.Nil(t, UnwrapError(CleanConfig(&rawConfig)))

	rawConfig = configTestRawConfig(sd)
	rawConfig.BaseURL = Ptr("https://δρασλ.example.com/")
	rawConfig.Domain = Ptr("δρασλ.example.com")
	config, err := CleanConfig(&rawConfig)
	assert.Nil(t, err)
	assert.Equal(t, "https://xn--mxafwwl.example.com", config.BaseURL)
	assert.Equal(t, "xn--mxafwwl.example.com", config.Domain)

	rawConfig = configTestRawConfig(sd)
	rawConfig.BaseURL = Ptr("")
	assert.NotNil(t, UnwrapError(CleanConfig(&rawConfig)))

	rawConfig = configTestRawConfig(sd)
	rawConfig.BaseURL = Ptr(":an invalid URL")
	assert.NotNil(t, UnwrapError(CleanConfig(&rawConfig)))

	rawConfig = configTestRawConfig(sd)
	rawConfig.DefaultPreferredLanguage = Ptr("xx")
	assert.NotNil(t, UnwrapError(CleanConfig(&rawConfig)))

	rawConfig = configTestRawConfig(sd)
	rawConfig.Domain = Ptr("")
	assert.NotNil(t, UnwrapError(CleanConfig(&rawConfig)))

	rawConfig = configTestRawConfig(sd)
	rawConfig.InstanceName = Ptr("")
	assert.NotNil(t, UnwrapError(CleanConfig(&rawConfig)))

	rawConfig = configTestRawConfig(sd)
	rawConfig.ListenAddress = Ptr("")
	assert.NotNil(t, UnwrapError(CleanConfig(&rawConfig)))

	rawConfig = configTestRawConfig(sd)
	rawConfig.DefaultMaxPlayerCount = Ptr(Constants.MaxPlayerCountUseDefault)
	assert.NotNil(t, UnwrapError(CleanConfig(&rawConfig)))

	rawConfig = configTestRawConfig(sd)
	rawConfig.DefaultMaxPlayerCount = Ptr(Constants.MaxPlayerCountUnlimited)
	assert.Nil(t, UnwrapError(CleanConfig(&rawConfig)))

	// Missing state directory should be ignored
	rawConfig = configTestRawConfig(sd)
	rawConfig.StateDirectory = Ptr("/tmp/DraslInvalidStateDirectoryNothingHere")
	assert.Nil(t, UnwrapError(CleanConfig(&rawConfig)))

	rawConfig = configTestRawConfig(sd)
	rawConfig.FallbackAPIServers = []rawFallbackAPIServerConfig{
		{
			Nickname:    Ptr("Example"),
			SessionURL:  Ptr("https://δρασλ.example.com/"),
			AccountURL:  Ptr("https://drasl.example.com/"),
			ServicesURL: Ptr("https://drasl.example.com/"),
			SetSkinURL:  Ptr("https://drasl.example.com/editskin"),
		},
	}
	rawConfig.RegistrationUsernamePassword = &rawRegistrationUsernamePasswordConfig{
		NewPlayer: &rawNewPlayerConfig{Allow: Ptr(true)},
		ExistingPlayer: []rawExistingPlayerConfig{
			{FallbackAPIServerNickname: Ptr("Example"), RequireSkinVerification: Ptr(true)},
		},
	}
	config, err = CleanConfig(&rawConfig)
	assert.Nil(t, err)
	assert.Equal(t, "https://xn--mxafwwl.example.com", config.FallbackAPIServers[0].SessionURL)
	assert.Equal(t, "https://drasl.example.com", config.FallbackAPIServers[0].AccountURL)
	assert.Equal(t, "https://drasl.example.com/editskin", config.FallbackAPIServers[0].SetSkinURL)
	assert.True(t, config.RegistrationUsernamePassword.NewPlayer.Allow)
	assert.Equal(t, 1, len(config.RegistrationUsernamePassword.ExistingPlayer))
	assert.Equal(t, "Example", config.RegistrationUsernamePassword.ExistingPlayer[0].FallbackAPIServerNickname)
	assert.True(t, config.RegistrationUsernamePassword.ExistingPlayer[0].RequireSkinVerification)

	// ExistingPlayer with unknown FallbackAPIServerNickname should fail
	rawConfig = configTestRawConfig(sd)
	rawConfig.FallbackAPIServers = []rawFallbackAPIServerConfig{
		{Nickname: Ptr("Example"), SessionURL: Ptr("https://example.com"), AccountURL: Ptr("https://example.com"), ServicesURL: Ptr("https://example.com")},
	}
	rawConfig.RegistrationUsernamePassword = &rawRegistrationUsernamePasswordConfig{
		ExistingPlayer: []rawExistingPlayerConfig{
			{FallbackAPIServerNickname: Ptr("Nonexistent")},
		},
	}
	assert.NotNil(t, UnwrapError(CleanConfig(&rawConfig)))

	rawConfig = configTestRawConfig(sd)
	testFallbackAPIServer := rawFallbackAPIServerConfig{
		Nickname:    Ptr("Nickname"),
		SessionURL:  Ptr("https://δρασλ.example.com/"),
		AccountURL:  Ptr("https://δρασλ.example.com/"),
		ServicesURL: Ptr("https://δρασλ.example.com/"),
		SkinDomains: Ptr([]string{"δρασλ.example.com"}),
	}
	fb := testFallbackAPIServer
	rawConfig.FallbackAPIServers = []rawFallbackAPIServerConfig{fb}
	config, err = CleanConfig(&rawConfig)
	assert.Nil(t, err)

	assert.Equal(t, 1, len(config.FallbackAPIServers))
	assert.Equal(t, *fb.Nickname, config.FallbackAPIServers[0].Nickname)
	assert.Equal(t, "https://xn--mxafwwl.example.com", config.FallbackAPIServers[0].SessionURL)
	assert.Equal(t, "https://xn--mxafwwl.example.com", config.FallbackAPIServers[0].AccountURL)
	assert.Equal(t, "https://xn--mxafwwl.example.com", config.FallbackAPIServers[0].ServicesURL)
	assert.Equal(t, []string{"xn--mxafwwl.example.com"}, config.FallbackAPIServers[0].SkinDomains)

	fb = testFallbackAPIServer
	fb.Nickname = Ptr("")
	rawConfig.FallbackAPIServers = []rawFallbackAPIServerConfig{fb}
	assert.NotNil(t, UnwrapError(CleanConfig(&rawConfig)))

	fb = testFallbackAPIServer
	fb.SessionURL = Ptr("")
	rawConfig.FallbackAPIServers = []rawFallbackAPIServerConfig{fb}
	assert.NotNil(t, UnwrapError(CleanConfig(&rawConfig)))

	fb = testFallbackAPIServer
	fb.SessionURL = Ptr(":invalid URL")
	rawConfig.FallbackAPIServers = []rawFallbackAPIServerConfig{fb}
	assert.NotNil(t, UnwrapError(CleanConfig(&rawConfig)))

	fb = testFallbackAPIServer
	fb.AccountURL = Ptr("")
	rawConfig.FallbackAPIServers = []rawFallbackAPIServerConfig{fb}
	assert.NotNil(t, UnwrapError(CleanConfig(&rawConfig)))

	fb = testFallbackAPIServer
	fb.AccountURL = Ptr(":invalid URL")
	rawConfig.FallbackAPIServers = []rawFallbackAPIServerConfig{fb}
	assert.NotNil(t, UnwrapError(CleanConfig(&rawConfig)))

	fb = testFallbackAPIServer
	fb.ServicesURL = Ptr("")
	rawConfig.FallbackAPIServers = []rawFallbackAPIServerConfig{fb}
	assert.NotNil(t, UnwrapError(CleanConfig(&rawConfig)))

	fb = testFallbackAPIServer
	fb.ServicesURL = Ptr(":invalid URL")
	rawConfig.FallbackAPIServers = []rawFallbackAPIServerConfig{fb}
	assert.NotNil(t, UnwrapError(CleanConfig(&rawConfig)))

	// Test that TEMPLATE_CONFIG_FILE is valid
	var templateConfig Config
	_, err = toml.Decode(TEMPLATE_CONFIG_FILE, &templateConfig)
	assert.Nil(t, err)

	// Test that the example configs are valid
	_, deprecations, err := ReadConfig("example/config-example.toml", false)
	assert.Empty(t, deprecations)
	assert.Nil(t, err)

	// The example configs should all be the same
	correctBytes, err := os.ReadFile("example/config-example.toml")
	assert.Nil(t, err)

	configBytes, err := os.ReadFile("example/docker/config/config.toml")
	assert.Nil(t, err)
	assert.Equal(t, correctBytes, configBytes)

	configBytes, err = os.ReadFile("example/docker-caddy/config/config.toml")
	assert.Nil(t, err)
	assert.Equal(t, correctBytes, configBytes)
}
