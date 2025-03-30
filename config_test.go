package main

import (
	"github.com/BurntSushi/toml"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func configTestConfig(stateDirectory string) *Config {
	config := testConfig()
	config.StateDirectory = stateDirectory
	config.DataDirectory = "."
	return config
}

func TestConfig(t *testing.T) {
	t.Parallel()
	sd := Unwrap(os.MkdirTemp("", "tmp"))
	defer os.RemoveAll(sd)

	config := configTestConfig(sd)
	assert.Nil(t, CleanConfig(config))

	config = configTestConfig(sd)
	config.BaseURL = "https://δρασλ.example.com/"
	config.Domain = "δρασλ.example.com"
	assert.Nil(t, CleanConfig(config))
	assert.Equal(t, "https://xn--mxafwwl.example.com", config.BaseURL)
	assert.Equal(t, "xn--mxafwwl.example.com", config.Domain)

	config = configTestConfig(sd)
	config.BaseURL = ""
	assert.NotNil(t, CleanConfig(config))

	config = configTestConfig(sd)
	config.BaseURL = ":an invalid URL"
	assert.NotNil(t, CleanConfig(config))

	config = configTestConfig(sd)
	config.DefaultPreferredLanguage = "xx"
	assert.NotNil(t, CleanConfig(config))

	config = configTestConfig(sd)
	config.Domain = ""
	assert.NotNil(t, CleanConfig(config))

	config = configTestConfig(sd)
	config.InstanceName = ""
	assert.NotNil(t, CleanConfig(config))

	config = configTestConfig(sd)
	config.ListenAddress = ""
	assert.NotNil(t, CleanConfig(config))

	config = configTestConfig(sd)
	config.DefaultMaxPlayerCount = Constants.MaxPlayerCountUseDefault
	assert.NotNil(t, CleanConfig(config))

	config = configTestConfig(sd)
	config.DefaultMaxPlayerCount = Constants.MaxPlayerCountUnlimited
	assert.Nil(t, CleanConfig(config))

	// Missing state directory should be ignored
	config = configTestConfig(sd)
	config.StateDirectory = "/tmp/DraslInvalidStateDirectoryNothingHere"
	assert.Nil(t, CleanConfig(config))

	config = configTestConfig(sd)
	config.RegistrationExistingPlayer.Allow = true
	config.ImportExistingPlayer.Allow = true
	config.ImportExistingPlayer.Nickname = "Example"
	config.ImportExistingPlayer.SessionURL = "https://δρασλ.example.com/"
	config.ImportExistingPlayer.AccountURL = "https://drasl.example.com/"
	assert.Nil(t, CleanConfig(config))
	assert.Equal(t, "https://xn--mxafwwl.example.com", config.ImportExistingPlayer.SessionURL)
	assert.Equal(t, "https://drasl.example.com", config.ImportExistingPlayer.AccountURL)

	config = configTestConfig(sd)
	config.RegistrationExistingPlayer.Allow = true
	config.ImportExistingPlayer.Nickname = ""
	assert.NotNil(t, CleanConfig(config))

	config = configTestConfig(sd)
	config.RegistrationExistingPlayer.Allow = true
	config.ImportExistingPlayer.SessionURL = ""
	assert.NotNil(t, CleanConfig(config))

	config = configTestConfig(sd)
	config.RegistrationExistingPlayer.Allow = true
	config.ImportExistingPlayer.AccountURL = ""
	assert.NotNil(t, CleanConfig(config))

	config = configTestConfig(sd)
	testFallbackAPIServer := FallbackAPIServer{
		Nickname:    "Nickname",
		SessionURL:  "https://δρασλ.example.com/",
		AccountURL:  "https://δρασλ.example.com/",
		ServicesURL: "https://δρασλ.example.com/",
		SkinDomains: []string{"δρασλ.example.com"},
	}
	fb := testFallbackAPIServer
	config.FallbackAPIServers = []FallbackAPIServer{fb}
	assert.Nil(t, CleanConfig(config))

	assert.Equal(t, []FallbackAPIServer{{
		Nickname:    fb.Nickname,
		SessionURL:  "https://xn--mxafwwl.example.com",
		AccountURL:  "https://xn--mxafwwl.example.com",
		ServicesURL: "https://xn--mxafwwl.example.com",
		SkinDomains: []string{"xn--mxafwwl.example.com"},
	}}, config.FallbackAPIServers)

	fb = testFallbackAPIServer
	fb.Nickname = ""
	config.FallbackAPIServers = []FallbackAPIServer{fb}
	assert.NotNil(t, CleanConfig(config))

	fb = testFallbackAPIServer
	fb.SessionURL = ""
	config.FallbackAPIServers = []FallbackAPIServer{fb}
	assert.NotNil(t, CleanConfig(config))

	fb = testFallbackAPIServer
	fb.SessionURL = ":invalid URL"
	config.FallbackAPIServers = []FallbackAPIServer{fb}
	assert.NotNil(t, CleanConfig(config))

	fb = testFallbackAPIServer
	fb.AccountURL = ""
	config.FallbackAPIServers = []FallbackAPIServer{fb}
	assert.NotNil(t, CleanConfig(config))

	fb = testFallbackAPIServer
	fb.AccountURL = ":invalid URL"
	config.FallbackAPIServers = []FallbackAPIServer{fb}
	assert.NotNil(t, CleanConfig(config))

	fb = testFallbackAPIServer
	fb.ServicesURL = ""
	config.FallbackAPIServers = []FallbackAPIServer{fb}
	assert.NotNil(t, CleanConfig(config))

	fb = testFallbackAPIServer
	fb.ServicesURL = ":invalid URL"
	config.FallbackAPIServers = []FallbackAPIServer{fb}
	assert.NotNil(t, CleanConfig(config))

	// Test that TEMPLATE_CONFIG_FILE is valid
	var templateConfig Config
	_, err := toml.Decode(TEMPLATE_CONFIG_FILE, &templateConfig)
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
