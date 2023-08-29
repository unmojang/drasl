package main

import (
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
	sd := Unwrap(os.MkdirTemp("", "tmp"))
	defer os.RemoveAll(sd)

	config := configTestConfig(sd)
	assert.Nil(t, CleanConfig(config))

	config = configTestConfig(sd)
	config.BaseURL = "https://drasl.example.com/"
	assert.Nil(t, CleanConfig(config))
	assert.Equal(t, "https://drasl.example.com", config.BaseURL)

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
	config.DataDirectory = "/tmp/DraslInvalidPathNothingHere"
	assert.NotNil(t, CleanConfig(config))

	config = configTestConfig(sd)
	config.StateDirectory = "/tmp/DraslInvalidPathNothingHere"
	assert.NotNil(t, CleanConfig(config))

	config = configTestConfig(sd)
	config.RegistrationExistingPlayer.Allow = true
	config.RegistrationExistingPlayer.SessionURL = "https://drasl.lab.evangoo.de/"
	config.RegistrationExistingPlayer.AccountURL = "https://drasl.lab.evangoo.de/"
	assert.Nil(t, CleanConfig(config))
	assert.Equal(t, "https://drasl.lab.evangoo.de", config.RegistrationExistingPlayer.SessionURL)
	assert.Equal(t, "https://drasl.lab.evangoo.de", config.RegistrationExistingPlayer.AccountURL)

	config = configTestConfig(sd)
	config.RegistrationExistingPlayer.Allow = true
	config.RegistrationExistingPlayer.SessionURL = ""
	assert.NotNil(t, CleanConfig(config))

	config = configTestConfig(sd)
	config.RegistrationExistingPlayer.Allow = true
	config.RegistrationExistingPlayer.AccountURL = ""
	assert.NotNil(t, CleanConfig(config))

	config = configTestConfig(sd)
	testFallbackAPIServer := FallbackAPIServer{
		Nickname:    "Nickname",
		SessionURL:  "https://drasl.example.com/",
		AccountURL:  "https://drasl.example.com/",
		ServicesURL: "https://drasl.example.com/",
	}
	fb := testFallbackAPIServer
	config.FallbackAPIServers = []FallbackAPIServer{fb}
	assert.Nil(t, CleanConfig(config))
	assert.Equal(t, "https://drasl.example.com", config.FallbackAPIServers[0].SessionURL)
	assert.Equal(t, "https://drasl.example.com", config.FallbackAPIServers[0].AccountURL)
	assert.Equal(t, "https://drasl.example.com", config.FallbackAPIServers[0].ServicesURL)

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
}
