package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"github.com/BurntSushi/toml"
	"log"
	"lukechampine.com/blake3"
	"os"
	"path"
)

type serverConfig struct {
	URL           string
	ListenAddress string
}

type FallbackAPIServer struct {
	Nickname   string
	SessionURL string
	AccountURL string
}

type anonymousLoginConfig struct {
	Allow         bool
	UsernameRegex string
	Password      string
}

type registrationNewPlayerConfig struct {
	Allow             bool
	AllowChoosingUUID bool
}

type registrationExistingPlayerConfig struct {
	Allow                   bool
	Nickname                string
	SessionURL              string
	AccountURL              string
	SetSkinURL              string
	RequireSkinVerification bool
}

type Config struct {
	InstanceName               string
	StateDirectory             string
	DataDirectory              string
	ApplicationOwner           string
	SignPublicKeys             bool
	LogRequests                bool
	HideListenAddress          bool
	DefaultPreferredLanguage   string
	AllowHighResolutionSkins   bool
	AllowChangingPlayerName    bool
	MinPasswordLength          int
	SkinForwarding             bool
	FallbackAPIServers         []FallbackAPIServer
	AnonymousLogin             anonymousLoginConfig
	RegistrationNewPlayer      registrationNewPlayerConfig
	RegistrationExistingPlayer registrationExistingPlayerConfig
	UnifiedServer              *serverConfig
	FrontEndServer             serverConfig
	AuthServer                 serverConfig
	AccountServer              serverConfig
	SessionServer              serverConfig
	ServicesServer             serverConfig
}

func DefaultConfig() Config {
	return Config{
		InstanceName:             "Drasl",
		StateDirectory:           "/var/lib/drasl",
		DataDirectory:            "/usr/share/drasl",
		ApplicationOwner:         "Unmojang",
		LogRequests:              true,
		SignPublicKeys:           false,
		DefaultPreferredLanguage: "en",
		AllowHighResolutionSkins: false,
		AllowChangingPlayerName:  true,
		HideListenAddress:        false,
		SkinForwarding:           true,
		MinPasswordLength:        1,
		FallbackAPIServers: []FallbackAPIServer{{
			Nickname:   "Mojang",
			SessionURL: "https://sessionserver.mojang.com",
			AccountURL: "https://api.mojang.com",
		}},
		AnonymousLogin: anonymousLoginConfig{
			Allow: false,
		},
		RegistrationNewPlayer: registrationNewPlayerConfig{
			Allow:             true,
			AllowChoosingUUID: false,
		},
		RegistrationExistingPlayer: registrationExistingPlayerConfig{
			Allow:                   true,
			Nickname:                "Mojang",
			SessionURL:              "https://sessionserver.mojang.com",
			AccountURL:              "https://api.mojang.com",
			SetSkinURL:              "https://www.minecraft.net/msaprofile/mygames/editskin",
			RequireSkinVerification: true,
		},
		FrontEndServer: serverConfig{
			URL:           "https://drasl.example.com",
			ListenAddress: "0.0.0.0:9090",
		},
		AuthServer: serverConfig{
			URL:           "https://auth.drasl.example.com",
			ListenAddress: "0.0.0.0:9091",
		},
		AccountServer: serverConfig{
			URL:           "https://account.drasl.example.com",
			ListenAddress: "0.0.0.0:9092",
		},
		SessionServer: serverConfig{
			URL:           "https://session.drasl.example.com",
			ListenAddress: "0.0.0.0:9093",
		},
		ServicesServer: serverConfig{
			URL:           "https://services.drasl.example.com",
			ListenAddress: "0.0.0.0:9094",
		},
	}
}

func ReadOrCreateConfig(path string) *Config {
	config := DefaultConfig()

	_, err := os.Stat(path)
	if err != nil {
		// File doesn't exist? Try to create it
		f, err := os.Create(path)
		Check(err)

		defer f.Close()

		err = toml.NewEncoder(f).Encode(config)
		Check(err)
	}

	_, err = toml.DecodeFile(path, &config)

	// Config post-processing
	if config.UnifiedServer != nil {
		// Use the unified server, rewrite the other server URLs
		config.FrontEndServer.URL = config.UnifiedServer.URL
		config.AuthServer.URL = config.UnifiedServer.URL
		config.AccountServer.URL = config.UnifiedServer.URL
		config.SessionServer.URL = config.UnifiedServer.URL
		config.ServicesServer.URL = config.UnifiedServer.URL
	}

	log.Println("Loaded config: ", config)
	Check(err)

	return &config
}

func KeyB3Sum512(key *rsa.PrivateKey) []byte {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	Check(err)

	sum := blake3.Sum512(der)
	return sum[:]
}

func ReadOrCreateKey(config *Config) *rsa.PrivateKey {
	err := os.MkdirAll(config.StateDirectory, os.ModePerm)
	Check(err)
	path := path.Join(config.StateDirectory, "key.pkcs8")

	der, err := os.ReadFile(path)
	if err == nil {
		key, err := x509.ParsePKCS8PrivateKey(der)
		Check(err)

		return key.(*rsa.PrivateKey)
	} else {
		key, err := rsa.GenerateKey(rand.Reader, 4096)
		Check(err)

		der, err := x509.MarshalPKCS8PrivateKey(key)
		Check(err)
		err = os.WriteFile(path, der, 0600)
		Check(err)

		return key
	}
}
