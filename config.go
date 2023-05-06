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

type authConfig struct {
	URL           string
	ListenAddress string
}

type accountConfig struct {
	URL           string
	ListenAddress string
}

type sessionConfig struct {
	URL           string
	ListenAddress string
}

type servicesConfig struct {
	URL           string
	ListenAddress string
}

type frontConfig struct {
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
	ServicesURL             string
	RequireSkinVerification bool
}

type Config struct {
	InstanceName               string
	DataDirectory              string
	ApplicationOwner           string
	SignPublicKeys             bool
	LogRequests                bool
	HideListenAddress          bool
	DefaultPreferredLanguage   string
	AllowHighResolutionSkins   bool
	MinPasswordLength          int
	FallbackAPIServers         []FallbackAPIServer
	AnonymousLogin             anonymousLoginConfig
	RegistrationNewPlayer      registrationNewPlayerConfig
	RegistrationExistingPlayer registrationExistingPlayerConfig
	FrontEndServer             frontConfig
	AuthServer                 authConfig
	AccountServer              accountConfig
	SessionServer              sessionConfig
	ServicesServer             servicesConfig
}

func DefaultConfig() Config {
	return Config{
		InstanceName:             "Drasl",
		DataDirectory:            "/var/lib/drasl",
		ApplicationOwner:         "Unmojang",
		LogRequests:              true,
		SignPublicKeys:           false,
		DefaultPreferredLanguage: "en",
		AllowHighResolutionSkins: false,
		HideListenAddress:        false,
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
			ServicesURL:             "https://api.mojang.com",
			RequireSkinVerification: true,
		},
		FrontEndServer: frontConfig{
			URL:           "https://drasl.example.com",
			ListenAddress: "0.0.0.0:9090",
		},
		AuthServer: authConfig{
			URL:           "https://auth.drasl.example.com",
			ListenAddress: "0.0.0.0:9091",
		},
		AccountServer: accountConfig{
			URL:           "https://account.drasl.example.com",
			ListenAddress: "0.0.0.0:9092",
		},
		SessionServer: sessionConfig{
			URL:           "https://session.drasl.example.com",
			ListenAddress: "0.0.0.0:9093",
		},
		ServicesServer: servicesConfig{
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
	err := os.MkdirAll(config.DataDirectory, os.ModePerm)
	Check(err)
	path := path.Join(config.DataDirectory, "key.pkcs8")

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
