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

type rateLimitConfig struct {
	Enable            bool
	RequestsPerSecond float64
}

type bodySizeLimitConfig struct {
	Enable    bool
	SizeLimit string
}

type FallbackAPIServer struct {
	Nickname    string
	SessionURL  string
	AccountURL  string
	ServicesURL string
	SkinDomains []string
	CacheTTL    int
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
	Domain                     string
	BaseURL                    string
	InstanceName               string
	ApplicationOwner           string
	StateDirectory             string
	DataDirectory              string
	ListenAddress              string
	HideListenAddress          bool
	RateLimit                  rateLimitConfig
	BodySize                   bodySizeLimitConfig
	LogRequests                bool
	ForwardSkins               bool
	FallbackAPIServers         []FallbackAPIServer
	AnonymousLogin             anonymousLoginConfig
	RegistrationNewPlayer      registrationNewPlayerConfig
	RegistrationExistingPlayer registrationExistingPlayerConfig
	SignPublicKeys             bool
	EnableTokenExpiry          bool
	DefaultPreferredLanguage   string
	SkinSizeLimit              int
	AllowChangingPlayerName    bool
	MinPasswordLength          int
}

var defaultRateLimitConfig = rateLimitConfig{
	Enable:            true,
	RequestsPerSecond: 5,
}

func DefaultConfig() Config {
	return Config{
		InstanceName:             "Drasl",
		Domain:                   "drasl.example.com",
		StateDirectory:           "/var/lib/drasl",
		DataDirectory:            "/usr/share/drasl",
		ApplicationOwner:         "Anonymous",
		BaseURL:                  "https://drasl.example.com",
		ListenAddress:            "0.0.0.0:25585",
		RateLimit:                defaultRateLimitConfig,
		LogRequests:              true,
		SignPublicKeys:           true,
		DefaultPreferredLanguage: "en",
		SkinSizeLimit:            128,
		AllowChangingPlayerName:  true,
		HideListenAddress:        false,
		ForwardSkins:             true,
		MinPasswordLength:        1,
		EnableTokenExpiry:        false,
		AnonymousLogin: anonymousLoginConfig{
			Allow: false,
		},
		RegistrationNewPlayer: registrationNewPlayerConfig{
			Allow:             true,
			AllowChoosingUUID: false,
		},
		RegistrationExistingPlayer: registrationExistingPlayerConfig{
			Allow:                   false,
			Nickname:                "Mojang",
			SessionURL:              "https://sessionserver.mojang.com",
			AccountURL:              "https://api.mojang.com",
			SetSkinURL:              "https://www.minecraft.net/msaprofile/mygames/editskin",
			RequireSkinVerification: true,
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
	// TODO validate URLS
	// remove trailing slashes
	// TODO all required options should be set
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
