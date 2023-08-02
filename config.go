package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"github.com/BurntSushi/toml"
	"log"
	"os"
	"path"
)

type rateLimitConfig struct {
	Enable            bool
	RequestsPerSecond float64
}

type bodyLimitConfig struct {
	Enable       bool
	SizeLimitKiB int
}

type FallbackAPIServer struct {
	Nickname        string
	SessionURL      string
	AccountURL      string
	ServicesURL     string
	SkinDomains     []string
	CacheTTLSeconds int
}

type anonymousLoginConfig struct {
	Allow         bool
	UsernameRegex string
	Password      string
}

type registrationNewPlayerConfig struct {
	Allow             bool
	AllowChoosingUUID bool
	RequireInvite     bool
}

type registrationExistingPlayerConfig struct {
	Allow                   bool
	Nickname                string
	SessionURL              string
	AccountURL              string
	SetSkinURL              string
	RequireSkinVerification bool
	RequireInvite           bool
}

type Config struct {
	Domain                     string
	BaseURL                    string
	InstanceName               string
	ApplicationOwner           string
	StateDirectory             string
	DataDirectory              string
	ListenAddress              string
	DefaultAdmins              []string
	TestMode                   bool
	RateLimit                  rateLimitConfig
	BodyLimit                  bodyLimitConfig
	LogRequests                bool
	ForwardSkins               bool
	AllowSkins                 bool
	AllowCapes                 bool
	FallbackAPIServers         []FallbackAPIServer
	AnonymousLogin             anonymousLoginConfig
	RegistrationNewPlayer      registrationNewPlayerConfig
	RegistrationExistingPlayer registrationExistingPlayerConfig
	SignPublicKeys             bool
	AllowMultipleAccessTokens  bool
	TokenExpireSec             int
	TokenStaleSec              int
	DefaultPreferredLanguage   string
	SkinSizeLimit              int
	AllowChangingPlayerName    bool
	MinPasswordLength          int
}

var defaultRateLimitConfig = rateLimitConfig{
	Enable:            true,
	RequestsPerSecond: 5,
}
var defaultBodyLimitConfig = bodyLimitConfig{
	Enable:       true,
	SizeLimitKiB: 8192,
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
		DefaultAdmins:            []string{},
		RateLimit:                defaultRateLimitConfig,
		BodyLimit:                defaultBodyLimitConfig,
		LogRequests:              true,
		SignPublicKeys:           true,
		DefaultPreferredLanguage: "en",
		SkinSizeLimit:            128,
		AllowChangingPlayerName:  true,
		TestMode:                 false,
		ForwardSkins:             true,
		AllowSkins:               true,
		AllowCapes:               true,
		MinPasswordLength:        1,
		TokenStaleSec:            0,
		TokenExpireSec:           0,
		AnonymousLogin: anonymousLoginConfig{
			Allow: false,
		},
		RegistrationNewPlayer: registrationNewPlayerConfig{
			Allow:             true,
			AllowChoosingUUID: false,
			RequireInvite:     false,
		},
		RegistrationExistingPlayer: registrationExistingPlayerConfig{
			Allow:                   false,
			Nickname:                "Mojang",
			SessionURL:              "https://sessionserver.mojang.com",
			AccountURL:              "https://api.mojang.com",
			SetSkinURL:              "https://www.minecraft.net/msaprofile/mygames/editskin",
			RequireSkinVerification: true,
			RequireInvite:           false,
		},
	}
}

func ReadOrCreateConfig(path string) *Config {
	config := DefaultConfig()

	_, err := os.Stat(path)
	if err != nil {
		// File doesn't exist? Try to create it
		f := Unwrap(os.Create(path))
		defer f.Close()

		err = toml.NewEncoder(f).Encode(config)
		Check(err)
	}

	_, err = toml.DecodeFile(path, &config)
	Check(err)

	log.Println("Loading config from", path)

	// Config post-processing
	// TODO validate URLS
	// remove trailing slashes
	// TODO all required options should be set
	log.Println("Loaded config:", config)

	return &config
}

func ReadOrCreateKey(config *Config) *rsa.PrivateKey {
	err := os.MkdirAll(config.StateDirectory, os.ModePerm)
	Check(err)
	path := path.Join(config.StateDirectory, "key.pkcs8")

	der, err := os.ReadFile(path)
	if err == nil {
		key := Unwrap(x509.ParsePKCS8PrivateKey(der))

		return key.(*rsa.PrivateKey)
	} else {
		key := Unwrap(rsa.GenerateKey(rand.Reader, 4096))

		der := Unwrap(x509.MarshalPKCS8PrivateKey(key))
		err = os.WriteFile(path, der, 0600)
		Check(err)

		return key
	}
}
