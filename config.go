package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"github.com/BurntSushi/toml"
	"log"
	"net/url"
	"os"
	"path"
	"strings"
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

type transientUsersConfig struct {
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
	AllowCapes                 bool
	AllowChangingPlayerName    bool
	AllowMultipleAccessTokens  bool
	AllowSkins                 bool
	ApplicationOwner           string
	BaseURL                    string
	BodyLimit                  bodyLimitConfig
	DataDirectory              string
	DefaultAdmins              []string
	DefaultPreferredLanguage   string
	Domain                     string
	EnableBackgroundEffect     bool
	FallbackAPIServers         []FallbackAPIServer
	ForwardSkins               bool
	InstanceName               string
	ListenAddress              string
	LogRequests                bool
	MinPasswordLength          int
	RateLimit                  rateLimitConfig
	RegistrationExistingPlayer registrationExistingPlayerConfig
	RegistrationNewPlayer      registrationNewPlayerConfig
	SignPublicKeys             bool
	SkinSizeLimit              int
	StateDirectory             string
	TestMode                   bool
	TokenExpireSec             int
	TokenStaleSec              int
	TransientUsers             transientUsersConfig
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
		AllowCapes:               true,
		AllowChangingPlayerName:  true,
		AllowSkins:               true,
		ApplicationOwner:         "Anonymous",
		BaseURL:                  "",
		BodyLimit:                defaultBodyLimitConfig,
		DataDirectory:            "/usr/share/drasl",
		DefaultAdmins:            []string{},
		DefaultPreferredLanguage: "en",
		Domain:                   "",
		EnableBackgroundEffect:   true,
		ForwardSkins:             true,
		InstanceName:             "Drasl",
		ListenAddress:            "0.0.0.0:25585",
		LogRequests:              true,
		MinPasswordLength:        8,
		RateLimit:                defaultRateLimitConfig,
		RegistrationExistingPlayer: registrationExistingPlayerConfig{
			Allow:                   false,
			Nickname:                "Mojang",
			SessionURL:              "https://sessionserver.mojang.com",
			AccountURL:              "https://api.mojang.com",
			SetSkinURL:              "https://www.minecraft.net/msaprofile/mygames/editskin",
			RequireSkinVerification: true,
			RequireInvite:           false,
		},
		RegistrationNewPlayer: registrationNewPlayerConfig{
			Allow:             true,
			AllowChoosingUUID: false,
			RequireInvite:     false,
		},
		SignPublicKeys: true,
		SkinSizeLimit:  128,
		StateDirectory: "/var/lib/drasl",
		TestMode:       false,
		TokenExpireSec: 0,
		TokenStaleSec:  0,
		TransientUsers: transientUsersConfig{
			Allow: false,
		},
	}
}

func CleanConfig(config *Config) error {
	if config.BaseURL == "" {
		return errors.New("BaseURL must be set. Example: https://drasl.example.com")
	}
	if _, err := url.Parse(config.BaseURL); err != nil {
		return fmt.Errorf("Invalid BaseURL: %s", err)
	}
	config.BaseURL = strings.TrimRight(config.BaseURL, "/")

	if !IsValidPreferredLanguage(config.DefaultPreferredLanguage) {
		return fmt.Errorf("Invalid DefaultPreferredLanguage %s", config.DefaultPreferredLanguage)
	}
	if config.Domain == "" {
		return errors.New("Domain must be set to a valid fully qualified domain name")
	}
	if config.InstanceName == "" {
		return errors.New("InstanceName must be set")
	}
	if config.ListenAddress == "" {
		return errors.New("ListenAddress must be set. Example: 0.0.0.0:25585")
	}
	if _, err := os.Open(config.DataDirectory); err != nil {
		return fmt.Errorf("Couldn't open DataDirectory: %s", err)
	}
	if _, err := os.Open(config.StateDirectory); err != nil {
		return fmt.Errorf("Couldn't open StateDirectory: %s", err)
	}
	if config.RegistrationExistingPlayer.Allow {
		if config.RegistrationExistingPlayer.Nickname == "" {
			return errors.New("RegistrationExistingPlayer.Nickname must be set")
		}
		if config.RegistrationExistingPlayer.SessionURL == "" {
			return errors.New("RegistrationExistingPlayer.SessionURL must be set. Example: https://sessionserver.mojang.com")
		}
		if _, err := url.Parse(config.RegistrationExistingPlayer.SessionURL); err != nil {
			return fmt.Errorf("Invalid RegistrationExistingPlayer.SessionURL: %s", err)
		}
		config.RegistrationExistingPlayer.SessionURL = strings.TrimRight(config.RegistrationExistingPlayer.SessionURL, "/")

		if config.RegistrationExistingPlayer.AccountURL == "" {
			return errors.New("RegistrationExistingPlayer.AccountURL must be set. Example: https://api.mojang.com")
		}
		if _, err := url.Parse(config.RegistrationExistingPlayer.AccountURL); err != nil {
			return fmt.Errorf("Invalid RegistrationExistingPlayer.AccountURL: %s", err)
		}
		config.RegistrationExistingPlayer.AccountURL = strings.TrimRight(config.RegistrationExistingPlayer.AccountURL, "/")
	}
	for _, fallbackAPIServer := range PtrSlice(config.FallbackAPIServers) {
		if fallbackAPIServer.Nickname == "" {
			return errors.New("FallbackAPIServer Nickname must be set")
		}

		if fallbackAPIServer.AccountURL == "" {
			return errors.New("FallbackAPIServer AccountURL must be set")
		}
		if _, err := url.Parse(fallbackAPIServer.AccountURL); err != nil {
			return fmt.Errorf("Invalid FallbackAPIServer AccountURL %s: %s", fallbackAPIServer.AccountURL, err)
		}
		fallbackAPIServer.AccountURL = strings.TrimRight(fallbackAPIServer.AccountURL, "/")

		if fallbackAPIServer.SessionURL == "" {
			return errors.New("FallbackAPIServer SessionURL must be set")
		}
		if _, err := url.Parse(fallbackAPIServer.SessionURL); err != nil {
			return fmt.Errorf("Invalid FallbackAPIServer SessionURL %s: %s", fallbackAPIServer.ServicesURL, err)
		}
		fallbackAPIServer.SessionURL = strings.TrimRight(fallbackAPIServer.SessionURL, "/")

		if fallbackAPIServer.ServicesURL == "" {
			return errors.New("FallbackAPIServer ServicesURL must be set")
		}
		if _, err := url.Parse(fallbackAPIServer.ServicesURL); err != nil {
			return fmt.Errorf("Invalid FallbackAPIServer ServicesURL %s: %s", fallbackAPIServer.ServicesURL, err)
		}
		fallbackAPIServer.ServicesURL = strings.TrimRight(fallbackAPIServer.ServicesURL, "/")
		for _, skinDomain := range fallbackAPIServer.SkinDomains {
			if skinDomain == "" {
				return fmt.Errorf("SkinDomain can't be blank for FallbackAPIServer \"%s\"", fallbackAPIServer.Nickname)
			}
		}
	}
	return nil
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

	err = CleanConfig(&config)
	if err != nil {
		log.Fatal(fmt.Errorf("Error in config: %s", err))
	}

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
