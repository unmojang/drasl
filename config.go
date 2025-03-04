package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"github.com/BurntSushi/toml"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/dgraph-io/ristretto"
	"log"
	"net/url"
	"os"
	"path"
	"path/filepath"
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
	Nickname         string
	SessionURL       string
	AccountURL       string
	ServicesURL      string
	SkinDomains      []string
	CacheTTLSeconds  int
	DenyUnknownUsers bool
}

type RegistrationOIDCConfig struct {
	Name          string
	Issuer        string
	ClientID      string
	ClientSecret  string
	PKCE          bool
	RequireInvite bool
}

type transientUsersConfig struct {
	Allow         bool
	UsernameRegex string
	Password      string
}

type v2RegistrationNewPlayerConfig struct {
	AllowChoosingUUID bool
}

type registrationNewPlayerConfig struct {
	v2RegistrationNewPlayerConfig
	Allow         bool
	RequireInvite bool
}

type v2RegistrationExistingPlayerConfig struct {
	Nickname                string
	SessionURL              string
	AccountURL              string
	SetSkinURL              string
	RequireSkinVerification bool
}

type registrationExistingPlayerConfig struct {
	v2RegistrationExistingPlayerConfig
	Allow         bool
	RequireInvite bool
}

type createNewPlayerConfig struct {
	Allow             bool
	AllowChoosingUUID bool
}

type importExistingPlayerConfig struct {
	Allow                   bool
	Nickname                string
	SessionURL              string
	AccountURL              string
	SetSkinURL              string
	RequireSkinVerification bool
}

type Config struct {
	AllowCapes                 bool
	AllowChangingPlayerName    bool
	AllowMultipleAccessTokens  bool
	AllowPasswordLogin         bool
	AllowSkins                 bool
	AllowTextureFromURL        bool
	ApplicationOwner           string
	ApplicationName            string
	BaseURL                    string
	BodyLimit                  bodyLimitConfig
	CORSAllowOrigins           []string
	CreateNewPlayer            createNewPlayerConfig
	DataDirectory              string
	DefaultAdmins              []string
	DefaultPreferredLanguage   string
	DefaultMaxPlayerCount      int
	Domain                     string
	EnableBackgroundEffect     bool
	EnableFooter               bool
	EnableWebFrontEnd          bool
	FallbackAPIServers         []FallbackAPIServer
	ForwardSkins               bool
	InstanceName               string
	ImportExistingPlayer       importExistingPlayerConfig
	ListenAddress              string
	LogRequests                bool
	MinPasswordLength          int
	RegistrationOIDC           []RegistrationOIDCConfig
	PreMigrationBackups        bool
	RateLimit                  rateLimitConfig
	RegistrationExistingPlayer registrationExistingPlayerConfig
	RegistrationNewPlayer      registrationNewPlayerConfig
	RequestCache               ristretto.Config
	SignPublicKeys             bool
	SkinSizeLimit              int
	OfflineSkins               bool
	StateDirectory             string
	TestMode                   bool
	TokenExpireSec             int
	TokenStaleSec              int
	TransientUsers             transientUsersConfig
	ValidPlayerNameRegex       string
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
		AllowCapes:              true,
		AllowChangingPlayerName: true,
		AllowPasswordLogin:      true,
		AllowSkins:              true,
		AllowTextureFromURL:     false,
		ApplicationName:         "Drasl",
		ApplicationOwner:        "Anonymous",
		BaseURL:                 "",
		BodyLimit:               defaultBodyLimitConfig,
		CORSAllowOrigins:        []string{},
		CreateNewPlayer: createNewPlayerConfig{
			Allow:             true,
			AllowChoosingUUID: false,
		},
		DataDirectory:            GetDefaultDataDirectory(),
		DefaultAdmins:            []string{},
		DefaultPreferredLanguage: "en",
		DefaultMaxPlayerCount:    1,
		Domain:                   "",
		EnableBackgroundEffect:   true,
		EnableFooter:             true,
		EnableWebFrontEnd:        true,
		ForwardSkins:             true,
		ImportExistingPlayer: importExistingPlayerConfig{
			Allow: false,
		},
		InstanceName:        "Drasl",
		ListenAddress:       "0.0.0.0:25585",
		LogRequests:         true,
		MinPasswordLength:   8,
		RegistrationOIDC:    []RegistrationOIDCConfig{},
		OfflineSkins:        true,
		PreMigrationBackups: true,
		RateLimit:           defaultRateLimitConfig,
		RegistrationExistingPlayer: registrationExistingPlayerConfig{
			Allow: false,
		},
		RegistrationNewPlayer: registrationNewPlayerConfig{
			Allow:         true,
			RequireInvite: false,
		},
		RequestCache: ristretto.Config{
			// Defaults from https://pkg.go.dev/github.com/dgraph-io/ristretto#readme-config
			NumCounters: 1e7,
			MaxCost:     1 << 30, // 1 GiB
			BufferItems: 64,
		},
		SignPublicKeys: true,
		SkinSizeLimit:  128,
		StateDirectory: GetDefaultStateDirectory(),
		TestMode:       false,
		TokenExpireSec: 0,
		TokenStaleSec:  0,
		TransientUsers: transientUsersConfig{
			Allow: false,
		},
		ValidPlayerNameRegex: "^[a-zA-Z0-9_]+$",
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
	if config.DefaultMaxPlayerCount < 0 && config.DefaultMaxPlayerCount != Constants.MaxPlayerCountUnlimited {
		return fmt.Errorf("DefaultMaxPlayerCount must be >= 0, or %d to indicate unlimited players", Constants.MaxPlayerCountUnlimited)
	}
	if config.RegistrationNewPlayer.Allow {
		if !config.CreateNewPlayer.Allow {
			return errors.New("If RegisterNewPlayer is allowed, CreateNewPlayer must be allowed.")
		}
	}
	if config.RegistrationExistingPlayer.Allow {
		if !config.ImportExistingPlayer.Allow {
			return errors.New("If RegistrationExistingPlayer is allowed, ImportExistingPlayer must be allowed.")
		}
		if config.ImportExistingPlayer.Nickname == "" {
			return errors.New("If RegistrationExistingPlayer is allowed, ImportExistingPlayer.Nickname must be set")
		}
		if config.ImportExistingPlayer.SessionURL == "" {
			return errors.New("If RegistrationExistingPlayer is allowed, ImportExistingPlayer.SessionURL must be set. Example: https://sessionserver.mojang.com")
		}
		if config.ImportExistingPlayer.AccountURL == "" {
			return errors.New("If RegistrationExistingPlayer is allowed, ImportExistingPlayer.AccountURL must be set. Example: https://api.mojang.com")
		}
	}
	if config.ImportExistingPlayer.Allow {
		if config.ImportExistingPlayer.Nickname == "" {
			return errors.New("ImportExistingPlayer.Nickname must be set")
		}
		if config.ImportExistingPlayer.SessionURL == "" {
			return errors.New("ImportExistingPlayer.SessionURL must be set. Example: https://sessionserver.mojang.com")
		}
		if _, err := url.Parse(config.ImportExistingPlayer.SessionURL); err != nil {
			return fmt.Errorf("Invalid ImportExistingPlayer.SessionURL: %s", err)
		}
		config.ImportExistingPlayer.SessionURL = strings.TrimRight(config.ImportExistingPlayer.SessionURL, "/")

		if config.ImportExistingPlayer.AccountURL == "" {
			return errors.New("ImportExistingPlayer.AccountURL must be set. Example: https://api.mojang.com")
		}
		if _, err := url.Parse(config.ImportExistingPlayer.AccountURL); err != nil {
			return fmt.Errorf("Invalid ImportExistingPlayer.AccountURL: %s", err)
		}
		config.ImportExistingPlayer.AccountURL = strings.TrimRight(config.ImportExistingPlayer.AccountURL, "/")
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

	oidcNames := mapset.NewSet[string]()
	for _, oidcConfig := range PtrSlice(config.RegistrationOIDC) {
		if oidcNames.Contains(oidcConfig.Name) {
			return fmt.Errorf("Duplicate RegistrationOIDC Name: %s", oidcConfig.Name)
		}
		if _, err := url.Parse(oidcConfig.Issuer); err != nil {
			return fmt.Errorf("Invalid RegistrationOIDC URL %s: %s", oidcConfig.Issuer, err)
		}
		oidcNames.Add(oidcConfig.Name)
	}
	return nil
}

const TEMPLATE_CONFIG_FILE = `# Drasl default config file

# Example: drasl.example.com
Domain = ""

# Example: https://drasl.example.com
BaseURL = ""

# List of usernames who automatically become admins of the Drasl instance
DefaultAdmins = [""]

[RegistrationNewPlayer]
Allow = true
RequireInvite = true
`

func HandleDeprecations(config Config, metadata *toml.MetaData) {
	warningTemplate := "Warning: config option %s is deprecated and will be removed in a future version. Use %s instead."
	if metadata.IsDefined("RegistrationNewPlayer", "AllowChoosingUUID") {
		log.Printf(warningTemplate, "RegistrationNewPlayer.AllowChoosingUUID", "CreateNewPlayer.AllowChoosingUUID")
		if !metadata.IsDefined("CreateNewPlayer", "AllowChoosingUUID") {
			config.CreateNewPlayer.AllowChoosingUUID = config.RegistrationNewPlayer.AllowChoosingUUID
		}
	}
	if metadata.IsDefined("RegistrationExistingPlayer", "Nickname") {
		log.Printf(warningTemplate, "RegistrationExistingPlayer.Nickname", "ImportExistingPlayer.Nickname")
		if !metadata.IsDefined("ImportExistingPlayer", "Nickname") {
			config.ImportExistingPlayer.Nickname = config.RegistrationExistingPlayer.Nickname
		}
	}
	if metadata.IsDefined("RegistrationExistingPlayer", "SessionURL") {
		log.Printf(warningTemplate, "RegistrationExistingPlayer.SessionURL", "ImportExistingPlayer.SessionURL")
		if !metadata.IsDefined("ImportExistingPlayer", "SessionURL") {
			config.ImportExistingPlayer.SessionURL = config.RegistrationExistingPlayer.SessionURL
		}
	}
	if metadata.IsDefined("RegistrationExistingPlayer", "AccountURL") {
		log.Printf(warningTemplate, "RegistrationExistingPlayer.AccountURL", "ImportExistingPlayer.AccountURL")
		if !metadata.IsDefined("ImportExistingPlayer", "AccountURL") {
			config.ImportExistingPlayer.AccountURL = config.RegistrationExistingPlayer.AccountURL
		}
	}
	if metadata.IsDefined("RegistrationExistingPlayer", "SetSkinURL") {
		log.Printf(warningTemplate, "RegistrationExistingPlayer.SetSkinURL", "ImportExistingPlayer.SetSkinURL")
		if !metadata.IsDefined("ImportExistingPlayer", "SetSkinURL") {
			config.ImportExistingPlayer.SetSkinURL = config.RegistrationExistingPlayer.SetSkinURL
		}
	}
	if metadata.IsDefined("RegistrationExistingPlayer", "RequireSkinVerification") {
		log.Printf(warningTemplate, "RegistrationExistingPlayer.RequireSkinVerification", "ImportExistingPlayer.RequireSkinVerification")
		if !metadata.IsDefined("ImportExistingPlayer", "RequireSkinVerification") {
			config.ImportExistingPlayer.RequireSkinVerification = config.RegistrationExistingPlayer.RequireSkinVerification
		}
	}
}

func ReadOrCreateConfig(path string) *Config {
	config := DefaultConfig()

	_, err := os.Stat(path)
	if err != nil {
		// File doesn't exist? Try to create it

		log.Println("Config file at", path, "doesn't exist, creating it with template values.")
		dir := filepath.Dir(path)
		err := os.MkdirAll(dir, 0755)
		Check(err)

		f := Unwrap(os.Create(path))
		defer f.Close()

		_, err = f.Write([]byte(TEMPLATE_CONFIG_FILE))
		Check(err)
	}

	log.Println("Loading config from", path)
	metadata, err := toml.DecodeFile(path, &config)
	Check(err)

	for _, key := range metadata.Undecoded() {
		log.Println("Warning: unknown config option", strings.Join(key, "."))
	}

	HandleDeprecations(config, &metadata)
	err = CleanConfig(&config)
	if err != nil {
		log.Fatal(fmt.Errorf("Error in config: %s", err))
	}

	return &config
}

func ReadOrCreateKey(config *Config) *rsa.PrivateKey {
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
