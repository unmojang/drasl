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
	"github.com/samber/mo"
	"golang.org/x/net/idna"
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
	Name                    string
	Issuer                  string
	ClientID                string
	ClientSecret            string
	PKCE                    bool
	RequireInvite           bool
	AllowChoosingPlayerName bool
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
	AllowCapes                   bool
	AllowChangingPlayerName      bool
	AllowMultipleAccessTokens    bool
	AllowPasswordLogin           bool
	AllowSkins                   bool
	AllowTextureFromURL          bool
	AllowCreatingDeletingPlayers bool
	ApplicationOwner             string
	ApplicationName              string
	BaseURL                      string
	BodyLimit                    bodyLimitConfig
	CORSAllowOrigins             []string
	CreateNewPlayer              createNewPlayerConfig
	DataDirectory                string
	DefaultAdmins                []string
	DefaultPreferredLanguage     string
	DefaultMaxPlayerCount        int
	Domain                       string
	EnableBackgroundEffect       bool
	EnableFooter                 bool
	EnableWebFrontEnd            bool
	FallbackAPIServers           []FallbackAPIServer
	ForwardSkins                 bool
	InstanceName                 string
	ImportExistingPlayer         importExistingPlayerConfig
	ListenAddress                string
	LogRequests                  bool
	MinPasswordLength            int
	RegistrationOIDC             []RegistrationOIDCConfig
	PreMigrationBackups          bool
	RateLimit                    rateLimitConfig
	RegistrationExistingPlayer   registrationExistingPlayerConfig
	RegistrationNewPlayer        registrationNewPlayerConfig
	RequestCache                 ristretto.Config
	SignPublicKeys               bool
	SkinSizeLimit                int
	OfflineSkins                 bool
	StateDirectory               string
	TokenExpireSec               int
	TokenStaleSec                int
	TransientUsers               transientUsersConfig
	ValidPlayerNameRegex         string
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
		AllowCapes:                   true,
		AllowChangingPlayerName:      true,
		AllowPasswordLogin:           true,
		AllowSkins:                   true,
		AllowTextureFromURL:          false,
		AllowCreatingDeletingPlayers: false,
		ApplicationName:              "Drasl",
		ApplicationOwner:             "Anonymous",
		BaseURL:                      "",
		BodyLimit:                    defaultBodyLimitConfig,
		CORSAllowOrigins:             []string{},
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
		TokenExpireSec: 0,
		TokenStaleSec:  0,
		TransientUsers: transientUsersConfig{
			Allow: false,
		},
		ValidPlayerNameRegex: "^[a-zA-Z0-9_]+$",
	}
}

func cleanURL(key string, required mo.Option[string], urlString string, trimTrailingSlash bool) (string, error) {
	if urlString == "" {
		if example, ok := required.Get(); ok {
			return "", fmt.Errorf("%s must be set. Example: %s", key, example)
		}
		return urlString, nil
	}

	parsedURL, err := url.Parse(urlString)
	if err != nil {
		return "", fmt.Errorf("Invalid %s: %s", key, err)
	}

	punycodeHost, err := idna.ToASCII(parsedURL.Host)
	if err != nil {
		return "", fmt.Errorf("Invalid %s: %s", key, err)
	}
	parsedURL.Host = punycodeHost

	if trimTrailingSlash {
		parsedURL.Path = strings.TrimSuffix(parsedURL.Path, "/")
	}
	return parsedURL.String(), nil
}

func cleanDomain(key string, required mo.Option[string], domain string) (string, error) {
	if domain == "" {
		if example, ok := required.Get(); ok {
			return "", fmt.Errorf("%s must be set. Example: %s", key, example)
		}
		return domain, nil
	}

	punycoded, err := idna.ToASCII(domain)
	if err != nil {
		return "", fmt.Errorf("Invalid %s: %s", key, err)
	}
	return punycoded, nil
}

func CleanConfig(config *Config) error {
	var err error
	config.BaseURL, err = cleanURL("BaseURL", mo.Some("https://drasl.example.com"), config.BaseURL, true)
	if err != nil {
		return err
	}

	if !IsValidPreferredLanguage(config.DefaultPreferredLanguage) {
		return fmt.Errorf("Invalid DefaultPreferredLanguage %s", config.DefaultPreferredLanguage)
	}

	if config.Domain == "" {
		return errors.New("Domain must be set to a valid fully qualified domain name")
	}

	config.Domain, err = cleanDomain(
		"Domain",
		mo.Some("drasl.example.com"),
		config.Domain,
	)
	if err != nil {
		return err
	}

	if config.InstanceName == "" {
		return errors.New("InstanceName must be set")
	}
	if config.ListenAddress == "" {
		return errors.New("ListenAddress must be set. Example: 0.0.0.0:25585")
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

		config.ImportExistingPlayer.SessionURL, err = cleanURL(
			"ImportExistingPlayer.SessionURL",
			mo.Some("https://sessionserver.mojang.com"),
			config.ImportExistingPlayer.SessionURL, true,
		)
		if err != nil {
			return err
		}

		config.ImportExistingPlayer.AccountURL, err = cleanURL(
			"ImportExistingPlayer.AccountURL",
			mo.Some("https://api.mojang.com"),
			config.ImportExistingPlayer.AccountURL, true,
		)
		if err != nil {
			return err
		}

		config.ImportExistingPlayer.SetSkinURL, err = cleanURL(
			"ImportExistingPlayer.SetSkinURL",
			mo.None[string](),
			config.ImportExistingPlayer.SetSkinURL, true,
		)
		if err != nil {
			return err
		}
	}

	fallbackAPIServerNames := mapset.NewSet[string]()
	for _, fallbackAPIServer := range PtrSlice(config.FallbackAPIServers) {
		if fallbackAPIServer.Nickname == "" {
			return errors.New("FallbackAPIServer Nickname must be set")
		}
		if fallbackAPIServerNames.Contains(fallbackAPIServer.Nickname) {
			return fmt.Errorf("Duplicate FallbackAPIServer Nickname: %s", fallbackAPIServer.Nickname)
		}
		fallbackAPIServerNames.Add(fallbackAPIServer.Nickname)

		fallbackAPIServer.SessionURL, err = cleanURL(
			fmt.Sprintf("FallbackAPIServer %s SessionURL", fallbackAPIServer.Nickname),
			mo.Some("https://sessionserver.mojang.com"),
			fallbackAPIServer.SessionURL, true,
		)
		if err != nil {
			return err
		}

		fallbackAPIServer.AccountURL, err = cleanURL(
			fmt.Sprintf("FallbackAPIServer %s AccountURL", fallbackAPIServer.Nickname),
			mo.Some("https://api.mojang.com"),
			fallbackAPIServer.AccountURL, true,
		)
		if err != nil {
			return err
		}

		fallbackAPIServer.ServicesURL, err = cleanURL(
			fmt.Sprintf("FallbackAPIServer %s ServicesURL", fallbackAPIServer.Nickname),
			mo.Some("https://api.minecraftservices.com"),
			fallbackAPIServer.ServicesURL, true,
		)
		if err != nil {
			return err
		}

		for _, skinDomain := range PtrSlice(fallbackAPIServer.SkinDomains) {
			*skinDomain, err = cleanDomain(
				fmt.Sprintf("FallbackAPIServer %s SkinDomain", fallbackAPIServer.Nickname),
				mo.Some("textures.minecraft.net"),
				*skinDomain,
			)
			if err != nil {
				return err
			}
		}
	}

	oidcNames := mapset.NewSet[string]()
	for _, oidcConfig := range PtrSlice(config.RegistrationOIDC) {
		if oidcConfig.Name == "" {
			return errors.New("RegistrationOIDC Name must be set")
		}
		if oidcNames.Contains(oidcConfig.Name) {
			return fmt.Errorf("Duplicate RegistrationOIDC Name: %s", oidcConfig.Name)
		}
		oidcNames.Add(oidcConfig.Name)
		oidcConfig.Issuer, err = cleanURL(
			fmt.Sprintf("RegistrationOIDC %s Issuer", oidcConfig.Name),
			mo.Some("https://idm.example.com/oauth2/openid/drasl"),
			oidcConfig.Issuer,
			false,
		)
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

func HandleDeprecations(config Config, metadata *toml.MetaData) [][]string {
	deprecatedPaths := make([][]string, 0, 0)

	warningTemplate := "Warning: config option %s is deprecated and will be removed in a future version. Use %s instead."

	path_ := []string{"RegistrationNewPlayer", "AllowChoosingUUID"}
	if metadata.IsDefined(path_...) {
		LogInfo(fmt.Sprintf(warningTemplate, strings.Join(path_, "."), "CreateNewPlayer.AllowChoosingUUID"))
		deprecatedPaths = append(deprecatedPaths, path_)
		if !metadata.IsDefined("CreateNewPlayer", "AllowChoosingUUID") {
			config.CreateNewPlayer.AllowChoosingUUID = config.RegistrationNewPlayer.AllowChoosingUUID
		}
	}
	path_ = []string{"RegistrationExistingPlayer", "Nickname"}
	if metadata.IsDefined(path_...) {
		LogInfo(fmt.Sprintf(warningTemplate, strings.Join(path_, "."), "ImportExistingPlayer.Nickname"))
		deprecatedPaths = append(deprecatedPaths, path_)
		if !metadata.IsDefined("ImportExistingPlayer", "Nickname") {
			config.ImportExistingPlayer.Nickname = config.RegistrationExistingPlayer.Nickname
		}
	}
	path_ = []string{"RegistrationExistingPlayer", "SessionURL"}
	if metadata.IsDefined(path_...) {
		LogInfo(fmt.Sprintf(warningTemplate, strings.Join(path_, "."), "ImportExistingPlayer.SessionURL"))
		deprecatedPaths = append(deprecatedPaths, path_)
		if !metadata.IsDefined("ImportExistingPlayer", "SessionURL") {
			config.ImportExistingPlayer.SessionURL = config.RegistrationExistingPlayer.SessionURL
		}
	}
	path_ = []string{"RegistrationExistingPlayer", "AccountURL"}
	if metadata.IsDefined(path_...) {
		LogInfo(fmt.Sprintf(warningTemplate, strings.Join(path_, "."), "ImportExistingPlayer.AccountURL"))
		deprecatedPaths = append(deprecatedPaths, path_)
		if !metadata.IsDefined("ImportExistingPlayer", "AccountURL") {
			config.ImportExistingPlayer.AccountURL = config.RegistrationExistingPlayer.AccountURL
		}
	}
	path_ = []string{"RegistrationExistingPlayer", "SetSkinURL"}
	if metadata.IsDefined(path_...) {
		LogInfo(fmt.Sprintf(warningTemplate, strings.Join(path_, "."), "ImportExistingPlayer.SetSkinURL"))
		deprecatedPaths = append(deprecatedPaths, path_)
		if !metadata.IsDefined("ImportExistingPlayer", "SetSkinURL") {
			config.ImportExistingPlayer.SetSkinURL = config.RegistrationExistingPlayer.SetSkinURL
		}
	}
	path_ = []string{"RegistrationExistingPlayer", "RequireSkinVerification"}
	if metadata.IsDefined(path_...) {
		LogInfo(fmt.Sprintf(warningTemplate, strings.Join(path_, "."), "ImportExistingPlayer.RequireSkinVerification"))
		deprecatedPaths = append(deprecatedPaths, path_)
		if !metadata.IsDefined("ImportExistingPlayer", "RequireSkinVerification") {
			config.ImportExistingPlayer.RequireSkinVerification = config.RegistrationExistingPlayer.RequireSkinVerification
		}
	}

	return deprecatedPaths
}

func ReadConfig(path string, createIfNotExists bool) (Config, [][]string, error) {
	config := DefaultConfig()

	_, err := os.Stat(path)
	if err != nil {
		if !createIfNotExists {
			return Config{}, nil, err
		}

		LogInfo("Config file at", path, "doesn't exist, creating it with template values.")
		dir := filepath.Dir(path)
		err := os.MkdirAll(dir, 0755)
		Check(err)

		f := Unwrap(os.Create(path))
		defer f.Close()

		_, err = f.Write([]byte(TEMPLATE_CONFIG_FILE))
		Check(err)
	}

	LogInfo("Loading config from", path)
	metadata, err := toml.DecodeFile(path, &config)
	Check(err)

	for _, key := range metadata.Undecoded() {
		LogInfo("Warning: unknown config option", strings.Join(key, "."))
	}

	deprecations := HandleDeprecations(config, &metadata)
	err = CleanConfig(&config)
	if err != nil {
		return Config{}, nil, err
	}

	return config, deprecations, nil
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
