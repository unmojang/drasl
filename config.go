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
	"reflect"
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

type rawFallbackAPIServerConfig struct {
	Nickname             *string
	SessionURL           *string
	AccountURL           *string
	ServicesURL          *string
	SkinDomains          *[]string
	CacheTTLSeconds      *int
	DenyUnknownUsers     *bool
	EnableAuthentication *bool
}

type FallbackAPIServerConfig struct {
	Nickname             string
	SessionURL           string
	AccountURL           string
	ServicesURL          string
	SkinDomains          []string
	CacheTTLSeconds      int
	DenyUnknownUsers     bool
	EnableAuthentication bool
}

type rawRegistrationOIDCConfig struct {
	Name                    *string
	Issuer                  *string
	ClientID                *string
	ClientSecret            *string
	ClientSecretFile        *string
	PKCE                    *bool
	RequireInvite           *bool
	AllowChoosingPlayerName *bool
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

type BaseConfig struct {
	AllowCapes                 bool
	AllowChangingPlayerName    bool
	AllowPasswordLogin         bool
	AllowSkins                 bool
	AllowTextureFromURL        bool
	AllowAddingDeletingPlayers bool
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
	EnableClientConfiguration  bool
	EnableServerConfiguration  bool
	EnableFooter               bool
	EnableWebFrontEnd          bool
	ForwardSkins               bool
	InstanceName               string
	ImportExistingPlayer       importExistingPlayerConfig
	ListenAddress              string
	LogRequests                bool
	MinPasswordLength          int
	PlayerUUIDGeneration       string
	PreMigrationBackups        bool
	RateLimit                  rateLimitConfig
	RegistrationExistingPlayer registrationExistingPlayerConfig
	RegistrationNewPlayer      registrationNewPlayerConfig
	RequestCache               ristretto.Config
	SignPublicKeys             bool
	SkinSizeLimit              int
	OfflineSkins               bool
	StateDirectory             string
	TokenExpireSec             int
	TokenStaleSec              int
	TransientUsers             transientUsersConfig
	ValidPlayerNameRegex       string
}

type Config struct {
	BaseConfig
	FallbackAPIServers []FallbackAPIServerConfig
	RegistrationOIDC   []RegistrationOIDCConfig
}

type RawConfig struct {
	BaseConfig
	FallbackAPIServers []rawFallbackAPIServerConfig
	RegistrationOIDC   []rawRegistrationOIDCConfig
}

var defaultRateLimitConfig = rateLimitConfig{
	Enable:            true,
	RequestsPerSecond: 5,
}
var defaultBodyLimitConfig = bodyLimitConfig{
	Enable:       true,
	SizeLimitKiB: 8192,
}

var DefaultRistrettoConfig = &ristretto.Config{
	// Defaults from https://pkg.go.dev/github.com/dgraph-io/ristretto#readme-config
	NumCounters: 1e7,
	MaxCost:     1 << 30, // 1 GiB
	BufferItems: 64,
}

func DefaultRawConfig() RawConfig {
	return RawConfig{
		BaseConfig: BaseConfig{
			AllowCapes:                 true,
			AllowChangingPlayerName:    true,
			AllowPasswordLogin:         true,
			AllowSkins:                 true,
			AllowTextureFromURL:        false,
			AllowAddingDeletingPlayers: false,
			ApplicationName:            "Drasl",
			ApplicationOwner:           "Anonymous",
			BaseURL:                    "",
			BodyLimit:                  defaultBodyLimitConfig,
			CORSAllowOrigins:           []string{},
			CreateNewPlayer: createNewPlayerConfig{
				Allow:             true,
				AllowChoosingUUID: false,
			},
			DataDirectory:             GetDefaultDataDirectory(),
			DefaultAdmins:             []string{},
			DefaultPreferredLanguage:  "en",
			DefaultMaxPlayerCount:     1,
			Domain:                    "",
			EnableBackgroundEffect:    true,
			EnableClientConfiguration: true,
			EnableServerConfiguration: true,
			EnableFooter:              true,
			EnableWebFrontEnd:         true,
			ForwardSkins:              true,
			ImportExistingPlayer: importExistingPlayerConfig{
				Allow: false,
			},
			InstanceName:         "Drasl",
			ListenAddress:        "0.0.0.0:25585",
			LogRequests:          true,
			MinPasswordLength:    8,
			OfflineSkins:         true,
			PlayerUUIDGeneration: "random",
			PreMigrationBackups:  true,
			RateLimit:            defaultRateLimitConfig,
			RegistrationExistingPlayer: registrationExistingPlayerConfig{
				Allow: false,
			},
			RegistrationNewPlayer: registrationNewPlayerConfig{
				Allow:         true,
				RequireInvite: false,
			},
			RequestCache:   *DefaultRistrettoConfig,
			SignPublicKeys: true,
			SkinSizeLimit:  64,
			StateDirectory: GetDefaultStateDirectory(),
			TokenExpireSec: 0,
			TokenStaleSec:  0,
			TransientUsers: transientUsersConfig{
				Allow: false,
			},
			ValidPlayerNameRegex: "^[a-zA-Z0-9_]+$",
		},
		FallbackAPIServers: []rawFallbackAPIServerConfig{},
		RegistrationOIDC:   []rawRegistrationOIDCConfig{},
	}
}

func DefaultConfig() Config {
	return Config{
		BaseConfig: DefaultRawConfig().BaseConfig,
	}
}

func DefaultFallbackAPIServer() FallbackAPIServerConfig {
	return FallbackAPIServerConfig{
		CacheTTLSeconds:      600,
		DenyUnknownUsers:     false,
		EnableAuthentication: true,
		SkinDomains:          []string{},
	}
}

func DefaultRegistrationOIDC() RegistrationOIDCConfig {
	return RegistrationOIDCConfig{
		AllowChoosingPlayerName: true,
		PKCE:                    true,
		RequireInvite:           false,
	}
}

func AssignConfig[Res, Raw any](defaults Res, raw Raw) Res {
	configType := reflect.TypeOf(defaults)

	rawValue := reflect.ValueOf(raw)
	defaultsValue := reflect.ValueOf(defaults)

	out := new(Res)
	outValue := reflect.ValueOf(out).Elem()

	for i := 0; i < configType.NumField(); i += 1 {
		key := configType.Field(i).Name

		rawField := rawValue.FieldByName(key)
		if rawField == (reflect.Value{}) {
			continue
		}

		outField := outValue.FieldByName(key)
		if rawField.IsNil() {
			outField.Set(defaultsValue.FieldByName(key))
		} else {
			rawField := rawValue.FieldByName(key).Elem()
			outField.Set(rawField)
		}
	}

	return *out
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

func CleanConfig(rawConfig *RawConfig) (Config, error) {
	config := Config{}
	config.BaseConfig = rawConfig.BaseConfig

	var err error
	config.BaseURL, err = cleanURL("BaseURL", mo.Some("https://drasl.example.com"), config.BaseURL, true)
	if err != nil {
		return Config{}, err
	}

	if !IsValidPreferredLanguage(config.DefaultPreferredLanguage) {
		return Config{}, fmt.Errorf("Invalid DefaultPreferredLanguage %s", config.DefaultPreferredLanguage)
	}

	if config.Domain == "" {
		return Config{}, errors.New("Domain must be set to a valid fully qualified domain name")
	}

	config.Domain, err = cleanDomain(
		"Domain",
		mo.Some("drasl.example.com"),
		config.Domain,
	)
	if err != nil {
		return Config{}, err
	}

	if config.InstanceName == "" {
		return Config{}, errors.New("InstanceName must be set")
	}
	if config.ListenAddress == "" {
		return Config{}, errors.New("ListenAddress must be set. Example: 0.0.0.0:25585")
	}
	if config.DefaultMaxPlayerCount < 0 && config.DefaultMaxPlayerCount != Constants.MaxPlayerCountUnlimited {
		return Config{}, fmt.Errorf("DefaultMaxPlayerCount must be >= 0, or %d to indicate unlimited players", Constants.MaxPlayerCountUnlimited)
	}
	if config.RegistrationNewPlayer.Allow {
		if !config.CreateNewPlayer.Allow {
			return Config{}, errors.New("If RegisterNewPlayer is allowed, CreateNewPlayer must be allowed.")
		}
	}
	switch config.PlayerUUIDGeneration {
	case PlayerUUIDGenerationRandom:
	case PlayerUUIDGenerationOffline:
	default:
		return Config{}, errors.New(`PlayerUUIDGeneration must be either "random" or "offline".`)
	}
	if config.RegistrationExistingPlayer.Allow {
		if !config.ImportExistingPlayer.Allow {
			return Config{}, errors.New("If RegistrationExistingPlayer is allowed, ImportExistingPlayer must be allowed.")
		}
		if config.ImportExistingPlayer.Nickname == "" {
			return Config{}, errors.New("If RegistrationExistingPlayer is allowed, ImportExistingPlayer.Nickname must be set")
		}
		if config.ImportExistingPlayer.SessionURL == "" {
			return Config{}, errors.New("If RegistrationExistingPlayer is allowed, ImportExistingPlayer.SessionURL must be set. Example: https://sessionserver.mojang.com")
		}
		if config.ImportExistingPlayer.AccountURL == "" {
			return Config{}, errors.New("If RegistrationExistingPlayer is allowed, ImportExistingPlayer.AccountURL must be set. Example: https://api.mojang.com")
		}
	}
	if config.ImportExistingPlayer.Allow {
		if config.ImportExistingPlayer.Nickname == "" {
			return Config{}, errors.New("ImportExistingPlayer.Nickname must be set")
		}

		config.ImportExistingPlayer.SessionURL, err = cleanURL(
			"ImportExistingPlayer.SessionURL",
			mo.Some("https://sessionserver.mojang.com"),
			config.ImportExistingPlayer.SessionURL, true,
		)
		if err != nil {
			return Config{}, err
		}

		config.ImportExistingPlayer.AccountURL, err = cleanURL(
			"ImportExistingPlayer.AccountURL",
			mo.Some("https://api.mojang.com"),
			config.ImportExistingPlayer.AccountURL, true,
		)
		if err != nil {
			return Config{}, err
		}

		config.ImportExistingPlayer.SetSkinURL, err = cleanURL(
			"ImportExistingPlayer.SetSkinURL",
			mo.None[string](),
			config.ImportExistingPlayer.SetSkinURL, true,
		)
		if err != nil {
			return Config{}, err
		}
	}

	fallbackAPIServerNames := mapset.NewSet[string]()
	for _, rawFallbackAPIServer := range PtrSlice(rawConfig.FallbackAPIServers) {
		fallbackAPIServerConfig := AssignConfig(DefaultFallbackAPIServer(), *rawFallbackAPIServer)

		if fallbackAPIServerConfig.Nickname == "" {
			return Config{}, errors.New("FallbackAPIServer Nickname must be set")
		}
		if fallbackAPIServerNames.Contains(fallbackAPIServerConfig.Nickname) {
			return Config{}, fmt.Errorf("Duplicate FallbackAPIServer Nickname: %s", fallbackAPIServerConfig.Nickname)
		}
		fallbackAPIServerNames.Add(fallbackAPIServerConfig.Nickname)

		fallbackAPIServerConfig.SessionURL, err = cleanURL(
			fmt.Sprintf("FallbackAPIServer %s SessionURL", fallbackAPIServerConfig.Nickname),
			mo.Some("https://sessionserver.mojang.com"),
			fallbackAPIServerConfig.SessionURL, true,
		)
		if err != nil {
			return Config{}, err
		}

		fallbackAPIServerConfig.AccountURL, err = cleanURL(
			fmt.Sprintf("FallbackAPIServer %s AccountURL", fallbackAPIServerConfig.Nickname),
			mo.Some("https://api.mojang.com"),
			fallbackAPIServerConfig.AccountURL, true,
		)
		if err != nil {
			return Config{}, err
		}

		fallbackAPIServerConfig.ServicesURL, err = cleanURL(
			fmt.Sprintf("FallbackAPIServer %s ServicesURL", fallbackAPIServerConfig.Nickname),
			mo.Some("https://api.minecraftservices.com"),
			fallbackAPIServerConfig.ServicesURL, true,
		)
		if err != nil {
			return Config{}, err
		}

		for _, skinDomain := range PtrSlice(fallbackAPIServerConfig.SkinDomains) {
			*skinDomain, err = cleanDomain(
				fmt.Sprintf("FallbackAPIServer %s SkinDomain", fallbackAPIServerConfig.Nickname),
				mo.Some("textures.minecraft.net"),
				*skinDomain,
			)
			if err != nil {
				return Config{}, err
			}
		}

		config.FallbackAPIServers = append(config.FallbackAPIServers, fallbackAPIServerConfig)
	}

	oidcNames := mapset.NewSet[string]()
	for _, rawOIDCConfig := range PtrSlice(rawConfig.RegistrationOIDC) {
		if rawOIDCConfig.ClientSecret != nil && rawOIDCConfig.ClientSecretFile != nil {
			return Config{}, errors.New("can't supply both a ClientSecret and a ClientSecretFile")
		}
		if rawOIDCConfig.ClientSecretFile != nil {
			value, err := loadSecretFromFile(*rawOIDCConfig.ClientSecretFile)
			if err != nil {
				return Config{}, fmt.Errorf("couldn't read ClientSecretFile: %w", err)
			}
			rawOIDCConfig.ClientSecret = &value
		}

		oidcConfig := AssignConfig(DefaultRegistrationOIDC(), *rawOIDCConfig)

		if oidcConfig.Name == "" {
			return Config{}, errors.New("RegistrationOIDC Name must be set")
		}
		if oidcNames.Contains(oidcConfig.Name) {
			return Config{}, fmt.Errorf("Duplicate RegistrationOIDC Name: %s", oidcConfig.Name)
		}
		oidcNames.Add(oidcConfig.Name)
		oidcConfig.Issuer, err = cleanURL(
			fmt.Sprintf("RegistrationOIDC %s Issuer", oidcConfig.Name),
			mo.Some("https://idm.example.com/oauth2/openid/drasl"),
			oidcConfig.Issuer,
			false,
		)
		if err != nil {
			return Config{}, err
		}

		config.RegistrationOIDC = append(config.RegistrationOIDC, oidcConfig)
	}
	return config, nil
}

func loadSecretFromFile(path string) (string, error) {
	secretBytes, err := os.ReadFile(os.ExpandEnv(path))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(secretBytes)), nil
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

func HandleDeprecations(oldRawConfig *RawConfig, metadata *toml.MetaData) (RawConfig, [][]string) {
	rawConfig := *oldRawConfig
	deprecatedPaths := make([][]string, 0)

	warningTemplate := "Warning: config option %s is deprecated and will be removed in a future version. Use %s instead."

	path_ := []string{"RegistrationNewPlayer", "AllowChoosingUUID"}
	if metadata.IsDefined(path_...) {
		LogInfo(fmt.Sprintf(warningTemplate, strings.Join(path_, "."), "CreateNewPlayer.AllowChoosingUUID"))
		deprecatedPaths = append(deprecatedPaths, path_)
		if !metadata.IsDefined("CreateNewPlayer", "AllowChoosingUUID") {
			rawConfig.CreateNewPlayer.AllowChoosingUUID = rawConfig.RegistrationNewPlayer.AllowChoosingUUID
		}
	}
	path_ = []string{"RegistrationExistingPlayer", "Nickname"}
	if metadata.IsDefined(path_...) {
		LogInfo(fmt.Sprintf(warningTemplate, strings.Join(path_, "."), "ImportExistingPlayer.Nickname"))
		deprecatedPaths = append(deprecatedPaths, path_)
		if !metadata.IsDefined("ImportExistingPlayer", "Nickname") {
			rawConfig.ImportExistingPlayer.Nickname = rawConfig.RegistrationExistingPlayer.Nickname
		}
	}
	path_ = []string{"RegistrationExistingPlayer", "SessionURL"}
	if metadata.IsDefined(path_...) {
		LogInfo(fmt.Sprintf(warningTemplate, strings.Join(path_, "."), "ImportExistingPlayer.SessionURL"))
		deprecatedPaths = append(deprecatedPaths, path_)
		if !metadata.IsDefined("ImportExistingPlayer", "SessionURL") {
			rawConfig.ImportExistingPlayer.SessionURL = rawConfig.RegistrationExistingPlayer.SessionURL
		}
	}
	path_ = []string{"RegistrationExistingPlayer", "AccountURL"}
	if metadata.IsDefined(path_...) {
		LogInfo(fmt.Sprintf(warningTemplate, strings.Join(path_, "."), "ImportExistingPlayer.AccountURL"))
		deprecatedPaths = append(deprecatedPaths, path_)
		if !metadata.IsDefined("ImportExistingPlayer", "AccountURL") {
			rawConfig.ImportExistingPlayer.AccountURL = rawConfig.RegistrationExistingPlayer.AccountURL
		}
	}
	path_ = []string{"RegistrationExistingPlayer", "SetSkinURL"}
	if metadata.IsDefined(path_...) {
		LogInfo(fmt.Sprintf(warningTemplate, strings.Join(path_, "."), "ImportExistingPlayer.SetSkinURL"))
		deprecatedPaths = append(deprecatedPaths, path_)
		if !metadata.IsDefined("ImportExistingPlayer", "SetSkinURL") {
			rawConfig.ImportExistingPlayer.SetSkinURL = rawConfig.RegistrationExistingPlayer.SetSkinURL
		}
	}
	path_ = []string{"RegistrationExistingPlayer", "RequireSkinVerification"}
	if metadata.IsDefined(path_...) {
		LogInfo(fmt.Sprintf(warningTemplate, strings.Join(path_, "."), "ImportExistingPlayer.RequireSkinVerification"))
		deprecatedPaths = append(deprecatedPaths, path_)
		if !metadata.IsDefined("ImportExistingPlayer", "RequireSkinVerification") {
			rawConfig.ImportExistingPlayer.RequireSkinVerification = rawConfig.RegistrationExistingPlayer.RequireSkinVerification
		}
	}

	return rawConfig, deprecatedPaths
}

func ReadConfig(path string, createIfNotExists bool) (Config, [][]string, error) {
	rawConfig := DefaultRawConfig()

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
	metadata, err := toml.DecodeFile(path, &rawConfig)
	Check(err)

	for _, key := range metadata.Undecoded() {
		LogInfo("Warning: unknown config option", strings.Join(key, "."))
	}

	rawConfig, deprecations := HandleDeprecations(&rawConfig, &metadata)
	config, err := CleanConfig(&rawConfig)
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
