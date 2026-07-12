package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/BurntSushi/toml"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/dgraph-io/ristretto"
	"github.com/samber/mo"
	"golang.org/x/net/idna"
)

type rateLimitConfig struct {
	Enable            bool
	RequestsPerSecond float64
	Burst             int
}

type bodyLimitConfig struct {
	Enable       bool
	SizeLimitKiB int64
}

type createNewPlayerConfig struct {
	Allow             bool
	AllowChoosingUUID bool
}

type newPlayerConfig struct {
	createNewPlayerConfig
	RequireInvite bool
}

type existingPlayerConfig struct {
	importExistingPlayerConfig
	RequireInvite bool
}

type importExistingPlayerConfig struct {
	FallbackAPIServerNickname string
	RequireSkinVerification   bool
}

type registrationUsernamePasswordConfig struct {
	NewPlayer      newPlayerConfig
	ExistingPlayer []existingPlayerConfig
}

type rawFallbackAPIServerConfig struct {
	Nickname             *string   `toml:"Nickname"`
	SessionURL           *string   `toml:"SessionURL"`
	AccountURL           *string   `toml:"AccountURL"`
	ServicesURL          *string   `toml:"ServicesURL"`
	SkinDomains          *[]string `toml:"SkinDomains"`
	CacheTTLSeconds      *int      `toml:"CacheTTLSeconds"`
	DenyUnknownUsers     *bool     `toml:"DenyUnknownUsers"`
	EnableAuthentication *bool     `toml:"EnableAuthentication"`
	ForwardSkins         *bool     `toml:"ForwardSkins"`
	SetSkinURL           *string   `toml:"SetSkinURL"`
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
	ForwardSkins         bool
	SetSkinURL           string
}

type rawRegistrationOIDCConfig struct {
	Name                    *string
	Issuer                  *string
	ClientID                *string
	ClientSecret            *string
	ClientSecretFile        *string
	PKCE                    *bool
	AllowChoosingPlayerName *bool
	NewPlayer               *rawNewPlayerConfig       `toml:"NewPlayer"`
	ExistingPlayer          []rawExistingPlayerConfig `toml:"ExistingPlayer"`
}

type RegistrationOIDCConfig struct {
	Name                    string
	Issuer                  string
	ClientID                string
	ClientSecret            string
	PKCE                    bool
	AllowChoosingPlayerName bool
	NewPlayer               newPlayerConfig
	ExistingPlayer          []existingPlayerConfig
}

type rawNewPlayerConfig struct {
	Allow             *bool `toml:"Allow"`
	AllowChoosingUUID *bool `toml:"AllowChoosingUUID"`
	RequireInvite     *bool `toml:"RequireInvite"`
}

type rawExistingPlayerConfig struct {
	FallbackAPIServerNickname *string `toml:"FallbackAPIServerNickname"`
	RequireInvite             *bool   `toml:"RequireInvite"`
	RequireSkinVerification   *bool   `toml:"RequireSkinVerification"`
}

type rawImportExistingPlayerConfig struct {
	FallbackAPIServerNickname *string `toml:"FallbackAPIServerNickname"`
	RequireSkinVerification   *bool   `toml:"RequireSkinVerification"`
}

type rawRegistrationUsernamePasswordConfig struct {
	NewPlayer      *rawNewPlayerConfig       `toml:"NewPlayer"`
	ExistingPlayer []rawExistingPlayerConfig `toml:"ExistingPlayer"`
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
	BlockedServers             []string
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
	InstanceName               string
	ListenAddress              string
	LogRequests                bool
	MinPasswordLength          int
	PlayerUUIDGeneration       string
	PreMigrationBackups        bool
	ClassicPublicIP            string
	RateLimit                  rateLimitConfig
	RequestCache               ristretto.Config
	SignPublicKeys             bool
	SkinSizeLimit              int
	OfflineSkins               bool
	StateDirectory             string
	TokenExpireSec             int
	TokenStaleSec              int
	ValidPlayerNameRegex       string
}

type Config struct {
	BaseConfig
	FallbackAPIServers           []FallbackAPIServerConfig
	RegistrationOIDC             []RegistrationOIDCConfig
	RegistrationUsernamePassword registrationUsernamePasswordConfig
	ImportExistingPlayer         []importExistingPlayerConfig
}

type RawConfig struct {
	BaseConfig
	FallbackAPIServers           []rawFallbackAPIServerConfig
	RegistrationOIDC             []rawRegistrationOIDCConfig
	RegistrationUsernamePassword *rawRegistrationUsernamePasswordConfig
	ImportExistingPlayer         []rawImportExistingPlayerConfig
}

var defaultRateLimitConfig = rateLimitConfig{
	Enable:            true,
	RequestsPerSecond: 2.0,
	Burst:             60,
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
			BlockedServers:             []string{},
			BodyLimit:                  defaultBodyLimitConfig,
			CORSAllowOrigins:           []string{},
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
			InstanceName:             "Drasl",
			ListenAddress:            "0.0.0.0:25585",
			LogRequests:              true,
			MinPasswordLength:        8,
			OfflineSkins:             true,
			PlayerUUIDGeneration:     "random",
			PreMigrationBackups:      true,
			ClassicPublicIP:           "",
			RateLimit:                defaultRateLimitConfig,
			RequestCache:             *DefaultRistrettoConfig,
			SignPublicKeys:           true,
			SkinSizeLimit:            64,
			StateDirectory:           GetDefaultStateDirectory(),
			TokenExpireSec:           0,
			TokenStaleSec:            0,
			ValidPlayerNameRegex:     "^[a-zA-Z0-9_]+$",
		},
		FallbackAPIServers:   []rawFallbackAPIServerConfig{},
		RegistrationOIDC:     []rawRegistrationOIDCConfig{},
		ImportExistingPlayer: []rawImportExistingPlayerConfig{},
		RegistrationUsernamePassword: &rawRegistrationUsernamePasswordConfig{
			NewPlayer: &rawNewPlayerConfig{
				Allow:         Ptr(true),
				RequireInvite: Ptr(false),
			},
		},
	}
}

func DefaultConfig() Config {
	return Config{
		BaseConfig: DefaultRawConfig().BaseConfig,
		RegistrationUsernamePassword: registrationUsernamePasswordConfig{
			NewPlayer: DefaultNewPlayer(),
		},
	}
}

func DefaultFallbackAPIServer() FallbackAPIServerConfig {
	return FallbackAPIServerConfig{
		CacheTTLSeconds:      600,
		DenyUnknownUsers:     false,
		EnableAuthentication: true,
		SkinDomains:          []string{},
		ForwardSkins:         true,
	}
}

func DefaultRegistrationOIDC() RegistrationOIDCConfig {
	return RegistrationOIDCConfig{
		AllowChoosingPlayerName: true,
		PKCE:                    true,
	}
}

func DefaultNewPlayer() newPlayerConfig {
	return newPlayerConfig{
		createNewPlayerConfig: createNewPlayerConfig{
			Allow:             true,
			AllowChoosingUUID: false,
		},
		RequireInvite: false,
	}
}

func AssignConfig[Res, Raw any](defaults Res, raw Raw) Res {
	defaultsValue := reflect.ValueOf(defaults)
	rawValue := reflect.ValueOf(raw)

	out := new(Res)
	outValue := reflect.ValueOf(out).Elem()

	assignStructFields(outValue, defaultsValue, rawValue)

	return *out
}

// assignStructFields copies fields from raw into out, falling back to defaults
// for nil/absent fields. When a field is a pointer in `raw` and a struct in
// `out`/`defaults`, it recurses into the struct so that partially-specified
// nested configs are merged with their defaults field-by-field. When a field
// is a slice of structs with differing element types, it recurses
// element-by-element.
func assignStructFields(out, defaults, raw reflect.Value) {
	t := out.Type()
	for i := 0; i < t.NumField(); i += 1 {
		key := t.Field(i).Name

		rawField := raw.FieldByName(key)
		if rawField == (reflect.Value{}) {
			continue
		}

		outField := out.FieldByName(key)
		defaultField := defaults.FieldByName(key)

		if rawField.Kind() == reflect.Pointer {
			if rawField.IsNil() {
				outField.Set(defaultField)
			} else {
				elem := rawField.Elem()
				if elem.Kind() == reflect.Struct && outField.Kind() == reflect.Struct && elem.Type() != outField.Type() {
					// Nested raw struct with different type than the resolved
					// struct. Recurse, matching fields by name.
					assignStructFields(outField, defaultField, elem)
				} else {
					outField.Set(elem)
				}
			}
		} else if rawField.Kind() == reflect.Slice && outField.Kind() == reflect.Slice &&
			rawField.Type().Elem().Kind() == reflect.Struct &&
			outField.Type().Elem().Kind() == reflect.Struct &&
			rawField.Type().Elem() != outField.Type().Elem() {
			// Slice of structs with differing element types. Recurse
			// element-by-element.
			n := rawField.Len()
			slice := reflect.MakeSlice(outField.Type(), 0, n)
			for j := 0; j < n; j += 1 {
				elemOut := reflect.New(outField.Type().Elem()).Elem()
				assignStructFields(elemOut, reflect.New(defaultField.Type().Elem()).Elem(), rawField.Index(j))
				slice = reflect.Append(slice, elemOut)
			}
			outField.Set(slice)
		} else {
			outField.Set(rawField)
		}
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
	switch config.PlayerUUIDGeneration {
	case PlayerUUIDGenerationRandom:
	case PlayerUUIDGenerationOffline:
	default:
		return Config{}, errors.New(`PlayerUUIDGeneration must be either "random" or "offline".`)
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

		fallbackAPIServerConfig.SetSkinURL, err = cleanURL(
			fmt.Sprintf("FallbackAPIServer %s SetSkinURL", fallbackAPIServerConfig.Nickname),
			mo.None[string](),
			fallbackAPIServerConfig.SetSkinURL, true,
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

	if rawConfig.RegistrationUsernamePassword != nil {
		rp := *rawConfig.RegistrationUsernamePassword
		config.RegistrationUsernamePassword.NewPlayer = cleanNewPlayer(rp.NewPlayer)
		for _, rawReg := range rp.ExistingPlayer {
			entry := cleanExistingPlayer(rawReg)
			if entry.FallbackAPIServerNickname == "" {
				return Config{}, errors.New("RegistrationUsernamePassword.ExistingPlayer.FallbackAPIServerNickname must be set")
			}
			if !fallbackAPIServerNames.Contains(entry.FallbackAPIServerNickname) {
				return Config{}, fmt.Errorf("RegistrationUsernamePassword.ExistingPlayer references unknown FallbackAPIServer Nickname: %s", entry.FallbackAPIServerNickname)
			}
			config.RegistrationUsernamePassword.ExistingPlayer = append(config.RegistrationUsernamePassword.ExistingPlayer, entry)
		}
	}

	for _, rawImportExistingPlayer := range rawConfig.ImportExistingPlayer {
		importExistingPlayer := importExistingPlayerConfig{
			FallbackAPIServerNickname: "",
			RequireSkinVerification:   false,
		}
		if rawImportExistingPlayer.FallbackAPIServerNickname != nil {
			importExistingPlayer.FallbackAPIServerNickname = *rawImportExistingPlayer.FallbackAPIServerNickname
		}
		if rawImportExistingPlayer.RequireSkinVerification != nil {
			importExistingPlayer.RequireSkinVerification = *rawImportExistingPlayer.RequireSkinVerification
		}
		if importExistingPlayer.FallbackAPIServerNickname == "" {
			return Config{}, errors.New("ImportExistingPlayer.FallbackAPIServerNickname must be set")
		}
		if !fallbackAPIServerNames.Contains(importExistingPlayer.FallbackAPIServerNickname) {
			return Config{}, fmt.Errorf("ImportExistingPlayer references unknown FallbackAPIServer Nickname: %s", importExistingPlayer.FallbackAPIServerNickname)
		}
		config.ImportExistingPlayer = append(config.ImportExistingPlayer, importExistingPlayer)
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

		oidcConfig.NewPlayer = cleanNewPlayer(rawOIDCConfig.NewPlayer)
		for _, rawReg := range rawOIDCConfig.ExistingPlayer {
			entry := cleanExistingPlayer(rawReg)
			if entry.FallbackAPIServerNickname == "" {
				return Config{}, fmt.Errorf("RegistrationOIDC %s ExistingPlayer.FallbackAPIServerNickname must be set", oidcConfig.Name)
			}
			if !fallbackAPIServerNames.Contains(entry.FallbackAPIServerNickname) {
				return Config{}, fmt.Errorf("RegistrationOIDC %s ExistingPlayer references unknown FallbackAPIServer Nickname: %s", oidcConfig.Name, entry.FallbackAPIServerNickname)
			}
			oidcConfig.ExistingPlayer = append(oidcConfig.ExistingPlayer, entry)
		}

		config.RegistrationOIDC = append(config.RegistrationOIDC, oidcConfig)
	}
	return config, nil
}

func cleanNewPlayer(raw *rawNewPlayerConfig) newPlayerConfig {
	out := DefaultNewPlayer()
	if raw == nil {
		return out
	}
	if raw.Allow != nil {
		out.Allow = *raw.Allow
	}
	if raw.AllowChoosingUUID != nil {
		out.AllowChoosingUUID = *raw.AllowChoosingUUID
	}
	if raw.RequireInvite != nil {
		out.RequireInvite = *raw.RequireInvite
	}
	return out
}

func cleanExistingPlayer(raw rawExistingPlayerConfig) existingPlayerConfig {
	out := existingPlayerConfig{}
	if raw.FallbackAPIServerNickname != nil {
		out.FallbackAPIServerNickname = *raw.FallbackAPIServerNickname
	}
	if raw.RequireInvite != nil {
		out.RequireInvite = *raw.RequireInvite
	}
	if raw.RequireSkinVerification != nil {
		out.RequireSkinVerification = *raw.RequireSkinVerification
	}
	return out
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

[RegistrationUsernamePassword.NewPlayer]
Allow = true
RequireInvite = false
AllowChoosingUUID = false
`

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

	config, err := CleanConfig(&rawConfig)
	if err != nil {
		return Config{}, nil, err
	}

	return config, nil, nil
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
