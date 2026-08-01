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
	"strings"

	"github.com/BurntSushi/toml"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/dgraph-io/ristretto"
	"github.com/samber/mo"
	"golang.org/x/net/idna"
)

type rawRateLimitConfig struct {
	Enable            *bool    `toml:"Enable"`
	RequestsPerSecond *float64 `toml:"RequestsPerSecond"`
	Burst             *int     `toml:"Burst"`
}

type rateLimitConfig struct {
	Enable            bool
	RequestsPerSecond float64
	Burst             int
}

type rawBodyLimitConfig struct {
	Enable       *bool  `toml:"Enable"`
	SizeLimitKiB *int64 `toml:"SizeLimitKiB"`
}

type bodyLimitConfig struct {
	Enable       bool
	SizeLimitKiB int64
}

type rawCreateNewPlayerConfig struct {
	Allow             *bool `toml:"Allow"`
	AllowChoosingUUID *bool `toml:"AllowChoosingUUID"`
}

type createNewPlayerConfig struct {
	Allow             bool
	AllowChoosingUUID bool
}

type rawRegCreateNewPlayerConfig struct {
	rawCreateNewPlayerConfig
	RequireInvite *bool `toml:"RequireInvite"`
}

type regCreateNewPlayerConfig struct {
	createNewPlayerConfig
	RequireInvite bool
}

type rawRegImportExistingPlayerConfig struct {
	FallbackAPIServerNickname *string `toml:"FallbackAPIServerNickname"`
	RequireInvite             *bool   `toml:"RequireInvite"`
	RequireSkinVerification   *bool   `toml:"RequireSkinVerification"`
}

type regImportExistingPlayerConfig struct {
	importExistingPlayerConfig
	RequireInvite bool
}

type rawImportExistingPlayerConfig struct {
	FallbackAPIServerNickname *string `toml:"FallbackAPIServerNickname"`
	RequireSkinVerification   *bool   `toml:"RequireSkinVerification"`
}

type importExistingPlayerConfig struct {
	FallbackAPIServerNickname string
	RequireSkinVerification   bool
}

// legacyImportExistingPlayer captures the deprecated single-table form
// `[ImportExistingPlayer]`, which carried inline API server URLs. It is
// migrated to the new `[[ImportExistingPlayer]]` + `[[FallbackAPIServers]]`
// model in CleanConfig.
type legacyImportExistingPlayer struct {
	Allow                   bool
	Nickname                string
	SessionURL              string
	AccountURL              string
	SetSkinURL              string
	RequireSkinVerification bool
}

// rawImportExistingPlayer accepts both the deprecated single-table form
// `[ImportExistingPlayer]` and the new array-of-tables form
// `[[ImportExistingPlayer]]`. The unmarshaler parses the array-of-tables into
// Entries and the single-table form into Legacy.
type rawImportExistingPlayer struct {
	Entries []rawImportExistingPlayerConfig
	Legacy  *legacyImportExistingPlayer
}

func toString(v any) (string, bool) {
	s, ok := v.(string)
	return s, ok
}

func toBool(v any) (bool, bool) {
	b, ok := v.(bool)
	return b, ok
}

func (r *rawImportExistingPlayer) UnmarshalTOML(p any) error {
	switch v := p.(type) {
	case map[string]any:
		legacy := legacyImportExistingPlayer{}
		if b, ok := toBool(v["Allow"]); ok {
			legacy.Allow = b
		}
		if s, ok := toString(v["Nickname"]); ok {
			legacy.Nickname = s
		}
		if s, ok := toString(v["SessionURL"]); ok {
			legacy.SessionURL = s
		}
		if s, ok := toString(v["AccountURL"]); ok {
			legacy.AccountURL = s
		}
		if s, ok := toString(v["SetSkinURL"]); ok {
			legacy.SetSkinURL = s
		}
		if b, ok := toBool(v["RequireSkinVerification"]); ok {
			legacy.RequireSkinVerification = b
		}
		r.Legacy = &legacy
		if !legacy.Allow {
			r.Entries = []rawImportExistingPlayerConfig{}
			return nil
		}
		r.Entries = []rawImportExistingPlayerConfig{{
			FallbackAPIServerNickname: Ptr(legacy.Nickname),
			RequireSkinVerification:   Ptr(legacy.RequireSkinVerification),
		}}
		return nil

	case []map[string]any:
		entries := make([]rawImportExistingPlayerConfig, 0, len(v))
		for _, m := range v {
			entry := rawImportExistingPlayerConfig{}
			if s, ok := toString(m["FallbackAPIServerNickname"]); ok {
				entry.FallbackAPIServerNickname = Ptr(s)
			}
			if b, ok := toBool(m["RequireSkinVerification"]); ok {
				entry.RequireSkinVerification = Ptr(b)
			}
			entries = append(entries, entry)
		}
		r.Entries = entries
		return nil

	default:
		return fmt.Errorf("ImportExistingPlayer must be a table ([ImportExistingPlayer]) or array of tables ([[ImportExistingPlayer]])")
	}
}

type rawRegUsernamePasswordConfig struct {
	CreateNewPlayer      *rawRegCreateNewPlayerConfig       `toml:"CreateNewPlayer"`
	ImportExistingPlayer []rawRegImportExistingPlayerConfig `toml:"ImportExistingPlayer"`
}

type regUsernamePasswordConfig struct {
	CreateNewPlayer      regCreateNewPlayerConfig
	ImportExistingPlayer []regImportExistingPlayerConfig
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
	// Deprecated in 4.0.0
	RequireInvite *bool

	Name                    *string
	Issuer                  *string
	ClientID                *string
	ClientSecret            *string
	ClientSecretFile        *string
	PKCE                    *bool
	AllowChoosingPlayerName *bool
	CreateNewPlayer         *rawRegCreateNewPlayerConfig       `toml:"CreateNewPlayer"`
	ImportExistingPlayer    []rawRegImportExistingPlayerConfig `toml:"ImportExistingPlayer"`
}

type RegistrationOIDCConfig struct {
	Name                    string
	Issuer                  string
	ClientID                string
	ClientSecret            string
	PKCE                    bool
	AllowChoosingPlayerName bool
	CreateNewPlayer         regCreateNewPlayerConfig
	ImportExistingPlayer    []regImportExistingPlayerConfig
}

type rawRequestCacheConfig struct {
	NumCounters *int64 `toml:"NumCounters"`
	MaxCost     *int64 `toml:"MaxCost"`
	BufferItems *int64 `toml:"BufferItems"`
}

type rawRegistrationNewPlayerConfig struct {
	Allow         *bool `toml:"Allow"`
	RequireInvite *bool `toml:"RequireInvite"`
}

type rawRegistrationExistingPlayerConfig struct {
	Allow         *bool
	RequireInvite *bool
}

type RawConfig struct {
	// Deprecated in 4.0.0
	ForwardSkins               *bool                                `toml:"ForwardSkins"`
	AllowAddingDeletingPlayers *bool                                `toml:"AllowAddingDeletingPlayers"`
	RegistrationNewPlayer      *rawRegistrationNewPlayerConfig      `toml:"RegistrationNewPlayer"`
	RegistrationExistingPlayer *rawRegistrationExistingPlayerConfig `toml:"RegistrationExistingPlayer"`

	AllowCapes               *bool                     `toml:"AllowCapes"`
	AllowChangingPlayerName  *bool                     `toml:"AllowChangingPlayerName"`
	AllowPasswordLogin       *bool                     `toml:"AllowPasswordLogin"`
	AllowSkins               *bool                     `toml:"AllowSkins"`
	AllowTextureFromURL      *bool                     `toml:"AllowTextureFromURL"`
	ApplicationName          *string                   `toml:"ApplicationName"`
	ApplicationOwner         *string                   `toml:"ApplicationOwner"`
	BaseURL                  *string                   `toml:"BaseURL"`
	BlockedServers           *[]string                 `toml:"BlockedServers"`
	BodyLimit                *rawBodyLimitConfig       `toml:"BodyLimit"`
	CORSAllowOrigins         *[]string                 `toml:"CORSAllowOrigins"`
	CreateNewPlayer          *rawCreateNewPlayerConfig `toml:"CreateNewPlayer"`
	DataDirectory            *string                   `toml:"DataDirectory"`
	DefaultAdmins            *[]string                 `toml:"DefaultAdmins"`
	DefaultMaxPlayerCount    *int                      `toml:"DefaultMaxPlayerCount"`
	DefaultPreferredLanguage *string                   `toml:"DefaultPreferredLanguage"`
	Domain                   *string                   `toml:"Domain"`
	EnableBackgroundEffect   *bool                     `toml:"EnableBackgroundEffect"`
	EnableFooter             *bool                     `toml:"EnableFooter"`
	EnableWebFrontEnd        *bool                     `toml:"EnableWebFrontEnd"`
	InstanceName             *string                   `toml:"InstanceName"`
	ListenAddress            *string                   `toml:"ListenAddress"`
	LogRequests              *bool                     `toml:"LogRequests"`
	MinPasswordLength        *int                      `toml:"MinPasswordLength"`
	OfflineSkins             *bool                     `toml:"OfflineSkins"`
	PlayerUUIDGeneration     *string                   `toml:"PlayerUUIDGeneration"`
	PreMigrationBackups      *bool                     `toml:"PreMigrationBackups"`
	ClassicPublicIP          *string                   `toml:"ClassicPublicIP"`
	RateLimit                *rawRateLimitConfig       `toml:"RateLimit"`
	RequestCache             *rawRequestCacheConfig    `toml:"RequestCache"`
	SignPublicKeys           *bool                     `toml:"SignPublicKeys"`
	SkinSizeLimit            *int                      `toml:"SkinSizeLimit"`
	StateDirectory           *string                   `toml:"StateDirectory"`
	TokenExpireSec           *int                      `toml:"TokenExpireSec"`
	TokenStaleSec            *int                      `toml:"TokenStaleSec"`
	ValidPlayerNameRegex     *string                   `toml:"ValidPlayerNameRegex"`

	FallbackAPIServers           []rawFallbackAPIServerConfig  `toml:"FallbackAPIServers"`
	ImportExistingPlayer         rawImportExistingPlayer       `toml:"ImportExistingPlayer"`
	RegistrationOIDC             []rawRegistrationOIDCConfig   `toml:"RegistrationOIDC"`
	RegistrationUsernamePassword *rawRegUsernamePasswordConfig `toml:"RegistrationUsernamePassword"`
}

type Config struct {
	AllowCapes               bool
	AllowChangingPlayerName  bool
	AllowPasswordLogin       bool
	AllowSkins               bool
	AllowTextureFromURL      bool
	ApplicationName          string
	ApplicationOwner         string
	BaseURL                  string
	BlockedServers           []string
	BodyLimit                bodyLimitConfig
	CORSAllowOrigins         []string
	CreateNewPlayer          createNewPlayerConfig
	DataDirectory            string
	DefaultAdmins            []string
	DefaultMaxPlayerCount    int
	DefaultPreferredLanguage string
	Domain                   string
	EnableBackgroundEffect   bool
	EnableFooter             bool
	EnableWebFrontEnd        bool
	InstanceName             string
	ListenAddress            string
	LogRequests              bool
	MinPasswordLength        int
	OfflineSkins             bool
	PlayerUUIDGeneration     string
	PreMigrationBackups      bool
	ClassicPublicIP          string
	RateLimit                rateLimitConfig
	RequestCache             ristretto.Config
	SignPublicKeys           bool
	SkinSizeLimit            int
	StateDirectory           string
	TokenExpireSec           int
	TokenStaleSec            int
	ValidPlayerNameRegex     string

	FallbackAPIServers           []FallbackAPIServerConfig
	ImportExistingPlayer         []importExistingPlayerConfig
	RegistrationOIDC             []RegistrationOIDCConfig
	RegistrationUsernamePassword regUsernamePasswordConfig
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
var defaultCreateNewPlayerConfig = createNewPlayerConfig{
	Allow:             false,
	AllowChoosingUUID: false,
}

var DefaultRistrettoConfig = &ristretto.Config{
	// Defaults from https://pkg.go.dev/github.com/dgraph-io/ristretto#readme-config
	NumCounters: 1e7,
	MaxCost:     1 << 30, // 1 GiB
	BufferItems: 64,
}

func defaultFallbackAPIServer() FallbackAPIServerConfig {
	return FallbackAPIServerConfig{
		CacheTTLSeconds:      600,
		DenyUnknownUsers:     false,
		EnableAuthentication: true,
		SkinDomains:          []string{},
		ForwardSkins:         true,
	}
}

func defaultRegistrationOIDC() RegistrationOIDCConfig {
	return RegistrationOIDCConfig{
		AllowChoosingPlayerName: true,
		PKCE:                    true,
	}
}

func defaultRegCreateNewPlayer() regCreateNewPlayerConfig {
	return regCreateNewPlayerConfig{
		createNewPlayerConfig: createNewPlayerConfig{
			Allow:             true,
			AllowChoosingUUID: false,
		},
		RequireInvite: false,
	}
}

func defaultImportExistingPlayer() importExistingPlayerConfig {
	return importExistingPlayerConfig{
		FallbackAPIServerNickname: "",
		RequireSkinVerification:   false,
	}
}

func defaultImportExistingPlayerReg() regImportExistingPlayerConfig {
	return regImportExistingPlayerConfig{
		importExistingPlayerConfig: defaultImportExistingPlayer(), RequireInvite: false,
	}
}

func DefaultConfig() Config {
	return Config{
		AllowCapes:               true,
		AllowChangingPlayerName:  true,
		AllowPasswordLogin:       true,
		AllowSkins:               true,
		AllowTextureFromURL:      false,
		ApplicationName:          "Drasl",
		ApplicationOwner:         "Anonymous",
		BaseURL:                  "",
		BlockedServers:           []string{},
		BodyLimit:                defaultBodyLimitConfig,
		CORSAllowOrigins:         []string{},
		CreateNewPlayer:          defaultCreateNewPlayerConfig,
		DataDirectory:            GetDefaultDataDirectory(),
		DefaultAdmins:            []string{},
		DefaultMaxPlayerCount:    1,
		DefaultPreferredLanguage: "en",
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
		ClassicPublicIP:          "",
		RateLimit:                defaultRateLimitConfig,
		RequestCache:             *DefaultRistrettoConfig,
		SignPublicKeys:           true,
		SkinSizeLimit:            64,
		StateDirectory:           GetDefaultStateDirectory(),
		TokenExpireSec:           0,
		TokenStaleSec:            0,
		ValidPlayerNameRegex:     "^[a-zA-Z0-9_]+$",

		FallbackAPIServers:   []FallbackAPIServerConfig{},
		ImportExistingPlayer: []importExistingPlayerConfig{},
		RegistrationOIDC:     []RegistrationOIDCConfig{},
		RegistrationUsernamePassword: regUsernamePasswordConfig{
			CreateNewPlayer: defaultRegCreateNewPlayer(),
		},
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
		return "", fmt.Errorf("invalid %s: %s", key, err)
	}

	punycodeHost, err := idna.ToASCII(parsedURL.Host)
	if err != nil {
		return "", fmt.Errorf("invalid %s: %s", key, err)
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
		return "", fmt.Errorf("invalid %s: %s", key, err)
	}
	return punycoded, nil
}

func cleanRegCreateNewPlayer(raw *rawRegCreateNewPlayerConfig) regCreateNewPlayerConfig {
	defaultCreateNewPlayerStruct := defaultRegCreateNewPlayer()
	if raw == nil {
		return defaultCreateNewPlayerStruct
	}
	return regCreateNewPlayerConfig{
		createNewPlayerConfig: createNewPlayerConfig{
			Allow:             orElse(raw.Allow, defaultCreateNewPlayerStruct.Allow),
			AllowChoosingUUID: orElse(raw.AllowChoosingUUID, defaultCreateNewPlayerStruct.AllowChoosingUUID),
		},
		RequireInvite: orElse(raw.RequireInvite, defaultCreateNewPlayerStruct.RequireInvite),
	}
}

type Deprecation struct {
	Path    string
	Message string
}

func cleanRegImportExistingPlayers(key string, fallbackAPIServerNicknames mapset.Set[string], rawConfigs []rawRegImportExistingPlayerConfig) ([]regImportExistingPlayerConfig, error) {
	defaultImportExistingPlayerStruct := defaultImportExistingPlayerReg()

	importExistingPlayerConfigs := make([]regImportExistingPlayerConfig, 0, len(rawConfigs))

	for _, rawImportExistingPlayer := range rawConfigs {
		fallbackAPIServerNickname := orElse(rawImportExistingPlayer.FallbackAPIServerNickname, defaultImportExistingPlayerStruct.FallbackAPIServerNickname)
		if fallbackAPIServerNickname == "" {
			return []regImportExistingPlayerConfig{}, fmt.Errorf("%s FallbackAPIServerNickname must be set", key)
		}
		if !fallbackAPIServerNicknames.Contains(fallbackAPIServerNickname) {
			return []regImportExistingPlayerConfig{}, fmt.Errorf("%s references unknown FallbackAPIServer Nickname: %s", key, fallbackAPIServerNickname)
		}
		importExistingPlayerConfigs = append(importExistingPlayerConfigs, regImportExistingPlayerConfig{
			importExistingPlayerConfig: importExistingPlayerConfig{
				FallbackAPIServerNickname: fallbackAPIServerNickname,
				RequireSkinVerification:   orElse(rawImportExistingPlayer.RequireSkinVerification, defaultImportExistingPlayerStruct.RequireSkinVerification),
			},
			RequireInvite: orElse(rawImportExistingPlayer.RequireInvite, defaultImportExistingPlayerStruct.RequireInvite),
		})
	}
	return importExistingPlayerConfigs, nil
}

func CleanConfig(rawConfig *RawConfig) (Config, []Deprecation, error) {
	defaults := DefaultConfig()
	deprecations := []Deprecation{}

	rateLimit := defaults.RateLimit
	if rawRateLimit := rawConfig.RateLimit; rawRateLimit != nil {
		rateLimit.Enable = orElse(rawRateLimit.Enable, defaults.RateLimit.Enable)
		rateLimit.RequestsPerSecond = orElse(rawRateLimit.RequestsPerSecond, defaults.RateLimit.RequestsPerSecond)
		rateLimit.Burst = orElse(rawRateLimit.Burst, defaults.RateLimit.Burst)
	}

	bodyLimit := defaults.BodyLimit
	if rawBodyLimit := rawConfig.BodyLimit; rawBodyLimit != nil {
		bodyLimit.Enable = orElse(rawBodyLimit.Enable, defaults.BodyLimit.Enable)
		bodyLimit.SizeLimitKiB = orElse(rawBodyLimit.SizeLimitKiB, defaults.BodyLimit.SizeLimitKiB)
	}

	createNewPlayer := defaults.CreateNewPlayer
	if rawCreateNewPlayer := rawConfig.CreateNewPlayer; rawCreateNewPlayer != nil {
		createNewPlayer.Allow = orElse(rawCreateNewPlayer.Allow, defaults.CreateNewPlayer.Allow)
		createNewPlayer.AllowChoosingUUID = orElse(rawCreateNewPlayer.AllowChoosingUUID, defaults.CreateNewPlayer.AllowChoosingUUID)
	}

	requestCache := defaults.RequestCache
	if rawRequestCache := rawConfig.RequestCache; rawRequestCache != nil {
		requestCache.NumCounters = orElse(rawRequestCache.NumCounters, defaults.RequestCache.NumCounters)
		requestCache.MaxCost = orElse(rawRequestCache.MaxCost, defaults.RequestCache.MaxCost)
		requestCache.BufferItems = orElse(rawRequestCache.BufferItems, defaults.RequestCache.BufferItems)
	}

	baseURL := orElse(rawConfig.BaseURL, defaults.BaseURL)
	var err error
	baseURL, err = cleanURL("BaseURL", mo.Some("https://drasl.example.com"), baseURL, true)
	if err != nil {
		return Config{}, nil, err
	}

	defaultPreferredLanguage := orElse(rawConfig.DefaultPreferredLanguage, defaults.DefaultPreferredLanguage)
	if !IsValidPreferredLanguage(defaultPreferredLanguage) {
		return Config{}, nil, fmt.Errorf("invalid DefaultPreferredLanguage %s", defaultPreferredLanguage)
	}

	domain := orElse(rawConfig.Domain, defaults.Domain)
	if domain == "" {
		return Config{}, nil, errors.New("Domain must be set to a valid fully qualified domain name. Example: drasl.example.com")
	}
	domain, err = cleanDomain(
		"Domain",
		mo.Some("drasl.example.com"),
		domain,
	)
	if err != nil {
		return Config{}, nil, err
	}

	instanceName := orElse(rawConfig.InstanceName, defaults.InstanceName)
	if instanceName == "" {
		return Config{}, nil, errors.New("InstanceName must be set")
	}

	listenAddress := orElse(rawConfig.ListenAddress, defaults.ListenAddress)
	if listenAddress == "" {
		return Config{}, nil, errors.New("ListenAddress must be set. Example: 0.0.0.0:25585")
	}

	defaultMaxPlayerCount := orElse(rawConfig.DefaultMaxPlayerCount, defaults.DefaultMaxPlayerCount)
	if defaultMaxPlayerCount < 0 && defaultMaxPlayerCount != Constants.MaxPlayerCountUnlimited {
		return Config{}, nil, fmt.Errorf("DefaultMaxPlayerCount must be >= 0, or %d to indicate unlimited players", Constants.MaxPlayerCountUnlimited)
	}

	playerUUIDGeneration := orElse(rawConfig.PlayerUUIDGeneration, defaults.PlayerUUIDGeneration)
	switch playerUUIDGeneration {
	case PlayerUUIDGenerationRandom:
	case PlayerUUIDGenerationOffline:
	default:
		return Config{}, nil, errors.New(`PlayerUUIDGeneration must be either "random" or "offline"`)
	}

	{
		// Deprecated in 4.0.0
		if rawConfig.ForwardSkins != nil {
			deprecations = append(deprecations, Deprecation{"ForwardSkins", "The global version of this option is deprecated. Instead, set the ForwardSkins option on individual FallbackAPIServers."})
		}
	}

	fallbackAPIServers := []FallbackAPIServerConfig{}
	fallbackAPIServerNicknames := mapset.NewSet[string]()

	var synthesizedRawFallbackAPIServer *rawFallbackAPIServerConfig = nil
	effectiveFallbackAPIServers := rawConfig.FallbackAPIServers
	{
		// [ImportExistingPlayer] deprecated in 4.0.0
		// Migrate the deprecated single-table [ImportExistingPlayer] form. When
		// present, emit a deprecation and, if Allow = true, synthesize a matching
		// [[FallbackAPIServers]] entry from the legacy inline URLs (unless one
		// with the same Nickname is already defined).
		if legacy := rawConfig.ImportExistingPlayer.Legacy; legacy != nil {
			deprecations = append(deprecations, Deprecation{
				Path:    "ImportExistingPlayer",
				Message: "The single-table [ImportExistingPlayer] form is deprecated. Use [[ImportExistingPlayer]] with FallbackAPIServerNickname, and define the API server in [[FallbackAPIServers]].",
			})
			if legacy.Allow {
				if legacy.Nickname == "" {
					return Config{}, nil, errors.New("ImportExistingPlayer.Nickname must be set when ImportExistingPlayer.Allow = true")
				}
				nicknameAlreadyDefined := false
				for _, fb := range rawConfig.FallbackAPIServers {
					if fb.Nickname != nil && *fb.Nickname == legacy.Nickname {
						nicknameAlreadyDefined = true
						break
					}
				}
				if !nicknameAlreadyDefined {
					synthesizedRawFallbackAPIServer = &rawFallbackAPIServerConfig{
						Nickname:    Ptr(legacy.Nickname),
						SessionURL:  Ptr(legacy.SessionURL),
						AccountURL:  Ptr(legacy.AccountURL),
						ServicesURL: Ptr("https://api.minecraftservices.com"),
						SetSkinURL:  Ptr(legacy.SetSkinURL),
					}
					effectiveFallbackAPIServers = append(
						append([]rawFallbackAPIServerConfig{}, rawConfig.FallbackAPIServers...),
						*synthesizedRawFallbackAPIServer,
					)
				}
			}
		}
	}

	for _, rawFallbackAPIServer := range PtrSlice(effectiveFallbackAPIServers) {
		fallbackAPIServerDefault := defaultFallbackAPIServer()

		nickname := orElse(rawFallbackAPIServer.Nickname, fallbackAPIServerDefault.Nickname)
		if nickname == "" {
			return Config{}, nil, errors.New("FallbackAPIServer Nickname must be set")
		}
		if fallbackAPIServerNicknames.Contains(nickname) {
			return Config{}, nil, fmt.Errorf("duplicate FallbackAPIServer Nickname: %s", nickname)
		}
		fallbackAPIServerNicknames.Add(nickname)

		sessionURL := orElse(rawFallbackAPIServer.SessionURL, fallbackAPIServerDefault.SessionURL)
		sessionURL, err = cleanURL(
			fmt.Sprintf("FallbackAPIServer %s SessionURL", nickname),
			mo.Some("https://sessionserver.mojang.com"),
			sessionURL, true,
		)
		if err != nil {
			return Config{}, nil, err
		}

		accountURL := orElse(rawFallbackAPIServer.AccountURL, fallbackAPIServerDefault.AccountURL)
		accountURL, err = cleanURL(
			fmt.Sprintf("FallbackAPIServer %s AccountURL", nickname),
			mo.Some("https://api.mojang.com"),
			accountURL, true,
		)
		if err != nil {
			return Config{}, nil, err
		}

		servicesURL := orElse(rawFallbackAPIServer.ServicesURL, fallbackAPIServerDefault.ServicesURL)
		servicesURL, err = cleanURL(
			fmt.Sprintf("FallbackAPIServer %s ServicesURL", nickname),
			mo.Some("https://api.minecraftservices.com"),
			servicesURL, true,
		)
		if err != nil {
			return Config{}, nil, err
		}

		setSkinURL := orElse(rawFallbackAPIServer.SetSkinURL, fallbackAPIServerDefault.SetSkinURL)
		setSkinURL, err = cleanURL(
			fmt.Sprintf("FallbackAPIServer %s SetSkinURL", nickname),
			mo.None[string](),
			setSkinURL, true,
		)
		if err != nil {
			return Config{}, nil, err
		}

		skinDomains := orElse(rawFallbackAPIServer.SkinDomains, fallbackAPIServerDefault.SkinDomains)
		for _, skinDomain := range PtrSlice(skinDomains) {
			*skinDomain, err = cleanDomain(
				fmt.Sprintf("FallbackAPIServer %s SkinDomains", nickname),
				mo.Some("textures.minecraft.net"),
				*skinDomain,
			)
			if err != nil {
				return Config{}, nil, err
			}
		}

		forwardSkins := fallbackAPIServerDefault.ForwardSkins
		{
			// ForwardSkins deprecated in 4.0.0
			if rawConfig.ForwardSkins != nil {
				forwardSkins = *rawConfig.ForwardSkins
			}
		}
		fallbackAPIServers = append(fallbackAPIServers, FallbackAPIServerConfig{
			Nickname:             nickname,
			SessionURL:           sessionURL,
			AccountURL:           accountURL,
			ServicesURL:          servicesURL,
			SkinDomains:          skinDomains,
			CacheTTLSeconds:      orElse(rawFallbackAPIServer.CacheTTLSeconds, fallbackAPIServerDefault.CacheTTLSeconds),
			DenyUnknownUsers:     orElse(rawFallbackAPIServer.DenyUnknownUsers, fallbackAPIServerDefault.DenyUnknownUsers),
			EnableAuthentication: orElse(rawFallbackAPIServer.EnableAuthentication, fallbackAPIServerDefault.EnableAuthentication),
			ForwardSkins:         orElse(rawFallbackAPIServer.ForwardSkins, forwardSkins),
			SetSkinURL:           setSkinURL,
		})
	}

	{
		// RegistrationNewPlayer deprecated in 4.0.0
		if rawConfig.RegistrationNewPlayer != nil {
			deprecations = append(deprecations, Deprecation{
				"RegistrationNewPlayer",
				"Replaced by RegistrationUsernamePassword.CreateNewPlayer and RegistrationOIDC.CreateNewPlayer",
			})
		}
		// RegistrationExistingPlayer deprecated in 4.0.0
		if rawConfig.RegistrationExistingPlayer != nil {
			deprecations = append(deprecations, Deprecation{
				"RegistrationExistingPlayer",
				"Replaced by RegistrationUsernamePassword.ImportExistingPlayer and RegistrationOIDC.ImportExistingPlayer",
			})
		}
	}

	var registrationUsernamePassword regUsernamePasswordConfig
	if rawConfig.RegistrationUsernamePassword != nil {
		createNewPlayer := cleanRegCreateNewPlayer(rawConfig.RegistrationUsernamePassword.CreateNewPlayer)
		importExistingPlayerConfigs, err := cleanRegImportExistingPlayers(
			"RegistrationUsernamePassword.ImportExistingPlayer",
			fallbackAPIServerNicknames,
			rawConfig.RegistrationUsernamePassword.ImportExistingPlayer,
		)
		if err != nil {
			return Config{}, nil, err
		}

		registrationUsernamePassword = regUsernamePasswordConfig{
			CreateNewPlayer:      createNewPlayer,
			ImportExistingPlayer: importExistingPlayerConfigs,
		}
	} else {
		createNewPlayer := defaultRegCreateNewPlayer()
		importExistingPlayer := []regImportExistingPlayerConfig{}
		{
			// RegistrationNewPlayer deprecated in 4.0.0
			if rawConfig.RegistrationNewPlayer != nil {
				createNewPlayer.Allow = orElse(rawConfig.RegistrationNewPlayer.Allow, true)
				createNewPlayer.RequireInvite = orElse(rawConfig.RegistrationNewPlayer.RequireInvite, false)
			}
			// RegistrationExistingPlayer deprecated in 4.0.0
			if rawConfig.RegistrationExistingPlayer != nil && synthesizedRawFallbackAPIServer != nil && rawConfig.ImportExistingPlayer.Legacy != nil {
				if rawConfig.RegistrationExistingPlayer.Allow != nil && *rawConfig.RegistrationExistingPlayer.Allow {
					importExistingPlayer = append(importExistingPlayer, regImportExistingPlayerConfig{
						importExistingPlayerConfig: importExistingPlayerConfig{
							FallbackAPIServerNickname: orElse(synthesizedRawFallbackAPIServer.Nickname, ""),
							RequireSkinVerification:   rawConfig.ImportExistingPlayer.Legacy.RequireSkinVerification,
						},
						RequireInvite: orElse(rawConfig.RegistrationExistingPlayer.RequireInvite, false),
					})
				}
			}
		}
		registrationUsernamePassword = regUsernamePasswordConfig{
			CreateNewPlayer:      createNewPlayer,
			ImportExistingPlayer: importExistingPlayer,
		}
	}

	defaultImportExistingPlayerStruct := defaultImportExistingPlayer()
	importExistingPlayer := []importExistingPlayerConfig{}
	for _, rawImportExistingPlayer := range rawConfig.ImportExistingPlayer.Entries {
		fallbackAPIServerNickname := orElse(rawImportExistingPlayer.FallbackAPIServerNickname, defaultImportExistingPlayerStruct.FallbackAPIServerNickname)
		if fallbackAPIServerNickname == "" {
			return Config{}, nil, errors.New("ImportExistingPlayer.FallbackAPIServerNickname must be set")
		}
		if !fallbackAPIServerNicknames.Contains(fallbackAPIServerNickname) {
			return Config{}, nil, fmt.Errorf("ImportExistingPlayer references unknown FallbackAPIServer Nickname: %s", fallbackAPIServerNickname)
		}
		requireSkinVerification := orElse(rawImportExistingPlayer.RequireSkinVerification, defaultImportExistingPlayerStruct.RequireSkinVerification)
		importExistingPlayer = append(importExistingPlayer, importExistingPlayerConfig{
			FallbackAPIServerNickname: fallbackAPIServerNickname,
			RequireSkinVerification:   requireSkinVerification,
		})
	}

	// AllowAddingDeletingPlayers deprecated in 4.0.0
	{
		if rawConfig.AllowAddingDeletingPlayers != nil {
			deprecations = append(deprecations, Deprecation{
				Path:    "AllowAddingDeletingPlayers",
				Message: "Now controlled solely by CreateNewPlayer.Allow and the presence of ImportExistingPlayer",
			})
			if !*rawConfig.AllowAddingDeletingPlayers {
				createNewPlayer.Allow = false
				importExistingPlayer = []importExistingPlayerConfig{}
			}
		}
	}

	regOIDC := []RegistrationOIDCConfig{}
	regOIDCNames := mapset.NewSet[string]()
	for _, rawRegistrationOIDCConfig := range PtrSlice(rawConfig.RegistrationOIDC) {
		if rawRegistrationOIDCConfig.ClientSecret != nil && rawRegistrationOIDCConfig.ClientSecretFile != nil {
			return Config{}, nil, errors.New("can't supply both a ClientSecret and a ClientSecretFile")
		}
		clientSecret := orElse(rawRegistrationOIDCConfig.ClientSecret, "")
		if rawRegistrationOIDCConfig.ClientSecretFile != nil {
			value, err := loadSecretFromFile(*rawRegistrationOIDCConfig.ClientSecretFile)
			if err != nil {
				return Config{}, nil, fmt.Errorf("couldn't read ClientSecretFile: %w", err)
			}
			clientSecret = value
		}

		name := orElse(rawRegistrationOIDCConfig.Name, "")
		if name == "" {
			return Config{}, nil, errors.New("RegistrationOIDC Name must be set")
		}
		if regOIDCNames.Contains(name) {
			return Config{}, nil, fmt.Errorf("duplicate RegistrationOIDC Name: %s", name)
		}
		regOIDCNames.Add(name)

		issuer := orElse(rawRegistrationOIDCConfig.Issuer, "")
		issuer, err = cleanURL(
			fmt.Sprintf("RegistrationOIDC %s Issuer", name),
			mo.Some("https://idm.example.com/oauth2/openid/drasl"),
			issuer,
			false,
		)
		if err != nil {
			return Config{}, nil, err
		}

		clientID := orElse(rawRegistrationOIDCConfig.ClientID, "")
		registrationOIDCDefault := defaultRegistrationOIDC()
		pkce := orElse(rawRegistrationOIDCConfig.PKCE, registrationOIDCDefault.PKCE)
		allowChoosingPlayerName := orElse(rawRegistrationOIDCConfig.AllowChoosingPlayerName, registrationOIDCDefault.AllowChoosingPlayerName)

		{
			// RegistrationOIDC.RequireInvite deprecated in 4.0.0
			if rawRegistrationOIDCConfig.RequireInvite != nil {
				deprecations = append(deprecations, Deprecation{
					Path:    "RegistrationOIDC.RequireInvite",
					Message: "Replaced by RegistrationOIDC.CreateNewPlayer.RequireInvite and RegistrationOIDC.ImportExistingPlayer.RequireInvite",
				})
			}
		}

		createNewPlayer := cleanRegCreateNewPlayer(rawRegistrationOIDCConfig.CreateNewPlayer)
		{
			// RegistrationNewPlayer deprecated in 4.0.0
			// RegistrationOIDC.RequireInvite deprecated in 4.0.0
			if rawRegistrationOIDCConfig.CreateNewPlayer == nil {
				if rawConfig.RegistrationNewPlayer != nil {
					createNewPlayer.Allow = orElse(rawConfig.RegistrationNewPlayer.Allow, createNewPlayer.Allow)
				}
				globalRequireInvite := false
				if rawConfig.RegistrationNewPlayer != nil {
					globalRequireInvite = orElse(rawConfig.RegistrationNewPlayer.RequireInvite, false)
				}
				perOIDCRequireInvite := orElse(rawRegistrationOIDCConfig.RequireInvite, false)
				createNewPlayer.RequireInvite = globalRequireInvite || perOIDCRequireInvite
			}
		}
		importExistingPlayerConfigs, err := cleanRegImportExistingPlayers(
			fmt.Sprintf("RegistrationOIDC %s ImportExistingPlayer", name),
			fallbackAPIServerNicknames,
			rawRegistrationOIDCConfig.ImportExistingPlayer,
		)
		if err != nil {
			return Config{}, nil, err
		}
		{
			// RegistrationExistingPlayer deprecated in 4.0.0
			// RegistrationOIDC.RequireInvite deprecated in 4.0.0
			if len(importExistingPlayerConfigs) == 0 &&
				rawConfig.RegistrationExistingPlayer != nil &&
				synthesizedRawFallbackAPIServer != nil &&
				rawConfig.ImportExistingPlayer.Legacy != nil {
				if orElse(rawConfig.RegistrationExistingPlayer.Allow, false) {
					globalRequireInvite := orElse(rawConfig.RegistrationExistingPlayer.RequireInvite, false)
					perOIDCRequireInvite := orElse(rawRegistrationOIDCConfig.RequireInvite, false)
					importExistingPlayerConfigs = append(importExistingPlayerConfigs, regImportExistingPlayerConfig{
						importExistingPlayerConfig: importExistingPlayerConfig{
							FallbackAPIServerNickname: *synthesizedRawFallbackAPIServer.Nickname,
							RequireSkinVerification:   rawConfig.ImportExistingPlayer.Legacy.RequireSkinVerification,
						},
						RequireInvite: globalRequireInvite || perOIDCRequireInvite,
					})
				}
			}
		}

		regOIDC = append(regOIDC, RegistrationOIDCConfig{
			Name:                    name,
			Issuer:                  issuer,
			ClientID:                clientID,
			ClientSecret:            clientSecret,
			PKCE:                    pkce,
			AllowChoosingPlayerName: allowChoosingPlayerName,
			CreateNewPlayer:         createNewPlayer,
			ImportExistingPlayer:    importExistingPlayerConfigs,
		})
	}

	return Config{
		AllowCapes:               orElse(rawConfig.AllowCapes, defaults.AllowCapes),
		AllowChangingPlayerName:  orElse(rawConfig.AllowChangingPlayerName, defaults.AllowChangingPlayerName),
		AllowPasswordLogin:       orElse(rawConfig.AllowPasswordLogin, defaults.AllowPasswordLogin),
		AllowSkins:               orElse(rawConfig.AllowSkins, defaults.AllowSkins),
		AllowTextureFromURL:      orElse(rawConfig.AllowTextureFromURL, defaults.AllowTextureFromURL),
		ApplicationName:          orElse(rawConfig.ApplicationName, defaults.ApplicationName),
		ApplicationOwner:         orElse(rawConfig.ApplicationOwner, defaults.ApplicationOwner),
		BaseURL:                  baseURL,
		BlockedServers:           orElse(rawConfig.BlockedServers, defaults.BlockedServers),
		BodyLimit:                bodyLimit,
		CORSAllowOrigins:         orElse(rawConfig.CORSAllowOrigins, defaults.CORSAllowOrigins),
		CreateNewPlayer:          createNewPlayer,
		DataDirectory:            orElse(rawConfig.DataDirectory, defaults.DataDirectory),
		DefaultAdmins:            orElse(rawConfig.DefaultAdmins, defaults.DefaultAdmins),
		DefaultMaxPlayerCount:    defaultMaxPlayerCount,
		DefaultPreferredLanguage: defaultPreferredLanguage,
		Domain:                   domain,
		EnableBackgroundEffect:   orElse(rawConfig.EnableBackgroundEffect, defaults.EnableBackgroundEffect),
		EnableFooter:             orElse(rawConfig.EnableFooter, defaults.EnableFooter),
		EnableWebFrontEnd:        orElse(rawConfig.EnableWebFrontEnd, defaults.EnableWebFrontEnd),
		InstanceName:             instanceName,
		ListenAddress:            listenAddress,
		LogRequests:              orElse(rawConfig.LogRequests, defaults.LogRequests),
		MinPasswordLength:        orElse(rawConfig.MinPasswordLength, defaults.MinPasswordLength),
		OfflineSkins:             orElse(rawConfig.OfflineSkins, defaults.OfflineSkins),
		PlayerUUIDGeneration:     playerUUIDGeneration,
		PreMigrationBackups:      orElse(rawConfig.PreMigrationBackups, defaults.PreMigrationBackups),
		ClassicPublicIP:          orElse(rawConfig.ClassicPublicIP, defaults.ClassicPublicIP),
		RateLimit:                rateLimit,
		RequestCache:             requestCache,
		SignPublicKeys:           orElse(rawConfig.SignPublicKeys, defaults.SignPublicKeys),
		SkinSizeLimit:            orElse(rawConfig.SkinSizeLimit, defaults.SkinSizeLimit),
		StateDirectory:           orElse(rawConfig.StateDirectory, defaults.StateDirectory),
		TokenExpireSec:           orElse(rawConfig.TokenExpireSec, defaults.TokenExpireSec),
		TokenStaleSec:            orElse(rawConfig.TokenStaleSec, defaults.TokenStaleSec),
		ValidPlayerNameRegex:     orElse(rawConfig.ValidPlayerNameRegex, defaults.ValidPlayerNameRegex),

		FallbackAPIServers:           fallbackAPIServers,
		RegistrationOIDC:             regOIDC,
		RegistrationUsernamePassword: registrationUsernamePassword,
		ImportExistingPlayer:         importExistingPlayer,
	}, deprecations, nil
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
Domain = "CHANGEME"

# Example: https://drasl.example.com
BaseURL = "https://CHANGEME"

# List of usernames who automatically become admins of the Drasl instance
DefaultAdmins = [""]

# UUIDs of new players match their player UUIDs in online-mode=false servers
PlayerUUIDGeneration = "offline"

# Registration with username and password is allowed but requires an invite
[RegistrationUsernamePassword.CreateNewPlayer]
Allow = true
RequireInvite = true
`

func ReadConfig(path string, createIfNotExists bool) (Config, []Deprecation, []toml.Key, error) {
	rawConfig := RawConfig{}

	_, err := os.Stat(path)
	if err != nil {
		if !createIfNotExists {
			return Config{}, nil, nil, err
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

	unknownKeys := []toml.Key{}
	for _, key := range metadata.Undecoded() {
		unknownKeys = append(unknownKeys, key)
	}

	config, deprecations, err := CleanConfig(&rawConfig)
	if err != nil {
		return Config{}, nil, nil, err
	}

	return config, deprecations, unknownKeys, nil
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
