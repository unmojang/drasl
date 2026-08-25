package main

import (
	"github.com/BurntSushi/toml"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func configTestRawConfig(stateDirectory string) RawConfig {
	return RawConfig{
		BaseURL:        Ptr("https://drasl.example.com"),
		Domain:         Ptr("drasl.example.com"),
		RateLimit:      &rawRateLimitConfig{Enable: Ptr(false)},
		LogRequests:    Ptr(false),
		StateDirectory: Ptr(stateDirectory),
		DataDirectory:  Ptr("."),
	}
}

func assertClean(t *testing.T, rawConfig RawConfig) {
	_, deprecations, err := CleanConfig(&rawConfig)
	assert.Empty(t, deprecations)
	assert.Nil(t, err)
}

func assertUnclean(t *testing.T, rawConfig RawConfig) {
	_, deprecations, err := CleanConfig(&rawConfig)
	assert.Empty(t, deprecations)
	assert.NotNil(t, err)
}

func TestConfig(t *testing.T) {
	t.Parallel()
	sd := Unwrap(os.MkdirTemp("", "tmp"))
	defer os.RemoveAll(sd)

	rawConfig := configTestRawConfig(sd)
	assertClean(t, rawConfig)

	rawConfig = configTestRawConfig(sd)
	rawConfig.BaseURL = Ptr("https://δρασλ.example.com/")
	rawConfig.Domain = Ptr("δρασλ.example.com")
	config, deprecations, err := CleanConfig(&rawConfig)
	assert.Nil(t, err)
	assert.Empty(t, deprecations)
	assert.Equal(t, "https://xn--mxafwwl.example.com", config.BaseURL)
	assert.Equal(t, "xn--mxafwwl.example.com", config.Domain)

	rawConfig = configTestRawConfig(sd)
	rawConfig.BaseURL = Ptr("")
	assertUnclean(t, rawConfig)

	rawConfig = configTestRawConfig(sd)
	rawConfig.BaseURL = Ptr(":an invalid URL")
	assertUnclean(t, rawConfig)

	rawConfig = configTestRawConfig(sd)
	rawConfig.DefaultPreferredLanguage = Ptr("xx")
	assertUnclean(t, rawConfig)

	rawConfig = configTestRawConfig(sd)
	rawConfig.Domain = Ptr("")
	assertUnclean(t, rawConfig)

	rawConfig = configTestRawConfig(sd)
	rawConfig.InstanceName = Ptr("")
	assertUnclean(t, rawConfig)

	rawConfig = configTestRawConfig(sd)
	rawConfig.ListenAddress = Ptr("")
	assertUnclean(t, rawConfig)

	rawConfig = configTestRawConfig(sd)
	rawConfig.DefaultMaxPlayerCount = Ptr(Constants.MaxPlayerCountUseDefault)
	assertUnclean(t, rawConfig)

	rawConfig = configTestRawConfig(sd)
	rawConfig.DefaultMaxPlayerCount = Ptr(Constants.MaxPlayerCountUnlimited)
	assertClean(t, rawConfig)

	rawConfig = configTestRawConfig(sd)
	rawConfig.MaxPlayerNameLength = Ptr(0)
	assertUnclean(t, rawConfig)

	rawConfig = configTestRawConfig(sd)
	rawConfig.MinPlayerNameLength = Ptr(0)
	assertUnclean(t, rawConfig)

	rawConfig = configTestRawConfig(sd)
	rawConfig.MinPlayerNameLength = Ptr(5)
	rawConfig.MaxPlayerNameLength = Ptr(4)
	assertUnclean(t, rawConfig)

	rawConfig = configTestRawConfig(sd)
	rawConfig.MinPlayerNameLength = Ptr(4)
	rawConfig.MaxPlayerNameLength = Ptr(4)
	assertClean(t, rawConfig)

	// Missing state directory should be ignored
	rawConfig = configTestRawConfig(sd)
	rawConfig.StateDirectory = Ptr("/tmp/DraslInvalidStateDirectoryNothingHere")
	assertClean(t, rawConfig)

	rawConfig = configTestRawConfig(sd)
	rawConfig.FallbackAPIServers = []rawFallbackAPIServerConfig{
		{
			Nickname:    Ptr("Example"),
			SessionURL:  Ptr("https://δρασλ.example.com/"),
			AccountURL:  Ptr("https://drasl.example.com/"),
			ServicesURL: Ptr("https://drasl.example.com/"),
			SetSkinURL:  Ptr("https://drasl.example.com/editskin"),
		},
	}
	rawConfig.RegistrationUsernamePassword = &rawRegUsernamePasswordConfig{
		CreateNewPlayer: &rawRegCreateNewPlayerConfig{rawCreateNewPlayerConfig: rawCreateNewPlayerConfig{Allow: Ptr(true)}},
		ImportExistingPlayer: []rawRegImportExistingPlayerConfig{
			{FallbackAPIServerNickname: Ptr("Example"), RequireSkinVerification: Ptr(true)},
		},
	}
	config, deprecations, err = CleanConfig(&rawConfig)
	assert.Nil(t, err)
	assert.Empty(t, deprecations)
	assert.True(t, config.FallbackAPIServers[0].URLs.IsArg3())
	assert.Equal(t, "https://drasl.example.com/editskin", config.FallbackAPIServers[0].SetSkinURL)
	assert.True(t, config.RegistrationUsernamePassword.CreateNewPlayer.Allow)
	assert.Equal(t, 1, len(config.RegistrationUsernamePassword.ImportExistingPlayer))
	assert.Equal(t, "Example", config.RegistrationUsernamePassword.ImportExistingPlayer[0].FallbackAPIServerNickname)
	assert.True(t, config.RegistrationUsernamePassword.ImportExistingPlayer[0].RequireSkinVerification)

	// FallbackAPIServer player name rules are unset by default
	rawConfig = configTestRawConfig(sd)
	rawConfig.FallbackAPIServers = []rawFallbackAPIServerConfig{
		{Nickname: Ptr("Example"), AuthlibInjectorURL: Ptr("https://example.com/yggdrasil")},
	}
	config, deprecations, err = CleanConfig(&rawConfig)
	assert.Nil(t, err)
	assert.Empty(t, deprecations)
	assert.True(t, config.FallbackAPIServers[0].ValidPlayerNameRegex.IsAbsent())
	assert.True(t, config.FallbackAPIServers[0].MinPlayerNameLength.IsAbsent())
	assert.True(t, config.FallbackAPIServers[0].MaxPlayerNameLength.IsAbsent())

	rawConfig = configTestRawConfig(sd)
	rawConfig.FallbackAPIServers = []rawFallbackAPIServerConfig{
		{Nickname: Ptr("Example"), AuthlibInjectorURL: Ptr("https://example.com/yggdrasil"), ValidPlayerNameRegex: Ptr("^[a-zA-Z0-9_]+$"), MinPlayerNameLength: Ptr(3), MaxPlayerNameLength: Ptr(16)},
	}
	assertClean(t, rawConfig)

	rawConfig = configTestRawConfig(sd)
	rawConfig.FallbackAPIServers = []rawFallbackAPIServerConfig{
		{Nickname: Ptr("Example"), AuthlibInjectorURL: Ptr("https://example.com/yggdrasil"), ValidPlayerNameRegex: Ptr("^[a-z")},
	}
	assertUnclean(t, rawConfig)

	rawConfig = configTestRawConfig(sd)
	rawConfig.FallbackAPIServers = []rawFallbackAPIServerConfig{
		{Nickname: Ptr("Example"), AuthlibInjectorURL: Ptr("https://example.com/yggdrasil"), MinPlayerNameLength: Ptr(0)},
	}
	assertUnclean(t, rawConfig)

	rawConfig = configTestRawConfig(sd)
	rawConfig.FallbackAPIServers = []rawFallbackAPIServerConfig{
		{Nickname: Ptr("Example"), AuthlibInjectorURL: Ptr("https://example.com/yggdrasil"), MinPlayerNameLength: Ptr(17), MaxPlayerNameLength: Ptr(16)},
	}
	assertUnclean(t, rawConfig)

	// ImportExistingPlayer with unknown FallbackAPIServerNickname should fail
	rawConfig = configTestRawConfig(sd)
	rawConfig.FallbackAPIServers = []rawFallbackAPIServerConfig{
		{Nickname: Ptr("Example"), SessionURL: Ptr("https://example.com"), AccountURL: Ptr("https://example.com"), ServicesURL: Ptr("https://example.com")},
	}
	rawConfig.RegistrationUsernamePassword = &rawRegUsernamePasswordConfig{
		ImportExistingPlayer: []rawRegImportExistingPlayerConfig{
			{FallbackAPIServerNickname: Ptr("Nonexistent")},
		},
	}
	assertUnclean(t, rawConfig)

	// New [[ImportExistingPlayer]] array-of-tables form: no deprecation.
	rawConfig = configTestRawConfig(sd)
	rawConfig.FallbackAPIServers = []rawFallbackAPIServerConfig{
		{Nickname: Ptr("Mojang"), SessionURL: Ptr("https://sessionserver.mojang.com"), AccountURL: Ptr("https://api.mojang.com"), ServicesURL: Ptr("https://api.minecraftservices.com")},
	}
	rawConfig.ImportExistingPlayer = rawImportExistingPlayer{
		Entries: []rawImportExistingPlayerConfig{
			{FallbackAPIServerNickname: Ptr("Mojang"), RequireSkinVerification: Ptr(true)},
		},
	}
	config, deprecations, err = CleanConfig(&rawConfig)
	assert.Nil(t, err)
	assert.Empty(t, deprecations)
	assert.Equal(t, 1, len(config.ImportExistingPlayer))
	assert.Equal(t, "Mojang", config.ImportExistingPlayer[0].FallbackAPIServerNickname)
	assert.True(t, config.ImportExistingPlayer[0].RequireSkinVerification)

	// Unmarshaler: TOML snippets should populate Entries/Legacy as expected.
	decodeImportExistingPlayer := func(snippet string) rawImportExistingPlayer {
		var rc struct {
			ImportExistingPlayer rawImportExistingPlayer `toml:"ImportExistingPlayer"`
		}
		_, err := toml.Decode(snippet, &rc)
		assert.Nil(t, err)
		return rc.ImportExistingPlayer
	}

	legacyFromTOML := decodeImportExistingPlayer(`[ImportExistingPlayer]
Allow = true
Nickname = "Mojang"
SessionURL = "https://sessionserver.mojang.com"
AccountURL = "https://api.mojang.com"
SetSkinURL = "https://www.minecraft.net/msaprofile/mygames/editskin"
RequireSkinVerification = true
`)
	assert.NotNil(t, legacyFromTOML.Legacy)
	assert.True(t, legacyFromTOML.Legacy.Allow)
	assert.Equal(t, "Mojang", legacyFromTOML.Legacy.Nickname)
	assert.Equal(t, "https://sessionserver.mojang.com", legacyFromTOML.Legacy.SessionURL)
	assert.Equal(t, 1, len(legacyFromTOML.Entries))
	assert.Equal(t, "Mojang", *legacyFromTOML.Entries[0].FallbackAPIServerNickname)
	assert.True(t, *legacyFromTOML.Entries[0].RequireSkinVerification)

	legacyAllowFalse := decodeImportExistingPlayer(`[ImportExistingPlayer]
Allow = false
Nickname = "Mojang"
`)
	assert.NotNil(t, legacyAllowFalse.Legacy)
	assert.False(t, legacyAllowFalse.Legacy.Allow)
	assert.Equal(t, 0, len(legacyAllowFalse.Entries))

	newFormFromTOML := decodeImportExistingPlayer(`[[ImportExistingPlayer]]
FallbackAPIServerNickname = "Ely.by"
RequireSkinVerification = false

[[ImportExistingPlayer]]
FallbackAPIServerNickname = "Mojang"
RequireSkinVerification = true
`)
	assert.Nil(t, newFormFromTOML.Legacy)
	assert.Equal(t, 2, len(newFormFromTOML.Entries))
	assert.Equal(t, "Ely.by", *newFormFromTOML.Entries[0].FallbackAPIServerNickname)
	assert.False(t, *newFormFromTOML.Entries[0].RequireSkinVerification)
	assert.Equal(t, "Mojang", *newFormFromTOML.Entries[1].FallbackAPIServerNickname)
	assert.True(t, *newFormFromTOML.Entries[1].RequireSkinVerification)

	// Test that TEMPLATE_CONFIG_FILE is valid
	var templateConfig Config
	_, err = toml.Decode(TEMPLATE_CONFIG_FILE, &templateConfig)
	assert.Nil(t, err)

	// Test that the example configs are valid
	_, deprecations, unknownKeys, err := ReadConfig("example/config-example.toml", false)
	assert.Empty(t, deprecations)
	assert.Empty(t, unknownKeys)
	assert.Nil(t, err)

	// The example configs should all be the same
	correctBytes, err := os.ReadFile("example/config-example.toml")
	assert.Nil(t, err)

	configBytes, err := os.ReadFile("example/docker/config/config.toml")
	assert.Nil(t, err)
	assert.Equal(t, correctBytes, configBytes)

	configBytes, err = os.ReadFile("example/docker-caddy/config/config.toml")
	assert.Nil(t, err)
	assert.Equal(t, correctBytes, configBytes)
}

// findDeprecation returns the Deprecation with the given Path, or nil.
func findDeprecation(deprecations []Deprecation, path string) *Deprecation {
	for i := range deprecations {
		if deprecations[i].Path == path {
			return &deprecations[i]
		}
	}
	return nil
}

// hasDeprecation reports whether a Deprecation with the given Path was emitted.
func hasDeprecation(deprecations []Deprecation, path string) bool {
	return findDeprecation(deprecations, path) != nil
}

func TestConfigDeprecations(t *testing.T) {
	t.Parallel()
	sd := Unwrap(os.MkdirTemp("", "tmp"))
	defer os.RemoveAll(sd)

	// ForwardSkins (deprecated in 4.0.0)

	// The global ForwardSkins is still respected if a FallbackAPIServer does
	// not set FallbackAPIServer.ForwardSkins
	{
		rawConfig := configTestRawConfig(sd)
		rawConfig.ForwardSkins = Ptr(false)
		rawConfig.FallbackAPIServers = []rawFallbackAPIServerConfig{
			{Nickname: Ptr("Mojang"), SessionURL: Ptr("https://sessionserver.mojang.com"), AccountURL: Ptr("https://api.mojang.com"), ServicesURL: Ptr("https://api.minecraftservices.com")},
		}
		config, deprecations, err := CleanConfig(&rawConfig)
		assert.Nil(t, err)
		assert.True(t, hasDeprecation(deprecations, "ForwardSkins"))
		assert.False(t, config.FallbackAPIServers[0].ForwardSkins)
	}

	// FallbackAPIServer.ForwardSkins wins over ForwardSkins
	{
		rawConfig := configTestRawConfig(sd)
		rawConfig.ForwardSkins = Ptr(false)
		rawConfig.FallbackAPIServers = []rawFallbackAPIServerConfig{
			{Nickname: Ptr("Mojang"), SessionURL: Ptr("https://sessionserver.mojang.com"), AccountURL: Ptr("https://api.mojang.com"), ServicesURL: Ptr("https://api.minecraftservices.com"), ForwardSkins: Ptr(true)},
		}
		config, deprecations, err := CleanConfig(&rawConfig)
		assert.Nil(t, err)
		assert.True(t, hasDeprecation(deprecations, "ForwardSkins"))
		assert.True(t, config.FallbackAPIServers[0].ForwardSkins)
	}

	// AllowAddingDeletingPlayers (deprecated in 4.0.0)

	// AllowAddingDeletingPlayers = false overrides CreateNewPlayer.Allow to
	// false and clears ImportExistingPlayer entries.
	{
		rawConfig := configTestRawConfig(sd)
		rawConfig.AllowAddingDeletingPlayers = Ptr(false)
		rawConfig.FallbackAPIServers = []rawFallbackAPIServerConfig{
			{Nickname: Ptr("Mojang"), SessionURL: Ptr("https://sessionserver.mojang.com"), AccountURL: Ptr("https://api.mojang.com"), ServicesURL: Ptr("https://api.minecraftservices.com")},
		}
		rawConfig.ImportExistingPlayer = rawImportExistingPlayer{
			Entries: []rawImportExistingPlayerConfig{
				{FallbackAPIServerNickname: Ptr("Mojang"), RequireSkinVerification: Ptr(true)},
			},
		}
		config, deprecations, err := CleanConfig(&rawConfig)
		assert.Nil(t, err)
		assert.True(t, hasDeprecation(deprecations, "AllowAddingDeletingPlayers"))
		assert.False(t, config.CreateNewPlayer.Allow)
		assert.Equal(t, 0, len(config.ImportExistingPlayer))
	}

	// AllowAddingDeletingPlayers = true is a no-op, but the deprecation is
	// still emitted.
	{
		rawConfig := configTestRawConfig(sd)
		rawConfig.AllowAddingDeletingPlayers = Ptr(true)
		config, deprecations, err := CleanConfig(&rawConfig)
		assert.Nil(t, err)
		assert.True(t, hasDeprecation(deprecations, "AllowAddingDeletingPlayers"))
		assert.False(t, config.CreateNewPlayer.Allow)
	}

	// RegistrationNewPlayer (deprecated in 4.0.0)

	// RegistrationNewPlayer migrates to RegistrationUsernamePassword.CreateNewPlayer
	// when RegistrationUsernamePassword is absent.
	{
		rawConfig := configTestRawConfig(sd)
		rawConfig.RegistrationNewPlayer = &rawRegistrationNewPlayerConfig{
			Allow:         Ptr(false),
			RequireInvite: Ptr(true),
		}
		config, deprecations, err := CleanConfig(&rawConfig)
		assert.Nil(t, err)
		assert.True(t, hasDeprecation(deprecations, "RegistrationNewPlayer"))
		assert.False(t, config.RegistrationUsernamePassword.CreateNewPlayer.Allow)
		assert.True(t, config.RegistrationUsernamePassword.CreateNewPlayer.RequireInvite)
	}

	// When RegistrationUsernamePassword.CreateNewPlayer is explicitly set, the
	// deprecated RegistrationNewPlayer is ignored for the username/password
	// provider (but the deprecation is still emitted).
	{
		rawConfig := configTestRawConfig(sd)
		rawConfig.RegistrationNewPlayer = &rawRegistrationNewPlayerConfig{
			Allow:         Ptr(false),
			RequireInvite: Ptr(true),
		}
		rawConfig.RegistrationUsernamePassword = &rawRegUsernamePasswordConfig{
			CreateNewPlayer: &rawRegCreateNewPlayerConfig{
				rawCreateNewPlayerConfig: rawCreateNewPlayerConfig{Allow: Ptr(true)},
				RequireInvite:            Ptr(false),
			},
		}
		config, deprecations, err := CleanConfig(&rawConfig)
		assert.Nil(t, err)
		assert.True(t, hasDeprecation(deprecations, "RegistrationNewPlayer"))
		assert.True(t, config.RegistrationUsernamePassword.CreateNewPlayer.Allow)
		assert.False(t, config.RegistrationUsernamePassword.CreateNewPlayer.RequireInvite)
	}

	// RegistrationExistingPlayer (deprecated in 4.0.0)

	// RegistrationExistingPlayer with Allow = true migrates to
	// RegistrationUsernamePassword.ImportExistingPlayer only when the legacy
	// [ImportExistingPlayer] form (with Allow = true) is also present, so a
	// synthesized FallbackAPIServer exists to reference.
	{
		rawConfig := configTestRawConfig(sd)
		rawConfig.RegistrationExistingPlayer = &rawRegistrationExistingPlayerConfig{
			Allow:         Ptr(true),
			RequireInvite: Ptr(true),
		}
		rawConfig.ImportExistingPlayer = rawImportExistingPlayer{
			Legacy: &legacyImportExistingPlayer{
				Allow:                   true,
				Nickname:                "Mojang",
				SessionURL:              "https://sessionserver.mojang.com",
				AccountURL:              "https://api.mojang.com",
				SetSkinURL:              "https://www.minecraft.net/msaprofile/mygames/editskin",
				RequireSkinVerification: true,
			},
			Entries: []rawImportExistingPlayerConfig{{
				FallbackAPIServerNickname: Ptr("Mojang"),
				RequireSkinVerification:   Ptr(true),
			}},
		}
		config, deprecations, err := CleanConfig(&rawConfig)
		assert.Nil(t, err)
		assert.True(t, hasDeprecation(deprecations, "RegistrationExistingPlayer"))
		assert.True(t, hasDeprecation(deprecations, "ImportExistingPlayer"))
		assert.Equal(t, 1, len(config.RegistrationUsernamePassword.ImportExistingPlayer))
		ep := config.RegistrationUsernamePassword.ImportExistingPlayer[0]
		assert.Equal(t, "Mojang", ep.FallbackAPIServerNickname)
		assert.True(t, ep.RequireSkinVerification)
		assert.True(t, ep.RequireInvite)
	}

	// RegistrationExistingPlayer with Allow = false produces no
	// ImportExistingPlayer entry (but deprecation is emitted).
	{
		rawConfig := configTestRawConfig(sd)
		rawConfig.RegistrationExistingPlayer = &rawRegistrationExistingPlayerConfig{
			Allow:         Ptr(false),
			RequireInvite: Ptr(true),
		}
		rawConfig.ImportExistingPlayer = rawImportExistingPlayer{
			Legacy: &legacyImportExistingPlayer{
				Allow:      true,
				Nickname:   "Mojang",
				SessionURL: "https://sessionserver.mojang.com",
				AccountURL: "https://api.mojang.com",
			},
			Entries: []rawImportExistingPlayerConfig{{
				FallbackAPIServerNickname: Ptr("Mojang"),
			}},
		}
		config, deprecations, err := CleanConfig(&rawConfig)
		assert.Nil(t, err)
		assert.True(t, hasDeprecation(deprecations, "RegistrationExistingPlayer"))
		assert.Equal(t, 0, len(config.RegistrationUsernamePassword.ImportExistingPlayer))
	}

	// RegistrationExistingPlayer without the legacy ImportExistingPlayer form
	// does not migrate (no synthesized FallbackAPIServer to reference).
	{
		rawConfig := configTestRawConfig(sd)
		rawConfig.RegistrationExistingPlayer = &rawRegistrationExistingPlayerConfig{
			Allow:         Ptr(true),
			RequireInvite: Ptr(true),
		}
		config, deprecations, err := CleanConfig(&rawConfig)
		assert.Nil(t, err)
		assert.True(t, hasDeprecation(deprecations, "RegistrationExistingPlayer"))
		assert.Equal(t, 0, len(config.RegistrationUsernamePassword.ImportExistingPlayer))
	}

	// RegistrationOIDC.RequireInvite (deprecated in 4.0.0)

	// RegistrationOIDC.RequireInvite migrates to
	// RegistrationOIDC.CreateNewPlayer.RequireInvite
	{
		rawConfig := configTestRawConfig(sd)
		rawConfig.RegistrationOIDC = []rawRegistrationOIDCConfig{
			{Name: Ptr("oidc1"), Issuer: Ptr("https://idm.example.com"), RequireInvite: Ptr(true)},
		}
		config, deprecations, err := CleanConfig(&rawConfig)
		assert.Nil(t, err)
		assert.True(t, hasDeprecation(deprecations, "RegistrationOIDC.RequireInvite"))
		assert.Equal(t, 1, len(config.RegistrationOIDC))
		assert.True(t, config.RegistrationOIDC[0].CreateNewPlayer.RequireInvite)
	}

	// Invite required for OIDC registration with new player when
	// RegistrationNewPlayer.RequireInvite = false and
	// RegistrationOIDC.RequireInvite = true
	{
		rawConfig := configTestRawConfig(sd)
		rawConfig.RegistrationNewPlayer = &rawRegistrationNewPlayerConfig{
			Allow:         Ptr(true),
			RequireInvite: Ptr(false),
		}
		rawConfig.RegistrationOIDC = []rawRegistrationOIDCConfig{
			{Name: Ptr("oidc1"), Issuer: Ptr("https://idm.example.com"), RequireInvite: Ptr(true)},
		}
		config, deprecations, err := CleanConfig(&rawConfig)
		assert.Nil(t, err)
		assert.True(t, hasDeprecation(deprecations, "RegistrationOIDC.RequireInvite"))
		assert.True(t, config.RegistrationOIDC[0].CreateNewPlayer.RequireInvite)
	}

	// Invite required for OIDC registration with new player when
	// RegistrationNewPlayer.RequireInvite = true and
	// RegistrationOIDC.RequireInvite = false
	{
		rawConfig := configTestRawConfig(sd)
		rawConfig.RegistrationNewPlayer = &rawRegistrationNewPlayerConfig{
			Allow:         Ptr(true),
			RequireInvite: Ptr(true),
		}
		rawConfig.RegistrationOIDC = []rawRegistrationOIDCConfig{
			{Name: Ptr("oidc1"), Issuer: Ptr("https://idm.example.com"), RequireInvite: Ptr(false)},
		}
		config, deprecations, err := CleanConfig(&rawConfig)
		assert.Nil(t, err)
		assert.True(t, hasDeprecation(deprecations, "RegistrationOIDC.RequireInvite"))
		assert.True(t, config.RegistrationOIDC[0].CreateNewPlayer.RequireInvite)
	}

	// RegistrationOIDC.CreateNewPlayer.RequireInvite wins over
	// RegistrationOIDC.RequireInvite
	{
		rawConfig := configTestRawConfig(sd)
		rawConfig.RegistrationOIDC = []rawRegistrationOIDCConfig{
			{
				Name:            Ptr("oidc1"),
				Issuer:          Ptr("https://idm.example.com"),
				RequireInvite:   Ptr(true),
				CreateNewPlayer: &rawRegCreateNewPlayerConfig{RequireInvite: Ptr(false)},
			},
		}
		config, deprecations, err := CleanConfig(&rawConfig)
		assert.Nil(t, err)
		assert.True(t, hasDeprecation(deprecations, "RegistrationOIDC.RequireInvite"))
		assert.False(t, config.RegistrationOIDC[0].CreateNewPlayer.RequireInvite)
	}

	// Invite required for synthesized RegistrationOIDC.ImportExistingPlayer
	// when RegistrationOIDC.RequireInvite = true and
	// RegistrationExistingPlayer.RequireInvite = false
	{
		rawConfig := configTestRawConfig(sd)
		rawConfig.RegistrationExistingPlayer = &rawRegistrationExistingPlayerConfig{
			Allow:         Ptr(true),
			RequireInvite: Ptr(false),
		}
		rawConfig.ImportExistingPlayer = rawImportExistingPlayer{
			Legacy: &legacyImportExistingPlayer{
				Allow:      true,
				Nickname:   "Mojang",
				SessionURL: "https://sessionserver.mojang.com",
				AccountURL: "https://api.mojang.com",
			},
			Entries: []rawImportExistingPlayerConfig{{FallbackAPIServerNickname: Ptr("Mojang")}},
		}
		rawConfig.RegistrationOIDC = []rawRegistrationOIDCConfig{
			{Name: Ptr("oidc1"), Issuer: Ptr("https://idm.example.com"), RequireInvite: Ptr(true)},
		}
		config, deprecations, err := CleanConfig(&rawConfig)
		assert.Nil(t, err)
		assert.True(t, hasDeprecation(deprecations, "RegistrationOIDC.RequireInvite"))
		assert.Equal(t, 1, len(config.RegistrationOIDC))
		oidc := config.RegistrationOIDC[0]
		assert.Equal(t, 1, len(oidc.ImportExistingPlayer))
		assert.True(t, oidc.ImportExistingPlayer[0].RequireInvite)
		assert.Equal(t, "Mojang", oidc.ImportExistingPlayer[0].FallbackAPIServerNickname)
	}

	// Invite required for synthesized RegistrationOIDC.ImportExistingPlayer
	// when RegistrationOIDC.RequireInvite = false and
	// RegistrationExistingPlayer.RequireInvite = true
	{
		rawConfig := configTestRawConfig(sd)
		rawConfig.RegistrationExistingPlayer = &rawRegistrationExistingPlayerConfig{
			Allow:         Ptr(true),
			RequireInvite: Ptr(true),
		}
		rawConfig.ImportExistingPlayer = rawImportExistingPlayer{
			Legacy: &legacyImportExistingPlayer{
				Allow:      true,
				Nickname:   "Mojang",
				SessionURL: "https://sessionserver.mojang.com",
				AccountURL: "https://api.mojang.com",
			},
			Entries: []rawImportExistingPlayerConfig{{FallbackAPIServerNickname: Ptr("Mojang")}},
		}
		rawConfig.RegistrationOIDC = []rawRegistrationOIDCConfig{
			{Name: Ptr("oidc1"), Issuer: Ptr("https://idm.example.com"), RequireInvite: Ptr(false)},
		}
		config, deprecations, err := CleanConfig(&rawConfig)
		assert.Nil(t, err)
		assert.True(t, hasDeprecation(deprecations, "RegistrationOIDC.RequireInvite"))
		oidc := config.RegistrationOIDC[0]
		assert.Equal(t, 1, len(oidc.ImportExistingPlayer))
		assert.True(t, oidc.ImportExistingPlayer[0].RequireInvite)
	}

	// Legacy [ImportExistingPlayer] single-table form (deprecated in 4.0.0)

	// Legacy form with Allow = true and no matching [[FallbackAPIServers]]
	// entry: synthesize one, emit a deprecation.
	{
		rawConfig := configTestRawConfig(sd)
		rawConfig.ImportExistingPlayer = rawImportExistingPlayer{
			Legacy: &legacyImportExistingPlayer{
				Allow:                   true,
				Nickname:                "Mojang",
				SessionURL:              "https://sessionserver.mojang.com",
				AccountURL:              "https://api.mojang.com",
				SetSkinURL:              "https://www.minecraft.net/msaprofile/mygames/editskin",
				RequireSkinVerification: true,
			},
			Entries: []rawImportExistingPlayerConfig{{
				FallbackAPIServerNickname: Ptr("Mojang"),
				RequireSkinVerification:   Ptr(true),
			}},
		}
		config, deprecations, err := CleanConfig(&rawConfig)
		assert.Nil(t, err)
		assert.True(t, hasDeprecation(deprecations, "ImportExistingPlayer"))
		assert.Len(t, deprecations, 1)
		assert.Equal(t, 1, len(config.FallbackAPIServers))
		assert.Equal(t, "Mojang", config.FallbackAPIServers[0].Nickname)
		legacy2 := config.FallbackAPIServers[0].URLs.MustArg3()
		assert.Equal(t, "https://sessionserver.mojang.com", legacy2.SessionURL)
		assert.Equal(t, "https://api.mojang.com", legacy2.AccountURL)
		assert.Equal(t, "https://www.minecraft.net/msaprofile/mygames/editskin", config.FallbackAPIServers[0].SetSkinURL)
		assert.Equal(t, 1, len(config.ImportExistingPlayer))
		assert.Equal(t, "Mojang", config.ImportExistingPlayer[0].FallbackAPIServerNickname)
		assert.True(t, config.ImportExistingPlayer[0].RequireSkinVerification)
	}

	// Legacy form with Allow = true and a matching [[FallbackAPIServers]]
	// entry: do not duplicate the entry; reference the existing one.
	{
		rawConfig := configTestRawConfig(sd)
		rawConfig.FallbackAPIServers = []rawFallbackAPIServerConfig{
			{Nickname: Ptr("Mojang"), SessionURL: Ptr("https://sessionserver.mojang.com"), AccountURL: Ptr("https://api.mojang.com"), ServicesURL: Ptr("https://api.minecraftservices.com")},
		}
		rawConfig.ImportExistingPlayer = rawImportExistingPlayer{
			Legacy: &legacyImportExistingPlayer{
				Allow:                   true,
				Nickname:                "Mojang",
				SessionURL:              "https://sessionserver.mojang.com",
				AccountURL:              "https://api.mojang.com",
				RequireSkinVerification: true,
			},
			Entries: []rawImportExistingPlayerConfig{{
				FallbackAPIServerNickname: Ptr("Mojang"),
				RequireSkinVerification:   Ptr(true),
			}},
		}
		config, deprecations, err := CleanConfig(&rawConfig)
		assert.Nil(t, err)
		assert.True(t, hasDeprecation(deprecations, "ImportExistingPlayer"))
		assert.Len(t, deprecations, 1)
		assert.Equal(t, 1, len(config.FallbackAPIServers))
		legacy3 := config.FallbackAPIServers[0].URLs.MustArg3()
		assert.Equal(t, "https://api.minecraftservices.com", legacy3.ServicesURL)
		assert.Equal(t, 1, len(config.ImportExistingPlayer))
	}

	// Legacy form with Allow = false: no entries, no synthesized
	// FallbackAPIServer.
	{
		rawConfig := configTestRawConfig(sd)
		rawConfig.ImportExistingPlayer = rawImportExistingPlayer{
			Legacy: &legacyImportExistingPlayer{Allow: false},
		}
		config, deprecations, err := CleanConfig(&rawConfig)
		assert.Nil(t, err)
		assert.True(t, hasDeprecation(deprecations, "ImportExistingPlayer"))
		assert.Len(t, deprecations, 1)
		assert.Equal(t, 0, len(config.FallbackAPIServers))
		assert.Equal(t, 0, len(config.ImportExistingPlayer))
	}

	// Legacy form with Allow = true but empty Nickname should fail.
	{
		rawConfig := configTestRawConfig(sd)
		rawConfig.ImportExistingPlayer = rawImportExistingPlayer{
			Legacy: &legacyImportExistingPlayer{Allow: true, Nickname: ""},
		}
		assertUnclean(t, rawConfig)
	}

	// All deprecated options together

	// A fully old-style config exercises every migration path at once.
	{
		rawConfig := configTestRawConfig(sd)
		rawConfig.ForwardSkins = Ptr(false)
		rawConfig.AllowAddingDeletingPlayers = Ptr(true)
		rawConfig.RegistrationNewPlayer = &rawRegistrationNewPlayerConfig{
			Allow:         Ptr(true),
			RequireInvite: Ptr(true),
		}
		rawConfig.RegistrationExistingPlayer = &rawRegistrationExistingPlayerConfig{
			Allow:         Ptr(true),
			RequireInvite: Ptr(false),
		}
		rawConfig.ImportExistingPlayer = rawImportExistingPlayer{
			Legacy: &legacyImportExistingPlayer{
				Allow:                   true,
				Nickname:                "Mojang",
				SessionURL:              "https://sessionserver.mojang.com",
				AccountURL:              "https://api.mojang.com",
				SetSkinURL:              "https://www.minecraft.net/msaprofile/mygames/editskin",
				RequireSkinVerification: true,
			},
			Entries: []rawImportExistingPlayerConfig{{
				FallbackAPIServerNickname: Ptr("Mojang"),
				RequireSkinVerification:   Ptr(true),
			}},
		}
		rawConfig.RegistrationOIDC = []rawRegistrationOIDCConfig{
			{Name: Ptr("oidc1"), Issuer: Ptr("https://idm.example.com"), RequireInvite: Ptr(true)},
		}
		config, deprecations, err := CleanConfig(&rawConfig)
		assert.Nil(t, err)
		// Every deprecated option should be flagged.
		assert.True(t, hasDeprecation(deprecations, "ForwardSkins"))
		assert.True(t, hasDeprecation(deprecations, "AllowAddingDeletingPlayers"))
		assert.True(t, hasDeprecation(deprecations, "RegistrationNewPlayer"))
		assert.True(t, hasDeprecation(deprecations, "RegistrationExistingPlayer"))
		assert.True(t, hasDeprecation(deprecations, "ImportExistingPlayer"))
		assert.True(t, hasDeprecation(deprecations, "RegistrationOIDC.RequireInvite"))
		// Synthesized FallbackAPIServer from legacy ImportExistingPlayer.
		assert.Equal(t, 1, len(config.FallbackAPIServers))
		assert.False(t, config.FallbackAPIServers[0].ForwardSkins) // global false migrated
		// RegistrationUsernamePassword.ImportExistingPlayer got the migrated entry.
		assert.Equal(t, 1, len(config.RegistrationUsernamePassword.ImportExistingPlayer))
		// Username/password CreateNewPlayer migrated from RegistrationNewPlayer.
		assert.True(t, config.RegistrationUsernamePassword.CreateNewPlayer.Allow)
		assert.True(t, config.RegistrationUsernamePassword.CreateNewPlayer.RequireInvite)
		// OIDC CreateNewPlayer.RequireInvite via OR (global true || per-OIDC true).
		assert.True(t, config.RegistrationOIDC[0].CreateNewPlayer.RequireInvite)
		// OIDC ImportExistingPlayer migrated with OR (global false || per-OIDC true).
		assert.Equal(t, 1, len(config.RegistrationOIDC[0].ImportExistingPlayer))
		assert.True(t, config.RegistrationOIDC[0].ImportExistingPlayer[0].RequireInvite)
	}
}

func TestConfigFallbackAPIServerURLs(t *testing.T) {
	t.Parallel()
	sd := Unwrap(os.MkdirTemp("", "tmp"))
	defer os.RemoveAll(sd)

	// AuthlibInjectorURL form
	{
		rawConfig := configTestRawConfig(sd)
		rawConfig.FallbackAPIServers = []rawFallbackAPIServerConfig{
			{Nickname: Ptr("ALI"), AuthlibInjectorURL: Ptr("https://littleskin.cn/api/yggdrasil/")},
		}
		config, deprecations, err := CleanConfig(&rawConfig)
		assert.Nil(t, err)
		assert.Empty(t, deprecations)
		assert.True(t, config.FallbackAPIServers[0].URLs.IsArg2())
		assert.Equal(t, "https://littleskin.cn/api/yggdrasil", config.FallbackAPIServers[0].URLs.MustArg2().AuthlibInjectorURL)
	}
	{
		rawConfig := configTestRawConfig(sd)
		rawConfig.FallbackAPIServers = []rawFallbackAPIServerConfig{
			{Nickname: Ptr("ALI"), AuthlibInjectorURL: Ptr("https://δρασλ.example.com/")},
		}
		config, _, err := CleanConfig(&rawConfig)
		assert.Nil(t, err)
		assert.Equal(t, "https://xn--mxafwwl.example.com", config.FallbackAPIServers[0].URLs.MustArg2().AuthlibInjectorURL)
	}
	{
		rawConfig := configTestRawConfig(sd)
		rawConfig.FallbackAPIServers = []rawFallbackAPIServerConfig{
			{Nickname: Ptr("ALI"), AuthlibInjectorURL: Ptr(":invalid")},
		}
		assertUnclean(t, rawConfig)
	}
	{
		rawConfig := configTestRawConfig(sd)
		rawConfig.FallbackAPIServers = []rawFallbackAPIServerConfig{
			{Nickname: Ptr("ALI"), AuthlibInjectorURL: Ptr("")},
		}
		assertUnclean(t, rawConfig)
	}

	// DiscoveryMinecraftClientURL form
	{
		rawConfig := configTestRawConfig(sd)
		rawConfig.FallbackAPIServers = []rawFallbackAPIServerConfig{
			{Nickname: Ptr("Discovery"), DiscoveryMinecraftClientURL: Ptr("https://discovery.minecraftservices.com/minecraft/client/")},
		}
		config, deprecations, err := CleanConfig(&rawConfig)
		assert.Nil(t, err)
		assert.Empty(t, deprecations)
		assert.True(t, config.FallbackAPIServers[0].URLs.IsArg1())
		assert.Equal(t, "https://discovery.minecraftservices.com/minecraft/client", config.FallbackAPIServers[0].URLs.MustArg1().DiscoveryMinecraftClientURL)
	}
	{
		rawConfig := configTestRawConfig(sd)
		rawConfig.FallbackAPIServers = []rawFallbackAPIServerConfig{
			{Nickname: Ptr("Discovery"), DiscoveryMinecraftClientURL: Ptr("https://δρασλ.example.com/minecraft/client")},
		}
		config, _, err := CleanConfig(&rawConfig)
		assert.Nil(t, err)
		assert.Equal(t, "https://xn--mxafwwl.example.com/minecraft/client", config.FallbackAPIServers[0].URLs.MustArg1().DiscoveryMinecraftClientURL)
	}
	{
		rawConfig := configTestRawConfig(sd)
		rawConfig.FallbackAPIServers = []rawFallbackAPIServerConfig{
			{Nickname: Ptr("Discovery"), DiscoveryMinecraftClientURL: Ptr(":invalid")},
		}
		assertUnclean(t, rawConfig)
	}

	// Legacy form
	{
		rawConfig := configTestRawConfig(sd)
		rawConfig.FallbackAPIServers = []rawFallbackAPIServerConfig{
			{
				Nickname:    Ptr("Legacy"),
				SessionURL:  Ptr("https://δρασλ.example.com/"),
				AccountURL:  Ptr("https://δρασλ.example.com/"),
				ServicesURL: Ptr("https://δρασλ.example.com/"),
				SkinDomains: Ptr([]string{"δρασλ.example.com"}),
			},
		}
		config, deprecations, err := CleanConfig(&rawConfig)
		assert.Nil(t, err)
		assert.Empty(t, deprecations)
		assert.True(t, config.FallbackAPIServers[0].URLs.IsArg3())
		legacy := config.FallbackAPIServers[0].URLs.MustArg3()
		assert.Equal(t, "https://xn--mxafwwl.example.com", legacy.SessionURL)
		assert.Equal(t, "https://xn--mxafwwl.example.com", legacy.AccountURL)
		assert.Equal(t, "https://xn--mxafwwl.example.com", legacy.ServicesURL)
		assert.Equal(t, []string{"xn--mxafwwl.example.com"}, legacy.SkinDomains)
	}
	{
		rawConfig := configTestRawConfig(sd)
		rawConfig.FallbackAPIServers = []rawFallbackAPIServerConfig{
			{
				Nickname:    Ptr("Legacy"),
				SessionURL:  Ptr(":invalid"),
				AccountURL:  Ptr("https://api.mojang.com"),
				ServicesURL: Ptr("https://api.minecraftservices.com"),
			},
		}
		assertUnclean(t, rawConfig)
	}
	{
		rawConfig := configTestRawConfig(sd)
		rawConfig.FallbackAPIServers = []rawFallbackAPIServerConfig{
			{
				Nickname:    Ptr(""),
				SessionURL:  Ptr("https://sessionserver.mojang.com"),
				AccountURL:  Ptr("https://api.mojang.com"),
				ServicesURL: Ptr("https://api.minecraftservices.com"),
			},
		}
		assertUnclean(t, rawConfig)
	}

	// The three forms are mutually exclusive.
	{
		rawConfig := configTestRawConfig(sd)
		rawConfig.FallbackAPIServers = []rawFallbackAPIServerConfig{
			{
				Nickname:           Ptr("Both"),
				SessionURL:         Ptr("https://sessionserver.mojang.com"),
				AccountURL:         Ptr("https://api.mojang.com"),
				ServicesURL:        Ptr("https://api.minecraftservices.com"),
				AuthlibInjectorURL: Ptr("https://littleskin.cn/api/yggdrasil"),
			},
		}
		_, _, err := CleanConfig(&rawConfig)
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "legacy URLs and AuthlibInjectorURL")
	}
	{
		rawConfig := configTestRawConfig(sd)
		rawConfig.FallbackAPIServers = []rawFallbackAPIServerConfig{
			{
				Nickname:                    Ptr("Both"),
				SessionURL:                  Ptr("https://sessionserver.mojang.com"),
				AccountURL:                  Ptr("https://api.mojang.com"),
				ServicesURL:                 Ptr("https://api.minecraftservices.com"),
				DiscoveryMinecraftClientURL: Ptr("https://discovery.minecraftservices.com/minecraft/client"),
			},
		}
		_, _, err := CleanConfig(&rawConfig)
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "legacy URLs and DiscoveryMinecraftClientURL")
	}
	{
		rawConfig := configTestRawConfig(sd)
		rawConfig.FallbackAPIServers = []rawFallbackAPIServerConfig{
			{
				Nickname:                    Ptr("Both"),
				AuthlibInjectorURL:          Ptr("https://littleskin.cn/api/yggdrasil"),
				DiscoveryMinecraftClientURL: Ptr("https://discovery.minecraftservices.com/minecraft/client"),
			},
		}
		_, _, err := CleanConfig(&rawConfig)
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "AuthlibInjectorURL and DiscoveryMinecraftClientURL")
	}

	// None supplied
	{
		rawConfig := configTestRawConfig(sd)
		rawConfig.FallbackAPIServers = []rawFallbackAPIServerConfig{
			{Nickname: Ptr("Lonely")},
		}
		_, _, err := CleanConfig(&rawConfig)
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "must supply either an AuthlibInjectorURL, a DiscoveryMinecraftClientURL, or legacy URLs")
	}
}
