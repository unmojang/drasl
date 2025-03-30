# Recipes

This document is intended to exhibit the variety of use cases Drasl can support.
Each example includes a complete configuration file and may be used as a starting place to configure your own instance.

See [configuration.md](./configuration.md) for detailed documentation of each config option.

### Example 1: Basic, minimal setup

- Private and standalone: does not interact with any other API servers
- Registering a new account requires an invite from an admin
- Users can choose their player's UUID when they register, useful for migrating from Mojang accounts

```
Domain = "drasl.example.com"          # CHANGE ME!
BaseURL = "https://drasl.example.com" # CHANGE ME!
DefaultAdmins = ["myusername"]        # CHANGE ME!

[CreateNewPlayer]
  AllowChoosingUUID = true

[RegistrationNewPlayer]
  Allow = true
  RequireInvite = true
```

### Example 2: Mojang-dependent

- Users can register a new account only if they verify ownership of a Mojang account. Their account will be assigned the UUID of the Mojang account, so servers will see them as the same player. (`RegistrationExistingPlayer`, `RegistrationExistingPlayer.RequireSkinVerification`).
- Clients logged in with _either_ Drasl _or_ Mojang will be able to play on the same server (`FallbackAPIServers`, `ForwardSkins`).
- Drasl players will be able to see Mojang players' skins (but not vice-versa) (`[[FallbackAPIServers]]`, `ForwardSkins`).
- Useful for public instances wanting to limit registration.

<details>
<summary>Show config.toml</summary>

```
Domain = "drasl.example.com"          # CHANGE ME!
BaseURL = "https://drasl.example.com" # CHANGE ME!
DefaultAdmins = ["myusername"]        # CHANGE ME!

ForwardSkins = true
AllowChangingPlayerName = false

[RegistrationNewPlayer]
  Allow = false

[ImportExistingPlayer]
  Allow = true
  Nickname = "Mojang"
  SessionURL = "https://sessionserver.mojang.com"
  AccountURL = "https://api.mojang.com"
  SetSkinURL = "https://www.minecraft.net/msaprofile/mygames/editskin"
  RequireSkinVerification = true

[RegistrationExistingPlayer]
  Allow = true

[[FallbackAPIServers]]
  Nickname = "Mojang"
  SessionURL = "https://sessionserver.mojang.com"
  AccountURL = "https://api.mojang.com"
  ServicesURL = "https://api.minecraftservices.com"
  SkinDomains = ["textures.minecraft.net"]
  CacheTTLSeconds = 60
```

</details>

### Example 3: Proxy multiple authentication servers

- Allow users to authenticate with either an Ely.by account or a Blessing Skin account (`[[FallbackAPIServers]]`)
- Players logged in with Ely.by unfortunately won't see the skins of players logged in with Blessing Skin, and vice versa. You might be able to fix that by using [CustomSkinLoader](https://github.com/xfl03/MCCustomSkinLoader) to have the clients load skins through Drasl.
- Registration is disabled (`RegistrationNewPlayer.Allow`)
- **Warning**: Fallback API Servers are tried in the order they are listed in the config file. A malicious user may be able to impersonate a user on the second-listed Fallback API Server by making an account on the first-listed Fallback API Server with the same username (or possibly even the same UUID).

<details>
<summary>Show config.toml</summary>

```
Domain = "drasl.example.com"          # CHANGE ME!
BaseURL = "https://drasl.example.com" # CHANGE ME!
DefaultAdmins = ["myusername"]        # CHANGE ME!

[RegistrationNewPlayer]
  Allow = false

[[FallbackAPIServers]]
  Nickname = "Ely.by"
  SessionURL = "https://account.ely.by/api/authlib-injector/sessionserver"
  AccountURL = "https://account.ely.by/api"
  ServicesURL = "https://account.ely.by/api/authlib-injector/minecraftservices"
  SkinDomains = ["ely.by", ".ely.by"]
  CacheTTLSeconds = 60

[[FallbackAPIServers]]
  Nickname = "Blessing Skin"
  SessionURL = "https://skin.example.net/api/yggdrasil/sessionserver"
  AccountURL = "https://skin.example.net/api/yggdrasil/api"
  ServicesURL = "https://skin.example.net/api/yggdrasl/minecraftservices"
  SkinDomains = ["skin.example.net"]
  CacheTTLSeconds = 60
```

</details>

### Example 4: Stealth setup

- Basic setup, but add a random, secret suffix to the `BaseURL` to limit unwanted access. Everything still works even if `/` is not the root of the API.

<details>

<summary>Show config.toml</summary>

```
Domain = "drasl.example.com"                  # CHANGE ME!
BaseURL = "https://drasl.example.com/jaek7iNe # CHANGE ME!
DefaultAdmins = ["myusername"]                # CHANGE ME!

[CreateNewPlayer]
  AllowChoosingUUID = true

[RegistrationNewPlayer]
  Allow = true
  RequireInvite = true
```

</details>

### Example 5: Single sign-on (SSO) via OpenID Connect (OIDC)

- Users can sign in to Drasl using the OIDC providers idm.example.com and/or lastlogin.net (`[[RegistrationOIDC]]`). Drasl users linked to one or more OIDC accounts will not be able to log in with a password. To log in to Minecraft launchers, they'll need to instead use their "Minecraft Token" shown on their user page.
- Users will not be allowed to register an account with a password (`AllowPasswordLogin = false`). Existing Drasl users who already have an account with a password will not be able to sign in until they link their account with an OIDC provider.

<details>

<summary>Show config.toml</summary>

```
Domain = "drasl.example.com"                  # CHANGE ME!
BaseURL = "https://drasl.example.com          # CHANGE ME!
DefaultAdmins = ["myusername"]                # CHANGE ME!

AllowPasswordLogin = false

[RegistrationNewPlayer]
  Allow = true

[[RegistrationOIDC]]
  Name = "Kanidm"
  Issuer = "https://idm.example.com/oauth2/openid/drasl"            # CHANGE ME!
  ClientID = "drasl"                                                # CHANGE ME!
  ClientSecret = "yfUfeFuUI6YiTU23ngJtq8ioYq75FxQid8ls3RdNf0qWSiBO" # CHANGE ME!
  RequireInvite = false
  PKCE = true
  AllowChoosingPlayerName = true

[[RegistrationOIDC]]
  Name = "LastLogin"
  Issuer = "https://lastlogin.net"                                  # CHANGE ME!
  ClientID = "https://drasl.example.com"                            # CHANGE ME!
  ClientSecret = ""                                                 # CHANGE ME!
  RequireInvite = false
  PKCE = true
  AllowChoosingPlayerName = true
```

</details>

## Configurations for common fallback servers

Note for fallback servers implementing the authlib-injector API: authlib-injector provides the `Session`, `Account`, and `Services` all under one API route. To find the `SessionURL`, `AccountURL`, and `ServicesURL` of an authlib-injector-compatible server hosted at https://example.com:

1. Get the canonical authlib-injector API location: `curl --head https://example.com | grep x-authlib-injector-api-location`
2. Let's say the authlib-injector API location was https://example.com/api/authlib-injector. Then your URLs would be:

- `SessionURL`: https://example.com/api/authlib-injector/sessionserver
- `AccountURL`: https://example.com/api/authlib-injector/api
- `ServicesURL`: https://example.com/api/authlib-injector/minecraftservices

3. The skin domains should be listed at root of the API (https://example.com/api/authlib-injector).

### Mojang

```
[[FallbackAPIServers]]
  Nickname = "Mojang"
  SessionURL = "https://sessionserver.mojang.com"
  AccountURL = "https://api.mojang.com"
  ServicesURL = "https://api.minecraftservices.com"
  SkinDomains = ["textures.minecraft.net"]
  CacheTTLSeconds = 60

[ImportExistingPlayer]
  Allow = true
  Nickname = "Mojang"
  AccountURL = "https://api.mojang.com"
  SessionURL = "https://sessionserver.mojang.com"
  SetSkinURL = "https://www.minecraft.net/msaprofile/mygames/editskin"
```

### Ely.by

```
[[FallbackAPIServers]]
  Nickname = "Ely.by"
  SessionURL = "https://authserver.ely.by/api/authlib-injector/sessionserver"
  AccountURL = "https://authserver.ely.by/api"
  ServicesURL = "https://authserver.ely.by/api/authlib-injector/minecraftservices"
  SkinDomains = ["ely.by", ".ely.by"]
  CacheTTLSeconds = 60

[ImportExistingPlayer]
  Allow = true
  Nickname = "Ely.by"
  AccountURL = "https://authserver.ely.by/api"
  SessionURL = "https://authserver.ely.by/api/authlib-injector/sessionserver"
  SetSkinURL = "https://ely.by/skins/add"
```

### Blessing Skin

```
# For a Blessing Skin instance hosted at `skin.example.com`:

[[FallbackAPIServers]]
  Nickname = "Blessing Skin"
  SessionURL = "https://skin.example.com/api/yggdrasil/sessionserver"
  AccountURL = "https://skin.example.com/api/yggdrasil/api"
  ServicesURL = "https://skin.example.com/api/yggdrasl/minecraftservices"
  SkinDomains = ["skin.example.com"]
  CacheTTLSeconds = 60

[ImportExistingPlayer]
  Allow = true
  Nickname = "Blessing Skin"
  AccountURL = "https://skin.example.com/api/yggdrasil/api"
  SessionURL = "https://skin.example.com/api/yggdrasil/sessionserver"
  SetSkinURL = "https://skin.example.com/skinlib/upload"
```
