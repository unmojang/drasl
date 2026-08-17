# Release notes

## Drasl 4.0.0

Please read these release notes thoroughly before upgrading!

### Major changes

- **Previously, `AllowAddingDeletingPlayers` was false by default, meaning users could not add or delete new players by default. Now, users can add or delete players if and only if `CreateNewPlayer.Allow = true` OR `ImportExistingPlayer.Allow = true`. If you do not want users to add or delete players, ensure `CreateNewPlayer.Allow = false` AND `ImportExistingPlayer.Allow = false`!**
- Configuration options moved or deprecated in 3.0.0 are now removed.
- The registration configuration options were restructured to be more powerful and intuitive.
  - Previously, configuration was shared between username/password registration and OIDC registration. Now, they can be configured independently. You can, for example, require an invite to register as a new player via username and password (`RegistrationUsernamePassword.CreateNewPlayer.RequireInvite = true`) but not when registering via OIDC (`RegistrationOIDC.CreateNewPlayer.RequireInvite = false`).
  - Previously, registration as a new player required setting both `RegistrationNewPlayer.Allow = true` and `CreateNewPlayer.Allow = true`. Now, the global `CreateNewPlayer` applies only to existing Drasl users creating additional new players, and there are new `RegistrationUsernamePassword.CreateNewPlayer` and `RegistrationOIDC.CreateNewPlayer` configuration sections. Same with `ImportExistingPlayer`.
- Previously, only one `ImportExistingPlayer` source was supported. Now, existing players can now be imported from multiple sources.
- Textures are now named after their SHA256 hash, not their BLAKE3 hash, to follow Mojang. Texture URLs from 3.x.x are therefore no longer valid.
- Drasl will now automatically determine whether your OIDC IDP uses PKCE; it's no longer necessary to set `RegistrationOIDC.PKCE`.
- OIDC IDPs must now grant Drasl the `profile` scope in addition to `email` and `openid`. (Drasl still fetches the same information from IDPs, just in a more spec-compliant way).
- Added two new ways to configure fallback API servers. Instead of specifying multiple URLs for each (`SessionURL`, `AccountURL`, `SessionURL`, etc.), specify ONE of:

  - `FallbackAPIServers.DiscoveryMinecraftClientURL`: used for Mojang. Mojang's `DiscoveryMinecraftClientURL` is `"https://discovery.minecraftservices.com/minecraft/client"`.
  - `FallbackAPIServers.AuthlibInjectorURL`: used for most other API servers, including other Drasl instances, Ely.by, and Blessing Skin/Littleskin. A Drasl instance at `https://drasl.example.com` would have `AuthlibInjectorURL = "https://drasl.example.com/authlib-injector"`.

### API changes

- API version bumped to 3
- `APICreatePlayerRequest` and `APICreateUserRequest`: boolean `existingPlayer` field replaced with string `fallbackApiServer` which identifies which fallback API server to import the player from

### Configuration migration guide

The deprecated configuration options mostly function as they did in 3.x.x, but compatibility will be removed in the next major version. Update your configuration files as soon as possible.

<details>

<summary>

#### Old 3.0.0 configuration

</summary>

```toml
# Global, applied to every FallbackAPIServer
ForwardSkins = true

AllowAddingDeletingPlayers = false

[CreateNewPlayer]
Allow = true

# Single source for importing existing players
[ImportExistingPlayer]
Allow = true
Nickname = "Mojang"
SessionURL = "https://sessionserver.mojang.com"
AccountURL = "https://api.mojang.com"
SetSkinURL = "https://www.minecraft.net/msaprofile/mygames/editskin"
RequireSkinVerification = true

# Password registration policy
[RegistrationNewPlayer]
Allow = true
RequireInvite = true

[RegistrationExistingPlayer]
Allow = true
RequireInvite = false

# OIDC registration policy
[[RegistrationOIDC]]
Name = "Kanidm"
Issuer = "https://idm.example.com/oauth2/openid/drasl"
ClientID = "drasl"
ClientSecret = "yfUfeFuUI6YiTU23ngJtq8ioYq75FxQid8ls3RdNf0qWSiBO"
RequireInvite = true
```

</details>

<details>
<summary>

#### New 4.0.0 configuration

</summary>

```toml
[[FallbackAPIServers]]
Nickname = "Mojang"
# Mojang can now be configured with `DiscoveryMinecraftClientURL`
DiscoveryMinecraftClientURL = "https://discovery.minecraftservices.com/minecraft/client"
SetSkinURL = "https://www.minecraft.net/msaprofile/mygames/editskin"
# ForwardSkins is now per FallbackAPIServer instead of global. ForwardSkins = true by default.
ForwardSkins = true

# Other API servers can now be configured with `AuthlibInjectorURL`
[[FallbackAPIServers]]
Nickname = "Ely.by"
AuthlibInjectorURL = "https://account.ely.by/api/authlib-injector"

[[FallbackAPIServers]]
Nickname = "LittleSkin"
AuthlibInjectorURL = "https://littleskin.cn/api/yggdrasil"

[[FallbackAPIServers]]
Nickname = "Other Drasl"
AuthlibInjectorURL = "https://other-drasl.example.com/authlib-injector"

# ImportExistingPlayer is now an array of tables, referencing a
# FallbackAPIServer by Nickname
[[ImportExistingPlayer]]
FallbackAPIServerNickname = "Mojang"
RequireSkinVerification = true

# Password registration policy now lives under RegistrationUsernamePassword
[RegistrationUsernamePassword.CreateNewPlayer]
Allow = true
RequireInvite = true

[[RegistrationUsernamePassword.ImportExistingPlayer]]
FallbackAPIServerNickname = "Mojang"
RequireInvite = false
RequireSkinVerification = true

# OIDC registration policy: RequireInvite moved under CreateNewPlayer/ImportExistingPlayer
[[RegistrationOIDC]]
Name = "Kanidm"
...

  [RegistrationOIDC.CreateNewPlayer]
  Allow = true
  RequireInvite = true

  [[RegistrationOIDC.ImportExistingPlayer]]
  FallbackAPIServerNickname = "Mojang"
  RequireInvite = true
  RequireSkinVerification = true
```

</details>

### Deprecated configuration options

  - `AllowAddingDeletingPlayers`: Going forward, users can add or delete players if and only if `CreateNewPlayer.Allow = true` or `ImportExistingPlayer.Allow = true`. For now, `AllowAddingDeletingPlayers = false` implies `CreateNewPlayer.Allow = false` and `ImportExistingPlayer.Allow = false`.
  - `ImportExistingPlayer`: changed from a table to an array of tables. Multiple sources for existing players can now be set up.
  - `RegistrationNewPlayer`: replaced with `RegistrationUsernamePassword.CreateNewPlayer` and `RegistrationOIDC.CreateNewPlayer`
  - `RegistrationExistingPlayer`: replaced with `RegistrationUsernamePassword.ImportExistingPlayer` and `RegistrationOIDC.ImportExistingPlayer`

### Removed options

These options were deprecated in Drasl 3.0.0.

  - `RegistrationNewPlayer.AllowChoosingUUID`
  - `RegistrationExistingPlayer.Nickname`
  - `RegistrationExistingPlayer.AccountURL`
  - `RegistrationExistingPlayer.SessionURL`
  - `RegistrationExistingPlayer.SetSkinURL`
  - `RegistrationExistingPlayer.RequireSkinVerification`

## Drasl 3.0.0

### Major changes

- Allow multiple players per user (`DefaultMaxPlayerCount`)
- Support for login and registration via OpenID Connect (`[[RegistrationOIDC]]`)
- Major database schema changes, hence Drasl will now (by default) back up the database when upgrading to a new database version (`PreMigrationBackups`).
- Drasl API version incremented to v2
- Minimum Go version increased from 1.19 to 1.23 due to new dependencies

### New configuration options

- `AllowPasswordLogin`: Allow registration and login with passwords. Disable to force users to register via OIDC (see `[[RegistrationOIDC]]`). If disabled, users must use Minecraft Tokens to log in to Minecraft launchers. If this option is disabled after being previously enabled, password accounts will still have the option to link an OIDC provider to their account. Boolean. Default value: `true`.
- `AllowAddingDeletingPlayers`: Allow users to create and delete players up to their individual max player count. The default max player count is controlled by `DefaultMaxPlayerCount`. If this option is disabled, users will only be allowed the one player that is created for them when they register. Admins can create and delete players regardless of this setting. Boolean. Default value: `false`.
- `DefaultMaxPlayerCount`: Number of players each user is allowed to own by default. Admins can increase or decrease each user's individual limit. Use `-1` to allow creating an unlimited number of players. Has no effect unless `AllowAddingDeletingPlayers` is set to `true`. Integer. Default value: `1`.
- `CORSAllowOrigins`: List of origins that may access Drasl API routes. See https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Origin. Necessary for allowing browsers to access the Drasl API. Set to `["*"]` to allow all origins. Array of strings. Example value: `["https://front-end.example.com"]`. Default value: `[]`.
- `EnableWebFrontEnd`: Whether to enable the web UI. Boolean. Default value: `true`.
- `PreMigrationBackups`: Back up the database to `/path/to/StateDirectory/drasl.X.YYYY-mm-ddTHH-MM-SSZ.db` (where `X` is the old database version) before migrating to a new database version. Boolean. Default value: `true`.
- `[[RegistrationOIDC]]`: Allow users to register via [OpenID Connect](https://openid.net/developers/how-connect-works) as well as link their existing Drasl account to OIDC providers. Compatible with both `[RegistrationNewPlayer]` and `[RegistrationExistingPlayer]`. If a user account is linked to one or more OIDC providers, **they will no longer be able to log in to the Drasl web UI or Minecraft using their Drasl password**. For the Drasl web UI, they will have to log in via OIDC. For Minecraft, they will have to use the "Minecraft Token" shown on their user page. Use `$BaseURL/web/oidc-callback/$Name` as the OIDC redirect URI when registering Drasl with your OIDC identity provider, where `$BaseURL` is your Drasl `BaseURL` and `$Name` is the `Name` of the `[[RegistrationOIDC]]` provider. For example, `https://drasl.example.com/web/oidc-callback/Kanidm`.

### Moved configuration options

- `RegistrationNewPlayer.AllowChoosingUUID` moved to `CreateNewPlayer.AllowChoosingUUID`
- `RegistrationExistingPlayer.Nickname` moved to `ImportExistingPlayer.Nickname`
- `RegistrationExistingPlayer.AccountURL` moved to `ImportExistingPlayer.AccountURL`
- `RegistrationExistingPlayer.SessionURL` moved to `ImportExistingPlayer.SessionURL`
- `RegistrationExistingPlayer.SetSkinURL` moved to `ImportExistingPlayer.SetSkinURL`
- `RegistrationExistingPlayer.RequireSkinVerification` moved to `ImportExistingPlayer.RequireSkinVerification`
