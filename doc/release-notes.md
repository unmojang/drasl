# Release notes

## Drasl 4.0.0


### Major changes

- The spread of registration configuration options was restructured to be more powerful and intuitive.
- Existing players can now be imported from multiple sources; previously only one `ImportExistingPlayer` source was supported.

### API changes

- API version bumped to 3
- `APICreatePlayerRequest` and `APICreateUserRequest`: boolean `existingPlayer` field replaced with string `fallbackApiServer` which identifies which fallback API server to import the player from

### Configuration migration guide

The deprecated configuration options (and thus existing configuration files) _should_ function as they did in 3.x.x, but compatibility will be removed in the next major version. Update your configuration files as soon as possible.

<details>

<summary>

#### Old 3.0.0 configuration

</summary>

```
# Global, applied to every FallbackAPIServer
ForwardSkins = true

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

```
# ForwardSkins is now per FallbackAPIServer instead of global
[[FallbackAPIServers]]
Nickname = "Mojang"
SessionURL = "https://sessionserver.mojang.com"
AccountURL = "https://api.mojang.com"
ServicesURL = "https://api.minecraftservices.com"
SetSkinURL = "https://www.minecraft.net/msaprofile/mygames/editskin"
ForwardSkins = true

# ImportExistingPlayer is now an array of tables, referencing a
# FallbackAPIServer by Nickname
[[ImportExistingPlayer]]
FallbackAPIServerNickname = "Mojang"
RequireSkinVerification = true

# Password registration policy now lives under RegistrationUsernamePassword
[RegistrationUsernamePassword.NewPlayer]
Allow = true
RequireInvite = true

[[RegistrationUsernamePassword.ExistingPlayer]]
FallbackAPIServerNickname = "Mojang"
RequireInvite = false
RequireSkinVerification = true

# OIDC registration policy: RequireInvite moved under NewPlayer/ExistingPlayer
[[RegistrationOIDC]]
Name = "Kanidm"
...

  [RegistrationOIDC.NewPlayer]
  Allow = true
  RequireInvite = true

  [[RegistrationOIDC.ExistingPlayer]]
  FallbackAPIServerNickname = "Mojang"
  RequireInvite = true
  RequireSkinVerification = true
```

</details>

### Deprecated configuration options

  - `AllowAddingDeletingPlayers`: no longer has any effect. Users can add or delete players if and only if `CreateNewPlayer.Allow` or `ImportExistingPlayer.Allow` is true.
  - `ImportExistingPlayer`: changed from a table to an array of tables. Multiple sources for existing players can now be set up.
  - `RegistrationNewPlayer`: replaced with `RegistrationUsernamePassword.NewPlayer` and `RegistrationOIDC.NewPlayer`
  - `RegistrationExistingPlayer`: replaced with `RegistrationUsernamePassword.ExistingPlayer` and `RegistrationOIDC.ExistingPlayer`

### Removed options

These options were deprecated in Drasl 3.0.0.

  - `RegistrationNewPlayer.AllowChoosingUUID`
  - `RegistrationExistingPlayer.Nickname`
  - `RegistrationExistingPlayer.AccountURL`
  - `RegistrationExistingPlayer.SessionURL`
  - `RegistrationExistingPlayer.SetSkinURL`
  - `RegistrationExistingPlayer.RequireSkinVerification`

### TODO
  - `PKCE`
  - `RequestCache`
  - `SessionURL` etc moved to `AuthlibInjectorURL` or `DiscoveryURL`


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
