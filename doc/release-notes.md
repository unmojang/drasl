# Release notes

## Drasl 3.0.0

Major changes:

- Allow multiple players per user (`DefaultMaxPlayerCount`)
- Support for login and registration via OpenID Connect (`[[RegistrationOIDC]]`)
- Major database schema changes, hence Drasl will now (by default) back up the database when upgrading to a new database version (`PreMigrationBackups`).
- Drasl API version incremented to v2
- Minimum Go version increased from 1.19 to 1.23 due to new dependencies

New configuration options:

- `AllowPasswordLogin`: Allow registration and login with passwords. Disable to force users to register via OIDC (see `[[RegistrationOIDC]]`). If disabled, users must use Minecraft Tokens to log in to Minecraft launchers. If this option is disabled after being previously enabled, password accounts will still have the option to link an OIDC provider to their account. Boolean. Default value: `true`.
- `AllowAddingDeletingPlayers`: Allow users to create and delete players up to their individual max player count. The default max player count is controlled by `DefaultMaxPlayerCount`. If this option is disabled, users will only be allowed the one player that is created for them when they register. Admins can create and delete players regardless of this setting. Boolean. Default value: `false`.
- `DefaultMaxPlayerCount`: Number of players each user is allowed to own by default. Admins can increase or decrease each user's individual limit. Use `-1` to allow creating an unlimited number of players. Has no effect unless `AllowAddingDeletingPlayers` is set to `true`. Integer. Default value: `1`.
- `CORSAllowOrigins`: List of origins that may access Drasl API routes. See https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Origin. Necessary for allowing browsers to access the Drasl API. Set to `["*"]` to allow all origins. Array of strings. Example value: `["https://front-end.example.com"]`. Default value: `[]`.
- `EnableWebFrontEnd`: Whether to enable the web UI. Boolean. Default value: `true`.
- `PreMigrationBackups`: Back up the database to `/path/to/StateDirectory/drasl.X.YYYY-mm-ddTHH-MM-SSZ.db` (where `X` is the old database version) before migrating to a new database version. Boolean. Default value: `true`.
- `[[RegistrationOIDC]]`: Allow users to register via [OpenID Connect](https://openid.net/developers/how-connect-works) as well as link their existing Drasl account to OIDC providers. Compatible with both `[RegistrationNewPlayer]` and `[RegistrationExistingPlayer]`. If a user account is linked to one or more OIDC providers, **they will no longer be able to log in to the Drasl web UI or Minecraft using their Drasl password**. For the Drasl web UI, they will have to log in via OIDC. For Minecraft, they will have to use the "Minecraft Token" shown on their user page. Use `$BaseURL/web/oidc-callback/$Name` as the OIDC redirect URI when registering Drasl with your OIDC identity provider, where `$BaseURL` is your Drasl `BaseURL` and `$Name` is the `Name` of the `[[RegistrationOIDC]]` provider. For example, `https://drasl.example.com/web/oidc-callback/Kanidm`.

Moved configuration options:

- `RegistrationNewPlayer.AllowChoosingUUID` moved to `CreateNewPlayer.AllowChoosingUUID`
- `RegistrationExistingPlayer.Nickname` moved to `ImportExistingPlayer.Nickname`
- `RegistrationExistingPlayer.AccountURL` moved to `ImportExistingPlayer.AccountURL`
- `RegistrationExistingPlayer.SessionURL` moved to `ImportExistingPlayer.SessionURL`
- `RegistrationExistingPlayer.SetSkinURL` moved to `ImportExistingPlayer.SetSkinURL`
- `RegistrationExistingPlayer.RequireSkinVerification` moved to `ImportExistingPlayer.RequireSkinVerification`
