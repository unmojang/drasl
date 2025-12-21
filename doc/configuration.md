# Configuration

Configure Drasl by editing its [TOML](https://toml.io/en/) configuration file, `/etc/drasl/config.toml`.

When running Drasl on the command line instead of with a service manager or Docker, a different config file can be specified with `drasl --config /path/to/config.toml`.

See [recipes.md](recipes.md) for example configurations for common setups.

At a bare minimum, you MUST set the following options:

- `Domain`: the fully qualified domain name where your instance is hosted. Clients using authlib-injector may not see skins if this option is not correctly set. String. Default value: `"drasl.example.com"`.
- `BaseURL`: the URL of your instance. String. Default value: `"https://drasl.example.com"`.

Other available options:

- `InstanceName`: the name of your Drasl instance. String. Example: `My Drasl Instance`. Default value: `"Drasl"`.
- `ApplicationOwner`: you or your organization's name. String. Default value: `"Anonymous"`.
- `StateDirectory`: directory to store application state, including the database (`drasl.db`), skins, and capes. String. Default value: `"/var/lib/drasl/"`.
- `DataDirectory`: directory where Drasl's static assets are installed. String. Default value: `"/usr/share/drasl"`.
- `ListenAddress`: IP address and port to listen on. Depending on how you configure your reverse proxy and whether you run Drasl in a container, you should consider setting the listen address to `"127.0.0.1:25585"` to ensure Drasl is only accessible through the reverse proxy. If your reverse proxy is unable to connect to Drasl, try setting this back to the default value. String. Default value: `"0.0.0.0:25585"`.
- `DefaultAdmins`: Usernames of the instance's permanent admins. Admin rights can be granted to other accounts using the web UI, but admins defined via `DefaultAdmins` cannot be demoted unless they are removed from the config file. Array of strings. Default value: `[]`.
- `DefaultMaxPlayerCount`: Number of players each user is allowed to own by default. Admins can increase or decrease each user's individual limit. Use `-1` to allow creating an unlimited number of players. Has no effect unless `AllowAddingDeletingPlayers` is `true`. Integer. Default value: `1`.
- `PreMigrationBackups`: Back up the database to `/path/to/StateDirectory/drasl.X.YYYY-mm-ddTHH-MM-SSZ.db` (where `X` is the old database version) before migrating to a new database version. Boolean. Default value: `true`.
- `EnableBackgroundEffect`: Whether to enable the 3D background animation in the web UI. Boolean. Default value: `true`.
- `EnableClientConfiguration`: Whether to show client configuration guide on the main page in the web UI. Boolean. Default value: `true`.
- `EnableServerConfiguration`: Whether to show server configuration guide on the main page in the web UI. Boolean. Default value: `true`.
- `EnableFooter`: Whether to enable the page footer in the web UI. Boolean. Default value: `true`.
- `EnableWebFrontEnd`: Whether to enable the web UI. Boolean. Default value: `true`.
- `[RateLimit]`: Rate-limit requests per IP address to limit abuse. Only applies to certain web UI routes, not any Yggdrasil routes. Requests for skins, capes, and web pages are also unaffected. Uses [Echo](https://echo.labstack.com)'s [rate limiter middleware](https://echo.labstack.com/middleware/rate-limiter/).
  - `Enable`: Boolean. Default value: `true`.
  - `RequestsPerSecond`: Number of requests per second allowed per IP address. Integer. Default value: `5`.
- `[BodyLimit]`: Limit the maximum size of a request body limit abuse. The default settings should be fine unless you want to support humongous skins (greater than 1024 × 1024 pixels).
  - `Enable`: Boolean. Default value: `true`.
  - `SizeLimitKiB`: Maximum size of a request body in kibibytes. Integer. Default value: `8192`.
- `LogRequests`: Log each incoming request on stdout. Boolean. Default value: `true`.
- `ForwardSkins`: When `true`, if a user doesn't have a skin or cape set, Drasl will try to serve a skin from the fallback API servers. Boolean. Default value: `true`.
  - Vanilla clients will not accept skins or capes that are not hosted on Mojang's servers. If you want to support vanilla clients, enable `ForwardSkins` and configure Mojang as a fallback API server.
  - For players who do not have a account on the Drasl instance, skins will always be forwarded from the fallback API servers.
- `[[FallbackAPIServers]]`: Allows players to authenticate using other API servers. For example, say you had a Minecraft server configured to authenticate players with your Drasl instance. You could configure Mojang's API as a fallback, and a player signed in with either a Drasl account or a Mojang account could play on your server. Does not work with Minecraft servers that have `enforce-secure-profile=true` in server.properties. See [recipes.md](recipes.md) for example configurations.

  - You can configure any number of fallback API servers, and they will be tried in sequence, in the order they appear in the config file. By default, none are configured.
  - `Nickname`: A name for the API server. String. Example value: `"Mojang"`.
  - `AccountURL`: The URL of the "account" server. String. Example value: `"https://api.mojang.com"`.
  - `SessionURL`: The URL of the "session" server. String. Example value: `"https://sessionserver.mojang.com"`.
  - `ServicesURL`: The URL of the "services" server. String. Example value: `"https://api.minecraftservices.com"`.
  - `SkinDomains`: Array of domains where skins are hosted. For authlib-injector-compatible API servers, the correct value should be returned by the root of the API, e.g. go to [https://example.com/yggdrasil](https://example.com/yggdrasil) and look for the `skinDomains` field. Array of strings. Example value: `["textures.minecraft.net"]`.
  - Note: API servers set up for authlib-injector may only give you one URL---if their API URL is e.g. `https://example.com/yggdrasil`, then you would use the following settings:

    ```
    AccountURL = https://example.com/yggdrasil/api
    SessionURL = https://example.com/yggdrasil/sessionserver
    ServicesURL = https://example.com/yggdrasil/minecraftservices
    ```

  - `CacheTTLSec`: Time in seconds to cache API server responses. This option is set to `0` by default, which disables caching. For authentication servers like Mojang which may rate-limit, it's recommended to at least set it to something small like `60`. Integer. Default value: `600` (10 minutes).

  - `DenyUnknownUsers`: Don't allow clients using this authentication server to log in to a Minecraft server using Drasl unless there is a Drasl user with the client's player name. This option effectively allows you to use Drasl as a whitelist for your Minecraft server. You could allow users to authenticate using, for example, Mojang's authentication server, but only if they are also registered on Drasl. Boolean. Default value: `false`.

  - `EnableAuthentication`: Allow Minecraft clients using this authentication server to log in to a Minecraft server using Drasl. Disable this option if you, for example, want to use `ForwardSkins = true` but don't want to allow authentication from the fallback API server. Boolean. Default value: `true`.

- `OfflineSkins`: Try to resolve skins for "offline" UUIDs. When `online-mode` is set to `false` in `server.properties` (sometimes called "offline mode"), players' UUIDs are computed deterministically from their player names instead of being managed by the authentication server. If this option is enabled and a skin for an unknown UUID is requested, Drasl will search for a matching player by offline UUID. This option is required to see other players' skins on offline servers. Boolean. Default value: `true`.

<!-- - `[TransientLogin]`: Allow certain usernames to authenticate with a shared password, without registering. Useful for supporting bot accounts. -->
<!--     - `Allow`: Boolean. Default value: `false`. -->
<!--     - `UsernameRegex`: If a username matches this regular expression, it will be allowed to log in with the shared password. Use `".*"` to allow transient login for any username. String. Example value: `"[Bot] .*"`. -->
<!--     - `Password`: The shared password for transient login. Not restricted by `MinPasswordLength`. String. Example value: `"hunter2"`. -->

- `[CreateNewPlayer]`: Policy for creating new players.
  - `Allow`: Allow users to create players with new UUIDs, up to their individual `MaxPlayerCount` limit. Boolean. Default value: `true`.
  - `AllowChoosingUUID`: Allow users to choose a UUID for the new player. If disabled, the new player's UUID will always be generated according to the strategy specified by the `PlayerUUIDGeneration` option. Boolean. Default value: `false`.
- `[RegistrationNewPlayer]`
  - `Allow`: Allow users to register a new Drasl account by creating a player with a new UUID. Requires `CreateNewPlayer.Allow = true`. Boolean. Default value: `true`.
  - `RequireInvite`: Whether registration requires an invite. If enabled, users will only be able to create a new account if they use an invite link generated by an admin (see `DefaultAdmins`). Boolean. Default value: `false`.
- `[ImportExistingPlayer]`: Policy for importing existing players from another API server. The UUID of the existing player will be used for the Drasl player.
  - `Allow`: Boolean. Default value: `false`.
  - `Nickname`: A name for the API server. String. Example value: `"Mojang"`.
  - `AccountURL`: The URL of the "account" server. String. Example value: `"https://api.mojang.com"`.
  - `SessionURL`: The URL of the "session" server. String. Example value: `"https://sessionserver.mojang.com"`.
  - `SetSkinURL`: A link to the web page where you set your skin on the API server. Example value: `"https://www.minecraft.net/msaprofile/mygames/editskin"`.
  - `RequireSkinVerification`: Require users to set a skin on the existing player to verify their ownership. Boolean. Default value: `false`.
- `[RegistrationExistingPlayer]`
  - `Allow`: Allow users to register a new Drasl account by importing an existing player from another API server. Requires `ImportExistingPlayer.Allow = true`. Boolean. Default value: `false`.
  - `RequireInvite`: Whether registration requires an invite. If enabled, users will only be able to create a new account if they use an invite link generated by an admin (see `DefaultAdmins`). Boolean. Default value: `false`.
  - Note: API servers set up for authlib-injector may only give you one URL---if their API URL is e.g. `https://example.com/yggdrasil`, then you would use the following settings:

    ```
    SessionURL = https://example.com/yggdrasil/sessionserver
    ServicesURL = https://example.com/yggdrasil/minecraftservices
    ```

- `[[RegistrationOIDC]]`: Allow users to register via [OpenID Connect](https://openid.net/developers/how-connect-works) or link an existing Drasl account to one or more OIDC providers. 

    Compatible with both `[RegistrationNewPlayer]` and `[RegistrationExistingPlayer]`.

    When registering a new accout via OIDC, The OIDC user’s email address will be used as their Drasl username. The user’s player name will be the IDP-provided `preferred_username` or the player name of the user’s choice if `AllowChoosingPlayerName = true`.

    If a user account is linked to one or more OIDC providers, **they will no longer be able to log in to the Drasl web UI or Minecraft using their Drasl password**. For the Drasl web UI, they will have to log in via OIDC. For Minecraft, they will have to use the "Minecraft Token" shown on their user page.

    Use `$BaseURL/web/oidc-callback/$Name` as the OIDC redirect URI when registering Drasl with your OIDC identity provider, where `$BaseURL` is your Drasl `BaseURL` and `$Name` is the `Name` of the `[[RegistrationOIDC]]` provider. For example, `https://drasl.example.com/web/oidc-callback/Kanidm`.
  - `Name`: The name of the OIDC provider. String. Example value: `"Kanidm"`.
  - `Issuer`: OIDC issuer URL. String. Example value: `"https://idm.example.com/oauth2/openid/drasl"`.
  - `ClientID`: OIDC client ID. String. Example value: `"drasl"`.
  - `ClientSecret`: OIDC client secret. String. Example value: `"yfUfeFuUI6YiTU23ngJtq8ioYq75FxQid8ls3RdNf0qWSiBO"`.
  - `ClientSecretFile`: Path to a file containing an OIDC client secret. Environment variables in the path will be expanded. Surrounding whitespace in the file will be trimmed. Do not set both `ClientSecret` and `ClientSecretFile`. String. Example value: `"/path/to/oidc-client-secret.txt"`.
  - `PKCE`: Whether to use [PKCE](https://datatracker.ietf.org/doc/html/rfc7636). Recommended, but must be supported by the OIDC provider. Boolean. Default value: `true`.
  - `RequireInvite`: Whether registration via this OIDC provider requires an invite. If enabled, users will only be able to create a new account via this OIDC provider if they use an invite link generated by an admin (see `DefaultAdmins`). Boolean. Default value: `false`.
  - `AllowChoosingPlayerName`: Whether to allow choosing a player name other than the OIDC user's `preferredUsername` during registration. Boolean. Default value: `true`.

- `[RequestCache]`: Settings for the cache used for `FallbackAPIServers`. You probably don't need to change these settings. Modify `[[FallbackAPIServers]].CacheTTLSec` instead if you want to disable caching. See [https://pkg.go.dev/github.com/dgraph-io/ristretto#readme-config](https://pkg.go.dev/github.com/dgraph-io/ristretto#readme-config).

  - `NumCounters`: The number of keys to track frequency of. Integer. Default value: `10000000` (`1e7`).
  - `MaxCost`: The maximum size of the cache in bytes. Integer. Default value: `1073741824` (equal to `1 << 30` or 1 GiB).
  - `BufferItems`: The number of keys per Get buffer. Default value: `64`.

- `MinPasswordLength`: Users will not be able to choose passwords shorter than this length. Integer. Default value: `8`.
- `DefaultPreferredLanguage`: Default "preferred language" for user accounts. The Minecraft client expects an account to have a "preferred language", but I have no idea what it's used for. Choose one of the two-letter codes from [https://www.oracle.com/java/technologies/javase/jdk8-jre8-suported-locales.html](https://www.oracle.com/java/technologies/javase/jdk8-jre8-suported-locales.html). String. Default value: `"en"`.
- `SkinSizeLimit`: The maximum width, in pixels, of a user-uploaded skin or cape. Normally, Minecraft skins are 64 × 64 pixels, and capes are 64 × 32 pixels. You can raise this limit to support high resolution skins and capes, but you will also need a client-side mod like [MCCustomSkinLoader](https://github.com/xfl03/MCCustomSkinLoader) (untested). Set to `0` to remove the limit entirely, but the size of the skin file will still be limited by `BodyLimit`. The dimensions of a skin must always be a multiple of 64 × 64 or 64 × 32 pixels, and the dimensions of a cape must always be a multiple of 64 × 32. Integer. Default value: `64`.
- `SignPublicKeys`: Whether to sign players' public keys. Boolean. Default value: `true`.
  - Must be enabled if you want to support servers with `enforce-secure-profile=true` in server.properties.
  - Limits servers' ability to forge messages from players.
  - Disable if you want clients to be able to send chat messages with plausible deniability and you don't need to support `enforce-secure-profile=true`.
  - Note: Minecraft 1.19 and earlier can only validate player public keys against Mojang's public key, not ours, so you should use `enforce-secure-profile=false` on versions earlier than 1.20.
- `TokenStaleSec`: number of seconds after which an access token will go "stale". A stale token needs to be refreshed before it can be used to log in to a Minecraft server. By default, `TokenStaleSec` is set to `0`, meaning tokens will never go stale, and you should never see an error in-game like "Failed to login: Invalid session (Try restarting your game)". To have tokens go stale after one day, for example, set this option to `86400`. Integer. Default value: `0`.
- `TokenExpireSec`: number of seconds after which an access token will expire. An expired token can neither be refreshed nor be used to log in to a Minecraft server. By default, `TokenExpireSec` is set to `0`, meaning tokens will never expire, and you should never have to log in again to your launcher if you've been away for a while. The security risks of non-expiring JWTs are actually quite mild; an attacker would still need access to a client's system to steal a token. But if you're concerned about security, you might, for example, set this option to `604800` to have tokens expire after one week. Integer. Default value: `0`.
- `AllowPasswordLogin`: Allow registration and login with passwords. Disable to force users to register via OIDC (see `[[RegistrationOIDC]]`). If disabled, users must use Minecraft Tokens to log in to Minecraft launchers. If this option is disabled after being previously enabled, password accounts will still have the option to link an OIDC provider to their account. Boolean. Default value: `true`.
- `AllowAddingDeletingPlayers`: Allow users to create and delete players up to their individual max player count. The default max player count is controlled by `DefaultMaxPlayerCount`. If this option is disabled, users will only be allowed the one player that is created for them when they register. Admins can create and delete players regardless of this setting. Boolean. Default value: `false`.
- `AllowChangingPlayerName`: Allow users to change their "player name" after their account has already been created. Could be useful in conjunction with `RegistrationExistingPlayer` if you want to make users register from an existing (e.g. Mojang) account but you want them to be able to choose a new player name. Admins can change the name of any player regardless of this setting. Beware: when `AllowAddingDeletingPlayers` is `true`, users can simply delete a player and create a new one with a new name. Boolean. Default value: `true`.
- `AllowSkins`: Allow users to upload skins. You may want to disable this option if you want to rely exclusively on `ForwardSkins`, e.g. to fully support Vanilla clients. Admins can set skins regardless of this setting. Boolean. Default value: `true`.
- `AllowCapes`: Allow users to upload capes. Admins can set capes regardless of this setting. Boolean. Default value: `true`.
- `AllowTextureFromURL`: Allow users to specify a skin or cape by providing a URL to the texture file. Previously, this option was always allowed; now it is opt-in. Admins can do this regardless of this setting. Boolean. Default value: `false`.
- `ValidPlayerNameRegex`: Regular expression (regex) that player names must match. Currently, Drasl usernames are validated using this regex too. Player names will be limited to a maximum of 16 characters no matter what. Mojang allows the characters `abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_`, and by default, Drasl follows suit. Minecraft servers may misbehave if additional characters are allowed. Change to `.+` if you want to allow any player name (that is 16 characters or shorter). String. Default value: `^[a-zA-Z0-9_]+$`.
- `CORSAllowOrigins`: List of origins that may access Drasl API routes. See https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Origin. Necessary for allowing browsers to access the Drasl API. Set to `["*"]` to allow all origins. Array of strings. Example value: `["https://front-end.example.com"]`. Default value: `[]`.
- `PlayerUUIDGeneration`: How to generate UUIDs for new players. Must be either `"random"` or `"offline"`. `"random"` generates a new random Version 4 UUID. `"offline"` means the player's UUID will be generated from the player's name using the same algorithm Minecraft uses to derive player UUIDs on `online-mode=false` servers. `PlayerUUIDGeneration = "offline"` is useful for migrating `online-mode=false` servers to Drasl since it lets player UUIDs (and thus inventories, permissions, etc.) remain the same when switching from `online-mode=false` to `online-mode=true`. Note: if a player's name is changed, their UUID will not change, even with `PlayerUUIDGeneration = "offline"`. String. Default value: `"random"`.
