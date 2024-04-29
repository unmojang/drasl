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
  - `Nickname`: A name for the API server
  - `AccountURL`: The URL of the "account" server. String. Example value: `"https://api.mojang.com"`.
  - `SessionURL`: The URL of the "session" server. String. Example value: `"https://sessionserver.mojang.com"`.
  - `ServicesURL`: The URL of the "services" server. String. Example value: `"https://api.minecraftservices.com"`.
  - `SkinDomains`: Array of domains where skins are hosted. For authlib-injector-compatible API servers, the correct value should be returned by the root of the API, e.g. go to [https://example.com/yggdrasil](https://example.com/yggdrasil) and look for the `skinDomains` field. Array of strings. Example value: `["textures.minecraft.net"]`
  - Note: API servers set up for authlib-injector may only give you one URL---if their API URL is e.g. `https://example.com/yggdrasil`, then you would use the following settings:

    ```
    AccountURL = https://example.com/yggdrasil/api
    SessionURL = https://example.com/yggdrasil/sessionserver
    ServicesURL = https://example.com/yggdrasil/minecraftservices
    ```

  - `CacheTTLSec`: Time in seconds to cache API server responses. This option is set to `0` by default, which disables caching. For authentication servers like Mojang which may rate-limit, it's recommended to at least set it to something small like `60`. Integer. Default value: `0`.

  - `DenyUnknownUsers`: Don't allow clients using this authentication server to log in to a Minecraft server using Drasl unless there is a Drasl user with the client's player name. This option effectively allows you to use Drasl as a whitelist for your Minecraft server. You could allow users to authenticate using, for example, Mojang's authentication server, but only if they are also registered on Drasl. Boolean. Default value: `false`.

  - `OfflineSkins`: Try to resolve skins for "offline" UUIDs. When `online-mode` is set to `false` in `server.properties` (sometimes called "offline mode"), players' UUIDs are computed deterministically from their player names instead of being managed by the authentication server. If this option is enabled and a skin for an unknown UUID is requested, Drasl will search for a matching player by offline UUID. This option is required to see other players' skins on offline servers. Boolean. Default value: `true`.

<!-- - `[TransientLogin]`: Allow certain usernames to authenticate with a shared password, without registering. Useful for supporting bot accounts. -->
<!--     - `Allow`: Boolean. Default value: `false`. -->
<!--     - `UsernameRegex`: If a username matches this regular expression, it will be allowed to log in with the shared password. Use `".*"` to allow transient login for any username. String. Example value: `"[Bot] .*"`. -->
<!--     - `Password`: The shared password for transient login. Not restricted by `MinPasswordLength`. String. Example value: `"hunter2"`. -->

- `[RegistrationNewPlayer]`: Registration policy for new players.
  - `Allow`: Boolean. Default value: `true`.
  - `AllowChoosingUUID`: Allow new users to choose the UUID for their account. Boolean. Default value: `false`.
  - `RequireInvite`: Whether registration requires an invite. If enabled, users will only be able to create a new account if they use an invite link generated by an admin (see `DefaultAdmins`).
- `[RegistrationExistingPlayer]`: Registration policy for signing up using an existing account on another API server. The UUID of the existing account will be used for the new account.

  - `Allow`: Boolean. Default value: `false`.
  - `Nickname`: A name for the API server used for registration. String. Example value: `"Mojang"`.
  - `AccountURL`: The URL of the "account" server. String. Example value: `"https://api.mojang.com"`.
  - `SessionURL`: The URL of the "session" server. String. Example value: `"https://sessionserver.mojang.com"`.
  - `SetSkinURL`: A link to the web page where you set your skin on the API server. Example value: `"https://www.minecraft.net/msaprofile/mygames/editskin"`.
  - `RequireSkinVerification`: Require users to set a skin on the existing account to verify their ownership. Boolean. Default value: `false`.
  - `RequireInvite`: Whether registration requires an invite. If enabled, users will only be able to create a new account if they use an invite link generated by an admin (see `DefaultAdmins`).
  - Note: API servers set up for authlib-injector may only give you one URL---if their API URL is e.g. `https://example.com/yggdrasil`, then you would use the following settings:

    ```
    SessionURL = https://example.com/yggdrasil/sessionserver
    ServicesURL = https://example.com/yggdrasil/minecraftservices
    ```

- `[RequestCache]`: Settings for the cache used for `FallbackAPIServers`. You probably don't need to change these settings. Modify `[[FallbackAPIServers]].CacheTTLSec` instead if you want to disable caching. See [https://pkg.go.dev/github.com/dgraph-io/ristretto#readme-config](https://pkg.go.dev/github.com/dgraph-io/ristretto#readme-config).

  - `NumCounters`: The number of keys to track frequency of. Integer. Default value: `10000000` (`1e7`).
  - `MaxCost`: The maximum size of the cache in bytes. Integer. Default value: `1073741824` (equal to `1 << 30` or 1 GiB).
  - `BufferItems`: The number of keys per Get buffer. Default value: `64`.

- `MinPasswordLength`: Users will not be able to choose passwords shorter than this length. Integer. Default value: `8`.
- `DefaultPreferredLanguage`: Default "preferred language" for user accounts. The Minecraft client expects an account to have a "preferred language", but I have no idea what it's used for. Choose one of the two-letter codes from [https://www.oracle.com/java/technologies/javase/jdk8-jre8-suported-locales.html](https://www.oracle.com/java/technologies/javase/jdk8-jre8-suported-locales.html). String. Default value: `"en"`.
- `SkinSizeLimit`: The maximum width, in pixels, of a user-uploaded skin or cape. Normally, Minecraft skins are 128 × 128 pixels, and capes are 128 × 64 pixels. You can raise this limit to support high resolution skins and capes, but you will also need a client-side mod like [MCCustomSkinLoader](https://github.com/xfl03/MCCustomSkinLoader) (untested). Set to `0` to remove the limit entirely, but the size of the skin file will still be limited by `BodyLimit`. Integer. Default value: `128`.
- `SignPublicKeys`: Whether to sign players' public keys. Boolean. Default value: `true`.
  - Must be enabled if you want to support servers with `enforce-secure-profile=true` in server.properties.
  - Limits servers' ability to forge messages from players.
  - Disable if you want clients to be able to send chat messages with plausible deniability and you don't need to support `enforce-secure-profile=true`.
  - Note: Minecraft 1.19 and earlier can only validate player public keys against Mojang's public key, not ours, so you should use `enforce-secure-profile=false` on versions earlier than 1.20.
- `TokenStaleSec`: number of seconds after which an access token will go "stale". A stale token needs to be refreshed before it can be used to log in to a Minecraft server. By default, `TokenStaleSec` is set to `0`, meaning tokens will never go stale, and you should never see an error in-game like "Failed to login: Invalid session (Try restarting your game)". To have tokens go stale after one day, for example, set this option to `86400`. Integer. Default value: `0`.
- `TokenExpireSec`: number of seconds after which an access token will expire. An expired token can neither be refreshed nor be used to log in to a Minecraft server. By default, `TokenExpireSec` is set to `0`, meaning tokens will never expire, and you should never have to log in again to your launcher if you've been away for a while. The security risks of non-expiring JWTs are actually quite mild; an attacker would still need access to a client's system to steal a token. But if you're concerned about security, you might, for example, set this option to `604800` to have tokens expire after one week. Integer. Default value: `0`.
- `AllowChangingPlayerName`: Allow users to change their "player name" after their account has already been created. Could be useful in conjunction with `RegistrationExistingPlayer` if you want to make users register from an existing (e.g. Mojang) account but you want them to be able to choose a new player name. Boolean. Default value: `true`.
- `AllowSkins`: Allow users to upload skins. You may want to disable this option if you want to rely exclusively on `ForwardSkins`, e.g. to fully support Vanilla clients. Boolean. Default value: `true`.
- `AllowCapes`: Allow users to upload capes. Boolean. Default value: `true`.
