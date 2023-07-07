# Configuration

Configure Drasl by editing its [TOML](https://toml.io/en/) configuration file, `/etc/drasl/config.toml`.

When running Drasl on the command line instead of with a service manager or Docker, a different config file can be specified with `drasl --config /path/to/config.toml`.

See [recipes.md](doc/recipes.md) for example configurations for common setups.

At a bare minimum, you MUST set the following options:

- `Domain`: the fully qualified domain name where your instance is hosted. Clients using authlib-injector may not see skins if this option is not correctly set. String. Default value: `"drasl.example.com"`.
- `BaseURL`: the URL of your instance. String. Default value: `"https://drasl.example.com"`.

Other available options:

- `InstanceName`: the name of your Drasl instance. String. Example: `My Drasl Instance`. Default value: `"Drasl"`.
- `ApplicationOwner`: you or your organization's name. String. Default value: `"Anonymous"`.
- `StateDirectory`: directory to store application state, including the database (`drasl.db`), skins, and capes. String. Default value: `"/var/lib/drasl/"`.
- `DataDirectory`: directory where Drasl's static assets are installed. String. Default value: `"/usr/share/drasl"`.
- `ListenAddress`: IP address and port to listen on. You probably want to change this to `"127.0.0.1:25585"` if you run your reverse proxy server on the same host. String. Default value: `"0.0.0.0:25585"`.
- `[RateLimit]`: Rate-limit requests per IP address to limit abuse. Only applies to certain web UI routes, not any Yggdrasil routes. Requests for skins, capes, and web pages are also unaffected. Uses [Echo](https://echo.labstack.com)'s [rate limiter middleware](https://echo.labstack.com/middleware/rate-limiter/).
    - `Enable`: Boolean. Default value: `true`.
    - `RequestsPerSecond`: Number of requests per second allowed per IP address. Integer. Default value: `5`.
- `LogRequests`: Log each incoming request on stdout. Boolean. Default value: `true`.
- `ForwardSkins`: When `true`, if a user doesn't have a skin or cape set, Drasl will try to serve a skin from the fallback API servers. Boolean. Default value: `true`.
    - Vanilla clients will not accept skins or capes that are not hosted on Mojang's servers. If you want to support vanilla clients, enable `ForwardSkins` and configure Mojang as a fallback API server.
    - For players who do not have a account on the Drasl instance, skins will always be forwarded from the fallback API servers.
- `[[FallbackAPIServers]]`: Allows players to authenticate using other API servers. For example, say you had a Minecraft server configured to authenticate players with your Drasl instance. You could configure Mojang's API as a fallback, and a player signed in with either a Drasl account or a Mojang account could play on your server. Does not work with servers that have `enforce-secure-profile=true` in server.properties. See [recipes.md](doc/recipes.md) for example configurations.
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

- `[AnonymousLogin]`: Allow certain usernames to authenticate with a shared password, without registering. Useful for supporting bot accounts.
    - `Allow`: Boolean. Default value: `false`.
    - `UsernameRegex`: If a username matches this regular expression, it will be allowed to log in with the shared password. Use `".*"` to allow anonymous login for any username. String. Example value: `"[Bot] .*"`.
    - `Password`: The shared password for anonymous login. Not restricted by `MinPasswordLength`. String. Example value: `"hunter2"`.
- `[RegistrationNewPlayer]`: Registration policy for new players.
    - `Allow`: Boolean. Default value: `true`.
    - `AllowChoosingUUID`: Allow new users to choose the UUID for their account. Boolean. Default value: `false`.
    - `RequireInvite`: Whether registration requires an invite. If enabled, users will only be able to create a new account if they use an invite link generated by an admin (the first created user is automatically made an admin; they can then grant admin privileges to other users via the web UI).
- `[RegistrationExistingPlayer]`: Registration policy for signing up using an existing account on another API server. The UUID of the existing account will be used for the new account.
    - `Allow`: Boolean. Default value: `false`.
    - `Nickname`: A name for the API server used for registration. String. Example value: `"Mojang"`.
    - `AccountURL`: The URL of the "account" server. String. Example value: `"https://api.mojang.com"`.
    - `SessionURL`: The URL of the "session" server. String. Example value: `"https://sessionserver.mojang.com"`.
    - `SetSkinURL`: A link to the web page where you set your skin on the API server. Example value: `"https://www.minecraft.net/msaprofile/mygames/editskin"`.
    - `RequireSkinVerification`: Require users to set a skin on the existing account to verify their ownership. Boolean. Default value: `false`.
    - `RequireInvite`: Whether registration requires an invite. If enabled, users will only be able to create a new account if they use an invite link generated by an admin (the first created user is automatically made an admin; they can then grant admin privileges to other users via the web UI).
    - Note: API servers set up for authlib-injector may only give you one URL---if their API URL is e.g. `https://example.com/yggdrasil`, then you would use the following settings:

        ```
        SessionURL = https://example.com/yggdrasil/sessionserver
        ServicesURL = https://example.com/yggdrasil/minecraftservices
        ```

- `MinPasswordLength`: Users will not be able to choose passwords shorter than this length. Integer. Default value: `1`.
- `DefaultPreferredLanguage`: Default "preferred language" for user accounts. The Minecraft client expects an account to have a "preferred language", but I have no idea what it's used for. Choose one of the two-letter codes from [https://www.oracle.com/java/technologies/javase/jdk8-jre8-suported-locales.html](https://www.oracle.com/java/technologies/javase/jdk8-jre8-suported-locales.html). String. Default value: `"en"`.
- `SkinSizeLimit`: The maximum width, in pixels, of a user-uploaded skin or cape. Normally, Minecraft skins are 128 × 128 pixels, and capes are 128 × 64 pixels. You can raise this limit to support high resolution skins and capes, but you will also need a client-side mod like [MCCustomSkinLoader](https://github.com/xfl03/MCCustomSkinLoader) (untested). Integer. Default value: `128`.
- `SignPublicKeys`: Whether to sign players' public keys. Boolean. Default value: `true`.
    - Must be enabled if you want to support servers with `enforce-secure-profile=true` in server.properties.
    - Limits servers' ability to forge messages from players.
    - Disable if you want clients to be able to send chat messages with plausible deniability and you don't need to support `enforce-secure-profile=true`.
    - Note: Minecraft 1.19 can only validate player public keys against Mojang's public key, not ours, so you should use `enforce-secure-profile=false` on versions earlier than 1.20.
- `EnableTokenExpiry`: By default, public keys will never expire and access tokens will stay valid even when you are logged in on multiple devices. If this option is set to `true`, public keys will expire after one day, and access tokens will be invalidated when you sign in on a different device. Enable this option if you are especially security-conscious and don't mind restarting your game more often. Boolean. Default value: `false`.
- `AllowChangingPlayerName`: Allow users to change their "player name" after their account has already been created. Could be useful in conjunction with `RegistrationExistingPlayer` if you want to make users register from an existing (e.g. Mojang) account but you want them to be able to choose a new player name. Boolean. Default value: `true`.
- `AllowSkins`: Allow users to upload skins. You may want to disable this option if you want to rely exclusively on `ForwardSkins`, e.g. to fully support Vanilla clients. Boolean. Default value: `true`.
- `AllowCapes`: Allow users to upload capes. Boolean. Default value: `true`.
