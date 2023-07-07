# Drasl

### Drasl is currently alpha software with pretty low test coverage! Use at your own risk! Targeting August 2023 for a more solid 1.0.0 release.

Drasl is an alternative API server for Minecraft that handles authentication, skins, capes, and more.
You can use it to host Minecraft servers that are completely independent from Mojang's infrastructure.
It's compatible with both authlib-injector and the vanilla Yggdrasil protocol, which means it supports a wide variety of Minecraft launchers, including [Prism Launcher](https://github.com/PrismLauncher/PrismLauncher) (if [this pull request](https://github.com/PrismLauncher/PrismLauncher/pull/543) gets merged), [HMCL](https://github.com/huanghongxun/HMCL), and [UltimMC](https://github.com/UltimMC/Launcher). It includes a minimalist web front end for registering and managing accounts.

## Background

You've always been able to host your own Minecraft server, but unless you run the server in offline mode, authentication and skins are usually still handled by Mojang's API servers.
There are many reasons to host your own API server instead of using Mojang's. Your community might want to:

- Experience the benefits of offline servers without losing skins, encrypted connections, or account security
- Create additional accounts to allow users to have multiple players logged in to a server simultaneously
    - Have a "camera account" spectate your character for content creation
    - Program [bots](https://mineflayer.prismarine.js.org/) to automate tedious tasks like AFKing, crafting, or even building map art.
- Have skins with transparency, or high-resolution skins (this would require a modded client as well)
- Play Minecraft in a country or on a network where Mojang's servers are inaccessible
- Keep your activity private from Mojang. Mojang knows which servers you are active on, when you log on, who else is on those servers, etc. If telemetry is enabled (since 1.18, it cannot be disabled without a [mod](https://github.com/kb-1000/no-telemetry)), they are also notified whenever you load a singleplayer world.
- Support players that don't have a Microsoft account
- Serve access tokens that last longer, so you don't run into "Invalid session" errors as often. These errors can be annoying with modpacks that take a long time to restart.
- Opt out of chat reporting
- Have a backup authentication system in case Mojang's servers go down

## Features

- Easy to host: a single Go binary plus a few static assets, no runtime dependencies
- Highly configurable
- Fast, minimalist, and highly-accessible web interface
- Optional: proxy requests to fallback API servers (see [FallbackAPIServers](doc/configuration.md))
    - You can configure your Minecraft server to accept users logged in with either a Mojang account or a Drasl account.
- Optional: disable access token and public key expiry (no more "Invalid session" or "Invalid signature for profile public key")
- Optional: sign player public keys to support chat signing and `enforce-secure-profile=true` (see [SignPublicKeys](doc/configuration.md))
- Optional: allow high-resolution skins (see [SkinSizeLimit](doc/configuration.md))
- Optional: allow registering from existing account an another API server (i.e. Mojang's) (see [RegistrationExistingPlayer](doc/configuration.md))
    - Useful if you want to keep your UUID
    - Optional: require a skin challenge to verify ownership of the existing account (see [RequireSkinVerification](doc/configuration.md))

## Drawbacks

- When not using authlib-injector, skins won't appear in game, since the Minecraft client verifies that skin data is signed by Mojang and only allows skins from Mojang domains. You can use the [DraslTweaks](https://github.com/Unmojang/DraslTweaks) mod to bypass these checks and get skins working.

<!-- ## Installation -->

<!-- See [doc/installation.md](...) -->

<!-- ## Recipes -->

<!-- See [doc/recipes.md](...) for common configuration patterns. -->

## Configuration

See [doc/configuration.md](doc/configuration.md)

## Building

If using Nix, simply run `nix build`.

Otherwise, install build dependencies:

```
sudo apt install -y make golang nodejs npm # Debian
sudo dnf install -y make go nodejs npm # Fedora
sudo pacman -S make go nodejs npm # Arch Linux
```

Then build the program with:
```
make
```

Run the tests with:
```
go test
```

<!-- ## Web API Documentation -->

<!-- See [doc/api.md](...) -->

## Alternatives

- [Blessing Skin](https://github.com/bs-community/blessing-skin-server) with the yggdrasil-api [plugin](https://github.com/bs-community/blessing-skin-plugins)
- [Ely.by](https://ely.by/)

## License

[GPLv3](https://github.com/unmojang/drasl/blob/master/LICENSE)

_Why GPL and not AGPL? Isn't this a web application?_

Drasl is intended to be self-hosted, customized, and hacked on. If it were licensed under the GNU Affero GPL, any user who tweaks their instance even slightly would be required to publish the changes, or else they would be violating the AGPL. While I'm a strong believer in copyleft, I don't want to place such a burden on the users in this particular case.
