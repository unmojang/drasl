# ![Drasl icon](doc/icon.png) Drasl

Drasl is an alternative API server for Minecraft that handles authentication, skins, and capes.
You can use it to host Minecraft servers that are completely independent from Mojang's infrastructure.
It's designed to be easy to host yourself, but a "reference instance" is hosted at [https://drasl.unmojang.org](https://drasl.unmojang.org) which currently requires a Minecraft account to register.

It's compatible with both [authlib-injector](https://github.com/yushijinhun/authlib-injector/blob/develop/README.en.md) and the vanilla Yggdrasil protocol, which means it supports:

- Minecraft launchers that support authlib-injector, such as [PollyMC](https://github.com/fn2006/PollyMC), [HMCL](https://github.com/huanghongxun/HMCL), or [PolyMC](https://github.com/PolyMC/PolyMC).
- Minecraft servers running authlib-injector
- Vanilla Minecraft servers running version 1.16 or later, via JVM arguments. Vanilla 1.16+ clients are supported too, but most launchers use authlib-injector for third-party accounts.

It includes a minimalist web front end for registering and managing accounts.

## Background

You've always been able to host your own Minecraft server, but unless you run the server in offline mode, authentication and skins are usually still handled by Mojang's API servers.
There are many reasons to host your own API server instead of using Mojang's. Your community might want to:

- Experience the benefits of offline servers without losing skins, encrypted connections, or account security
- Create additional accounts to allow users to have multiple players logged in to a server simultaneously
  - Have a "camera account" spectate your character for content creation
  - Program [bots](https://prismarinejs.github.io/) to automate tedious tasks like AFKing, crafting, or even building map art.
- Have skins with transparency, or high-resolution skins (this would require a modded client as well)
- Play Minecraft in a country or on a network where Mojang's servers are inaccessible
- Keep your activity private from Mojang. Mojang knows which servers you are active on, when you log on, who else is on those servers, etc. If telemetry is enabled (since 1.18, it cannot be disabled without a [mod](https://github.com/kb-1000/no-telemetry)), they are also notified whenever you load a singleplayer world.
- Support players that don't have a Microsoft account
- Serve access tokens that last longer, so you don't run into "Invalid session" errors as often. These errors can be annoying with modpacks that take a long time to restart.
- Opt out of chat reporting
- Have a backup authentication system in case Mojang's servers go down

## Features

- Easy to host: a single Go binary plus a few static assets, no runtime dependencies. See [doc/installation.md](doc/installation.md).
- Highly configurable
- Fast, minimalist, and highly-accessible web interface. JavaScript is used only for cosmetic effects and is not required.
- Optional: proxy requests to fallback API servers (see [FallbackAPIServers](doc/configuration.md))
  - You can configure your Minecraft server to accept users logged in with either a Mojang account or a Drasl account.
- Optional: disable access token and public key expiry (no more "Invalid session" or "Invalid signature for profile public key")
- Optional: sign player public keys to support chat signing and `enforce-secure-profile=true` (see [SignPublicKeys](doc/configuration.md))
- Optional: allow high-resolution skins (see [SkinSizeLimit](doc/configuration.md))
- Optional: allow registering from existing account an another API server (i.e. Mojang's) (see [RegistrationExistingPlayer](doc/configuration.md))
  - Useful if you want to keep your UUID
  - Optional: require a skin challenge to verify ownership of the existing account (see [RequireSkinVerification](doc/configuration.md))

## Installation

### Quick Setup (for Docker on Linux)

1. `git clone https://github.com/unmojang/drasl.git`
2. `sudo cp -RTi ./drasl/example/docker /srv/drasl`
3. `cd /srv/drasl`
4. Fill out `config/config.toml` according to one of the examples in [doc/recipes.md](doc/recipes.md)
5. `docker compose up -d`
6. Set up an HTTPS reverse proxy (using e.g. [Caddy](https://caddyserver.com/) or nginx) to `localhost:25585`.

See [doc/installation.md](doc/installation.md) for other setups, including instructions for setting up a reverse proxy.

## Configuration

See [doc/configuration.md](doc/configuration.md) for documentation of the configuration options and [doc/recipes.md](doc/recipes.md) for common configuration patterns.

### Usage

See [doc/usage.md](doc/usage.md) for post-installation instructions and guidance on setting up Minecraft clients and servers.

## API

Drasl implements the Mojang API, documented here on [wiki.vg](https://wiki.vg):

- [Mojang API](https://wiki.vg/Mojang_API)
- [Legacy Mojang Authentication](https://wiki.vg/Legacy_Mojang_Authentication)
- [Protocol Encryption](https://wiki.vg/Protocol_Encryption)

If you find that an API route behaves substantively different than the Mojang API, please [file an issue](https://github.com/unmojang/drasl/issues).

Drasl also implements (almost all of) the authlib-injector API at `/authlib-injector`, to the extent that it differs from Mojang's. The authlib-injector API is documented [here](https://github.com/yushijinhun/authlib-injector/wiki/Yggdrasil-%E6%9C%8D%E5%8A%A1%E7%AB%AF%E6%8A%80%E6%9C%AF%E8%A7%84%E8%8C%83) ([Google Translated to English](https://github-com.translate.goog/yushijinhun/authlib-injector/wiki/Yggdrasil-%E6%9C%8D%E5%8A%A1%E7%AB%AF%E6%8A%80%E6%9C%AF%E8%A7%84%E8%8C%83?_x_tr_sl=auto&_x_tr_tl=en&_x_tr_hl=en-US)).

A Drasl API for creating and administering accounts is [planned](https://github.com/unmojang/drasl/issues/18).

## Building

If using Nix (with flakes), simply run `nix build`.

Otherwise, install build dependencies. Go 1.19 or later is required:

```
sudo apt install make golang gcc nodejs npm    # Debian
sudo dnf install make go gcc nodejs npm        # Fedora
sudo pacman -S make go gcc nodejs npm          # Arch Linux
```

Then build the program with:

```
make
```

Run the tests with:

```
make test
```

## Alternatives

- [Blessing Skin](https://github.com/bs-community/blessing-skin-server) with the yggdrasil-api [plugin](https://github.com/bs-community/blessing-skin-plugins)
- [Ely.by](https://ely.by/)

## License

[GPLv3](https://github.com/unmojang/drasl/blob/master/LICENSE)

_Why GPL and not AGPL? Isn't this a web application?_

Drasl is intended to be self-hosted, customized, and hacked on. If it were licensed under the GNU Affero GPL, any user who tweaks their instance even slightly would be required to publish the changes, or else they would be violating the AGPL. While I'm a strong believer in copyleft, I don't want to place such a burden on the users in this particular case.
