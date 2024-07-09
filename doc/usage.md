# Usage

## Installation & Configuration

See [installation.md](installation.md) for installation instructions. Refer to [recipes.md](recipes.md) for sample configuration files and [configuration.md](configuration.md) for documentation of the available options.

## Initial setup

Start by creating an account. If you configured your instance to require an invite to register, an initial invite link will be printed to the log on stdout when Drasl starts. If you are running Drasl with Docker, you can view the log with `docker logs docker-drasl-1` or similar. If you're running it with systemd, use `sudo journalctl -u drasl`. You're searching for a line like:

```
No users found! Here's an invite URL: https://drasl.example.com/web/registration?invite=ST1dEC1dLeN
```

Make sure your new account's username is in the list of `DefaultAdmins` in your configuration file. Admins can access the "Admin" page via the link in the top right, where they can issue invites, manage other accounts, and make other users admins.

## Configuring your Minecraft client

Using Drasl on the client requires a third-party launcher that supports custom API servers. [Fjord Launcher](https://github.com/unmojang/FjordLauncher), a fork of Prism Launcher, is recommended, but [HMCL](https://github.com/huanghongxun/HMCL) also works. Both are free/libre.

### Fjord Launcher

1. Click your account in the top right and select "Manage Accounts...".
2. Click "Add authlib-injector" in the right-hand sidebar.
3. Enter the username and password of your Drasl account.
4. Use the base URL of your Drasl instance (the value of the `BaseURL` configuration option) as the URL for the API server, for example `https://drasl.example.com`.
5. Click "OK".

### HMCL

1. Go to the "Account List" view by clicking the account at the top of the sidebar.
2. At the bottom left, click "New Auth Server" and enter the `BaseURL` of your Drasl instance, for example `https://drasl.example.com`. Click "Next" and then "Finish".
3. In the sidebar, click the newly-added authentication server. Enter the username and password of your Drasl account and click "Login".

### Other launchers

Use the authlib-injector URL `https://drasl.example.com/authlib-injector`, replacing `https://drasl.example.com` with the `BaseURL` of your Drasl instance..

Or, if your launcher expects a separate URL for each API server, use these, replacing `https://drasl.example.com`:

- Authentication server: https://drasl.example.com/auth
- Account server: https://drasl.example.com/account
- Session server: https://drasl.example.com/session
- Services server: https://drasl.example.com/services

### CustomSkinLoader

Drasl can be used as a skin source for [CustomSkinLoader](https://github.com/xfl03/MCCustomSkinLoader), for example to see skins on offline servers while using a launcher that doesn't support custom API servers.

After installing CustomSkinLoader, launch the game once and join a world to populate the default CustomSkinLoader configuration file. Close the game.

Then, locate your `.minecraft` folder. If you're using Mojang's launcher, see [here](https://minecraft.wiki/w/.minecraft). If you're using Prism Launcher or one of its cousins, right-click your instance and select "Folder". `.minecraft` will be inside the instance folder, possibly hidden. The folder might be called `minecraft` without the leading `.`.

Inside `.minecraft`, edit `CustomSkinLoader/CustomSkinLoader.json` and add the following object to the `loadlist`, replacing `https://drasl.example.com` with the `BaseURL` of your Drasl instance:

```
{
    "name": "Drasl",
    "type": "MojangAPI",
    "apiRoot": "https://drasl.example.com/account/",
    "sessionRoot": "https://drasl.example.com/session/"
}
```

You can remove all the other skin sources if you want Drasl to be the only source, or you can keep them and just add Drasl to the end of the list.

The trailing slashes on the URLs are important, don't miss them.

### Mineflayer/node-minecraft-protocol

To use third-party API servers with Mineflayer, create a node-minecraft-protocol `Client` object and pass it to `mineflayer.createBot`, as follows.

Chat signing with third-party API servers is [currently not supported](https://github.com/unmojang/drasl/issues/67) by Mineflayer, so you'll need to set `enforce-secure-profile=false` in your `server.properties` and pass `disableChatSigning: true` to `mc.createClient`:

```
import mc from "minecraft-protocol";
import mineflayer from "mineflayer";

const client = mc.createClient({
    host: "minecraft-server.example.com",
    username: "Bot",
    password: "hunter2",
    auth: "mojang",
    authServer: "https://drasl.example.com/auth",
    sessionServer: "https://drasl.example.com/session",
    disableChatSigning: true,
});

const bot = mineflayer.createBot({client});
```

## Configuring your Minecraft server

### Minecraft 1.16 and later

On recent versions of Minecraft, you can use Drasl on an unmodified Vanilla server. To do so, add the following arguments before you specify the jar file when you start the server. Replace `https://drasl.example.com` with the `BaseURL` of your Drasl instance:

```
-Dminecraft.api.env=custom
-Dminecraft.api.auth.host=https://drasl.example.com/auth
-Dminecraft.api.account.host=https://drasl.example.com/account
-Dminecraft.api.session.host=https://drasl.example.com/session
-Dminecraft.api.services.host=https://drasl.example.com/services
```

For example, the full command you use to start the server might be:

```
java -Xmx1024M -Xms1024M \
    -Dminecraft.api.env=custom \
    -Dminecraft.api.auth.host=https://drasl.example.com/auth \
    -Dminecraft.api.account.host=https://drasl.example.com/account \
    -Dminecraft.api.session.host=https://drasl.example.com/session \
    -Dminecraft.api.services.host=https://drasl.example.com/services \
    -jar server.jar nogui
```

### Minecraft 1.15.2 and earlier

Refer to the authlib-injector documentation on setting up a server: [https://github.com/yushijinhun/authlib-injector/blob/develop/README.en.md#deploy](https://github.com/yushijinhun/authlib-injector/blob/develop/README.en.md#deploy).

Alternatively, you can patch your server to use a newer version of Mojang's authlib that supports custom API servers. See [https://github.com/tinytengu/minecraft-authlib](https://github.com/tinytengu/minecraft-authlib).

## Default skins

If a user has not set a skin and a skin is not forwarded from a fallback API server via `ForwardSkins`, Drasl will try to serve one of the "default skins" in `$STATE_DIRECTORY/default-skin/` (`/var/lib/drasl/default-skin/` by default). You can create this directory and place your own PNG textures inside to override the default Steve/Alex skins used by the client when a skin is not available.

Make sure the files are valid PNGs with names ending with `.png` (lowercase). Filenames ending in `slim.png`, such as `Alex-skin-slim.png` will be assumed to be for the "slim" player model. All other files will be assumed to be for the "classic" player model.

Drasl chooses which skin to serve based on the player's UUID. A player will be consistently assigned the same default skin, but this assignment will change if skins are added or removed from `$STATE_DIRECTORY/default-skin/`.

### Default capes

Similarly, a cape is arbitrarily chosen from `$STATE_DIRECTORY/default-cape/` (`/var/lib/drasl/default-cape`) when a user has not set a cape.
