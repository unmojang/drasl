# Installation

These instructions are written assuming you're running Linux, but the Docker setup process should be about the same on macOS or Windows.

Drasl is an HTTP server that listens on port 25585 (customize with the `ListenAddress` option). You'll want to put it behind a reverse proxy for HTTPS.

### Docker

On most systems, Docker is the easiest way to host Drasl:

1. In any working directory, clone the repository (you can delete it later if you want):

   `git clone https://github.com/unmojang/drasl.git`

2. Copy the `docker` example to wherever you want to store Drasl's data. I like `/srv/drasl`:

   `sudo cp -RTi ./drasl/example/docker /srv/drasl`

3. `cd /srv/drasl`
4. Fill out `config/config.toml` according to one of the examples in [doc/recipes.md](recipes.md).
5. `docker compose up -d`
6. Set up an reverse proxy (using e.g. [Caddy](https://caddyserver.com/) or nginx) from your base URL (e.g. `https://drasl.example.com`) to `http://localhost:25585`.

Note: when Drasl updates, you will have to manually pull the most recent version:

```
cd /srv/drasl
docker compose pull && docker compose up -d
```

### Docker with Caddy reverse proxy

If you don't already have a web server to use as a reverse proxy, you can use the `docker-caddy` example instead which sets up a Caddy server with automatic TLS:

1. In any directory, clone the repository (you can delete it later if you want):

   `git clone https://github.com/unmojang/drasl.git`

2. Copy the `docker-caddy` example to wherever you want to store Drasl's data:

   `sudo cp -RTi ./drasl/example/docker-caddy /srv/drasl`

3. `cd /srv/drasl`
4. Fill out `Caddyfile`
5. Fill out `config/config.toml` according to one of the examples in [doc/recipes.md](recipes.md).
6. `docker compose up -d`

Note: when Drasl updates, you will have to manually pull the most recent version:

```
cd /srv/drasl
docker compose pull && docker compose up -d
```

### Arch Linux (AUR)

Drasl is available in the AUR as `drasl-git`:

1. `yay -Syu drasl-git # (or whatever AUR helper is hot right now)`
2. Fill out `/etc/drasl/config.toml` according to one of the examples in [doc/recipes.md](recipes.md).
3. `sudo systemctl enable --now drasl`

### NixOS (flake)

For NixOS users, the project's flake provides a NixOS module. This example `/etc/nixos/flake.nix` shows how you might include it in your configuration:

```
{
    description = "Example Drasl NixOS configuration";
    inputs = {
        nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
        drasl = {
            type = "git";
            url = "https://github.com/unmojang/drasl.git";
            ref = "master";
        };
    };
    outputs = {self, nixpkgs, drasl, ...}@inputs: {
        nixosConfigurations = {
            "myhostname" = nixpkgs.lib.nixosSystem {
                system = "x86_64-linux";
                modules = [
                    drasl.nixosModules.drasl
                    ./configuration.nix
                ];
            };
        };
    };
}
```

Then, in your `configuration.nix`:

```
services.drasl = {
    enable = true;
    settings = {
        Domain = "drasl.example.com";
        BaseURL = "https://drasl.example.com";
        DefaultAdmins = [ "" ];
    };
};
```

See [doc/configuration.md](configuration.md) for documentation of the options in `services.drasl.settings`.

### NixOS (OCI containers)

This is a more declarative version of the Docker setup from above.

1. In any directory, clone the repository (you can delete it later if you want):

   `git clone https://github.com/unmojang/drasl.git`

2. Copy the `docker` example to wherever you want to store Drasl's data:

   `sudo cp -RTi ./drasl/example/docker /srv/drasl`

3. `cd /srv/drasl`
4. Fill out `config/config.toml` according to one of the examples in [doc/recipes.md](recipes.md).

5. Add the following to your `/etc/nixos/configuration.nix` and then `sudo nixos-rebuild switch`:

   ```
   virtualisation.oci-containers = {
       containers.drasl = {
           volumes = [ "/srv/drasl/config:/etc/drasl" "/srv/drasl/data:/var/lib/drasl" ];
           image = "unmojang/drasl";
           ports = [ "127.0.0.1:25585:25585" ];
           extraOptions = [ "--pull=newer" ]; # Optional: auto-update
       };
   };
   ```

### Manual Installation (Linux)

1. Install build dependencies:

   ```
   sudo apt install make golang gcc nodejs npm # Debian
   sudo dnf install make golang gcc nodejs npm # Fedora
   sudo pacman -S make go gcc nodejs npm       # Arch Linux
   ```

2. Clone the repository:

   ```
   git clone git@github.com:unmojang/drasl.git     # SSH
   git clone https://github.com/unmojang/drasl.git # HTTPS
   cd drasl
   ```

3. Build and install:

   ```
   make
   sudo make install
   ```

4. Create `/etc/drasl/config.toml` and fill it out according to one of the examples in [doc/recipes.md](recipes.md).

5. Install, enable, and start the provided systemd service:

   ```
   sudo install -m 644 ./example/drasl.service /etc/systemd/system/drasl.service
   sudo systemctl daemon-reload
   sudo systemctl enable --now drasl.service
   ```

### Post-installation

Consider setting up [Litestream](https://litestream.io/) and/or some other kind of backup system if you're running Drasl in production.

Continue to [usage.md](usage.md).
