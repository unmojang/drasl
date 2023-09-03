{
  description = "Self-hosted API server for Minecraft";

  # Nixpkgs / NixOS version to use.
  inputs = {
    nixpkgs.url = "nixpkgs/nixos-22.11";
    npmlock2nix = {
      url = "github:nix-community/npmlock2nix";
      flake = false;
    };
  };

  outputs = {
    self,
    nixpkgs,
    npmlock2nix,
  }: let
    version = "0.9.4";

    # System types to support.
    supportedSystems = ["x86_64-linux" "x86_64-darwin" "aarch64-linux" "aarch64-darwin"];

    # Helper function to generate an attrset '{ x86_64-linux = f "x86_64-linux"; ... }'.
    forAllSystems = nixpkgs.lib.genAttrs supportedSystems;

    # Nixpkgs instantiated for supported system types.
    nixpkgsFor = forAllSystems (system: let
      overlays = [
        (final: prev: {
          npmlock2nix = import npmlock2nix {pkgs = prev;};
        })
      ];
    in
      import nixpkgs {inherit system overlays;});
  in {
    # Provide some binary packages for selected system types.
    packages = forAllSystems (system: let
      pkgs = nixpkgsFor.${system};
      nodeModules = pkgs.npmlock2nix.v2.node_modules {
        src = ./.;
        nodejs = pkgs.nodejs;
      };
    in {
      drasl = pkgs.buildGoModule {
        pname = "drasl";
        inherit version;
        src = ./.;

        # Update whenever Go dependencies change
        vendorSha256 = "sha256-YNOTEza43Uvl2FaU4DiFo3GLmnn/o106pMnHyjQ+Je4=";

        outputs = ["out"];

        preConfigure = ''
          substituteInPlace build_config.go --replace "\"/usr/share/drasl\"" "\"$out/share/drasl\""
        '';

        preBuild = ''
          ln -s ${nodeModules}/node_modules node_modules
          ${pkgs.nodejs}/bin/node esbuild.config.js
          cp css/style.css public/
        '';

        postInstall = ''
          mkdir -p "$out/share/drasl"
          cp -R ./{assets,view,public} "$out/share/drasl"
        '';
      };
    });

    nixosModules.drasl = {
      config,
      lib,
      pkgs,
      ...
    }:
      with lib; let
        cfg = config.services.drasl;
        format = pkgs.formats.toml {};
      in {
        options.services.drasl = {
          enable = mkEnableOption (lib.mdDoc ''drasl'');
          settings = mkOption {
            type = format.type;
            default = {};
            description = lib.mdDoc ''
              config.toml for drasl
            '';
          };
        };
        config = mkIf cfg.enable {
          systemd.services.drasl = {
            description = "drasl";
            wantedBy = ["multi-user.target"];

            serviceConfig = let
              pkg = self.defaultPackage.${pkgs.system};
              config = format.generate "config.toml" cfg.settings;
            in {
              ExecStart = "${pkg}/bin/drasl -config ${config}";
              DynamicUser = true;
              StateDirectory = "drasl";
              Restart = "always";
            };
          };
        };
      };

    devShells = forAllSystems (system: let
      pkgs = nixpkgsFor.${system};
    in {
      default = pkgs.mkShell {
        buildInputs = with pkgs; [
          alejandra
          delve
          go
          go-tools
          golangci-lint
          gopls
          gore
          gotools
          nodejs
          pre-commit
          sqlite-interactive
        ];
      };
    });

    defaultPackage = forAllSystems (system: self.packages.${system}.drasl);
  };
}
