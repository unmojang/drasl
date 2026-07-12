{
  description = "Self-hosted API server for Minecraft";

  inputs = {
    nixpkgs.url = "nixpkgs/nixos-26.05";
    git-hooks.url = "github:cachix/git-hooks.nix";
  };

  outputs =
    {
      self,
      nixpkgs,
      git-hooks,
    }:
    let
      version =
        let
          buildConfig = builtins.readFile ./build_config.go;
          lines = nixpkgs.lib.strings.splitString "\n" buildConfig;
          versionExpr = "^const VERSION = \"([^\"]+)\"$";

          findVersion =
            lines:
            if builtins.length lines == 0 then
              builtins.error "VERSION not found in build_config.go"
            else
              let
                match = builtins.match versionExpr (nixpkgs.lib.head lines);
              in
              if match == null then findVersion (nixpkgs.lib.tail lines) else builtins.elemAt match 0;
        in
        findVersion lines;

      supportedSystems = [
        "x86_64-linux"
        "x86_64-darwin"
        "aarch64-linux"
        "aarch64-darwin"
      ];

      # Helper function to generate an attrset '{ x86_64-linux = f "x86_64-linux"; ... }'.
      forEachSystem = nixpkgs.lib.genAttrs supportedSystems;

      overlays = [ ];

      nixpkgsFor = forEachSystem (system: import nixpkgs { inherit system overlays; });
      nixpkgsCross = forEachSystem (
        localSystem:
        forEachSystem (crossSystem: import nixpkgs { inherit localSystem crossSystem overlays; })
      );
    in
    {
      formatter = forEachSystem (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          config = self.checks.${system}.pre-commit-check.config;
          inherit (config) package configFile;
          script = ''
            ${pkgs.lib.getExe package} run --all-files --config ${configFile}
          '';
        in
        pkgs.writeShellScriptBin "prek" script
      );
      checks = forEachSystem (system: {
        pre-commit-check = git-hooks.lib.${system}.run {
          src = ./.;
          hooks = {
            nixfmt.enable = true;
            trim-trailing-whitespace.enable = true;
            gofmt.enable = true;
            swag = {
              enable = true;
              name = "Generate Swagger/OpenAPI documentation";
              entry = "make swag";
              files = "\\.go$";
              pass_filenames = false;
            };
            swag-fmt = {
              enable = true;
              name = "format swag comments";
              entry = "go tool swag fmt";
              files = "\\.go$";
              pass_filenames = false;
            };
          };
        };
      });
      packages = forEachSystem (
        system:
        let
          buildDrasl =
            pkgs:
            let
              nodejs = pkgs.nodejs_26;
              npmDeps = pkgs.importNpmLock.buildNodeModules {
                inherit nodejs;
                npmRoot = ./.;
              };
            in
            pkgs.buildGoModule {
              pname = "drasl";
              inherit version;

              src = ./.;

              nativeBuildInputs = [
                nodejs
              ];

              # Update whenever Go dependencies change
              vendorHash = "sha256-lntObxC6KmX4aETbgjRSM9j2F+6EBgB/lRmgc306N5M=";

              outputs = [ "out" ];

              preConfigure = ''
                substituteInPlace build_config.go --replace-fail "\"/usr/share/drasl\"" "\"$out/share/drasl\""
              '';

              preBuild = ''
                ln -s ${npmDeps}/node_modules .
                make -o npm-install prebuild
              '';

              postInstall = ''
                mkdir -p "$out/share/drasl"
                cp -R ./{assets,view,public,locales} "$out/share/drasl"
              '';
            };

          buildOCIImage =
            pkgs:
            pkgs.dockerTools.buildLayeredImage {
              name = "unmojang/drasl";
              contents = with pkgs; [ cacert ];
              config.Cmd = [ "${buildDrasl pkgs}/bin/drasl" ];
            };
        in
        {
          drasl = buildDrasl nixpkgsFor.${system};

          drasl-cross-x86_64-linux = buildDrasl nixpkgsCross.${system}.x86_64-linux;
          # drasl-cross-x86_64-darwin = buildDrasl nixpkgsCross.${system}.x86_64-darwin;
          drasl-cross-aarch64-linux = buildDrasl nixpkgsCross.${system}.aarch64-linux;
          # drasl-cross-aarch64-darwin = buildDrasl nixpkgsCross.${system}.aarch64-darwin;

          oci = buildOCIImage nixpkgsFor.${system};

          oci-cross-x86_64-linux = buildOCIImage nixpkgsCross.${system}.x86_64-linux;
          # oci-cross-x86_64-darwin = buildOCIImage nixpkgsCross.${system}.x86_64-darwin;
          oci-cross-aarch64-linux = buildOCIImage nixpkgsCross.${system}.aarch64-linux;
          # oci-cross-aarch64-darwin = buildOCIImage nixpkgsCross.${system}.aarch64-darwin;
        }
      );

      nixosModules.drasl =
        {
          config,
          lib,
          pkgs,
          ...
        }:
        with lib;
        let
          cfg = config.services.drasl;
          format = pkgs.formats.toml { };
        in
        {
          options.services.drasl = {
            enable = mkEnableOption (lib.mdDoc "drasl");
            package = mkPackageOption {
              drasl = self.defaultPackage.${pkgs.stdenv.hostPlatform.system};
            } "drasl" { };
            settings = mkOption {
              type = format.type;
              default = { };
              description = lib.mdDoc ''
                config.toml for drasl
              '';
            };
          };
          config = mkIf cfg.enable {
            systemd.services.drasl = {
              description = "drasl";
              wantedBy = [ "multi-user.target" ];
              after = [
                "network-online.target"
                "nss-lookup.target"
              ];
              wants = [
                "network-online.target"
                "nss-lookup.target"
              ];

              serviceConfig =
                let
                  config = format.generate "config.toml" cfg.settings;
                in
                {
                  ExecStart = "${cfg.package}/bin/drasl -config ${config}";
                  DynamicUser = true;
                  StateDirectory = "drasl";
                  Restart = "always";
                };
            };
          };
        };

      devShells = forEachSystem (
        system:
        let
          pkgs = nixpkgsFor.${system};
          inherit (self.checks.${system}.pre-commit-check) shellHook enabledPackages;
        in
        {
          default = pkgs.mkShell {
            inherit shellHook;
            # https://github.com/go-delve/delve/issues/3085
            hardeningDisable = [ "fortify" ];
            buildInputs =
              with pkgs;
              [
                cabal-install
                nixfmt
                delve
                go
                go-tools
                golangci-lint
                gopls
                gore
                gotools
                nodejs
                prek
                sqlite-interactive
                gettext
              ]
              ++ enabledPackages;
          };
        }
      );

      defaultPackage = forEachSystem (system: self.packages.${system}.drasl);
    };
}
