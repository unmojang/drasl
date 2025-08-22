{
  description = "Self-hosted API server for Minecraft";

  inputs = {
    nixpkgs.url = "nixpkgs/nixos-unstable";
  };

  outputs =
    {
      self,
      nixpkgs,
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
      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;

      overlays = [ ];

      nixpkgsFor = forAllSystems (system: import nixpkgs { inherit system overlays; });
      nixpkgsCross = forAllSystems (
        localSystem:
        forAllSystems (crossSystem: import nixpkgs { inherit localSystem crossSystem overlays; })
      );
    in
    {
      packages = forAllSystems (
        system:
        let
          buildDrasl =
            pkgs:
            let
              nodejs = pkgs.nodejs_20;
              npmDeps = pkgs.importNpmLock.buildNodeModules {
                inherit nodejs;
                npmRoot = ./.;
              };
            in
            pkgs.buildGoModule {
              pname = "drasl";
              inherit version;

              src = ./.;

              nativeBuildInputs = with pkgs; [
                nodejs
                go-swag
              ];

              # Update whenever Go dependencies change
              vendorHash = "sha256-4Rk59bnDFYpraoGvkBUW6Z5fiXUmm2RLwS1wxScWAMQ=";

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
        rec {
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
            enable = mkEnableOption (lib.mdDoc ''drasl'');
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
                  pkg = self.defaultPackage.${pkgs.system};
                  config = format.generate "config.toml" cfg.settings;
                in
                {
                  ExecStart = "${pkg}/bin/drasl -config ${config}";
                  DynamicUser = true;
                  StateDirectory = "drasl";
                  Restart = "always";
                };
            };
          };
        };

      devShells = forAllSystems (
        system:
        let
          pkgs = nixpkgsFor.${system};
        in
        {
          default = pkgs.mkShell {
            # https://github.com/go-delve/delve/issues/3085
            hardeningDisable = [ "fortify" ];
            buildInputs = with pkgs; [
              cabal-install
              nixfmt-rfc-style
              delve
              go
              go-swag
              go-tools
              golangci-lint
              gopls
              gore
              gotools
              nodejs
              pre-commit
              sqlite-interactive
              swagger-codegen
              gettext
            ];
          };
        }
      );

      defaultPackage = forAllSystems (system: self.packages.${system}.drasl);
    };
}
