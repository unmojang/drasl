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

      buildXDraslText =
        pkgs:
        pkgs.buildGoModule {
          pname = "xdrasltext";
          inherit version;
          src = nixpkgs.lib.fileset.toSource {
            root = ./.;
            fileset = nixpkgs.lib.fileset.unions [
              ./cmd/xdrasltext
              ./go.mod
              ./go.sum
            ];
          };
          subPackages = [ "cmd/xdrasltext" ];
          vendorHash = "sha256-JNzrZi790/T+3Z7Td7X8sURSj2wcpsa7nKGINqb+fyg=";
        };
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
      checks = forEachSystem (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          pre-commit-check = git-hooks.lib.${system}.run {
            src = ./.;
            package = pkgs.prek;
            hooks = {
              nixfmt.enable = true;
              trim-trailing-whitespace.enable = true;
              gofmt.enable = true;
              swag = {
                enable = true;
                name = "Generate Swagger/OpenAPI documentation";
                extraPackages = [
                  pkgs.go
                  pkgs.go-swag
                ];
                entry = "make swag";
                files = "\\.go$";
                pass_filenames = false;
              };
              swag-fmt = {
                enable = true;
                name = "format swag comments";
                extraPackages = [
                  pkgs.go-swag
                ];
                entry = "swag fmt";
                files = "\\.go$";
                pass_filenames = false;
              };
              messages-pot = {
                enable = true;
                name = "Generate messages.pot";
                extraPackages = [ (buildXDraslText pkgs) ];
                entry = "make messages.pot";
                files = "\\.(tmpl|go)$";
                pass_filenames = false;
              };
            };
          };
        }
      );
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
              vendorHash = "sha256-07VlwgzgeHX4W2HAYqKzIpGmq6kN/kprYZPUsCwqhiw=";

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

              meta.mainProgram = "drasl";
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
        { ... }:
        {
          imports = [ ./nix/module.nix ];
          _module.args.self = self;
        };
      nixosModules.default = self.nixosModules.drasl;

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
