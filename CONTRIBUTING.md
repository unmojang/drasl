# Contributing

Pull requests are welcome. Most changes in code, especially new features, should be accompanied by new tests.

We recommend using [Nix](https://nixos.org) when working on Drasl. This repository includes a `flake.nix` supplying a development environment (run `nix develop` or use [direnv](https://direnv.net)) and a build script (run `nix build`).

We use [pre-commit](https://pre-commit.com) for pre-commit hooks. Before you `git commit`, set up [pre-commit](https://pre-commit.com) (it's already included in the Nix development environment) and run `pre-commit install`.
