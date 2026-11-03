{
  description = "Stogas command line: a verified local endpoint, sign-up and offline checks";

  # `nix run github:StogasAI/stogas -- serve --security tls` builds the CLI from this source with
  # nixpkgs's Rust, which must be at least the workspace's rust-version.
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
      forEachSystem = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
      workspace = (builtins.fromTOML (builtins.readFile ./Cargo.toml)).workspace.package;
    in
    {
      packages = forEachSystem (pkgs: {
        default = pkgs.rustPlatform.buildRustPackage {
          pname = "stogas";
          inherit (workspace) version;
          # Only what Cargo reads, so other changes reuse the build.
          src = pkgs.lib.fileset.toSource {
            root = ./.;
            fileset = pkgs.lib.fileset.unions [
              ./Cargo.toml
              ./Cargo.lock
              ./LICENSE
              ./README.md
              ./bindings/python
              ./crates
              ./include
              ./tests/fixtures
            ];
          };
          cargoLock.lockFile = ./Cargo.lock;
          cargoBuildFlags = [
            "--package"
            "stogas-cli"
          ];
          # The CLI's tests run in the repository's CI.
          doCheck = false;
          meta = {
            description = "Verified local endpoint, sign-up and offline checks for the Stogas AI gateway";
            homepage = "https://stogas.ai";
            license = pkgs.lib.licenses.asl20;
            mainProgram = "stogas";
            platforms = systems;
          };
        };
      });
    };
}
