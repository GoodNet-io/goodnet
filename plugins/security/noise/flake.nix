# Standalone dev / test / build flake for the goodnet-security-noise
# plugin. Reuses the kernel monorepo's per-plugin helpers
# (`goodnet.lib.plugin-helpers`) so every shared piece — sanitizer
# flag tuples, the dev-shell shape, the five-app set — lives in one
# place. Plugin-specific knobs stay here.
#
# Switch `inputs.goodnet.url` from `path:../../..` to `github:goodnet
# -io/kernel?ref=…` once the kernel extracts to its own repository.
{
  description = "GoodNet Noise XX security provider — standalone plugin flake.";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    goodnet.url = "path:../../..";
    goodnet.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = { self, nixpkgs, goodnet }:
    let
      forAllSystems = f:
        nixpkgs.lib.genAttrs [ "x86_64-linux" "aarch64-linux" ]
          (system: f system (import nixpkgs { inherit system; }));
      helpers = goodnet.lib.plugin-helpers;
    in
    {
      packages = forAllSystems (system: pkgs:
        let goodnet-core = goodnet.packages.${system}.goodnet-core;
        in {
          default = pkgs.callPackage ./default.nix { inherit goodnet-core; };
        });

      devShells = forAllSystems (system: pkgs: {
        default = helpers.mkPluginDevShell pkgs {
          plugin = self.packages.${system}.default;
          welcomeText = ''
  goodnet-security-noise  —  standalone plugin dev shell
    nix run .#build      — Release build (artefacts → ./build/)
    nix run .#test       — Release build with tests + ctest
    nix run .#test-asan  — ASan + UBSan build + ctest
    nix run .#test-tsan  — TSan build + ctest
    nix run .#debug      — Debug build + gdb on test_noise
'';
        };
      });

      apps = forAllSystems (system: pkgs:
        helpers.mkPluginApps pkgs {
          pluginName  = "noise";
          debugBinary = "test_noise";
        });
    };
}
