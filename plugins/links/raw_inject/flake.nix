{
  description = "GoodNet link plugin: raw-inject — standalone plugin flake.";

  inputs = {
    goodnet.url     = "git+file:../../..?dir=nix/kernel-only";
    nixpkgs.follows = "goodnet/nixpkgs";
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
          extraPackages = [ pkgs.zstd.dev ];
        };
      });
    };
}