# Reference operator flake. Drop this into a new git repo, adjust the
# plugin list / config / identity to taste, and `nix run .#default`
# launches a GoodNet node composed from the kernel and the plugins
# the operator chose. Each input is a separate Nix-store closure;
# adding or removing a plugin is one line in the `plugins` list.

{
  description = "GoodNet node — operator-side composition example";

  inputs = {
    nixpkgs.url  = "github:NixOS/nixpkgs/nixos-unstable";
    # Pin a release tag in production. `master` here for the example.
    goodnet.url  = "github:GoodNet-io/goodnet";
    goodnet.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = { self, nixpkgs, goodnet }:
    let
      system = "x86_64-linux";
      pkgs   = import nixpkgs { inherit system; };
      gnpkgs = goodnet.packages.${system};
    in
    {
      packages.${system} = {
        default = goodnet.lib.compose pkgs {
          kernel  = gnpkgs.goodnet-core;
          plugins = with gnpkgs; [
            goodnet-link-tcp
            goodnet-security-noise
            goodnet-handler-heartbeat
          ];
          # config = ./node.json;        # uncomment when ready
          # identity = ./identity.bin;   # uncomment when ready
        };
      };

      apps.${system}.default = {
        type    = "app";
        program = "${self.packages.${system}.default}/bin/goodnet-node";
      };
    };
}
