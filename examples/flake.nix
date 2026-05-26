{
  description = "GoodNet SDK examples: two_node, hello-echo, bench";

  inputs = {
    nixpkgs.url       = "github:NixOS/nixpkgs/nixos-unstable";
    goodnet.url       = "github:GoodNet-io/goodnet/dev";
    protocol-gnet.url = "github:GoodNet-io/protocol-gnet";

    link-tcp.url     = "github:GoodNet-io/link-tcp";
    link-tcp.inputs.goodnet.follows  = "goodnet";
    link-tcp.inputs.nixpkgs.follows  = "nixpkgs";

    security-noise.url = "github:GoodNet-io/security-noise";
    security-noise.inputs.goodnet.follows  = "goodnet";
    security-noise.inputs.nixpkgs.follows  = "nixpkgs";
  };

  outputs = { self, nixpkgs, goodnet, protocol-gnet, link-tcp, security-noise }:
    let
      allSystems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];

      devShellHook = ''
        if [ -d .goodnet/goodnet ]; then
          echo "goodnet-examples: local .goodnet/ overrides present."
          echo "  nix develop \\"
          echo "    --override-input goodnet path:.goodnet/goodnet \\"
          echo "    --override-input protocol-gnet path:.goodnet/protocol-gnet"
        fi
      '';

    in {
      packages = nixpkgs.lib.genAttrs allSystems (system:
        let
          pkgs   = import nixpkgs { inherit system; };
          kernel = goodnet.packages.${system}.goodnet-core
                or goodnet.packages.${system}.default;
          gnet   = protocol-gnet.packages.${system}.default;
          noise  = security-noise.packages.${system}.default;
          tcp    = link-tcp.packages.${system}.default;
          native = [ pkgs.cmake pkgs.ninja pkgs.pkg-config ];
          src    = ./.;
          meta   = {
            description = "GoodNet SDK examples (two_node, hello-echo).";
            license     = pkgs.lib.licenses.gpl2Only;
          };

          examples = pkgs.stdenv.mkDerivation {
            pname   = "goodnet-examples";
            version = "1.0.0";
            inherit src meta;
            nativeBuildInputs = native;
            buildInputs       = [ kernel gnet noise tcp pkgs.libsodium ];
            cmakeFlags = [
              "-DGOODNET_NOISE_PLUGIN_PATH=${noise}/lib/libgoodnet_security_noise.so"
              "-DGOODNET_TCP_PLUGIN_PATH=${tcp}/lib/libgoodnet_link_tcp.so"
            ];
            installPhase = ''
              runHook preInstall
              install -Dm755 bin/goodnet-demo    "$out/bin/goodnet-demo"
              install -Dm755 bin/hello-echo-client "$out/bin/hello-echo-client"
              install -Dm755 bin/hello-echo-server "$out/bin/hello-echo-server"
              runHook postInstall
            '';
          };

        in {
          default = examples;
        }
      );

      devShells = nixpkgs.lib.genAttrs allSystems (system:
        let
          pkgs   = import nixpkgs { inherit system; };
          kernel = goodnet.packages.${system}.goodnet-core
                or goodnet.packages.${system}.default;
          gnet   = protocol-gnet.packages.${system}.default;
          noise  = security-noise.packages.${system}.default;
          tcp    = link-tcp.packages.${system}.default;
        in {
          default = pkgs.mkShell {
            packages  = [ kernel gnet noise tcp
                          pkgs.libsodium
                          pkgs.cmake pkgs.ninja pkgs.pkg-config
                          pkgs.clang-tools ];
            # Make plugin .so files discoverable at runtime from the dev shell.
            GOODNET_NOISE_PLUGIN_PATH = "${noise}/lib/libgoodnet_security_noise.so";
            GOODNET_TCP_PLUGIN_PATH   = "${tcp}/lib/libgoodnet_link_tcp.so";
            shellHook = devShellHook;
          };
        }
      );
    };
}
