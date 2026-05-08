# nix/kernel-only/flake.nix — kernel-only flake.
#
# Plugin standalone flakes consume the kernel through this slim
# flake instead of the full monorepo so the input graph stays
# acyclic. Today the root flake exposes no plugin packages, so
# the cycle is latent rather than active — but the moment an
# aggregate-test job lands that imports plugin flakes as inputs
# of its own, a plugin's `goodnet` pointing at the root flake
# would loop. Keeping plugins on this slim subflake costs ~80
# lines of duplication and prevents the eventual cycle without
# anyone having to remember to refactor plugin inputs first.
# Pointing the plugin at `nix/kernel-only/` also keeps the
# plugin's eval surface focused: this flake never touches
# `plugins/` and never imports a plugin flake.
#
# Outputs surface only what plugins actually need to build:
#   packages.<system>.goodnet-core   the kernel + SDK + AddPlugin
#   packages.<system>.default        alias for goodnet-core
#   lib.plugin-helpers               sanitizer flags + dev shell +
#                                    five-app set used by every
#                                    plugin's standalone flake
#   lib.compose                      operator-side composition for
#                                    aggregating kernel + chosen
#                                    plugins into a node derivation
#
# Source for `goodnet-core` is filtered down to the kernel surface
# (sdk/, core/, cmake/, nix/, sdk/, top-level CMakeLists.txt). The
# plugin set, examples, top-level tests, and apps are excluded
# from the kernel derivation so a fresh `nix build .#default`
# never re-evaluates plugin source on a kernel-only build.

{
  description = "GoodNet kernel + SDK — slim flake for plugin consumers.";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      forAllSystems = f:
        nixpkgs.lib.genAttrs [ "x86_64-linux" "aarch64-linux" ]
          (system: f system (import nixpkgs { inherit system; }));

      # Plugin-helpers + composeNode are pure-Nix expressions that
      # do not import nixpkgs themselves; they are exposed verbatim
      # here so a plugin's flake reaches them through `goodnet
      # .lib.plugin-helpers` exactly as it did against the root
      # flake before the pivot.
      pluginHelpers = import ../plugin-helpers.nix;

      composeNode = pkgs:
        { kernel
        , plugins ? [ ]
        , config ? null
        , identity ? null
        , pname ? "goodnet-node"
        , version ? "0.1.0"
        }:
        pkgs.stdenv.mkDerivation {
          inherit pname version;
          dontUnpack = true;
          nativeBuildInputs = [ pkgs.makeWrapper ];

          buildPhase = ''
            mkdir -p plugins
            for p in ${pkgs.lib.concatStringsSep " " plugins}; do
              for so in $p/lib/goodnet/plugins/lib*.so; do
                cp -L "$so" plugins/
              done
            done
            ${kernel}/bin/goodnet manifest gen plugins/lib*.so > manifest.json
          '';

          installPhase = ''
            mkdir -p $out/bin $out/lib/goodnet/plugins $out/etc/goodnet
            cp ${kernel}/bin/goodnet $out/bin/goodnet
            cp plugins/lib*.so $out/lib/goodnet/plugins/
            sed "s|plugins/|$out/lib/goodnet/plugins/|g" \
                manifest.json > $out/etc/goodnet/manifest.json
            ${if config != null then ''
              cp ${config} $out/etc/goodnet/node.json
            '' else ''
              echo '{}' > $out/etc/goodnet/node.json
            ''}
            ${pkgs.lib.optionalString (identity != null) ''
              install -m 0600 ${identity} $out/etc/goodnet/identity.bin
            ''}

            makeWrapper $out/bin/goodnet $out/bin/goodnet-node \
              --add-flags "run" \
              --add-flags "--config $out/etc/goodnet/node.json" \
              --add-flags "--manifest $out/etc/goodnet/manifest.json" \
              ${pkgs.lib.optionalString (identity != null)
                "--add-flags \"--identity $out/etc/goodnet/identity.bin\""}
          '';

          meta = {
            description = "Composed GoodNet node — kernel + selected plugins.";
            mainProgram  = "goodnet-node";
            platforms    = pkgs.lib.platforms.linux;
          };
        };
    in
    {
      lib = {
        plugin-helpers = pluginHelpers;
        compose = composeNode;
      };

      packages = forAllSystems (system: pkgs:
        let
          stdenv = pkgs.gcc15Stdenv;
          coreBuildInputs = with pkgs; [
            asio spdlog fmt nlohmann_json libsodium openssl
          ];
          coreNative = with pkgs; [ cmake ninja pkg-config ];

          # Kernel-only source filter. Walks up two directories
          # to the monorepo root, then keeps only the directories
          # the kernel build needs: sdk/, core/, cmake/, nix/,
          # apps/ (operator CLI lives here), top-level CMakeLists
          # .txt + LICENSE + README. plugins/, examples/, tests/,
          # docs/, manifest/ are excluded so a kernel build never
          # re-reads them.
          monorepoRoot = ../..;
          # Top-level entries kept in the kernel-only derivation src.
          # `plugins/` is special-cased below — only the two
          # statically-linked plugins (`protocols/gnet`,
          # `protocols/raw`) are needed by the kernel binary; the
          # loadable plugins live in their own flakes.
          keepInRoot = [
            "CMakeLists.txt"
            "LICENSE"
            "README.md"
            "README.ru.md"
            ".clang-tidy"
            "sdk"
            "core"
            "cmake"
            "nix"
            "apps"
          ];
          isKept = path: type:
            let
              rel = pkgs.lib.removePrefix
                (toString monorepoRoot + "/") (toString path);
              topLevel = builtins.head (pkgs.lib.splitString "/" rel);
              # `plugins` dir itself + plugins/CMakeLists.txt +
              # everything under plugins/protocols/ is in scope so
              # gnet/raw (statically linked into the kernel binary)
              # build with the rest of the kernel; loadable plugins
              # under plugins/handlers, plugins/links, plugins/
              # security live in their own flakes and stay out.
              isKeptPlugin =
                rel == "plugins"
                || rel == "plugins/CMakeLists.txt"
                || rel == "plugins/protocols"
                || pkgs.lib.hasPrefix "plugins/protocols/" rel;
            in
            builtins.elem topLevel keepInRoot
            || (topLevel == "plugins" && isKeptPlugin);

          goodnet-core = stdenv.mkDerivation {
            pname   = "goodnet-core";
            version = "0.1.0";
            src     = pkgs.lib.cleanSourceWith {
              src    = monorepoRoot;
              filter = isKept;
            };
            nativeBuildInputs = coreNative;
            buildInputs       = coreBuildInputs;
            propagatedBuildInputs = coreBuildInputs;
            cmakeFlags = [
              "-DCMAKE_BUILD_TYPE=Release"
              "-DGOODNET_BUILD_TESTS=OFF"
              "-DGOODNET_BUILD_BUNDLED_PLUGINS=OFF"
            ];
            doCheck = false;
            meta = {
              description = "GoodNet kernel + SDK — slim distribution.";
              platforms = pkgs.lib.platforms.linux;
            };
          };
        in
        {
          inherit goodnet-core;
          default = goodnet-core;
        });
    };
}
