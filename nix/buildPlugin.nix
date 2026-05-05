# nix/buildPlugin.nix — packaging step for GoodNet plugins.
#
# Wraps a raw plugin build derivation, installs every produced
# .so into $out/lib/, and emits a paired <libfile>.json
# distribution manifest per docs/contracts/plugin-manifest.md §8.
#
# Inputs:
#   { lib, pkgs }
#
# Returned function:
#   { name, type, version, description ? "", drv }
#     name        — canonical plugin id (matches gn_plugin_descriptor::name)
#     type        — one of "security" | "link" | "handler" | "protocol"
#     version     — semver triple of the plugin distribution
#     description — single-line summary; may be empty
#     drv         — raw build derivation that produced one or more .so
#
# Failure modes (per project_goodnet_subplan_infrastructure §I-A):
#   - drv produced no .so files          → loud error, derivation fails
#   - type not in the four allowed kinds → loud error before install
#   - sha256 read fails                  → coreutils sha256sum non-zero, propagates
#   - jq invocation fails                → propagates with stderr
#
# No silent skips. No fallback hashing. The caller's drv is the
# source of truth for the plugin bytes.

{ lib, pkgs }:

let
  allowedTypes = [ "security" "link" "handler" "protocol" ];
in

{ name
, type
, version
, description ? ""
, drv
}:

assert lib.assertMsg (lib.elem type allowedTypes)
  "buildPlugin: type '${type}' not in ${lib.concatStringsSep ", " allowedTypes}";
assert lib.assertMsg (name != "")
  "buildPlugin: name must be non-empty";
assert lib.assertMsg (version != "")
  "buildPlugin: version must be non-empty (semver triple)";

pkgs.stdenv.mkDerivation {
  pname   = "${type}-${name}";
  inherit version;
  src     = drv;

  # Plugin metadata exported as env vars so the installPhase can pass
  # them to jq via `--arg name "$pluginName"` instead of inlining Nix
  # values into single-quoted shell — apostrophes in `description`
  # would otherwise break the splice.
  pluginName        = name;
  pluginType        = type;
  pluginVersion     = version;
  pluginDescription = description;

  nativeBuildInputs = [ pkgs.jq pkgs.coreutils ];

  # Pure shell — no scripts checked into the tree per the infrastructure
  # contract (no .sh artefacts). Inline shell stays inside the Nix
  # derivation builder, which is the intended Nix idiom.
  installPhase = ''
    set -euo pipefail

    mkdir -p $out/lib

    shopt -s nullglob
    so_count=0
    for sofile in "$src"/lib/*.so "$src"/*.so "$src"/lib/goodnet/plugins/*.so; do
      [ -f "$sofile" ] || continue
      cp "$sofile" "$out/lib/"
      so_count=$((so_count + 1))
    done
    shopt -u nullglob

    if [ "$so_count" -eq 0 ]; then
      echo "buildPlugin: drv produced no .so files in $src" >&2
      exit 1
    fi

    # Honour SOURCE_DATE_EPOCH so the manifest sidecar stays
    # bit-reproducible when the .so it describes is reproducible.
    timestamp=$(date -u -d "@''${SOURCE_DATE_EPOCH:-$(date -u +%s)}" \
                +"%Y-%m-%dT%H:%M:%SZ")

    shopt -s nullglob
    for libfile in "$out"/lib/*.so; do
      hash=$(sha256sum "$libfile" | cut -d' ' -f1)
      jq -n \
        --arg name        "$pluginName" \
        --arg type        "$pluginType" \
        --arg version     "$pluginVersion" \
        --arg description "$pluginDescription" \
        --arg timestamp   "$timestamp" \
        --arg hash        "$hash" \
        '{
          meta: {
            name:        $name,
            type:        $type,
            version:     $version,
            description: $description,
            timestamp:   $timestamp
          },
          integrity: {
            alg:  "sha256",
            hash: $hash
          }
        }' > "$libfile.json"
    done
    shopt -u nullglob
  '';

  meta = with lib; {
    description = if description != "" then description
                  else "GoodNet plugin: ${type}/${name}";
    platforms   = platforms.linux ++ platforms.darwin;
  };
}
