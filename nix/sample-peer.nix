# nix/sample-peer.nix — `nix run goodnet#sample-peer`.
#
# Spin up a throwaway GoodNet peer on `tcp://0.0.0.0:9101` so a
# downstream consumer that just ran `init-app` + `bootstrap-env`
# has something to dial against without first having to mint a
# second identity, configure plugins, and run a second daemon
# instance by hand.
#
# Layout written into a per-invocation temp dir:
#
#   $TMP/identity.bin     — fresh long-term identity (peer side)
#   $TMP/manifest.json    — manifest gen'd over the user's
#                           ~/.local/share/goodnet/plugins/lib*.so
#                           (so the peer admits the same baseline
#                            set the consumer's bootstrap step laid
#                            down).
#   $TMP/config.json      — minimal config pinning TCP listen +
#                           plugin path.
#
# Output to stdout (machine-readable lines first, so a wrapper can
# grep them):
#
#   peer_pubkey=<64 hex chars>
#   peer_url=tcp://0.0.0.0:9101
#   peer_workdir=<tempdir>
#
# SIGINT / SIGTERM trigger the trap that calls `goodnetd serve`'s
# graceful-stop path and rm-rf's the workdir. Any binary that
# missed its cleanup leaves the workdir on disk — operators see a
# warning pointing at the path so a hand cleanup is one rm away.
#
# `goodnetd` is the daemon binary from the standalone
# `GoodNet-io/goodnetd` repo. When goodnetd is not on PATH the
# script bails with the same pointer the rest of the bootstrap
# layer carries — install it via `nix profile install
# github:GoodNet-io/goodnetd` or run it directly through `nix run
# github:GoodNet-io/goodnetd`.

{ pkgs }:

pkgs.writeShellApplication {
  name = "gn-sample-peer";
  runtimeInputs = [ pkgs.coreutils ];
  text = ''
    set -euo pipefail

    listen_uri="''${GOODNET_SAMPLE_PEER_URI:-tcp://0.0.0.0:9101}"

    if [ $# -gt 0 ]; then
      case "$1" in
        -h|--help)
          cat <<USAGE
    Usage: nix run goodnet#sample-peer

    Spawn a throwaway peer listening on $listen_uri using the
    baseline plugin set laid down by \`nix run goodnet#bootstrap-env\`.

    Override the listen URI via GOODNET_SAMPLE_PEER_URI.

    Stdout:
      peer_pubkey=<hex>
      peer_url=<uri>
      peer_workdir=<tempdir>

    Ctrl-C tears down the peer + removes the workdir.
    USAGE
          exit 0
          ;;
        *) echo "sample-peer: unknown arg '$1'" >&2; exit 1 ;;
      esac
    fi

    if ! command -v goodnetd >/dev/null 2>&1; then
      echo "sample-peer: goodnetd not on PATH." >&2
      echo "  Install it via:" >&2
      echo "    nix profile install github:GoodNet-io/goodnetd" >&2
      echo "  or run a one-shot peer via:" >&2
      echo "    nix run github:GoodNet-io/goodnetd -- serve --listen $listen_uri" >&2
      exit 1
    fi

    xdg_data="''${XDG_DATA_HOME:-$HOME/.local/share}"
    plugin_path="$xdg_data/goodnet/plugins"
    if ! compgen -G "$plugin_path/lib*.so" >/dev/null; then
      echo "sample-peer: no plugins at $plugin_path." >&2
      echo "  Run \`nix run goodnet#bootstrap-env\` first." >&2
      exit 1
    fi

    workdir="$(mktemp -d -t gn-sample-peer.XXXXXX)"
    identity_file="$workdir/identity.bin"
    manifest_file="$workdir/manifest.json"
    config_file="$workdir/config.json"

    cleanup() {
      ec=$?
      if [ -n "''${peer_pid:-}" ] && kill -0 "$peer_pid" 2>/dev/null; then
        kill -TERM "$peer_pid" 2>/dev/null || true
        wait "$peer_pid" 2>/dev/null || true
      fi
      if [ -d "$workdir" ]; then
        rm -rf "$workdir" || \
          echo "sample-peer: workdir left at $workdir (rm failed)" >&2
      fi
      exit "$ec"
    }
    trap cleanup EXIT INT TERM

    goodnetd identity gen --out "$identity_file" >/dev/null
    chmod 0600 "$identity_file"

    # shellcheck disable=SC2046
    goodnetd manifest gen $(printf '%s ' "$plugin_path/"lib*.so) \
      > "$manifest_file"

    cat > "$config_file" <<EOF
    {
      "identity":      { "path": "$identity_file" },
      "manifest_path": "$manifest_file",
      "plugin_path":   "$plugin_path",
      "listen":        ["$listen_uri"],
      "log_level":     "info"
    }
    EOF

    # Print machine-readable header *before* the daemon backgrounds
    # so a caller can read it without racing the serve banner.
    pubkey="$(goodnetd identity pubkey --in "$identity_file" 2>/dev/null \
              || echo unknown)"
    echo "peer_pubkey=$pubkey"
    echo "peer_url=$listen_uri"
    echo "peer_workdir=$workdir"
    echo ""
    echo ">>> sample-peer: serving on $listen_uri (Ctrl-C to stop)"

    goodnetd serve \
      --config   "$config_file" \
      --manifest "$manifest_file" \
      --identity "$identity_file" &
    peer_pid=$!

    wait "$peer_pid"
  '';
}
