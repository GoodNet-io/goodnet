# nix/bootstrap-env.nix — `nix run goodnet#bootstrap-env`.
#
# One-shot per-user bootstrap that lays down everything a downstream
# consumer needs to talk to the kernel without re-typing the same
# 10+ commands. Mirrors what an operator would otherwise hand-roll:
#
#   * `~/.local/share/goodnet/identity/default.bin` — fresh
#     long-term identity key (`goodnetd identity gen`).
#   * `~/.local/share/goodnet/plugins/lib*.so` — the baseline
#     plugin .sos (link-tcp / link-udp / link-ws / security-noise /
#     security-null / handler-heartbeat) copied out of the
#     respective nix derivations.
#   * `~/.local/share/goodnet/manifests/baseline.json` — manifest
#     pinning the SHA-256 of each copied .so so
#     `gn_core_load_plugin` admits them.
#   * `~/.local/share/goodnet/config.json` — sample config pointing
#     at the three paths above.
#
# Idempotent: re-running on a fully-populated layout is a no-op for
# the identity step, an overwrite for plugins + manifest (so a new
# baseline lands on `bootstrap-env --refresh`), and a no-op for
# the config file (operator edits stay). The `--force` flag forces
# every step even if outputs are present.
#
# The plugin source is not built here — `nix build
# .#<plugin>` against the kernel flake is the supported way to
# materialise the .so. For now the script falls back gracefully if
# the operator hasn't yet got those derivations available: it warns
# and skips the missing plugin instead of failing the whole step,
# so a fresh checkout sequence (`init-app NAME` → `bootstrap-env` →
# `cmake --build`) still produces a usable workspace.
#
# `goodnetd` is the daemon binary from the standalone
# `GoodNet-io/goodnetd` repo; this script invokes it through the
# user's PATH (typically wired via `nix profile install` or via the
# `app` devShell). When goodnetd is not on PATH, the identity +
# manifest steps degrade to a stub message pointing at the
# standalone repo — same posture as the rest of the bootstrap
# layer.

{ pkgs }:

pkgs.writeShellApplication {
  name = "gn-bootstrap-env";
  runtimeInputs = [ pkgs.coreutils pkgs.nix ];
  text = ''
    set -euo pipefail

    force=0
    if [ $# -gt 0 ]; then
      case "$1" in
        --force|--refresh) force=1 ;;
        -h|--help)
          cat <<USAGE
    Usage: nix run goodnet#bootstrap-env [-- --force]

    Lays down ~/.local/share/goodnet/{identity,plugins,manifests,config.json}
    with sensible defaults. Re-running is idempotent; pass --force to
    overwrite the identity + config file as well.
    USAGE
          exit 0
          ;;
        *) echo "bootstrap-env: unknown arg '$1'" >&2; exit 1 ;;
      esac
    fi

    xdg_data="''${XDG_DATA_HOME:-$HOME/.local/share}"
    root="$xdg_data/goodnet"

    mkdir -p "$root/plugins" "$root/identity" "$root/manifests"

    # ── 1. identity ────────────────────────────────────────────────
    identity_file="$root/identity/default.bin"
    if [ ! -f "$identity_file" ] || [ "$force" -eq 1 ]; then
      if command -v goodnetd >/dev/null 2>&1; then
        echo ">>> bootstrap-env: identity gen → $identity_file"
        goodnetd identity gen --out "$identity_file"
        chmod 0600 "$identity_file"
      else
        echo "bootstrap-env: goodnetd not on PATH — identity step skipped." >&2
        echo "  Install it via \`nix profile install github:GoodNet-io/goodnetd\`" >&2
        echo "  and re-run, or drop a pre-generated identity at" >&2
        echo "    $identity_file" >&2
      fi
    else
      echo "bootstrap-env: $identity_file present — skipping (pass --force to regenerate)."
    fi

    # ── 2. plugins ────────────────────────────────────────────────
    # Baseline plugin set. The kernel flake builds each as a
    # separate package; copy the .so out of each derivation's
    # `lib/goodnet/plugins/` into the per-user plugin path.
    # Missing derivations are warned about but do not fail the
    # whole bootstrap — the standalone plugin gits land on GitHub
    # at their own pace.
    baseline_plugins="link-tcp link-udp link-ws security-noise security-null handler-heartbeat"
    pulled=0
    skipped=0
    for p in $baseline_plugins; do
      if out=$(nix build --no-link --print-out-paths \
                 "goodnet#$p" 2>/dev/null); then
        if compgen -G "$out/lib/goodnet/plugins/lib*.so" >/dev/null; then
          for so in "$out"/lib/goodnet/plugins/lib*.so; do
            cp -fL "$so" "$root/plugins/"
            chmod 0644 "$root/plugins/$(basename "$so")"
          done
          echo "bootstrap-env: plugin $p → $root/plugins/"
          pulled=$((pulled + 1))
        else
          echo "bootstrap-env: $p build produced no lib*.so — skipping." >&2
          skipped=$((skipped + 1))
        fi
      else
        echo "bootstrap-env: $p not in flake outputs yet — skipping." >&2
        skipped=$((skipped + 1))
      fi
    done

    # ── 3. manifest ───────────────────────────────────────────────
    manifest_file="$root/manifests/baseline.json"
    if compgen -G "$root/plugins/lib*.so" >/dev/null; then
      if command -v goodnetd >/dev/null 2>&1; then
        echo ">>> bootstrap-env: manifest gen → $manifest_file"
        # shellcheck disable=SC2046
        goodnetd manifest gen $(printf '%s ' "$root/plugins/"lib*.so) \
          > "$manifest_file"
      else
        echo "bootstrap-env: goodnetd not on PATH — manifest step skipped." >&2
        echo "  Generate manually:" >&2
        echo "    goodnetd manifest gen $root/plugins/lib*.so > $manifest_file" >&2
      fi
    else
      echo "bootstrap-env: no plugins materialised — manifest step skipped."
    fi

    # ── 4. config ─────────────────────────────────────────────────
    config_file="$root/config.json"
    if [ ! -f "$config_file" ] || [ "$force" -eq 1 ]; then
      cat > "$config_file" <<EOF
    {
      "identity": {
        "path": "$identity_file"
      },
      "manifest_path": "$manifest_file",
      "plugin_path": "$root/plugins",
      "log_level": "info",
      "_comment": "Generated by gn-bootstrap-env. Override per-app via GOODNET_CONFIG."
    }
    EOF
      chmod 0644 "$config_file"
      echo "bootstrap-env: wrote $config_file"
    else
      echo "bootstrap-env: $config_file present — preserving operator edits."
    fi

    echo ""
    echo "bootstrap-env: pulled $pulled plugins, skipped $skipped."
    echo "bootstrap-env: done."
    echo ""
    echo "  Layout:"
    echo "    $root/identity/default.bin"
    echo "    $root/plugins/lib*.so"
    echo "    $root/manifests/baseline.json"
    echo "    $root/config.json"
    echo ""
    echo "  Apps reading XDG defaults are ready — \`nix develop goodnet#app\`"
    echo "  exports GOODNET_* env vars pointing at this layout."
  '';
}
