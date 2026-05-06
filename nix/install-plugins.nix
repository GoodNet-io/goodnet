# nix/install-plugins.nix — `nix run .#install-plugins [-- --update]` app.
#
# Pulls the canonical loadable plugin set into the kernel's
# `plugins/<kind>/<name>/` slots so a fresh clone of the kernel
# becomes a fully-wired workspace in one command. Each plugin
# lives in its own git (own remote URL, own history); this app
# is the single hook a new contributor or a CI runner uses to
# materialise them locally.
#
# Repo list. The 8 loadable plugins that the kernel binary
# `dlopen`s at runtime: handler-heartbeat, link-{tcp, udp, ws,
# ipc, tls}, security-{noise, null}. Statically-linked plugins
# under `plugins/protocols/` are part of the kernel build and
# do not need pulling.
#
# Source lookup (first hit wins):
#   1. `${GOODNET_PLUGIN_MIRROR_DIR}/<repo>.git`  (env override)
#   2. `${XDG_DATA_HOME:-${HOME}/.local/share}/goodnet-mirrors/
#      <repo>.git`  (default — matches `init-mirrors`'s output
#      directory)
#   3. `https://github.com/goodnet-io/<repo>`  (post-rc1 org repo)
#
# Modes:
#   default — skip plugin slots that already exist on disk.
#   --update — for already-present plugins, run
#     `git -C <slot> pull --ff-only` against `origin` instead of
#     skipping.
#
# Failure mode. If a plugin is not present and none of the three
# sources resolve, exit non-zero with a clear message pointing
# the operator at `nix run .#init-mirrors` (which establishes
# the local mirrors when at least one operator already has the
# plugin gits checked out somewhere).

{ pkgs }:

pkgs.writeShellApplication {
  name = "goodnet-install-plugins";
  runtimeInputs = [ pkgs.git ];
  text = ''
    set -euo pipefail

    update=0
    if [ $# -gt 0 ]; then
      case "$1" in
        --update) update=1 ;;
        *) echo "install-plugins: unknown arg '$1'" >&2
           echo "  usage: nix run .#install-plugins [-- --update]" >&2
           exit 1 ;;
      esac
    fi

    if [ ! -f flake.nix ] || [ ! -d plugins ]; then
      echo "install-plugins: run from the kernel monorepo root" >&2
      exit 1
    fi

    mirror_dir="''${GOODNET_PLUGIN_MIRROR_DIR:-''${XDG_DATA_HOME:-$HOME/.local/share}/goodnet-mirrors}"

    declare -A slot_to_repo=(
      [handler-heartbeat]=handlers/heartbeat
      [link-tcp]=links/tcp
      [link-udp]=links/udp
      [link-ws]=links/ws
      [link-ipc]=links/ipc
      [link-tls]=links/tls
      [security-noise]=security/noise
      [security-null]=security/null
    )

    pulled=0
    skipped=0
    updated=0
    failed=()

    for repo in "''${!slot_to_repo[@]}"; do
      slot="plugins/''${slot_to_repo[$repo]}"

      if [ -d "$slot/.git" ]; then
        if [ "$update" -eq 1 ]; then
          if git -C "$slot" pull --ff-only --quiet 2>/dev/null; then
            echo "install-plugins: $slot updated"
            updated=$((updated + 1))
          else
            echo "install-plugins: $slot pull --ff-only failed" \
                 "(uncommitted changes or non-fast-forward)" >&2
            failed+=("$repo")
          fi
        else
          echo "install-plugins: $slot already present — skipping"
          skipped=$((skipped + 1))
        fi
        continue
      fi

      mkdir -p "$(dirname "$slot")"

      mirror="$mirror_dir/$repo.git"
      remote_url="https://github.com/goodnet-io/$repo"

      if [ -d "$mirror" ]; then
        echo "install-plugins: cloning $repo from $mirror"
        git clone --quiet "$mirror" "$slot"
        pulled=$((pulled + 1))
      elif git ls-remote --quiet "$remote_url" >/dev/null 2>&1; then
        echo "install-plugins: cloning $repo from $remote_url"
        git clone --quiet "$remote_url" "$slot"
        pulled=$((pulled + 1))
      else
        echo "install-plugins: $repo not available at" >&2
        echo "  - $mirror" >&2
        echo "  - $remote_url" >&2
        echo "  Run \`nix run .#init-mirrors\` from a checkout that" >&2
        echo "  already has the plugin gits, or wait until the org" >&2
        echo "  repo at $remote_url is published." >&2
        failed+=("$repo")
      fi
    done

    echo ""
    echo "install-plugins: pulled $pulled, updated $updated, skipped $skipped"
    if [ "''${#failed[@]}" -gt 0 ]; then
      echo "install-plugins: failed for ''${#failed[@]} plugin(s):" \
           "''${failed[*]}" >&2
      exit 1
    fi
    if [ "$pulled" -gt 0 ]; then
      echo "Re-run \`cmake -B build\` to pick up the new plugin targets."
    fi
  '';
}
