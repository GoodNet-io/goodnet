# nix/init-mirrors.nix — `nix run .#init-mirrors` app.
#
# Establishes the per-plugin "page" (a bare git mirror) that the
# eventual `goodnet-io/<repo>` github URL stands in for pre-rc1.
# For each plugin slot under `plugins/<kind>/<name>/` that has its
# own nested `.git/`:
#
#   - If a bare mirror at `${MIRROR_DIR}/<repo>.git` does not exist,
#     `git clone --bare` the plugin's working git into it.
#   - If the plugin's working git has no `origin` remote, add it
#     pointing at the mirror and `git push -u origin main` so the
#     mirror catches up.
#
# Idempotent — re-running on a fully-set-up tree is a no-op. Will
# not clobber an `origin` remote that already exists (refuses to
# rewrite the URL even if it points elsewhere).
#
# Mirror directory.
#   1. `${GOODNET_PLUGIN_MIRROR_DIR}` if set
#   2. `${XDG_DATA_HOME:-${HOME}/.local/share}/goodnet-mirrors`
#
# `pull-plugin` and `install-plugins` look at the same directory
# so a single `init-mirrors` run wires everything for the whole
# fresh-clone workflow.

{ pkgs }:

pkgs.writeShellApplication {
  name = "goodnet-init-mirrors";
  runtimeInputs = [ pkgs.git ];
  text = ''
    set -euo pipefail

    if [ ! -f flake.nix ] || [ ! -d plugins ]; then
      echo "init-mirrors: run from the kernel monorepo root" >&2
      exit 1
    fi

    mirror_dir="''${GOODNET_PLUGIN_MIRROR_DIR:-''${XDG_DATA_HOME:-$HOME/.local/share}/goodnet-mirrors}"
    mkdir -p "$mirror_dir"
    echo "init-mirrors: mirror directory $mirror_dir"

    # plugin slot path → repo name (matches the github org layout
    # post-rc1: `goodnet-io/<kind-singular>-<name>`).
    declare -A slot_to_repo=(
      [plugins/handlers/heartbeat]=handler-heartbeat
      [plugins/links/tcp]=link-tcp
      [plugins/links/udp]=link-udp
      [plugins/links/ws]=link-ws
      [plugins/links/ipc]=link-ipc
      [plugins/links/tls]=link-tls
      [plugins/security/noise]=security-noise
      [plugins/security/null]=security-null
      [tests/integration]=integration-tests
    )

    mirrored=0
    rewired=0
    skipped=0

    for slot in "''${!slot_to_repo[@]}"; do
      repo="''${slot_to_repo[$slot]}"
      mirror="$mirror_dir/$repo.git"

      if [ ! -d "$slot/.git" ]; then
        echo "init-mirrors: $slot has no nested git — skipping"
        skipped=$((skipped + 1))
        continue
      fi

      # Bare-mirror the working git if the mirror does not exist.
      if [ ! -d "$mirror" ]; then
        echo "init-mirrors: cloning bare mirror $slot → $mirror"
        git clone --quiet --bare "$slot" "$mirror"
        mirrored=$((mirrored + 1))
      fi

      # Wire `origin` in the working clone if absent. Refuse to
      # rewrite an existing remote even if it points elsewhere —
      # the operator may have set it deliberately.
      if ! git -C "$slot" remote get-url origin >/dev/null 2>&1; then
        echo "init-mirrors: adding origin to $slot → $mirror"
        git -C "$slot" remote add origin "$mirror"
        # Push the working clone's current branch so the mirror is
        # actually a copy of what the operator has, not a stale
        # snapshot from when the bare clone happened above.
        branch="$(git -C "$slot" symbolic-ref --short HEAD)"
        git -C "$slot" push --quiet -u origin "$branch"
        rewired=$((rewired + 1))
      fi
    done

    echo ""
    echo "init-mirrors: mirrored $mirrored, rewired $rewired, skipped $skipped"
  '';
}
