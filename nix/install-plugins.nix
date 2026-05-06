# nix/install-plugins.nix — `nix run .#install-plugins` app.
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
# Source lookup mirrors `pull-plugin`:
#   1. `${GOODNET_PLUGIN_MIRROR_DIR}/<repo-name>`   (env override)
#   2. `${HOME}/Desktop/projects/GoodNet-io/<repo-name>`  (default
#      pre-rc1 sibling layout)
#   3. `https://github.com/goodnet-io/<repo-name>`  (org repo
#      post-rc1)
#
# Already-pulled plugins are skipped silently — re-running the
# app on a checkout that already has plugins is a no-op. To
# replace a plugin, remove its directory first and re-run.

{ pkgs }:

pkgs.writeShellApplication {
  name = "goodnet-install-plugins";
  runtimeInputs = [ pkgs.git ];
  text = ''
    set -euo pipefail

    if [ ! -f flake.nix ] || [ ! -d plugins ]; then
      echo "install-plugins: run from the kernel monorepo root" >&2
      exit 1
    fi

    mirror_dir="''${GOODNET_PLUGIN_MIRROR_DIR:-$HOME/Desktop/projects/GoodNet-io}"

    # Repo name → "kind/name" mapping for the kernel's directory layout.
    declare -A plugins=(
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
    for repo_name in "''${!plugins[@]}"; do
      slot="plugins/''${plugins[$repo_name]}"

      if [ -e "$slot" ]; then
        echo "install-plugins: $slot already present — skipping"
        skipped=$((skipped + 1))
        continue
      fi

      mkdir -p "$(dirname "$slot")"

      local_mirror="$mirror_dir/$repo_name"
      if [ -d "$local_mirror/.git" ]; then
        echo "install-plugins: cloning $repo_name from local mirror"
        git clone --quiet "$local_mirror" "$slot"
      else
        remote_url="https://github.com/goodnet-io/$repo_name"
        echo "install-plugins: cloning $repo_name from $remote_url"
        git clone --quiet "$remote_url" "$slot"
      fi
      pulled=$((pulled + 1))
    done

    echo ""
    echo "install-plugins: pulled $pulled, skipped $skipped"
    if [ "$pulled" -gt 0 ]; then
      echo "Re-run \`cmake -B build\` to pick up the new plugin targets."
    fi
  '';
}
