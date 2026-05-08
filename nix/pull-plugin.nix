# nix/pull-plugin.nix — `nix run .#pull-plugin -- <repo-name>` app.
#
# Clones a loadable plugin's git into the kernel's
# `plugins/<kind>/<name>/` directory so the kernel build sees it
# again. Each loadable plugin lives in its own repo (e.g.
# `~/Desktop/projects/GoodNet-io/security-noise/` pre-rc1, or
# `https://github.com/goodnet-io/security-noise` once the org repos
# land); the kernel's `plugins/handlers/`, `plugins/links/`,
# `plugins/security/` directories stay empty until the operator
# pulls in what they want for local development.
#
# Repo-name convention.  Plugin repos are named `<kind-singular>
# -<name>` (e.g. `security-noise`, `link-tcp`,
# `handler-heartbeat`). The first hyphen
# splits the singular kind from the plugin name; the kernel's
# directory layout reverses it (`plugins/<plural-kind>/<name>/`):
#
#   handler-heartbeat → plugins/handlers/heartbeat/
#   link-tcp          → plugins/links/tcp/
#   protocol-raw      → plugins/protocols/raw/
#   security-noise    → plugins/security/noise/
#
# Source lookup order (first match wins):
#   1. `${GOODNET_PLUGIN_MIRROR_DIR}/<repo-name>.git`   (env override)
#   2. `${XDG_DATA_HOME:-${HOME}/.local/share}/goodnet-mirrors/
#      <repo-name>.git`  (default — matches `init-mirrors` output)
#   3. `https://github.com/goodnet-io/<repo-name>`  (org repo
#      post-rc1)
#
# Refuses to clobber an existing `plugins/<kind>/<name>/`
# directory; remove it manually first if a re-pull is intended.

{ pkgs }:

pkgs.writeShellApplication {
  name = "goodnet-pull-plugin";
  runtimeInputs = [ pkgs.git ];
  text = ''
    set -euo pipefail

    if [ $# -ne 1 ]; then
      cat >&2 <<USAGE
    Usage: nix run .#pull-plugin -- <repo-name>
      <repo-name>: <kind-singular>-<name>
                   examples: security-noise, link-tcp, handler-heartbeat
    USAGE
      exit 1
    fi

    repo_name="$1"

    if ! [[ "$repo_name" =~ ^(handler|link|protocol|security)-[a-z][a-z0-9_-]*$ ]]; then
      echo "pull-plugin: '$repo_name' must match" >&2
      echo "  (handler|link|protocol|security)-[a-z][a-z0-9_-]*" >&2
      echo "  examples: security-noise, link-tcp, handler-heartbeat" >&2
      exit 1
    fi

    kind_singular="''${repo_name%%-*}"
    plugin_name="''${repo_name#*-}"

    case "$kind_singular" in
      handler)  kind=handlers  ;;
      link)     kind=links     ;;
      protocol) kind=protocols ;;
      security) kind=security  ;;
    esac

    if [ ! -f flake.nix ] || [ ! -d plugins ]; then
      echo "pull-plugin: run from the kernel monorepo root" >&2
      exit 1
    fi

    plugin_dir="plugins/$kind/$plugin_name"
    if [ -e "$plugin_dir" ]; then
      echo "pull-plugin: $plugin_dir already exists, refusing to clobber." >&2
      echo "  Remove it manually before re-pulling." >&2
      exit 1
    fi

    mirror_dir="''${GOODNET_PLUGIN_MIRROR_DIR:-''${XDG_DATA_HOME:-$HOME/.local/share}/goodnet-mirrors}"
    mirror="$mirror_dir/$repo_name.git"
    remote_url="https://github.com/goodnet-io/$repo_name"

    mkdir -p "$(dirname "$plugin_dir")"

    if [ -d "$mirror" ]; then
      echo "pull-plugin: cloning $repo_name from $mirror"
      git clone --quiet "$mirror" "$plugin_dir"
    elif git ls-remote --quiet "$remote_url" >/dev/null 2>&1; then
      echo "pull-plugin: cloning $repo_name from $remote_url"
      git clone --quiet "$remote_url" "$plugin_dir"
    else
      echo "pull-plugin: $repo_name not available at" >&2
      echo "  - $mirror" >&2
      echo "  - $remote_url" >&2
      echo "  Run \`nix run .#init-mirrors\` from a checkout that" >&2
      echo "  already has the plugin gits, or wait until the org" >&2
      echo "  repo at $remote_url is published." >&2
      exit 1
    fi

    echo ""
    echo "Pulled $repo_name → $plugin_dir"
    echo "Re-run \`cmake -B build\` to pick up the new plugin's CMake target."
  '';
}
