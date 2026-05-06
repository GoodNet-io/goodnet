# nix/plugin.nix — `nix run .#plugin -- <subcommand> [args]` umbrella.
#
# Single dispatch over the plugin lifecycle subcommands — replaces
# the previous flat \`new-plugin\` / \`pull-plugin\` /
# \`install-plugins\` triplet. Each subcommand re-execs the
# underlying flat app so behaviour stays identical.
#
# Subcommands:
#   new     <kind> <name>   scaffold a fresh plugin
#   pull    <repo-name>     clone a single plugin into its slot
#   install                 pull every loadable plugin in one shot
#   update                  install --update (git pull --ff-only)

{ pkgs, new-plugin, pull-plugin, install-plugins }:

pkgs.writeShellApplication {
  name = "goodnet-plugin";
  runtimeInputs = [ ];
  text = ''
    set -euo pipefail

    if [ $# -lt 1 ]; then
      cat >&2 <<USAGE
    Usage: nix run .#plugin -- <subcommand> [args]
      new     <kind> <name>   scaffold a fresh plugin
      pull    <repo-name>     clone a single plugin into its slot
      install                 pull every loadable plugin
      update                  install --update (git pull --ff-only)
    USAGE
      exit 1
    fi

    sub="$1"; shift

    case "$sub" in
      new)
        exec ${new-plugin}/bin/goodnet-new-plugin "$@"
        ;;
      pull)
        exec ${pull-plugin}/bin/goodnet-pull-plugin "$@"
        ;;
      install)
        exec ${install-plugins}/bin/goodnet-install-plugins "$@"
        ;;
      update)
        exec ${install-plugins}/bin/goodnet-install-plugins --update "$@"
        ;;
      *)
        echo "plugin: unknown subcommand $sub (new|pull|install|update)" >&2
        exit 1
        ;;
    esac
  '';
}
