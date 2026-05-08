# nix/setup.nix — `nix run .#setup` umbrella.
#
# One-shot bootstrap for a fresh kernel checkout: bare-mirrors
# the in-tree plugin gits (so subsequent `install-plugins` calls
# have a remote to clone from), pulls every loadable plugin into
# its slot, then wires the local `.githooks/` clang-tidy gate.
# Replaces the previous flat `nix run .#init-mirrors`,
# `.#install-plugins`, `.#install-hooks` triplet with a single
# entry point for the operator.
#
# Idempotent — every step it dispatches to is itself idempotent.
# Re-running on a fully-set-up tree is a no-op.

{ pkgs, init-mirrors, install-plugins, install-hooks }:

pkgs.writeShellApplication {
  name = "goodnet-setup";
  runtimeInputs = [ ];
  text = ''
    set -euo pipefail

    if [ ! -f flake.nix ] || [ ! -d plugins ]; then
      echo "setup: run from the kernel monorepo root" >&2
      exit 1
    fi

    echo ">>> setup: init-mirrors"
    ${init-mirrors}/bin/goodnet-init-mirrors

    echo ""
    echo ">>> setup: install-plugins"
    ${install-plugins}/bin/goodnet-install-plugins

    echo ""
    echo ">>> setup: install-hooks"
    ${install-hooks}/bin/gn-install-hooks

    echo ""
    echo "setup: done."
  '';
}
