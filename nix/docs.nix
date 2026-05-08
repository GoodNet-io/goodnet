{ pkgs }:

# `nix run .#docs` — generate the kernel API reference and
# architecture diagrams in one shot.
#
# Order:
#   1. `tools/gen_diagrams.py`  → docs/img/*.svg
#   2. `tools/gen_canvas.py`    → docs/architecture.canvas
#   3. `doxygen docs/Doxyfile`  → build/doxygen/html/index.html
#
# Each step is a separate process so a failure halts the chain
# loudly. The diagram steps depend on a Python interpreter that
# already has the `graphviz` Python package wired in; the dev
# shell adds it through the same package set so `nix run .#docs`
# and an interactive `python3 tools/gen_diagrams.py` see the same
# environment.

let
  pythonWithDeps = pkgs.python3.withPackages (ps: [ ps.graphviz ]);
in
pkgs.writeShellApplication {
  name = "goodnet-docs";
  runtimeInputs = [
    pythonWithDeps
    pkgs.graphviz
    pkgs.doxygen
  ];
  text = ''
    set -euo pipefail
    if [ ! -f flake.nix ]; then
      echo "docs: run from the kernel monorepo root" >&2
      exit 1
    fi

    mkdir -p docs/img build/doxygen

    echo ">>> docs: generating SVG diagrams"
    python3 tools/gen_diagrams.py

    echo ">>> docs: generating architecture canvas"
    python3 tools/gen_canvas.py

    echo ">>> docs: generating Doxygen reference"
    doxygen docs/Doxyfile

    echo ""
    echo "docs: done."
    echo "  api reference: build/doxygen/html/index.html"
    echo "  diagrams:      docs/img/*.svg"
    echo "  canvas:        docs/architecture.canvas"
  '';
}
