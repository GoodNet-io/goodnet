{ pkgs }:

# `nix run .#docs` — refresh the source-derived facts, regenerate
# the architecture canvas + SVG diagrams, inject livedoc markers
# in the narrative markdown, and rebuild the Doxygen API reference.
#
# Order:
#   1. `tools/livedoc.py --all`  → docs/_facts/*.yaml,
#                                  docs/img/*.svg,
#                                  docs/architecture.canvas,
#                                  injects markers in docs/**/*.md
#   2. `doxygen docs/Doxyfile`   → build/doxygen/html/index.html
#
# livedoc.py runs gen_diagrams.py and gen_canvas.py internally
# after the fact files are written, so the diagrams always reflect
# the latest ABI shape. Each step is a separate process so a
# failure halts the chain loudly. The python interpreter has
# graphviz + libclang + pyyaml wired in; the dev shell adds the
# same package set so `nix run .#docs` and an interactive
# `python3 tools/livedoc.py` see the same environment.

let
  pythonWithDeps = pkgs.python3.withPackages (ps: [
    ps.graphviz
    ps.libclang
    ps.pyyaml
  ]);
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

    mkdir -p docs/img docs/_facts build/doxygen

    echo ">>> docs: refreshing livedoc facts + diagrams + canvas"
    python3 tools/livedoc.py --all

    echo ">>> docs: generating Doxygen reference"
    doxygen docs/Doxyfile

    echo ""
    echo "docs: done."
    echo "  api reference: build/doxygen/html/index.html"
    echo "  diagrams:      docs/img/*.svg"
    echo "  canvas:        docs/architecture.canvas"
    echo "  facts:         docs/_facts/*.yaml"
  '';
}
