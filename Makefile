# Makefile — thin convenience wrapper over `nix run .#…` apps.
#
# Linux only. The Nix flake is the source of truth for every build
# action; this Makefile exists so `make setup && make test` is the
# common ergonomic surface. Every recipe shells out to a single
# `nix run` call rather than re-implementing the build steps;
# nothing here is a checked-in shell script.

.DEFAULT_GOAL := help

.PHONY: help setup update dev \
        build build-release \
        test test-asan test-tsan test-all \
        run demo goodnet node \
        plugin-new plugin-pull plugin-install plugin-update \
        docs livedoc livedoc-check \
        clean

help:
	@echo "GoodNet — Make wrapper over the Nix flake"
	@echo ""
	@echo "Setup / refresh:"
	@echo "  make setup            init mirrors + install plugins + hooks"
	@echo "  make update           refresh kernel inputs + plugin pulls"
	@echo ""
	@echo "Dev / build:"
	@echo "  make dev              enter dev shell (nix develop)"
	@echo "  make build            Debug build (incremental)"
	@echo "  make build-release    Release build"
	@echo ""
	@echo "Test:"
	@echo "  make test             vanilla ctest (full suite)"
	@echo "  make test-asan        ASan + UBSan ctest"
	@echo "  make test-tsan        TSan ctest"
	@echo "  make test-all         vanilla + asan + tsan in sequence"
	@echo ""
	@echo "Run artefacts:"
	@echo "  make demo             two-node Noise-over-TCP quickstart"
	@echo "  make goodnet ARGS=…   operator multicall CLI"
	@echo "  make node ARGS=…      goodnet run alias"
	@echo ""
	@echo "Plugin lifecycle:"
	@echo "  make plugin-new KIND=… NAME=…   scaffold a fresh plugin"
	@echo "  make plugin-pull REPO=…         clone a single plugin"
	@echo "  make plugin-install             pull every loadable plugin"
	@echo "  make plugin-update              git pull --ff-only each"
	@echo ""
	@echo "Documentation:"
	@echo "  make docs             Doxygen API ref + diagrams + canvas"
	@echo "  make livedoc          refresh source-derived facts + injections"
	@echo "  make livedoc-check    fail if working tree drifts from sources"
	@echo ""
	@echo "Maintenance:"
	@echo "  make clean            remove build*/ and result/ symlinks"

# Setup / refresh
setup:
	nix run .#setup

update:
	nix run .#update

# Dev / build
dev:
	nix develop

build:
	nix run .#build

build-release:
	nix run .#build -- release

# Test
test:
	nix run .#test

test-asan:
	nix run .#test -- asan

test-tsan:
	nix run .#test -- tsan

test-all:
	nix run .#test -- all

# Run artefacts (ARGS forwarded after --)
run:
	nix run .#run -- $(ARGS)

demo:
	nix run .#run -- demo

goodnet:
	nix run .#run -- goodnet $(ARGS)

node:
	nix run .#run -- node $(ARGS)

# Plugin lifecycle
plugin-new:
	nix run .#plugin -- new $(KIND) $(NAME)

plugin-pull:
	nix run .#plugin -- pull $(REPO)

plugin-install:
	nix run .#plugin -- install

plugin-update:
	nix run .#plugin -- update

# Documentation
docs:
	nix run .#docs

# Livedoc — refresh source-derived facts + diagrams + canvas +
# inject into narrative markdown. Idempotent; commit the diff to
# keep docs in sync with the working tree.
livedoc:
	nix develop --command python3 tools/livedoc.py --all

# Same as `livedoc` but exits non-zero if the working tree drifts
# from what the generator would produce. Useful as a CI gate.
livedoc-check:
	nix develop --command python3 tools/livedoc.py --check

# Maintenance
clean:
	rm -rf build build-* result result-*
