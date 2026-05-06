# Makefile — thin convenience wrapper over `nix run .#…` apps.
#
# Linux only. The Nix flake is the source of truth for every build
# action; this Makefile exists so `make setup && make test` is the
# common ergonomic surface for operators and contributors who do
# not want to memorise Nix incantations. Every recipe shells out
# to a `nix run` invocation rather than re-implementing the build
# steps; nothing here is a checked-in shell script.

.DEFAULT_GOAL := help

.PHONY: help setup mirrors install-plugins update-plugins \
        dev build test test-asan test-tsan demo clean

help:
	@echo "GoodNet — Make wrapper over the Nix flake"
	@echo ""
	@echo "Setup:"
	@echo "  make mirrors          init bare mirrors for in-tree plugin gits"
	@echo "  make install-plugins  pull each loadable plugin into its slot"
	@echo "  make setup            mirrors + install-plugins (one-shot)"
	@echo "  make update-plugins   git pull --ff-only for each plugin"
	@echo ""
	@echo "Build / test:"
	@echo "  make dev              enter the development shell"
	@echo "  make build            Release build of the kernel"
	@echo "  make test             Debug build + ctest (full suite)"
	@echo "  make test-asan        ASan + UBSan ctest"
	@echo "  make test-tsan        TSan ctest"
	@echo "  make demo             two-node Noise-over-TCP quickstart"
	@echo ""
	@echo "Maintenance:"
	@echo "  make clean            remove build*/ and result/ symlinks"

mirrors:
	nix run .#init-mirrors

install-plugins:
	nix run .#install-plugins

update-plugins:
	nix run .#install-plugins -- --update

setup: mirrors install-plugins

dev:
	nix develop

build:
	nix run .#build

test:
	nix run .#test

test-asan:
	nix run .#test-asan

test-tsan:
	nix run .#test-tsan

demo:
	nix run .#demo

clean:
	rm -rf build build-* result result-*
