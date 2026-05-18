{ pkgs ? import <nixpkgs> { } }:

# Dev-shell helper for the Rust bindings workspace.
#
#   cd bindings/rust
#   nix-shell                  # rustc + cargo + libclang + kernel pointer
#   cargo build --workspace
#   cargo test  --workspace
#
# Same toolchain the flake-level `goodnet-rust` derivation uses, but
# without the full Nix-derivation rebuild loop — enter the shell once,
# iterate `cargo` calls inline.
#
# The shell points `GOODNET_CORE_DIR` at `../../result` so the
# in-tree fallback path in `goodnet-sys/build.rs` reaches the kernel
# Nix output produced by `nix build .#goodnet-core` at the repo
# root. Override by exporting a different `GOODNET_CORE_DIR` before
# entering the shell.

let
  rustToolchain = with pkgs; [ cargo rustc rustfmt clippy ];
in
pkgs.mkShell {
  nativeBuildInputs = with pkgs; [
    pkg-config
    # libclang is bindgen's runtime — required even when `clang` itself
    # is not the C compiler the kernel was built with. The crate looks
    # for `LIBCLANG_PATH` at build time when libclang is not in the
    # default loader path.
    llvmPackages.libclang
  ] ++ rustToolchain;

  buildInputs = with pkgs; [
    libsodium
    openssl
    spdlog
    fmt
    nlohmann_json
  ];

  # bindgen reads libclang through the `LIBCLANG_PATH` env var. The
  # `llvmPackages.libclang` derivation places the shared object under
  # `lib/`, so point bindgen at that exact dir.
  LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";

  shellHook = ''
    # Default GOODNET_CORE_DIR to the repo's `result/` symlink — the
    # `nix build .#goodnet-core` output the kernel build app produces.
    # Override before `nix-shell` if you point at a different install.
    if [ -z "''${GOODNET_CORE_DIR:-}" ]; then
      _repo_root="$(git -C "$PWD" rev-parse --show-toplevel 2>/dev/null || pwd)"
      if [ -e "$_repo_root/result/lib/libgoodnet_kernel.so" ]; then
        export GOODNET_CORE_DIR="$_repo_root/result"
        echo ">>> goodnet-rust: GOODNET_CORE_DIR=$GOODNET_CORE_DIR"
      else
        cat <<'EOF'
>>> goodnet-rust: no GOODNET_CORE_DIR set and no result/ symlink found.
    Build the kernel first:
        cd "$_repo_root" && nix build .#goodnet-core
    or export GOODNET_CORE_DIR=/path/to/goodnet-core/install
EOF
      fi
      unset _repo_root
    fi

    echo ""
    echo "GoodNet Rust bindings devShell"
    echo "  cargo build --workspace"
    echo "  cargo test  --workspace"
    echo ""
  '';
}
