//! Build script for `goodnet-sys`.
//!
//! Two responsibilities:
//!
//! 1. Locate the GoodNet kernel C ABI: header roots (so bindgen can
//!    parse `#include <sdk/core.h>` and friends) and the `libgoodnet_kernel`
//!    shared object (so the linker emits the right `-L` + `-l`).
//! 2. Run `bindgen` over `wrapper.h` and stash the resulting `bindings.rs`
//!    in `OUT_DIR`, where `src/lib.rs` picks it up via `include!`.
//!
//! Discovery order:
//!
//!   a. `GOODNET_CORE_DIR` env var. When set, expect `<dir>/include/sdk/core.h`
//!      and `<dir>/lib/libgoodnet_kernel.{so,a,dylib}`. This matches the
//!      Nix `goodnet-core` derivation's `$out` layout (see `nix/goodnet-core.nix`
//!      and the `sdk-headers` derivation in `flake.nix`), so a
//!      `nix develop` shell pointed at a built kernel "just works".
//!   b. `pkg-config --cflags --libs goodnet_kernel`. No `.pc` file ships
//!      with the kernel today; this branch is the future-proof path for
//!      when one lands. When pkg-config returns success, its include +
//!      lib paths are preferred over the in-tree fallback.
//!   c. Repository in-tree fallback. The crate sits at
//!      `<repo>/bindings/rust/goodnet-sys/`; walking three levels up
//!      lands on the kernel checkout. Include path is `<repo>/`
//!      (because SDK headers `#include <sdk/foo.h>` against the source
//!      tree). Link path is `<repo>/result/lib/` — the symlink
//!      `nix build .#goodnet-core` produces. Missing-build surfaces as
//!      a clear "no such directory" error at link time, not a silent
//!      empty link line.
//!
//! No matter which branch wins, `bindgen` always reads `wrapper.h`
//! from this crate's source dir. The include flags steer it at the
//! right tree.

use std::env;
use std::path::{Path, PathBuf};

fn main() {
    println!("cargo:rerun-if-env-changed=GOODNET_CORE_DIR");
    println!("cargo:rerun-if-changed=wrapper.h");
    println!("cargo:rerun-if-changed=build.rs");

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    let (include_paths, link_search_paths) = discover();

    // ── Emit linker directives ──
    for lib in &link_search_paths {
        println!("cargo:rustc-link-search=native={}", lib.display());
    }
    // `goodnet_kernel` is the shared object the kernel build emits
    // (see `core/CMakeLists.txt` — `OUTPUT_NAME goodnet_kernel`). On
    // Linux this resolves to `libgoodnet_kernel.so`; on macOS, the
    // matching `.dylib`. Cargo's `dylib` kind picks the platform-native
    // suffix without us hard-coding it.
    println!("cargo:rustc-link-lib=dylib=goodnet_kernel");

    // ── Run bindgen ──
    let mut builder = bindgen::Builder::default()
        .header(
            manifest_dir
                .join("wrapper.h")
                .to_string_lossy()
                .into_owned(),
        )
        // The kernel's C ABI is the `gn_*` symbol family; restricting
        // bindgen to that prefix keeps the output focused (no leaked
        // libc / posix typedefs). The block-list trims a few opaque
        // forward-declared aggregates whose layout is private to the
        // kernel — Rust callers only ever hold pointers to them.
        .allowlist_function("gn_.*")
        .allowlist_type("gn_.*")
        .allowlist_var("GN_.*")
        // Make C enums into Rust `#[repr(C)]` newtype-ish bitflags so
        // the safe wrapper can match exhaustively on result codes
        // without losing forward compatibility on unknown values.
        // `NewType` with `is_global: true` flattens enum variants to
        // module-level constants (`gn_result_e_GN_OK`) rather than
        // associated constants on the impl block. The flat shape lets
        // the safe wrapper match against `sys::gn_result_e_GN_*` without
        // pulling the typedef path in every arm.
        .default_enum_style(bindgen::EnumVariation::NewType {
            is_bitfield: false,
            is_global: true,
        })
        .layout_tests(false)
        .generate_comments(true)
        .derive_default(true)
        // The two static-inline helpers in `sdk/types.h` (`gn_strerror`,
        // `gn_pk_is_zero`) don't translate cleanly through FFI without
        // wrapper shims; bindgen would emit unreferenced static
        // definitions. Easier: hand-implement the equivalents in the
        // safe wrapper crate.
        .blocklist_function("gn_strerror")
        .blocklist_function("gn_pk_is_zero")
        // Use `core::ffi` for the integer-typed aliases (size_t / int32_t)
        // rather than the deprecated `std::os::raw` family — keeps the
        // crate `no_std`-compatible if a downstream ever asks.
        .use_core();

    for inc in &include_paths {
        builder = builder.clang_arg(format!("-I{}", inc.display()));
    }

    let bindings = builder
        .generate()
        .expect("bindgen: failed to generate goodnet-sys bindings");

    bindings
        .write_to_file(out_dir.join("bindings.rs"))
        .expect("bindgen: failed to write bindings.rs to OUT_DIR");
}

/// Returns `(include_paths, link_search_paths)`. Prefers the env-var
/// hint, then pkg-config, then the in-tree fallback. Each path the
/// function returns is required to exist on disk — a stale env-var
/// value that points at a moved tree should surface as a panic here
/// rather than a confused bindgen header-not-found later.
fn discover() -> (Vec<PathBuf>, Vec<PathBuf>) {
    // (a) explicit override
    if let Ok(dir) = env::var("GOODNET_CORE_DIR") {
        let root = PathBuf::from(&dir);
        let inc = root.join("include").join("goodnet");
        let lib = root.join("lib");
        assert!(
            inc.join("sdk").join("core.h").exists(),
            "GOODNET_CORE_DIR={} but {}/sdk/core.h is missing",
            dir,
            inc.display()
        );
        assert!(
            lib.exists(),
            "GOODNET_CORE_DIR={} but {} is missing",
            dir,
            lib.display()
        );
        return (vec![inc], vec![lib]);
    }

    // (b) pkg-config — currently no `.pc` ships with the kernel, but
    // the branch stays so a future kernel-side `goodnet_kernel.pc`
    // wires in without touching this crate.
    if let Ok(lib) = pkg_config::Config::new()
        .cargo_metadata(false)
        .probe("goodnet_kernel")
    {
        let includes: Vec<PathBuf> = lib.include_paths.clone();
        let search: Vec<PathBuf> = lib.link_paths.clone();
        if !includes.is_empty() && !search.is_empty() {
            return (includes, search);
        }
    }

    // (c) in-tree fallback. <manifest>/../../.. lands on the repo root.
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let repo_root = manifest_dir
        .ancestors()
        .nth(3)
        .expect("manifest dir has at least 3 ancestors")
        .to_path_buf();

    let inc = repo_root.clone();
    let lib = pick_first_existing(&[
        repo_root.join("result").join("lib"),
        repo_root.join("build").join("lib"),
        repo_root.join("build"),
        repo_root.join("build-release").join("lib"),
        repo_root.join("build-release"),
    ])
    .unwrap_or_else(|| {
        panic!(
            "goodnet-sys: could not locate libgoodnet_kernel — set \
             GOODNET_CORE_DIR or run `nix build .#goodnet-core` first \
             (searched under {})",
            repo_root.display()
        )
    });

    assert!(
        inc.join("sdk").join("core.h").exists(),
        "goodnet-sys: in-tree fallback expected {} to contain sdk/core.h",
        inc.display()
    );

    (vec![inc], vec![lib])
}

fn pick_first_existing(candidates: &[PathBuf]) -> Option<PathBuf> {
    for c in candidates {
        if c.is_dir() && libgoodnet_kernel_in(c) {
            return Some(c.clone());
        }
    }
    None
}

fn libgoodnet_kernel_in(dir: &Path) -> bool {
    for suffix in &[".so", ".a", ".dylib"] {
        if dir.join(format!("libgoodnet_kernel{suffix}")).exists() {
            return true;
        }
    }
    false
}
