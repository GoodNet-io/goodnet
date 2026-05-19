# GoodNet — Rust bindings

Two-crate Cargo workspace under `bridges/rust/`:

| crate | role |
|-------|------|
| `goodnet-sys` | Raw FFI, `bindgen`-generated at build time from `sdk/core.h`. |
| `goodnet` | Safe RAII wrapper: `Core` owns `*mut gn_core_t`, `Drop` calls `gn_core_destroy`. |

Bindings ship as **source only** — no pre-generated `bindings.rs`
checked into the repo. `bindgen` runs every `cargo build` against the
kernel's actual `sdk/*.h` so the binding always matches the kernel
SDK major in the same checkout.

---

## Prerequisites

1. **Kernel built and discoverable.** `goodnet-sys/build.rs` looks
   for `libgoodnet_kernel.{so,a,dylib}` + the `sdk/*.h` headers in
   one of three places, in order:

   - `$GOODNET_CORE_DIR` env var — expects `<dir>/include/goodnet/sdk/core.h`
     and `<dir>/lib/libgoodnet_kernel.*`. This is the canonical
     "I have a built kernel installed" path and matches the layout
     of the kernel's Nix `goodnet-core` derivation.
   - `pkg-config --libs goodnet_kernel`. **No `.pc` ships with the
     kernel today**; this branch stays as the future-proof entry
     for when one lands.
   - **In-tree fallback.** Walks three levels up from the crate's
     manifest dir to find the repo root, then looks for the
     kernel under `result/lib/` (the symlink `nix build .#goodnet-core`
     produces) or under any `build*/` tree.

2. **Rust toolchain + libclang.** `bindgen` needs libclang at runtime;
   `cargo` + `rustc` need a recent stable. The dev-shell entry below
   sets both up under Nix; on a host with `rustup` installed
   plus `clang` from your distro packages, `cargo build` should
   work without further env wiring.

---

## Build + test

From this directory:

```sh
# inside `nix develop`, or with rustup + clang on PATH:
cargo build --workspace
cargo test  --workspace
```

If `cargo build` fails with `goodnet-sys: could not locate
libgoodnet_kernel`, run a kernel build first:

```sh
nix build .#goodnet-core    # produces result/lib/libgoodnet_kernel.so
```

…then re-run `cargo build`. The in-tree fallback will pick up
`<repo>/result/lib/` automatically.

For an out-of-tree consumer (e.g. a downstream Rust binary that
depends on `goodnet` through git or a registry), point at a built
kernel:

```sh
export GOODNET_CORE_DIR=/nix/store/…-goodnet-core-1.0.0-rc4
cargo build
```

---

## Surface coverage

The safe `goodnet::Core` wraps the lifecycle + a representative
illustrative subset:

- `Core::create` / `Core::init` / `Core::start` / `Core::stop` /
  `Core::wait` / `Drop` ⇒ `gn_core_destroy`
- `Core::is_running`
- `Core::pubkey`
- `Core::load_plugin` / `Core::unload_plugin`
- `Core::register_protocol`
- `goodnet::version` / `goodnet::version_packed`

Everything else on the C ABI is reachable as raw FFI through
`goodnet::sys::*` (re-exported from `goodnet-sys`). That covers:

- Subscriptions: `gn_core_subscribe`, `gn_core_on_conn_state`,
  `gn_core_unsubscribe`, `gn_core_off_conn_state`
- In-process registration: `gn_core_register_handler`,
  `gn_core_register_link`, `gn_core_register_security`,
  `gn_core_register_extension`, `gn_core_unregister_extension`,
  `gn_core_query_extension_checked`
- Network: `gn_core_connect`, `gn_core_listen`, `gn_core_send_to`,
  `gn_core_broadcast`, `gn_core_disconnect`
- Stats / introspection: `gn_core_get_stats`,
  `gn_core_connection_count`, `gn_core_handler_count`,
  `gn_core_link_count`, `gn_core_is_running`
- Identity injection: `gn_core_install_identity_from_file`
- Config: `gn_core_reload_config_json`, `gn_core_set_limits`,
  `gn_core_limits`, `gn_core_create_from_json`
- Plugin batch: `gn_core_load_plugins_batch`
- `host_api` accessor: `gn_core_host_api`

Roughly **8 hand-wrapped entries / ~30 raw FFI**. The next pass adds
typed wrappers as concrete downstream Rust hosts (e.g. an `iroh`-
style example consumer) demand them; until then, raw FFI is the
escape hatch.

---

## Thread safety

Default: `Core` is `!Send + !Sync`. The C ABI documents the kernel
as internally thread-safe past `gn_core_init`, but the wrapper
defers the cross-thread-sharing decision to the host — a host that
wants to drive the same handle from multiple threads opts in with:

```rust
unsafe impl Send for goodnet::Core {}
unsafe impl Sync for goodnet::Core {}
```

…and accepts responsibility for any callback-thread invariants its
plugin set assumes.

---

## What this binding deliberately does NOT do

- **No async runtime.** v0.1 is a synchronous wrapper. The kernel
  is event-driven internally; subscriptions land on the kernel's
  dispatch thread. A future v0.2 may add a `tokio` adapter; the
  current shape leaves that decision to downstream crates.
- **No pre-generated bindings.** `bindings.rs` lives in `OUT_DIR`,
  never in git. `nix build .#goodnet-rust` re-runs bindgen every
  build, so a kernel-side ABI bump surfaces at the next Rust
  compile rather than at the next runtime call.
- **No `goodnet-handler-trait` / `goodnet-link-trait` macros.**
  Plugin-side abstractions ship under follow-up crates once the
  plugin C ABI's `gn_plugin_*` entries are mirrored here. Today the
  binding is host-side only — applications that drive a kernel from
  Rust, not plugins authored in Rust.

---

## Layout

```
bridges/rust/
├── Cargo.toml              workspace
├── README.md               this file
├── default.nix             Nix env wrapper (rustc + libclang + kernel hint)
├── goodnet-sys/
│   ├── Cargo.toml
│   ├── build.rs            discovery + bindgen runner
│   ├── wrapper.h           single TU bindgen reads
│   └── src/lib.rs          include!() the OUT_DIR bindings
└── goodnet/
    ├── Cargo.toml
    ├── src/lib.rs          safe wrapper + Error enum
    └── tests/smoke.rs      create → init → drop integration test
```
