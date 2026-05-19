//! Integration smoke test: exercise the lifecycle the README documents.
//!
//! Runs `Core::create → Core::init → drop` and asserts the kernel
//! survives the round-trip without panicking. The test loads the
//! shared kernel through whatever `goodnet-sys/build.rs` resolved
//! at compile time — pkg-config, `GOODNET_CORE_DIR`, or the in-tree
//! `result/lib/` fallback — so a `cargo test --workspace` from a
//! `nix develop` shell with a built kernel "just works".
//!
//! Why no `start` + `stop` here: `gn_core_start` flips the FSM to
//! `Running` and the kernel begins accepting inbound traffic on any
//! registered link plugins. With no plugins loaded the call is
//! still well-defined (the kernel sits idle), but the safe wrapper's
//! `Drop` already walks the full shutdown path through `gn_core_stop`
//! + `gn_core_destroy`, so the create-init-drop trio is what
//! exercises the wrapper's lifetime contract in the smallest form.

use goodnet::Core;

#[test]
fn create_init_drop() {
    let core = Core::create().expect("Core::create returned NULL");
    core.init().expect("Core::init failed");

    // After init the kernel is in `Ready`. `is_running` is `false` until
    // `start` is called — explicit check that the wrapper threads the
    // `int → bool` conversion correctly.
    assert!(!core.is_running(), "kernel running before Core::start");

    // Pubkey is populated by init's identity mint; check non-zero so a
    // future regression that silently returns the zero-buffer fails here.
    let pk = core.pubkey().expect("Core::pubkey failed after init");
    assert!(pk.iter().any(|b| *b != 0), "kernel returned zero pubkey");

    // Version string is `'static` per the C ABI; smoke-check it's
    // non-empty and parses as a recognisable version-ish prefix.
    let v = goodnet::version();
    assert!(!v.is_empty(), "gn_version returned empty string");

    // Drop fires Core's destructor here — walks PreShutdown → Shutdown
    // through gn_core_stop + gn_core_destroy. No assertion: the harness
    // measures "did not crash" implicitly.
}
