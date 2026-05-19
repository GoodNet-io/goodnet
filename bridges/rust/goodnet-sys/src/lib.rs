//! Raw FFI bindings for the GoodNet kernel C ABI.
//!
//! The whole content of this crate is bindgen-generated at build time
//! against `sdk/core.h` (see `build.rs`). Refer to the canonical contract
//! at `docs/contracts/core-c.en.md` for semantics; the doc comments
//! bindgen lifts off the C headers are reproduced inline so `cargo doc`
//! produces a self-contained reference.
//!
//! Most callers want the safe wrapper one crate up — `goodnet::Core` —
//! which handles `Drop`, `Result` conversion, and `&str` ⇒ `*const c_char`
//! marshalling. Reach for `goodnet_sys::*` directly only for entries the
//! wrapper has not (yet) covered: subscriptions, vtable registration,
//! the host_api accessor, stats snapshotting, broadcast, and the long
//! tail of `gn_core_*` introspection.

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]
#![allow(clippy::missing_safety_doc)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
