//! Safe RAII wrapper around the GoodNet kernel C ABI.
//!
//! Surfaces the lifecycle (create / init / start / stop / wait /
//! destroy), plugin loading, and protocol registration as idiomatic
//! `Result<_, Error>`-returning methods on a `Core` handle. The
//! `Drop` impl walks the same teardown the embedded-host quickstart
//! at the top of `sdk/core.h` documents (`gn_core_stop` + the kernel's
//! internal `PreShutdown → Shutdown` walk via `gn_core_destroy`), so
//! a panic anywhere between `Core::create` and the end of the scope
//! still drains the kernel cleanly.
//!
//! Raw FFI symbols are re-exported through [`sys`] for entries that
//! are not (yet) hand-wrapped — subscriptions (`gn_core_subscribe`,
//! `gn_core_on_conn_state`), stats (`gn_core_get_stats`), broadcast,
//! in-process vtable registration (handler / link / security /
//! extension), `host_api` accessor, and the version queries.
//!
//! ## Thread safety
//!
//! `sdk/core.h` documents the kernel as internally thread-safe past
//! `gn_core_init` — every `gn_core_*` entry can be called from any
//! thread on the same handle. The wrapper still defaults to
//! `!Send + !Sync` because the kernel's threading model assumes the
//! host owns the lifecycle from one driver thread (typically `main`);
//! a host that wants to share the handle across threads opts in
//! through `unsafe impl Send for Core {}` / `unsafe impl Sync for Core {}`
//! at the call site, accepting responsibility for the race the C ABI
//! permits but does not enforce.

#![deny(unsafe_op_in_unsafe_fn)]

use std::ffi::CString;
use std::marker::PhantomData;
use std::path::Path;
use std::ptr::NonNull;

pub use goodnet_sys as sys;

// ─── Error type ──────────────────────────────────────────────────────────────

/// Strongly-typed mirror of `gn_result_t`.
///
/// `GN_OK` is represented by `Ok(())`; everything else maps to a
/// variant. Unknown / future codes land in `Error::Unknown(raw)` —
/// per `sdk/types.h` consumers are required to default-handle
/// rather than enumerate, so the binding mirrors that contract.
#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    #[error("null argument where required")]
    NullArg,
    #[error("out of memory")]
    OutOfMemory,
    #[error("invalid envelope")]
    InvalidEnvelope,
    #[error("unknown receiver")]
    UnknownReceiver,
    #[error("payload exceeds max_payload_size")]
    PayloadTooLarge,
    #[error("partial frame buffered for retry")]
    DeframeIncomplete,
    #[error("frame deframe failed")]
    DeframeCorrupt,
    #[error("not implemented")]
    NotImplemented,
    #[error("plugin SDK major != kernel SDK major")]
    VersionMismatch,
    #[error("limit reached")]
    LimitReached,
    #[error("invalid state for the requested operation")]
    InvalidState,
    #[error("integrity / authenticity check failed")]
    IntegrityFailed,
    #[error("internal kernel error (exception across C ABI)")]
    Internal,
    #[error("not found")]
    NotFound,
    #[error("value outside permitted range")]
    OutOfRange,
    #[error("wire frame exceeds kMaxFrameBytes")]
    FrameTooLarge,
    #[error("wire-format decode failed")]
    WireDecode,
    #[error("string contained an interior NUL byte")]
    NulByte,
    #[error("path is not valid UTF-8")]
    NonUtf8Path,
    #[error("unknown gn_result_t {0}")]
    Unknown(i32),
}

impl Error {
    /// Convert a raw `gn_result_t` into `Result<(), Error>`. `GN_OK` ⇒ `Ok`.
    pub fn from_raw(raw: sys::gn_result_t) -> Result<(), Error> {
        // bindgen emits gn_result_t as `gn_result_t(i32)` newtype because
        // of the `EnumVariation::NewType` default in `build.rs`. Reach into
        // its `.0` to match.
        let code = raw.0 as i32;
        if code == sys::gn_result_e_GN_OK.0 {
            return Ok(());
        }
        Err(Self::from_code(code))
    }

    fn from_code(code: i32) -> Self {
        match code {
            c if c == sys::gn_result_e_GN_ERR_NULL_ARG.0           => Error::NullArg,
            c if c == sys::gn_result_e_GN_ERR_OUT_OF_MEMORY.0      => Error::OutOfMemory,
            c if c == sys::gn_result_e_GN_ERR_INVALID_ENVELOPE.0   => Error::InvalidEnvelope,
            c if c == sys::gn_result_e_GN_ERR_UNKNOWN_RECEIVER.0   => Error::UnknownReceiver,
            c if c == sys::gn_result_e_GN_ERR_PAYLOAD_TOO_LARGE.0  => Error::PayloadTooLarge,
            c if c == sys::gn_result_e_GN_ERR_DEFRAME_INCOMPLETE.0 => Error::DeframeIncomplete,
            c if c == sys::gn_result_e_GN_ERR_DEFRAME_CORRUPT.0    => Error::DeframeCorrupt,
            c if c == sys::gn_result_e_GN_ERR_NOT_IMPLEMENTED.0    => Error::NotImplemented,
            c if c == sys::gn_result_e_GN_ERR_VERSION_MISMATCH.0   => Error::VersionMismatch,
            c if c == sys::gn_result_e_GN_ERR_LIMIT_REACHED.0      => Error::LimitReached,
            c if c == sys::gn_result_e_GN_ERR_INVALID_STATE.0      => Error::InvalidState,
            c if c == sys::gn_result_e_GN_ERR_INTEGRITY_FAILED.0   => Error::IntegrityFailed,
            c if c == sys::gn_result_e_GN_ERR_INTERNAL.0           => Error::Internal,
            c if c == sys::gn_result_e_GN_ERR_NOT_FOUND.0          => Error::NotFound,
            c if c == sys::gn_result_e_GN_ERR_OUT_OF_RANGE.0       => Error::OutOfRange,
            c if c == sys::gn_result_e_GN_ERR_FRAME_TOO_LARGE.0    => Error::FrameTooLarge,
            c if c == sys::gn_result_e_GN_ERR_WIRE_DECODE.0        => Error::WireDecode,
            other => Error::Unknown(other),
        }
    }
}

// ─── Core handle ─────────────────────────────────────────────────────────────

/// Owned handle to a kernel instance.
///
/// Construction: `Core::create()` (defaults from `sdk/limits.h`).
///
/// Lifecycle: `init` → `start` → … → `stop` → drop. `Drop` is
/// idempotent against `stop` — calling `stop` explicitly before the
/// scope ends and letting `Drop` fire afterwards both end up walking
/// the same `PreShutdown → Shutdown` FSM.
///
/// The `_not_thread_safe` ZST tag wires `!Send + !Sync`; see the
/// crate-level doc above for the opt-in dance.
pub struct Core {
    handle: NonNull<sys::gn_core_t>,
    // Phantom marker pinning `Core` to a single thread by default.
    // Hosts that demand cross-thread sharing accept the kernel's
    // documented "internally thread-safe past gn_core_init" guarantee
    // by writing their own `unsafe impl Send for Core {}` against
    // their build's actual call pattern.
    _not_thread_safe: PhantomData<*mut ()>,
}

impl Core {
    /// Allocate a fresh kernel handle. Wraps `gn_core_create`.
    ///
    /// Returns `Err(Error::OutOfMemory)` only when the kernel C ABI
    /// signals out-of-memory (the only documented NULL-return cause
    /// per `sdk/core.h`).
    pub fn create() -> Result<Self, Error> {
        // SAFETY: gn_core_create has no preconditions and either
        // returns a heap-owned non-null `gn_core_t*` or NULL on
        // out-of-memory — both branches handled below.
        let raw = unsafe { sys::gn_core_create() };
        match NonNull::new(raw) {
            Some(handle) => Ok(Core {
                handle,
                _not_thread_safe: PhantomData,
            }),
            None => Err(Error::OutOfMemory),
        }
    }

    /// Raw kernel handle, for callers that need to drop into FFI
    /// directly (subscriptions, stats, the `host_api` accessor, etc.).
    ///
    /// # Safety
    ///
    /// The pointer stays valid for the lifetime of `&self`. Callers
    /// must not free it (the kernel owns the allocation) and must not
    /// retain it past the next `&mut self` borrow that could trigger
    /// `Drop`.
    pub fn as_ptr(&self) -> *mut sys::gn_core_t {
        self.handle.as_ptr()
    }

    /// Walk the FSM through `Load → Wire → Resolve → Ready`. Wraps
    /// `gn_core_init`.
    pub fn init(&self) -> Result<(), Error> {
        // SAFETY: `handle` is a valid, owned `gn_core_t*` from create();
        // `gn_core_init` is callable per the C ABI's lifecycle contract.
        let rc = unsafe { sys::gn_core_init(self.handle.as_ptr()) };
        Error::from_raw(rc)
    }

    /// Advance from `Ready` to `Running`. Wraps `gn_core_start`.
    pub fn start(&self) -> Result<(), Error> {
        // SAFETY: see `init`.
        let rc = unsafe { sys::gn_core_start(self.handle.as_ptr()) };
        Error::from_raw(rc)
    }

    /// Trigger graceful shutdown. Wraps `gn_core_stop`. Idempotent —
    /// safe to call from any thread, multiple times.
    pub fn stop(&self) {
        // SAFETY: `gn_core_stop` is documented idempotent and
        // thread-safe past init; a stop after destroy can't happen
        // because Drop borrows `&mut self`.
        unsafe { sys::gn_core_stop(self.handle.as_ptr()) };
    }

    /// Block until the kernel hits `Shutdown`. Wraps `gn_core_wait`.
    pub fn wait(&self) {
        // SAFETY: see `stop`.
        unsafe { sys::gn_core_wait(self.handle.as_ptr()) };
    }

    /// Non-zero iff the kernel is in `Running`. Wraps `gn_core_is_running`.
    pub fn is_running(&self) -> bool {
        // SAFETY: lock-free read per the C ABI contract.
        unsafe { sys::gn_core_is_running(self.handle.as_ptr()) != 0 }
    }

    /// Read the local Ed25519 public key. Wraps `gn_core_get_pubkey`.
    ///
    /// Available after `init` succeeds. Returns `Error::InvalidState`
    /// when called too early.
    pub fn pubkey(&self) -> Result<[u8; sys::GN_PUBLIC_KEY_BYTES as usize], Error> {
        let mut buf = [0u8; sys::GN_PUBLIC_KEY_BYTES as usize];
        // SAFETY: buf is 32 bytes wide, matching GN_PUBLIC_KEY_BYTES;
        // the C ABI takes a borrowed caller-allocated buffer.
        let rc = unsafe {
            sys::gn_core_get_pubkey(self.handle.as_ptr(), buf.as_mut_ptr())
        };
        Error::from_raw(rc).map(|_| buf)
    }

    /// Load a plugin shared object after manifest verification. Wraps
    /// `gn_core_load_plugin`.
    ///
    /// `sha256` is the 32-byte digest the host computed at manifest
    /// build time; a mismatch surfaces as `Error::IntegrityFailed`.
    pub fn load_plugin(&self, so_path: &Path, sha256: &[u8; 32]) -> Result<(), Error> {
        let path_str = so_path.to_str().ok_or(Error::NonUtf8Path)?;
        let c_path = CString::new(path_str).map_err(|_| Error::NulByte)?;
        // SAFETY: `c_path` is a valid NUL-terminated string borrowed
        // for the call; `sha256` is a 32-byte buffer the C ABI reads
        // from but does not retain.
        let rc = unsafe {
            sys::gn_core_load_plugin(
                self.handle.as_ptr(),
                c_path.as_ptr(),
                sha256.as_ptr(),
            )
        };
        Error::from_raw(rc)
    }

    /// Unload a previously loaded plugin by name. Wraps
    /// `gn_core_unload_plugin`. Idempotent past `Error::NotFound`.
    pub fn unload_plugin(&self, name: &str) -> Result<(), Error> {
        let c_name = CString::new(name).map_err(|_| Error::NulByte)?;
        // SAFETY: `c_name` is borrowed for the call only; the kernel
        // walks the plugin's shutdown sequence under its own anchor.
        let rc = unsafe {
            sys::gn_core_unload_plugin(self.handle.as_ptr(), c_name.as_ptr())
        };
        Error::from_raw(rc)
    }

    /// Register an in-process protocol layer vtable. Wraps
    /// `gn_core_register_protocol`.
    ///
    /// # Safety
    ///
    /// `vtable` and `self_ptr` must outlive every connection the
    /// kernel routes through this protocol; the C ABI keeps both as
    /// borrowed for the lifetime of the registration. Use this entry
    /// only when the host explicitly owns the lifetime — for a
    /// dlopened plugin, the kernel's loader manages the same wiring
    /// through `gn_core_load_plugin`.
    pub unsafe fn register_protocol(
        &self,
        vtable: *const sys::gn_protocol_layer_vtable_t,
        self_ptr: *mut std::ffi::c_void,
    ) -> Result<(), Error> {
        // SAFETY: forwarded to the caller's invariant per the doc
        // comment; the C ABI accepts both as borrowed.
        let rc = unsafe {
            sys::gn_core_register_protocol(self.handle.as_ptr(), vtable, self_ptr)
        };
        Error::from_raw(rc)
    }
}

impl Drop for Core {
    fn drop(&mut self) {
        // `gn_core_destroy` already walks `PreShutdown → Shutdown` per
        // sdk/core.h, so we don't need a defensive stop() first — but
        // calling stop() is documented idempotent, so a host that
        // forgot to wire shutdown explicitly still gets a clean drain.
        // SAFETY: `handle` originated from gn_core_create; no aliasing
        // borrow can outlive this Drop (rustc enforces it).
        unsafe {
            sys::gn_core_stop(self.handle.as_ptr());
            sys::gn_core_destroy(self.handle.as_ptr());
        }
    }
}

// ─── Version helpers ─────────────────────────────────────────────────────────

/// Kernel version string (e.g. "1.0.0-rc4"). Wraps `gn_version`.
pub fn version() -> &'static str {
    // SAFETY: gn_version returns a pointer to a static string literal
    // owned by the kernel binary; lifetime is `'static`.
    let ptr = unsafe { sys::gn_version() };
    if ptr.is_null() {
        return "unknown";
    }
    // SAFETY: the kernel guarantees NUL-terminated UTF-8 for this
    // string; fall back to a stub on a (theoretically impossible)
    // non-UTF-8 path rather than panic.
    unsafe { std::ffi::CStr::from_ptr(ptr) }
        .to_str()
        .unwrap_or("unknown")
}

/// Packed kernel version (`gn_version_pack` layout). Wraps `gn_version_packed`.
pub fn version_packed() -> u32 {
    // SAFETY: cheap getter; lock-free in the kernel.
    unsafe { sys::gn_version_packed() }
}
