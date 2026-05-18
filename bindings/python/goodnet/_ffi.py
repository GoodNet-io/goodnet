"""cffi ABI-mode binding loader for libgoodnet_kernel.

The cdef block below mirrors the public C surface declared in
``sdk/core.h`` and the result codes from ``sdk/types.h``. cffi's ABI
mode does not parse C headers; the cdef string is what cffi sees, so
the declarations must stay in sync with the SDK headers by hand. New
SDK entries that the Python wrapper needs are added here first, then
exposed through ``goodnet.core``.

The shared library is loaded through ``ffi.dlopen``. The default name
is ``libgoodnet_kernel.so`` (the kernel build output); the
``GOODNET_CORE_LIB`` environment variable overrides the lookup for
non-standard install paths (custom prefix, ``build/core/`` during
local development, etc).
"""
from __future__ import annotations

import os

from cffi import FFI

# ---------------------------------------------------------------------------
# cdef — hand-curated from sdk/core.h and sdk/types.h.
#
# Only the lifecycle + network + plugin-load surface is declared for v0.1.
# Adding new symbols here is a strictly additive change.
# ---------------------------------------------------------------------------

_CDEF = r"""
/* ── sdk/types.h: ABI versioning + identifiers ─────────────────────── */

typedef uint64_t gn_conn_id_t;
typedef uint64_t gn_handler_id_t;
typedef uint64_t gn_link_id_t;
typedef uint64_t gn_timer_id_t;

/* ── sdk/types.h: result codes ─────────────────────────────────────── */

typedef int gn_result_t;

/* ── sdk/core.h: opaque kernel handle ──────────────────────────────── */

typedef struct gn_core_s gn_core_t;

/* ── sdk/core.h: lifecycle ─────────────────────────────────────────── */

gn_core_t* gn_core_create(void);
gn_core_t* gn_core_create_from_json(const char* json_str);
void       gn_core_destroy(gn_core_t* core);

gn_result_t gn_core_install_identity_from_file(
    gn_core_t*  core,
    const char* path);

gn_result_t gn_core_init(gn_core_t* core);
gn_result_t gn_core_start(gn_core_t* core);
void        gn_core_stop(gn_core_t* core);
void        gn_core_wait(gn_core_t* core);
int         gn_core_is_running(gn_core_t* core);

gn_result_t gn_core_reload_config_json(gn_core_t* core,
                                       const char* json_str);

/* ── sdk/core.h: identity ──────────────────────────────────────────── */

gn_result_t gn_core_get_pubkey(gn_core_t* core, uint8_t* out_pk);

/* ── sdk/core.h: network ───────────────────────────────────────────── */

gn_result_t gn_core_connect(gn_core_t* core,
                            const char* uri,
                            const char* scheme,
                            gn_conn_id_t* out_conn);

gn_result_t gn_core_send_to(gn_core_t* core,
                            gn_conn_id_t conn,
                            uint32_t msg_id,
                            const uint8_t* payload,
                            size_t payload_size);

void        gn_core_broadcast(gn_core_t* core,
                              uint32_t msg_id,
                              const uint8_t* payload,
                              size_t payload_size);

gn_result_t gn_core_disconnect(gn_core_t* core, gn_conn_id_t conn);

/* ── sdk/core.h: introspection ─────────────────────────────────────── */

size_t gn_core_connection_count(gn_core_t* core);
size_t gn_core_handler_count(gn_core_t* core);
size_t gn_core_link_count(gn_core_t* core);

/* ── sdk/core.h: plugin lifecycle ──────────────────────────────────── */

gn_result_t gn_core_load_plugin(gn_core_t* core,
                                const char* so_path,
                                const uint8_t* expected_sha256);

gn_result_t gn_core_load_plugins_batch(gn_core_t* core,
                                       const char* const* so_paths,
                                       const uint8_t* expected_sha256s,
                                       size_t count);

gn_result_t gn_core_unload_plugin(gn_core_t* core, const char* name);

/* ── sdk/core.h: extensions ────────────────────────────────────────── */

const void* gn_core_query_extension_checked(gn_core_t* core,
                                            const char* name,
                                            uint32_t required_version);

gn_result_t gn_core_register_extension(gn_core_t* core,
                                       const char* name,
                                       uint32_t version,
                                       const void* vtable);

gn_result_t gn_core_unregister_extension(gn_core_t* core, const char* name);

/* ── sdk/core.h: version helpers ───────────────────────────────────── */

const char* gn_version(void);
uint32_t    gn_version_packed(void);
"""

# Functions declared in the cdef block above; surface metric exposed
# for the smoke test and downstream introspection.
CDEF_FUNCTIONS: tuple[str, ...] = (
    "gn_core_create",
    "gn_core_create_from_json",
    "gn_core_destroy",
    "gn_core_install_identity_from_file",
    "gn_core_init",
    "gn_core_start",
    "gn_core_stop",
    "gn_core_wait",
    "gn_core_is_running",
    "gn_core_reload_config_json",
    "gn_core_get_pubkey",
    "gn_core_connect",
    "gn_core_send_to",
    "gn_core_broadcast",
    "gn_core_disconnect",
    "gn_core_connection_count",
    "gn_core_handler_count",
    "gn_core_link_count",
    "gn_core_load_plugin",
    "gn_core_load_plugins_batch",
    "gn_core_unload_plugin",
    "gn_core_query_extension_checked",
    "gn_core_register_extension",
    "gn_core_unregister_extension",
    "gn_version",
    "gn_version_packed",
)

# Default library names tried in order when GOODNET_CORE_LIB is unset.
# The kernel build product is ``libgoodnet_kernel.so``; the older
# ``libgoodnet_core.so`` alias is checked as a fallback for embedders
# that ship under the legacy name.
_DEFAULT_LIB_NAMES: tuple[str, ...] = (
    "libgoodnet_kernel.so",
    "libgoodnet_core.so",
)

ffi = FFI()
ffi.cdef(_CDEF)


def _resolve_library_path() -> str:
    """Pick the shared-library path to dlopen.

    ``GOODNET_CORE_LIB`` wins when set — useful for development trees
    where the .so sits under ``build/core/`` and is not on the system
    loader path. Otherwise the soname is searched through the dynamic
    loader the same way ``ctypes.CDLL("libfoo.so")`` would resolve.
    """
    override = os.environ.get("GOODNET_CORE_LIB")
    if override:
        return override
    return _DEFAULT_LIB_NAMES[0]


def _open_library() -> "FFI.CData":
    """Attempt to dlopen the kernel shared library.

    Tries the override / default first; on failure walks the fallback
    list so an embedder that still ships ``libgoodnet_core.so`` keeps
    working. Raises ``OSError`` with the underlying loader message if
    every candidate fails.
    """
    path = _resolve_library_path()
    try:
        return ffi.dlopen(path)
    except OSError as primary_err:
        if os.environ.get("GOODNET_CORE_LIB"):
            # User pinned a path explicitly — do not silently fall back
            # to a different file.
            raise
        for candidate in _DEFAULT_LIB_NAMES[1:]:
            try:
                return ffi.dlopen(candidate)
            except OSError:
                continue
        raise OSError(
            f"goodnet: could not load any of {_DEFAULT_LIB_NAMES!r}; "
            f"set GOODNET_CORE_LIB to the absolute path of "
            f"libgoodnet_kernel.so. Original error: {primary_err}"
        ) from primary_err


# Lazily-initialised handle to the dlopened library. The module-level
# attribute stays None until the first ``lib()`` call so importing
# ``goodnet`` does not require the kernel .so on disk (useful for
# documentation generators and ``pip install`` introspection).
_lib: "FFI.CData | None" = None


def lib() -> "FFI.CData":
    """Return the dlopened library handle, opening it on first call."""
    global _lib
    if _lib is None:
        _lib = _open_library()
    return _lib


__all__ = ["CDEF_FUNCTIONS", "ffi", "lib"]
