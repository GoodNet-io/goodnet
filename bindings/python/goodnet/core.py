"""High-level wrapper over the ``gn_core_*`` C ABI.

``Core`` owns a ``gn_core_t*`` handle and walks the kernel lifecycle:

    create -> (optional) install_identity -> init -> start
          -> ... application work ...
          -> stop -> destroy

The class supports the context-manager protocol so callers can drive
the full lifecycle in a single ``with`` block:

    with Core() as core:
        core.load_plugin("link-tcp", Path("/path/libgoodnet_link_tcp.so"))

``__enter__`` runs ``init`` + ``start``; ``__exit__`` runs ``stop`` +
``destroy``. Calling these manually is also supported for embedders
that need a non-block-scoped lifetime.

Callback-based message handlers (``gn_core_subscribe`` /
``gn_core_on_conn_state``) are deferred to v0.2 — wiring them
through cffi requires ``@ffi.callback(...)`` plumbing and lifetime
management that v0.1 deliberately skips. See ``bindings/python/README.md``
for the current gap.
"""
from __future__ import annotations

import hashlib
import pathlib
from typing import Optional

from ._ffi import ffi, lib
from .errors import Error, check


class Core:
    """Pythonic wrapper around a ``gn_core_t*`` handle.

    The wrapper takes ownership of the handle returned by
    ``gn_core_create``; the underlying C object is freed by
    ``destroy()`` (which the context manager calls in ``__exit__``).
    Use ``Core.create()`` for an explicit constructor or call
    ``Core()`` directly — both allocate the handle eagerly so a
    failure surfaces at construction time rather than at the first
    method call.
    """

    def __init__(self, json_config: Optional[str] = None) -> None:
        """Allocate the kernel handle.

        Args:
            json_config: optional JSON document text passed through to
                ``gn_core_create_from_json``. When ``None`` the
                bare ``gn_core_create`` path is used and the kernel
                applies the defaults from ``sdk/limits.h``.
        """
        self._handle: "ffi.CData | None" = None
        if json_config is not None:
            handle = lib().gn_core_create_from_json(
                json_config.encode("utf-8")
            )
        else:
            handle = lib().gn_core_create()
        if handle == ffi.NULL:
            raise Error(
                -2,  # GN_ERR_OUT_OF_MEMORY — gn_core_create only fails on OOM
                context="gn_core_create",
            )
        self._handle = handle
        self._initialised = False
        self._running = False

    # ------------------------------------------------------------------
    # Construction helpers
    # ------------------------------------------------------------------

    @classmethod
    def create(cls, json_config: Optional[str] = None) -> "Core":
        """Allocate a fresh kernel handle.

        Mirrors ``gn_core_create`` / ``gn_core_create_from_json``.
        """
        return cls(json_config=json_config)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    @property
    def handle(self) -> "ffi.CData":
        """Raw ``gn_core_t*`` — useful for advanced callers."""
        if self._handle is None:
            raise RuntimeError("Core handle already destroyed")
        return self._handle

    def install_identity_from_file(self, path: pathlib.Path | str) -> None:
        """Pre-seed a stored Ed25519 identity from disk.

        Must be called between ``__init__`` (``gn_core_create``) and
        ``init()``; the kernel rejects the call once it has begun the
        FSM walk.
        """
        rc = lib().gn_core_install_identity_from_file(
            self.handle, str(path).encode("utf-8")
        )
        check(rc, "gn_core_install_identity_from_file")

    def init(self) -> None:
        """Walk the kernel FSM through ``Load -> Wire -> Resolve -> Ready``."""
        rc = lib().gn_core_init(self.handle)
        check(rc, "gn_core_init")
        self._initialised = True

    def start(self) -> None:
        """Advance the kernel from ``Ready`` to ``Running``."""
        rc = lib().gn_core_start(self.handle)
        check(rc, "gn_core_start")
        self._running = True

    def stop(self) -> None:
        """Trigger graceful shutdown. Idempotent."""
        if self._handle is None:
            return
        lib().gn_core_stop(self._handle)
        self._running = False

    def wait(self) -> None:
        """Block until ``gn_core_stop`` has been fired elsewhere."""
        lib().gn_core_wait(self.handle)

    def is_running(self) -> bool:
        """``True`` iff the kernel is currently in ``Phase::Running``."""
        if self._handle is None:
            return False
        return bool(lib().gn_core_is_running(self._handle))

    def reload_config(self, json_str: str) -> None:
        """Apply a fresh JSON config document. Atomic on failure."""
        rc = lib().gn_core_reload_config_json(
            self.handle, json_str.encode("utf-8")
        )
        check(rc, "gn_core_reload_config_json")

    def destroy(self) -> None:
        """Free the underlying handle. Idempotent."""
        if self._handle is None:
            return
        lib().gn_core_destroy(self._handle)
        self._handle = None
        self._initialised = False
        self._running = False

    # ------------------------------------------------------------------
    # Identity / introspection
    # ------------------------------------------------------------------

    def get_pubkey(self) -> bytes:
        """Read the local node's 32-byte Ed25519 device public key.

        Available after ``init()`` has returned ``GN_OK``.
        """
        buf = ffi.new("uint8_t[32]")
        rc = lib().gn_core_get_pubkey(self.handle, buf)
        check(rc, "gn_core_get_pubkey")
        return bytes(ffi.buffer(buf, 32))

    def connection_count(self) -> int:
        """Live entries in the kernel's ``ConnectionRegistry``."""
        return int(lib().gn_core_connection_count(self.handle))

    def handler_count(self) -> int:
        """Live entries in the kernel's ``HandlerRegistry``."""
        return int(lib().gn_core_handler_count(self.handle))

    def link_count(self) -> int:
        """Live entries in the kernel's ``LinkRegistry``."""
        return int(lib().gn_core_link_count(self.handle))

    # ------------------------------------------------------------------
    # Plugins
    # ------------------------------------------------------------------

    def load_plugin(
        self,
        name: str,
        path: pathlib.Path | str,
        expected_sha256: bytes | None = None,
    ) -> None:
        """Load a plugin shared object after manifest verification.

        Args:
            name: human-readable label for diagnostics — unused by the
                kernel (which derives the plugin name from the .so's
                descriptor), but accepted so call sites read clearly.
            path: filesystem path to the ``.so`` file.
            expected_sha256: 32-byte SHA-256 of the file contents. When
                ``None`` the digest is computed on the fly by reading
                the file — convenient for development; production
                callers should pass the manifest-side digest so the
                wrapper does not silently re-hash a tampered binary.
        """
        del name  # accepted for call-site clarity, see docstring
        path_str = str(path)
        if expected_sha256 is None:
            digest = hashlib.sha256()
            with open(path_str, "rb") as fh:
                for chunk in iter(lambda: fh.read(1 << 16), b""):
                    digest.update(chunk)
            expected_sha256 = digest.digest()
        if len(expected_sha256) != 32:
            raise ValueError(
                "expected_sha256 must be exactly 32 bytes "
                f"(got {len(expected_sha256)})"
            )
        sha_buf = ffi.new("uint8_t[32]", list(expected_sha256))
        rc = lib().gn_core_load_plugin(
            self.handle, path_str.encode("utf-8"), sha_buf
        )
        check(rc, "gn_core_load_plugin")

    def unload_plugin(self, name: str) -> None:
        """Tear down a previously loaded plugin by name."""
        rc = lib().gn_core_unload_plugin(self.handle, name.encode("utf-8"))
        check(rc, "gn_core_unload_plugin")

    # ------------------------------------------------------------------
    # Send / broadcast / disconnect
    # ------------------------------------------------------------------

    def connect(self, uri: str, scheme: Optional[str] = None) -> int:
        """Initiate an outbound connection. Returns the ``gn_conn_id_t``."""
        out_conn = ffi.new("gn_conn_id_t*")
        scheme_arg = ffi.NULL if scheme is None else scheme.encode("utf-8")
        rc = lib().gn_core_connect(
            self.handle, uri.encode("utf-8"), scheme_arg, out_conn
        )
        check(rc, "gn_core_connect")
        return int(out_conn[0])

    def send_to(self, conn: int, msg_id: int, payload: bytes) -> None:
        """Send a single application message on ``conn``."""
        buf = ffi.from_buffer("uint8_t[]", payload)
        rc = lib().gn_core_send_to(
            self.handle, conn, msg_id, buf, len(payload)
        )
        check(rc, "gn_core_send_to")

    def broadcast(self, msg_id: int, payload: bytes) -> None:
        """Send ``payload`` to every live connection. No return code."""
        buf = ffi.from_buffer("uint8_t[]", payload)
        lib().gn_core_broadcast(self.handle, msg_id, buf, len(payload))

    def disconnect(self, conn: int) -> None:
        """Tear down a connection by id."""
        rc = lib().gn_core_disconnect(self.handle, conn)
        check(rc, "gn_core_disconnect")

    # ------------------------------------------------------------------
    # Context-manager protocol
    # ------------------------------------------------------------------

    def __enter__(self) -> "Core":
        self.init()
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        # ``stop`` + ``destroy`` are both idempotent; the contract from
        # sdk/core.h guarantees that ``gn_core_destroy(NULL)`` is a
        # no-op. We swallow any exception here only insofar as the
        # destructor must run to completion — re-raising would be the
        # caller's outer exception, not ours.
        try:
            self.stop()
        finally:
            self.destroy()

    def __del__(self) -> None:
        # Best-effort cleanup for callers that forgot the context
        # manager. The kernel handle is GC-rooted on the Python side;
        # without this hook a dropped reference would leak the handle.
        try:
            if self._handle is not None:
                self.destroy()
        except Exception:
            # Destructors must not throw. The kernel-side teardown is
            # safe to skip on interpreter shutdown when the library is
            # already unloaded.
            pass


def version() -> str:
    """Human-readable kernel version, e.g. ``"1.0.0-rc3"``."""
    raw = lib().gn_version()
    if raw == ffi.NULL:
        return ""
    return ffi.string(raw).decode("utf-8")


def version_packed() -> int:
    """Packed kernel version per the ``gn_version_pack`` layout."""
    return int(lib().gn_version_packed())


__all__ = ["Core", "version", "version_packed"]
