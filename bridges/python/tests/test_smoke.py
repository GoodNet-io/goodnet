"""Smoke tests for the cffi binding.

The kernel shared library has to be reachable at import time. In a
local development tree the recipe is:

.. code-block:: bash

    export GOODNET_CORE_LIB=$PWD/build/core/libgoodnet_kernel.so
    pytest bindings/python/tests/

The tests skip cleanly when the library is not on the loader path so
``pytest`` still completes on developer machines that have not built
the kernel yet.
"""
from __future__ import annotations

import os

import pytest


def _try_load_lib():
    """Attempt to dlopen the kernel shared library.

    Returns the ``cffi.FFI.CData`` library handle on success, or
    raises ``pytest.skip.Exception`` when the loader cannot find the
    .so — that's the expected "no kernel built yet" outcome on a
    fresh developer machine.
    """
    from goodnet import _ffi

    try:
        return _ffi.lib()
    except OSError as exc:
        pytest.skip(
            f"libgoodnet_kernel.so not reachable "
            f"(set GOODNET_CORE_LIB): {exc}"
        )


def test_module_metadata():
    """Pure-Python parts of the package import without the .so."""
    import goodnet

    assert goodnet.__version__ == "0.1.0"
    assert hasattr(goodnet, "Core")
    assert hasattr(goodnet, "Error")
    assert hasattr(goodnet, "Status")
    # Smoke: error mapping covers GN_OK and a representative failure.
    assert goodnet.strerror(0) == "ok"
    assert goodnet.Status.from_code(0) == goodnet.Status.OK
    assert goodnet.Status.from_code(-12) == goodnet.Status.ERR_INTEGRITY_FAILED


def test_cdef_function_count():
    """The cdef block declares exactly the symbols the wrapper relies on."""
    from goodnet import _ffi

    # If a wrapper method picks up a new SDK entry, bump this number
    # alongside the addition. The number is also reported by the
    # smoke runner so the task contract surfaces it at a glance.
    assert len(_ffi.CDEF_FUNCTIONS) == 26


def test_create_destroy():
    """Round-trip ``gn_core_create`` -> ``gn_core_destroy``."""
    _try_load_lib()
    from goodnet import Core

    core = Core.create()
    try:
        # Pre-init state: ``is_running`` returns False.
        assert core.is_running() is False
    finally:
        core.destroy()
    # Idempotent.
    core.destroy()


def test_context_manager_round_trip():
    """``with Core() as c`` runs init + start, then stop + destroy."""
    _try_load_lib()
    from goodnet import Core

    with Core() as core:
        assert core is not None
        assert core.is_running() is True
        # Identity is available after init().
        pubkey = core.get_pubkey()
        assert isinstance(pubkey, bytes)
        assert len(pubkey) == 32
        # Counters should be zero on a fresh kernel.
        assert core.connection_count() == 0
        assert core.link_count() == 0


def test_version_string():
    """``gn_version`` returns a non-empty, ASCII-decodable string."""
    _try_load_lib()
    from goodnet import version, version_packed

    v = version()
    assert isinstance(v, str)
    assert v  # non-empty
    packed = version_packed()
    assert packed > 0


def test_double_destroy_is_safe():
    """``Core.destroy`` is idempotent — the wrapper survives a double call."""
    _try_load_lib()
    from goodnet import Core

    core = Core.create()
    core.destroy()
    core.destroy()  # no-op, no crash
    # Subsequent operations on a destroyed core should fail loudly.
    with pytest.raises(RuntimeError):
        core.get_pubkey()


def test_environment_override_branch():
    """``GOODNET_CORE_LIB`` is the documented escape hatch.

    Verifies the resolver picks the override path verbatim — we set
    the variable to an obviously-bogus value and expect ``OSError``
    (the loader cannot find ``/nonexistent.so``). This also documents
    the failure mode for downstream packagers.
    """
    from goodnet import _ffi

    saved = os.environ.get("GOODNET_CORE_LIB")
    os.environ["GOODNET_CORE_LIB"] = "/nonexistent-libgoodnet.so"
    try:
        # Force a fresh resolve by stashing the cached handle.
        cached = _ffi._lib  # type: ignore[attr-defined]
        _ffi._lib = None  # type: ignore[attr-defined]
        with pytest.raises(OSError):
            _ffi.lib()
        _ffi._lib = cached  # type: ignore[attr-defined]
    finally:
        if saved is None:
            del os.environ["GOODNET_CORE_LIB"]
        else:
            os.environ["GOODNET_CORE_LIB"] = saved
