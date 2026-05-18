"""GoodNet — Python bindings for the GoodNet network kernel.

This package wraps the C ABI declared in ``sdk/core.h`` (see the
upstream repository) through cffi's ABI mode: the kernel shared
library is loaded at runtime, the function signatures are declared by
hand in :mod:`goodnet._ffi`, and a Pythonic :class:`Core` class wraps
the opaque ``gn_core_t*`` handle.

Quick start:

.. code-block:: python

    from goodnet import Core

    with Core() as core:
        # init + start have already run; ``core.is_running()`` is True
        print("kernel pubkey:", core.get_pubkey().hex())
    # stop + destroy fire automatically here

The shared library is looked up through ``GOODNET_CORE_LIB`` first,
then by the soname ``libgoodnet_kernel.so`` (with ``libgoodnet_core.so``
as a legacy fallback). Set ``GOODNET_CORE_LIB`` to an absolute path
when running against a development build:

.. code-block:: bash

    export GOODNET_CORE_LIB=/abs/path/to/build/core/libgoodnet_kernel.so

The v0.1 surface ships the lifecycle (create / init / start / wait /
stop / destroy), plugin load/unload, send/broadcast/disconnect, and
introspection counters. Callback-based subscriptions
(``gn_core_subscribe`` / ``gn_core_on_conn_state``) are deferred to
v0.2 — see ``bindings/python/README.md`` for the gap notice.
"""
from __future__ import annotations

from .core import Core, version, version_packed
from .errors import Error, Status, check, strerror

__version__ = "0.1.0"

__all__ = [
    "Core",
    "Error",
    "Status",
    "__version__",
    "check",
    "strerror",
    "version",
    "version_packed",
]
