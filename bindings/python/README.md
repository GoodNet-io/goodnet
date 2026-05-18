# goodnet — Python bindings for the GoodNet network kernel

`pip install`-able wrapper over the GoodNet C ABI (`sdk/core.h`).
Uses [cffi](https://cffi.readthedocs.io/) in **ABI mode** — the
kernel shared library is loaded at runtime through `dlopen` and the
C function signatures are declared by hand in `goodnet/_ffi.py`. No
C compiler is required at install time.

## Status — v0.1

Ships:

- Full lifecycle: `create` → `init` → `start` → `wait` → `stop` →
  `destroy`, both as explicit methods and through the
  context-manager protocol.
- Identity install + readback (`install_identity_from_file`,
  `get_pubkey`).
- Plugin load / unload (`load_plugin`, `unload_plugin`).
- Application I/O slot (`connect`, `send_to`, `broadcast`,
  `disconnect`).
- Introspection counters (`connection_count`, `handler_count`,
  `link_count`).
- Error mapping (`Status` enum mirrors `gn_result_t`, `Error`
  exception, `strerror` helper).

**Deferred to v0.2** — callback-based subscriptions
(`gn_core_subscribe`, `gn_core_on_conn_state`). Wiring those through
cffi requires `@ffi.callback(...)` plumbing and lifetime
management; the v0.1 surface deliberately stops at the synchronous
control-plane slots. A `@core.handler(msg_id=0x0610)` decorator is
part of the same gap.

## Install

```bash
pip install -e bindings/python/
```

The package depends on `cffi>=1.16`; install pulls it transitively.

## Runtime dependency — the kernel `.so`

`goodnet` does **not** bundle the kernel shared library. The
`Core` constructor calls `dlopen` on first use; the loader needs to
be able to find `libgoodnet_kernel.so`. Three knobs:

1. **`GOODNET_CORE_LIB` environment variable** — absolute path to
   the `.so`. This wins over every other lookup.

   ```bash
   export GOODNET_CORE_LIB=/abs/path/to/build/core/libgoodnet_kernel.so
   ```

2. **`LD_LIBRARY_PATH`** — add the directory that contains the
   `.so`:

   ```bash
   export LD_LIBRARY_PATH=$PWD/build/core:$LD_LIBRARY_PATH
   ```

3. **System install** — the .so sitting under `/usr/lib`,
   `/usr/local/lib`, or wherever the system dynamic loader scans
   (`ldconfig -p | grep goodnet`).

The legacy soname `libgoodnet_core.so` is checked as a fallback
when the canonical name is missing.

## Smoke test

```bash
cd /path/to/goodnet-checkout
export GOODNET_CORE_LIB=$PWD/build/core/libgoodnet_kernel.so
pytest bindings/python/tests/
```

`test_create_destroy` and `test_context_manager_round_trip` exercise
the full lifecycle round-trip. Tests skip cleanly (rather than fail)
when the shared library is not on the loader path so `pytest` keeps
running on a fresh developer machine that has not built the kernel
yet.

## API at a glance

```python
from pathlib import Path
from goodnet import Core, Error, Status

with Core() as core:
    # ``with`` runs gn_core_init + gn_core_start.
    assert core.is_running()
    print("local pubkey:", core.get_pubkey().hex())

    # Loading a plugin computes SHA-256 over the .so on the fly;
    # production callers pass the manifest-side digest explicitly.
    core.load_plugin("link-tcp", Path("/path/libgoodnet_link_tcp.so"))

    conn_id = core.connect("tcp://peer.example:7676")
    core.send_to(conn_id, msg_id=0x0610, payload=b"hello")
# stop + destroy fire on context-exit.
```

Errors surface as `goodnet.Error`:

```python
try:
    with Core() as core:
        core.connect("tcp://nowhere:1")
except Error as exc:
    print(exc.status, exc.code, exc.context)
```

## Layout

```
bindings/python/
├── pyproject.toml      — package metadata, depends on cffi>=1.16
├── README.md           — this file
├── goodnet/
│   ├── __init__.py     — re-exports Core, Error, Status, helpers
│   ├── _ffi.py         — cffi ABI-mode binding, hand-curated cdef
│   ├── core.py         — high-level Core class + context manager
│   └── errors.py       — Status enum mirroring gn_result_t + Error
└── tests/
    └── test_smoke.py   — pytest, gated on the .so being reachable
```

## License

MIT, matching the upstream kernel.
