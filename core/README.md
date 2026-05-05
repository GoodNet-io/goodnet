# core/

Kernel sources. Built into `goodnet_kernel` (STATIC archive) and
`goodnet_kernel_shared` (SHARED `.so`) by the local `CMakeLists.txt`,
exported through `find_package(GoodNet)` as `GoodNet::kernel` and
`GoodNet::kernel_shared`.

## Layout

| Directory | Role |
|---|---|
| `config/`   | JSON parser + per-key access for the `Config` holder |
| `identity/` | Ed25519 keypair, NodeIdentity, attestation envelope |
| `kernel/`   | Kernel FSM, router, host-API builder, attestation dispatcher, service resolver, timer registry, metrics registry |
| `plugin/`   | PluginManager (dlopen + manifest SHA-256 + lifetime anchor + drain) and plugin manifest parser |
| `registry/` | Per-resource registries: connection, handler, link, security, extension |
| `security/` | Per-connection `SecuritySession` |
| `util/`     | Logger facade, log config loader, `safe_invoke` wrapper |

## Targets exported

- `GoodNet::kernel` — STATIC archive for hosts that link the kernel
  into their own binary.
- `GoodNet::kernel_shared` — SHARED `.so` for hosts that load the C
  ABI in `sdk/core.h` at runtime.
- `GoodNet::ctx_accessors` — STATIC archive carrying just the
  `gn_ctx_*` C ABI accessors. Protocol-layer plugins link this so
  they resolve the bridge symbols without dragging the rest of the
  kernel.

## License

GPL-2.0 with linking exception. See top-level `LICENSE`.
