# Contract: Core C ABI

**Status:** active · v1
**Owner:** `core/kernel/core_c.cpp`, every non-C++ host
**Implements:** size-prefix evolution per `abi-evolution.md`
**Last verified:** 2026-05-02
**Stability:** stable for v1.x; new entries appended at the tail.

---

## 1. Purpose

GoodNet ships `goodnet_kernel` as a shared library. `sdk/core.h` is
the C ABI a non-C++ host crosses to drive a kernel from outside the
C++ world — a Rust application, a Python tooling layer, a Go
control-plane panel, or a WebAssembly browser embed. Every public
operation on `gn::core::Kernel` and its registries is reachable
through one of the `gn_core_*` entries.

| Surface | Direction | Audience |
|---|---|---|
| `sdk/core.h` (this contract) | host → kernel | host binary embedding the kernel |
| `sdk/host_api.h` (`host-api.md`) | kernel → plugin | every loaded plugin |

The two surfaces are independent. A non-C++ binding ships both: it
crosses `sdk/core.h` to spin the kernel up, then exposes
`sdk/host_api.h` to its own plugins as the inverse direction.

GoodNet exposes only one opaque handle, `gn_core_t*`, to the host;
internal kernel state moves freely between minor releases without
forcing a host rebuild.

### 1.1 Conventions inherited from the SDK

This contract reuses the conventions defined elsewhere; the
references hold without restating:

- **Zero-init for value structs** — `host-api.md` §2 + `abi-evolution.md` §4.
- **Size-prefix gating** — `abi-evolution.md` §3.
- **Ownership tags** (`@owned`, `@borrowed`, `@in-out`) — `abi-evolution.md` §6.
- **Error codes** — `sdk/types.h` enumerates every `gn_result_t`.
- **Exception safety across the boundary** — `abi-evolution.md` §4a.

GoodNet wraps every host-side entry through the same `safe_invoke`
discipline: a C++ exception escaping kernel code never crosses the C
ABI; OOM and any other throw collapse to the documented failure
return (NULL handle, `GN_ERR_INTERNAL`, `GN_ERR_OUT_OF_MEMORY`, or
the slot's "no-op" sentinel).

---

## 2. Lifecycle FSM

The host walks the kernel through a linear phase chain. Phase
identifiers match `core/kernel/phase.hpp` and the diagram in
`fsm-events.md` §2.

```
   Construct ──gn_core_create──▶ (phase Load, Wire, Resolve, Ready
                                  not yet entered)
                                       │
                              gn_core_init
                                       │
                                       ▼
                        ┌──────────────────────────────┐
                        │  Load → Wire → Resolve → Ready│
                        │  identity generated           │
                        │  protocol layer registered    │
                        │  registries empty but live    │
                        └──────────────────────────────┘
                                       │
                              gn_core_start
                                       │
                                       ▼
                              ┌────────────────┐
                              │     Running     │
                              │  dispatch open  │
                              └────────────────┘
                                       │
                              gn_core_stop
                                       │
                                       ▼
                        ┌──────────────────────────────┐
                        │   PreShutdown → Shutdown      │
                        │   anchors drained             │
                        │   DISCONNECTED published      │
                        └──────────────────────────────┘
                                       │
                              gn_core_destroy
                                       │
                                       ▼
                                   (freed)
```

| Phase | Entered on | Legal `gn_core_*` |
|---|---|---|
| **(unphased)** | after `gn_core_create` | `set_limits`, `reload_config_json`, `init`, `destroy` |
| **Ready** | after `gn_core_init` | every `register_*`, `load_plugin`, `register_extension`, `query_extension_checked`, every read accessor, `host_api`, `start`, `stop`, `destroy` |
| **Running** | after `gn_core_start` | every Ready entry plus `connect`, `send_to`, `broadcast`, `disconnect`, every `subscribe`/`unsubscribe`, `is_running` returns non-zero |
| **PreShutdown / Shutdown** | after `gn_core_stop` | read accessors only; `is_running` returns zero, `wait` unblocks; further mutating calls are rejected by the kernel registries |
| **(freed)** | after `gn_core_destroy` | nothing — handle is dangling |

Forward-only ordering. `gn_core_init` returns `GN_ERR_INVALID_STATE`
on the second call (the bootstrap latch is one-shot).
`gn_core_start` is idempotent — calling on an already-Running kernel
returns `GN_OK` with no effect. `gn_core_stop` is idempotent and
race-safe through a single compare-and-exchange. `gn_core_destroy`
on `NULL` is a no-op.

`set_limits` is rejected with `GN_ERR_INVALID_STATE` after
`gn_core_init` returns `GN_OK` — limits are bootstrap-only.

---

## 3. Function specifications

Every entry returns `gn_result_t`, an opaque id, or `void`. Negative
returns are errors; the host **MUST** propagate or handle. Silent
drops are a contract violation per `fsm-events.md` §4.

### 3.1 Lifecycle

#### `gn_core_create`

| Property | Specification |
|---|---|
| Producer | kernel |
| Effect | Allocate a fresh kernel handle with `sdk/limits.h` defaults pre-applied; no I/O, no thread spawn, no identity generation. |
| Returns | `@owned gn_core_t*`; pair with `gn_core_destroy`. `NULL` on out-of-memory (the only failure mode). |
| Concurrency | thread-safe; allocator is the only shared state. |
| Ownership | host owns the handle until `gn_core_destroy` returns. |

#### `gn_core_create_from_json`

| Property | Specification |
|---|---|
| Producer | kernel |
| Effect | Equivalent to `gn_core_create` followed by `gn_core_reload_config_json(core, json_str)`. The JSON document is copied internally before return. |
| Parameters | `json_str` — `@borrowed` NUL-terminated UTF-8 JSON document. |
| Returns | `@owned gn_core_t*` on success; `NULL` on out-of-memory **or** when the JSON fails to parse (the failure modes collapse — the host detects parse failure by passing a known-good document to `reload_config_json` after `create`). |
| Concurrency | thread-safe. |
| Ownership | host owns the handle until `gn_core_destroy` returns. |

#### `gn_core_destroy`

| Property | Specification |
|---|---|
| Producer | kernel |
| Effect | Walks the FSM through `PreShutdown → Shutdown`, releases every host-side subscription (the message-handler registrations and conn-event channel tokens this handle owns), drains plugin anchors per `plugin-lifetime.md` §4 (default 1 s), publishes `DISCONNECTED` for every live connection, then frees the handle. |
| Parameters | `core` — `@owned`; consumed by the call. |
| Returns | `void`. |
| Concurrency | NOT safe to invoke concurrently with any other call on the same handle. The host **MUST** quiesce other threads before calling. |
| Ownership | the call consumes the handle. `gn_core_destroy(NULL)` is a no-op. |

#### `gn_core_init`

| Property | Specification |
|---|---|
| Producer | kernel |
| Effect | Generates a fresh `NodeIdentity` (Ed25519 device keypair), registers the canonical `gnet-v1` protocol layer, and walks the FSM through `Load → Wire → Resolve → Ready`. Plugins are not loaded here — the host registers them afterwards. |
| Parameters | `core` — `@borrowed`. |
| Returns | `GN_OK` on success; `GN_ERR_INVALID_STATE` when called a second time (the bootstrap latch is one-shot); `GN_ERR_INTEGRITY_FAILED` when libsodium identity generation fails; `GN_ERR_NULL_ARG` on `NULL` core. |
| Concurrency | concurrent calls race through a compare-and-exchange; one returns `GN_OK`, the rest `GN_ERR_INVALID_STATE`. |
| Ownership | the kernel retains the generated identity for the handle's lifetime. |

#### `gn_core_start`

| Property | Specification |
|---|---|
| Producer | kernel |
| Effect | Advances the kernel from `Ready` to `Running`. After return the kernel accepts inbound traffic and dispatches through the registered handler chain. The function returns immediately; the kernel is event-driven and runs whenever a link plugin posts inbound bytes. |
| Returns | `GN_OK` always when `core` is non-NULL — the call is idempotent on an already-Running kernel; `GN_ERR_NULL_ARG` on `NULL` core. |
| Concurrency | thread-safe; concurrent `start` callers all observe `GN_OK`. |

#### `gn_core_stop`

| Property | Specification |
|---|---|
| Producer | kernel |
| Effect | Triggers graceful shutdown: walks `PreShutdown → Shutdown`, drains plugin anchors, publishes `DISCONNECTED` for every live connection, wakes every `gn_core_wait` blocker. |
| Returns | `void`. |
| Concurrency | thread-safe; concurrent callers race through a single compare-and-exchange and the work runs once. |

#### `gn_core_wait`

| Property | Specification |
|---|---|
| Producer | kernel |
| Effect | Blocks the calling thread on a condition variable until the kernel reaches `Phase::Shutdown` or `Phase::Unload`. |
| Returns | `void`. |
| Concurrency | safe from any thread. Multiple threads may wait simultaneously; all wake when `gn_core_stop` fires. |

#### `gn_core_is_running`

| Property | Specification |
|---|---|
| Producer | kernel |
| Effect | none observable; pure phase query. |
| Returns | non-zero iff `current_phase() == Phase::Running`; zero otherwise (including on `NULL` core). |
| Concurrency | lock-free read. |

#### `gn_core_reload_config_json`

| Property | Specification |
|---|---|
| Producer | kernel |
| Effect | Re-parses `json_str`, validates it, and applies the new config atomically. On failure the previous config remains active — no partially-applied state is observable. After a successful reload the kernel publishes on `GN_SUBSCRIBE_CONFIG_RELOAD` per `conn-events.md` §3. |
| Parameters | `json_str` — `@borrowed` NUL-terminated UTF-8 JSON; copied internally before return. |
| Returns | `GN_OK` on success; `GN_ERR_NULL_ARG` on either NULL; the kernel's parse / validate error code on bad input. |
| Concurrency | thread-safe; concurrent reloads serialise. |

### 3.2 Configuration & limits

#### `gn_core_limits`

| Property | Specification |
|---|---|
| Producer | kernel |
| Effect | none observable; returns a pointer to the kernel's live limits struct. |
| Returns | `@borrowed const gn_limits_t*`; lifetime tied to `core`. `NULL` on `NULL` core. |
| Concurrency | safe from any thread; the underlying struct is read-only after `gn_core_init`. |
| Ownership | kernel-owned; the host **MUST NOT** free. |

#### `gn_core_set_limits`

| Property | Specification |
|---|---|
| Producer | kernel |
| Effect | Copies the limits struct into the kernel. The input pointer is not retained. |
| Parameters | `limits` — `@borrowed`; **MUST** be zero-initialised per `abi-evolution.md` §4. |
| Returns | `GN_OK` on success; `GN_ERR_NULL_ARG` on either NULL; `GN_ERR_INVALID_STATE` after `gn_core_init` has returned `GN_OK`. |
| Concurrency | bootstrap-only; the host calls it before `gn_core_init` returns. |

### 3.3 Identity

#### `gn_core_get_pubkey`

| Property | Specification |
|---|---|
| Producer | kernel |
| Effect | Copies the local node's Ed25519 device public key into the caller's buffer. |
| Parameters | `out_pk` — `@in-out` 32-byte caller-allocated buffer (`GN_PUBLIC_KEY_BYTES`). |
| Returns | `GN_OK` on success; `GN_ERR_NULL_ARG` on either NULL; `GN_ERR_INVALID_STATE` when called before `gn_core_init` has returned `GN_OK`. |
| Concurrency | safe from any thread. |
| Ownership | caller owns `out_pk`. |

### 3.4 Network

#### `gn_core_connect`

| Property | Specification |
|---|---|
| Producer | kernel |
| Effect | Resolves the `gn.link.<scheme>` extension and calls `connect(uri, &out_conn)` on its `gn_link_api_t` vtable. The kernel writes the freshly-allocated `gn_conn_id_t` to `*out_conn` on success and `GN_INVALID_ID` on entry. |
| Parameters | `uri` — `@borrowed` for the duration of the call. `scheme` — `@borrowed`; pass `NULL` (or empty string) to derive from the `<scheme>://` URI prefix. `out_conn` — `@in-out`. |
| Returns | `GN_OK` on success; `GN_ERR_NULL_ARG` on `core`/`uri`/`out_conn` NULL; `GN_ERR_NOT_FOUND` when the URI has no `://` separator and no explicit scheme was given, or when no link is registered for the resolved scheme; `GN_ERR_INVALID_ENVELOPE` when the resolved scheme overflows the internal name buffer (64 bytes); the link plugin's own error code on transport-level failure. |
| Concurrency | safe from any thread once `gn_core_init` has returned `GN_OK`. |
| Ownership | the kernel owns the new connection record; the link plugin's `disconnect` slot is the teardown path. |

#### `gn_core_send_to`

| Property | Specification |
|---|---|
| Producer | kernel |
| Effect | Frames the payload through the active protocol layer, encrypts through the bound security session, and hands the bytes to the link plugin's `send`. Equivalent to a plugin-side `host_api->send(...)`. |
| Parameters | `payload` — `@borrowed` for the duration of the call; `payload_size > 0` requires non-NULL `payload`. |
| Returns | `GN_OK` on success; `GN_ERR_NULL_ARG` on NULL `core`, or `payload == NULL && payload_size > 0`; `GN_ERR_NOT_IMPLEMENTED` when the embedded host_api has no `send` slot bound; otherwise the host_api `send` slot's return verbatim (backpressure, `GN_ERR_NOT_FOUND` when `conn` is unknown, link plugin's transport error). |
| Concurrency | safe from any thread. |

#### `gn_core_broadcast`

| Property | Specification |
|---|---|
| Producer | kernel |
| Effect | Walks every live connection record under the connection registry's per-shard read locks and invokes `gn_core_send_to` for each. Best-effort by contract — failures on individual connections do not stop the walk. |
| Parameters | `payload` — `@borrowed` for the duration of the call. |
| Returns | `void`; per-connection failures are not surfaced to the caller. |
| Concurrency | safe from any thread; the registry walk holds read locks for the duration of the iteration. |

#### `gn_core_disconnect`

| Property | Specification |
|---|---|
| Producer | kernel |
| Effect | Tears `conn` down through the owning link plugin's `disconnect` slot. The kernel publishes `DISCONNECTED` per `conn-events.md` §2a synchronously before this call returns. |
| Returns | `GN_OK` on success; `GN_ERR_NULL_ARG` on NULL `core`; `GN_ERR_NOT_IMPLEMENTED` when the embedded host_api has no `disconnect` slot bound; otherwise the host_api `disconnect` slot's return verbatim (`GN_ERR_NOT_FOUND` on unknown `conn`). |
| Concurrency | safe from any thread. |

### 3.5 Stats / introspection

#### `gn_core_get_stats`

| Property | Specification |
|---|---|
| Producer | kernel |
| Effect | Snapshots the aggregate counters into `*out`. The walk reads each connection record under its shard read lock, summing `bytes_in`, `bytes_out`, `frames_in`, `frames_out`. Reads are not coordinated; concurrent traffic may bump counters between field-by-field reads. |
| Parameters | `out` — `@in-out` caller-allocated; **MUST** be zero-initialised on first call (the kernel rejects non-NULL `_reserved` slots with `GN_ERR_INVALID_ENVELOPE` per `abi-evolution.md` §4). |
| Returns | `GN_OK` on success; `GN_ERR_NULL_ARG` on either NULL; `GN_ERR_INVALID_ENVELOPE` when any `_reserved` slot is non-NULL on entry. |
| Concurrency | safe from any thread. Per-frame consistency is bounded by the kernel's atomic counter granularity. |
| Ownership | caller owns `out`. The kernel does not retain the buffer. |

See §4 for the field-by-field pin on `gn_stats_t`.

#### `gn_core_connection_count` / `gn_core_handler_count` / `gn_core_link_count`

| Property | Specification |
|---|---|
| Producer | kernel |
| Effect | none observable; pure registry-size query. |
| Returns | `size_t` count; zero on `NULL` core. |
| Concurrency | lock-free atomic load against the registry's size counter. |

### 3.6 Subscriptions

#### `gn_core_subscribe`

| Property | Specification |
|---|---|
| Producer | kernel |
| Effect | Registers a `gn_message_cb_t` for every inbound envelope whose `msg_id` matches. The kernel installs an internal handler vtable under `(protocol_id = "gnet-v1", msg_id, priority = 128)` and bridges its dispatch to the callback. |
| Parameters | `cb` — `@borrowed` function pointer; the kernel keeps it alive until `gn_core_unsubscribe` (or `gn_core_destroy`) returns. `user_data` — `@borrowed` under the same lifetime; pass-through to every callback. |
| Returns | non-zero subscription token on success; `0` on NULL `core`/`cb`, on registry rejection, or when the handler registry returns `GN_INVALID_ID`. |
| Concurrency | safe from any thread. Callbacks fire on the kernel's dispatch thread; the callback **MUST NOT** block. |
| Ownership | kernel owns the registration; the host releases it through `gn_core_unsubscribe` or implicitly through `gn_core_destroy`. |

#### `gn_core_unsubscribe`

| Property | Specification |
|---|---|
| Producer | kernel |
| Effect | Cancels a message subscription by token. The kernel unregisters the bridging handler **after** releasing the handle's subs mutex, so a callback already in flight does not deadlock against the registry's retire path. |
| Returns | `void`. |
| Concurrency | safe from any thread. No-op on unknown token, on `0`, or on NULL `core`. |

#### `gn_core_on_conn_state`

| Property | Specification |
|---|---|
| Producer | kernel |
| Effect | Subscribes to the `CONNECTED` / `DISCONNECTED` / `TRUST_UPGRADED` / `BACKPRESSURE_*` channel per `conn-events.md` §2. The kernel translates each kernel-internal `ConnEvent` into a `gn_conn_event_t` payload before invoking the C callback. |
| Parameters | `cb` — `@borrowed`; lifetime as in `gn_core_subscribe`. |
| Returns | non-zero token on success; `0` on NULL `core`/`cb`. |
| Concurrency | safe from any thread. Callbacks fire synchronously on the publishing thread per `conn-events.md` §2a. |

#### `gn_core_off_conn_state`

| Property | Specification |
|---|---|
| Producer | kernel |
| Effect | Cancels a connection-event subscription by token. |
| Returns | `void`. No-op on unknown token, on `0`, or on NULL `core`. |
| Concurrency | safe from any thread. |

See §5 for the token semantics shared by both subscription families.

### 3.7 Plugin lifecycle

#### `gn_core_load_plugin`

| Property | Specification |
|---|---|
| Producer | kernel |
| Effect | Pins the embedded plugin manager into production mode (`set_manifest_required(true)`), installs a single-entry manifest `(so_path → expected_sha256)`, and calls `PluginManager::load`. The loader runs the per-plugin sequence from `plugin-manifest.md` §4 (integrity check before `dlopen`, `RESOLVE_NO_SYMLINKS \| RESOLVE_NO_MAGICLINKS` symlink defence on Linux 5.6+) and the two-phase activation from `plugin-lifetime.md` §5. |
| Parameters | `so_path` — `@borrowed` path to the .so; resolved relative to the kernel's working directory. `expected_sha256` — `@borrowed` 32-byte SHA-256 digest. |
| Returns | `GN_OK` on success; `GN_ERR_NULL_ARG` on any NULL; `GN_ERR_INTEGRITY_FAILED` on hash mismatch / unreadable file / manifest rejection; `GN_ERR_VERSION_MISMATCH` on SDK major-version drift; `GN_ERR_LIMIT_REACHED` when the manager is already active or the load would exceed `gn_limits_t::max_plugins`; the plugin's own init error code on setup failure. |
| Concurrency | bootstrap-only; the kernel rejects a second load while the manager is active. |
| Ownership | kernel owns the loaded shared object until `gn_core_destroy` (the manager's `shutdown` runs as part of teardown). |

See §4 for the plugin-load discipline this entry honours end-to-end.

#### `gn_core_unload_plugin`

| Property | Specification |
|---|---|
| Producer | kernel |
| Effect | Per-name unload through the plugin manager. |
| Parameters | `name` — `@borrowed` plugin name as registered in its descriptor. |
| Returns | `GN_ERR_NULL_ARG` on either NULL; otherwise `GN_ERR_NOT_IMPLEMENTED`. The plugin manager today exposes only full-teardown `shutdown()`; per-name unload is reserved for v1.x. Hosts that need full teardown go through `gn_core_destroy` + a fresh `gn_core_create`. |
| Concurrency | safe from any thread. |

### 3.8 Provider registration

These entries inject an in-process vtable without going through
`dlopen`. They cover the same registry the corresponding plugin-side
`host_api->register_*` slots cover.

#### `gn_core_register_security`

| Property | Specification |
|---|---|
| Producer | kernel |
| Effect | Registers an in-process security provider vtable. Equivalent to `host_api->register_security(meta->name, vtable, self)`. |
| Parameters | `meta` — `@borrowed`; **MUST** be zero-initialised per `abi-evolution.md` §4; `meta->name` doubles as the provider id. `vtable` — `@borrowed` for the lifetime of the registration. `self` — `@borrowed` provider-side state pointer. |
| Returns | `GN_OK` on success; `GN_ERR_NULL_ARG` on any NULL or NULL `meta->name`; `GN_ERR_NOT_IMPLEMENTED` when the embedded host_api has no `register_security` slot bound. |
| Concurrency | safe from any thread. |

#### `gn_core_register_protocol`

| Property | Specification |
|---|---|
| Producer | kernel |
| Effect | Registers an in-process protocol-layer vtable, overriding the default `gnet-v1` layer the kernel statically links during `gn_core_init`. Equivalent to assigning `kernel->set_protocol_layer(...)` from the C++ side. |
| Parameters | `vtable` — `@borrowed` for the lifetime of the registration; carries the framer / deframer entries per `protocol-layer.md` §2. `self` — `@borrowed` provider-side state. |
| Returns | `GN_OK` on success; `GN_ERR_NULL_ARG` when either pointer is NULL or the kernel has no embedded protocol-layer slot. |
| Concurrency | safe from any thread; one provider per kernel — re-registering replaces the incumbent. |
| Ordering | Call before `gn_core_init` in hosts that need a non-default layer; calling after `init` swaps the layer mid-run, which is supported but breaks any in-flight conn that already framed bytes through the old layer. |

#### `gn_core_register_handler`

| Property | Specification |
|---|---|
| Producer | kernel |
| Effect | Registers an in-process handler vtable. Equivalent to `host_api->register_vtable(GN_REGISTER_HANDLER, meta, vtable, self, &out_id)`. |
| Parameters | `meta` — `@borrowed`; per-handler shape from `sdk/types.h` (`name = protocol_id`, meaningful `msg_id`, meaningful `priority`). `vtable` — `@borrowed`. `self` — `@borrowed` handler-side state. |
| Returns | non-zero `gn_handler_id_t` on success; `GN_INVALID_HANDLER_ID` on NULL or registry rejection. |
| Concurrency | safe from any thread. The returned id encodes the kind tag in its top bits per `host-api.md` §2. |

#### `gn_core_register_link`

| Property | Specification |
|---|---|
| Producer | kernel |
| Effect | Registers an in-process link vtable. Equivalent to `host_api->register_vtable(GN_REGISTER_LINK, meta, vtable, self, &out_id)`. |
| Parameters | `meta` — `@borrowed`; per-link shape from `sdk/types.h` (`name = URI scheme`, `msg_id`/`priority` zeroed). `vtable` — `@borrowed`. |
| Returns | non-zero `gn_link_id_t` on success; `GN_INVALID_LINK_ID` on NULL or registry rejection. |
| Concurrency | safe from any thread. |

### 3.9 Extensions

GoodNet exposes a single typeless extension surface; bindings build
their typed accessors on top in their own language. No per-extension
typed C function lives in `sdk/core.h`, so adding a new extension
never bumps this surface's ABI.

#### `gn_core_query_extension_checked`

| Property | Specification |
|---|---|
| Producer | kernel |
| Effect | Versioned vtable lookup against the kernel's `ExtensionRegistry`. The kernel routes the call into the embedded `host_api->query_extension_checked` slot. |
| Parameters | `name` — `@borrowed` extension name. `required_version` — minimum producer version the consumer accepts. |
| Returns | `@borrowed const void*` vtable on success; `NULL` when the extension is missing, the registered version is older than `required_version`, the host_api slot is unbound, or either argument is NULL. Lifetime is tied to the providing plugin per `plugin-lifetime.md` §4. |
| Concurrency | safe from any thread. |
| Ownership | kernel-owned; the host **MUST NOT** free. |

#### `gn_core_register_extension`

| Property | Specification |
|---|---|
| Producer | kernel |
| Effect | Registers an extension vtable under `name`. Equivalent to `host_api->register_extension(name, version, vtable)`. |
| Parameters | `vtable` — `@borrowed` for the lifetime of the registration. |
| Returns | `GN_OK` on success; `GN_ERR_NULL_ARG` on any NULL; `GN_ERR_NOT_IMPLEMENTED` when the embedded host_api has no `register_extension` slot bound; otherwise the slot's return verbatim. |
| Concurrency | safe from any thread. |

#### `gn_core_unregister_extension`

| Property | Specification |
|---|---|
| Producer | kernel |
| Effect | Cancels an extension registration by name. |
| Returns | `GN_OK` on success; `GN_ERR_NULL_ARG` on either NULL; `GN_ERR_NOT_IMPLEMENTED` when the embedded host_api has no `unregister_extension` slot bound; otherwise the slot's return verbatim. |
| Concurrency | safe from any thread. |

### 3.10 host_api accessor

#### `gn_core_host_api`

| Property | Specification |
|---|---|
| Producer | kernel |
| Effect | Returns a pointer to the `host_api_t` table the embedded kernel built for the host. The host uses it to drive a slot that has no `gn_core_*` mirror — timers, posted tasks, structured logging at a custom level, foreign-payload injection. |
| Returns | `@borrowed const host_api_t*`; lifetime tied to `core`. `NULL` on NULL core. |
| Concurrency | safe from any thread. The returned table itself is reentrant per `host-api.md` §3. |
| Ownership | kernel-owned; the host **MUST NOT** free. |

### 3.11 Versioning

#### `gn_version`

| Property | Specification |
|---|---|
| Producer | kernel |
| Effect | none observable. |
| Returns | `@borrowed const char*` to a NUL-terminated static string ("1.0.0-dev" pre-RC, "1.0.0-rc1"+ thereafter). Lifetime is the loaded shared object. |
| Concurrency | safe from any thread. |

#### `gn_version_packed`

| Property | Specification |
|---|---|
| Producer | kernel |
| Effect | none observable. |
| Returns | `(GN_SDK_VERSION_MAJOR << 16) | (GN_SDK_VERSION_MINOR << 8) | GN_SDK_VERSION_PATCH` — the same triple `gn_plugin_sdk_version` exports, packed for cheap comparison. |
| Concurrency | safe from any thread. |

See §6 for the compatibility rule the host applies to the result.

---

## 4. Caller-allocated structs

`gn_stats_t` is the only value struct introduced by `sdk/core.h`.
The shared zero-init contract from `host-api.md` §2 + `abi-evolution.md`
§4 applies in full; this section pins the slot layout.

```c
typedef struct gn_stats_s {
    uint64_t connections_active;       /* live entries in ConnectionRegistry */
    uint64_t handlers_registered;      /* live entries in HandlerRegistry    */
    uint64_t links_registered;         /* live entries in LinkRegistry       */
    uint64_t extensions_registered;    /* live entries in ExtensionRegistry  */
    uint64_t bytes_in;                 /* sum of per-conn bytes_in           */
    uint64_t bytes_out;                /* sum of per-conn bytes_out          */
    uint64_t frames_in;                /* sum of per-conn frames_in          */
    uint64_t frames_out;               /* sum of per-conn frames_out         */
    uint64_t plugin_dlclose_leaks;     /* PluginManager::leaked_handles()    */
    void*    _reserved[4];             /* MUST be NULL on entry              */
} gn_stats_t;
```

| Field | Source | Semantics |
|---|---|---|
| `connections_active` | `ConnectionRegistry::size()` | live records |
| `handlers_registered` | `HandlerRegistry::size()` | live registrations |
| `links_registered` | `LinkRegistry::size()` | live registrations |
| `extensions_registered` | `ExtensionRegistry::size()` | live registrations |
| `bytes_in` | sum over `for_each` | snapshot total |
| `bytes_out` | sum over `for_each` | snapshot total |
| `frames_in` | sum over `for_each` | snapshot total |
| `frames_out` | sum over `for_each` | snapshot total |
| `plugin_dlclose_leaks` | `PluginManager::leaked_handles()` | tracks the `plugin.leak.dlclose_skipped` counter from `plugin-lifetime.md` §4 |
| `_reserved[4]` | reserved | **MUST** be NULL on every call |

Zero-init contract: the host either value-inits the struct (`gn_stats_t s = {0};`)
or `memset`s it to zero before calling `gn_core_get_stats`. Per
`abi-evolution.md` §4, partially-initialised reserved bytes carry stack
garbage that breaks the kernel's contiguous-range reads. The kernel
asserts on entry: any non-NULL `_reserved[i]` returns
`GN_ERR_INVALID_ENVELOPE` before any field is written, leaving
`*out` untouched in the failed slot.

Future fields are added by **promoting** a `_reserved` slot per
`abi-evolution.md` §4 (the slot becomes a named field, the array
shrinks by one, the struct's byte length stays constant).

---

## 5. Plugin-load discipline

`gn_core_load_plugin` is the one path a non-C++ host uses to bring a
plugin into the embedded kernel. The discipline it honours:

1. **Manifest SHA-256 is mandatory.** The host passes a 32-byte
   digest the operator computed at distribution time. The loader
   refuses every byte mismatch with `GN_ERR_INTEGRITY_FAILED` per
   `plugin-manifest.md` §6.
2. **Production mode is forced.** `gn_core_load_plugin` calls
   `set_manifest_required(true)` before the load runs. There is no
   developer-mode escape on this surface — every embedded host load
   produces a single-entry manifest that the loader consults before
   `dlopen`.
3. **Symlink defence.** On Linux 5.6+ the loader uses
   `openat2(AT_FDCWD, path, RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS)`
   to refuse every symlink along the path and every magic-link such
   as `/proc/self/fd/N` per `plugin-manifest.md` §4.1. Older kernels
   fall back to `O_NOFOLLOW` on the leaf component only. Hash and
   load operate on the same descriptor so a swap between the two
   cannot route the loader to a different inode.
4. **Hash before `dlopen`.** Static initialisers in a tampered
   binary are arbitrary code; the integrity check runs **before**
   the binary maps so a hostile constructor never executes.
5. **`dlopen(RTLD_NOW | RTLD_LOCAL)`.** `RTLD_NOW` resolves every
   symbol at load time so a missing dependency surfaces immediately
   rather than at first call. `RTLD_LOCAL` keeps the plugin's symbol
   table out of the global namespace so two plugins with overlapping
   internal names do not collide.
6. **5+1 entry symbols.** The loader drives the C entry symbols
   from `plugin-lifetime.md` §3 in order:
   `gn_plugin_sdk_version`, `gn_plugin_init`, `gn_plugin_register`,
   plus `gn_plugin_descriptor` (optional) on the way up;
   `gn_plugin_unregister`, `gn_plugin_shutdown` on the way down.
7. **Two-phase activation.** `init_all` runs across every loaded
   plugin before any `register_all` runs, so a partial init failure
   tears down the partial set without exposing handlers/links to
   live traffic per `plugin-lifetime.md` §5.

On hash mismatch the loader returns `GN_ERR_INTEGRITY_FAILED` and
no `dlopen` runs; the kernel state is untouched. On any later
phase failure the plugin manager runs the documented rollback
(`plugin-lifetime.md` §5 — `rollback_register` falls through to
`rollback_init`) so partial state never survives.

---

## 6. Subscription token semantics

`gn_core_subscribe` and `gn_core_on_conn_state` both return an opaque
`uint64_t` token. The token is:

- **Monotonic.** Allocated from a per-handle `next_token` atomic
  counter that starts at `1` and increments on every subscribe call
  across both families. Wraparound at 2^64 is structurally
  impossible across realistic process runtimes.
- **Not channel-tagged.** A token does not encode which family it
  belongs to. The host **MUST** pair `gn_core_subscribe` tokens
  with `gn_core_unsubscribe` and `gn_core_on_conn_state` tokens
  with `gn_core_off_conn_state` — passing a message-subscription
  token to `off_conn_state` (or vice versa) is a no-op, not an
  error, and the original subscription stays live.
- **Opaque.** The host **MUST NOT** interpret bits, compare for
  ordering, or use the token as a map key beyond identity equality.
- **Lifetime tied to the handle.** Tokens are scoped to the
  `gn_core_t*` that produced them. `gn_core_destroy` releases every
  outstanding subscription — the host's `unsubscribe`/`off_conn_state`
  calls on a destroyed handle are undefined behaviour, the same as
  any other access on a freed handle.

`0` is reserved as the failure sentinel; both subscribe entries
return `0` on any failure (NULL arg, registry rejection, OOM).
`gn_core_unsubscribe(core, 0)` and `gn_core_off_conn_state(core, 0)`
are no-ops.

The token remains valid through the kernel's full FSM range: a
subscription installed in `Ready` keeps firing through `Running`,
and the cancel call is legal up to (but not including)
`gn_core_destroy`.

---

## 7. Versioning

The kernel exposes its version twice: a human-readable string and a
packed integer.

```c
const char* gn_version(void);          /* "1.0.0-dev", "1.0.0-rc1", … */
uint32_t    gn_version_packed(void);   /* (MAJOR << 16) | (MINOR << 8) | PATCH */
```

The packed form is the comparable representation. The host computes
a compatibility decision through the same triple every plugin reports
through `gn_plugin_sdk_version`:

- **MAJOR** — incompatible. A host built against a different MAJOR
  rebuilds.
- **MINOR** — additive. A host built against `kernel.minor` keeps
  working at higher kernel minors. Slots appended at the tail
  (size-prefix-protected per `abi-evolution.md` §3) are gated by the
  host's compile-time view of the table.
- **PATCH** — non-binary. Documentation and comment changes only.

Hosts that wrap `sdk/core.h` in a binding library bake the
build-time triple into their wrapper and run the same
`major == kernel.major && kernel.minor >= host.minor` rule the
plugin manager runs at `gn_core_load_plugin` time. A mismatch is the
binding's responsibility to surface — the C ABI does not gate calls
on the host's compile-time view.

The string form is for log lines and operator UI; the host **MUST
NOT** parse it for compatibility decisions.

The pre-RC reshape window from `abi-evolution.md` §3b applies to
this surface: until `v1.0.0-rc1` is tagged the entries below may be
removed, renamed, or reordered without a major bump. The window
closes on the day the tag lands; from then on every rule in §3 of
`abi-evolution.md` applies without exception.

---

## 8. Cross-references

- Plugin-side surface (the inverse direction): `host-api.md`.
- Evolution rules and `_reserved` discipline: `abi-evolution.md`.
- Plugin entry symbols and two-phase activation: `plugin-lifetime.md`.
- Manifest format and verification ordering: `plugin-manifest.md`.
- FSM phase enumeration: `fsm-events.md` §2 +
  `core/kernel/phase.hpp`.
- `gn_conn_event_t` payload and the `BACKPRESSURE_*` rules:
  `conn-events.md`.
- `gn_message_t` envelope shape (referenced by `gn_message_cb_t`
  payload pointer): `protocol-layer.md`.
- Error-code semantics (`GN_ERR_NOT_FOUND` vs `GN_ERR_UNKNOWN_RECEIVER`,
  `GN_ERR_OUT_OF_RANGE`, etc.): `sdk/types.h`.
