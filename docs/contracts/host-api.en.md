# Contract: Host API

**Status:** active · v1
**Owner:** `core/kernel`, every plugin
**Implements:** size-prefix evolution per `abi-evolution.md`
**Last verified:** 2026-05-08
**Stability:** stable for v1.x; new entries appended at the tail.

---

## 1. Purpose

Plugins drive the kernel through one C ABI table: `host_api_t`. Every
operation a plugin can request — sending a message, looking up a peer,
querying an extension, registering a handler — goes through one of its
function pointers. The table is handed to the plugin once at init time
and remains live for the plugin's lifetime.

Two distinct vtables exist:

| Table | Audience | When passed |
|---|---|---|
| `host_api_t` | every plugin | once, on `gn_plugin_init` |
| `host_loader_api_t` | kernel-internal `PluginManager` only | never crosses the plugin boundary |

A plugin **cannot** see `host_loader_api_t`. The split is structural;
loader entries (such as `_create_plugin_ctx`) are not even declared in
public headers.

---

## 2. `host_api_t` structure

The full struct lives in `sdk/host_api.h`; this section names every
slot in declaration order so plugin authors can write against the
same surface without grepping the header.

```c
typedef struct host_api_s {
    uint32_t api_size;             /* sizeof(host_api_t) at build time */
    void*    host_ctx;             /* opaque, passed back unchanged */

    /* ── Messaging ───────────────────────────────────────────────────── */
    gn_result_t (*send)(void* host_ctx, gn_conn_id_t conn,
                        uint32_t msg_id,
                        const uint8_t* payload, size_t payload_size);

    gn_result_t (*disconnect)(void* host_ctx, gn_conn_id_t conn);

    /* ── Universal handler / link registration ─────────────────────── */
    /* `kind` selects the family; `meta` carries the per-family fields */
    /* (handler: name=protocol_id + msg_id + priority; link: name=URI  */
    /* scheme). The id encodes the kind in its top 4 bits so           */
    /* `unregister_vtable(id)` routes back to the right registry       */
    /* without naming the kind a second time.                          */
    gn_result_t (*register_vtable)(void* host_ctx,
                                    gn_register_kind_t kind,
                                    const gn_register_meta_t* meta,
                                    const void* vtable,
                                    void* self,
                                    uint64_t* out_id);

    gn_result_t (*unregister_vtable)(void* host_ctx, uint64_t id);

    /* ── Registry queries ────────────────────────────────────────────── */
    gn_result_t (*find_conn_by_pk)(void* host_ctx,
                                   const uint8_t pk[GN_PUBLIC_KEY_BYTES],
                                   gn_conn_id_t* out_conn);

    gn_result_t (*get_endpoint)(void* host_ctx, gn_conn_id_t conn,
                                gn_endpoint_t* out);

    /* ── Extension API ───────────────────────────────────────────────── */
    gn_result_t (*query_extension_checked)(void* host_ctx,
                                           const char* name,
                                           uint32_t version,
                                           const void** out_vtable);

    gn_result_t (*register_extension)(void* host_ctx, const char* name,
                                      uint32_t version,
                                      const void* vtable);

    gn_result_t (*unregister_extension)(void* host_ctx, const char* name);

    /* ── Configuration ───────────────────────────────────────────────── */
    /* `out_user_data` and `out_free` form a paired destructor handle  */
    /* the kernel hands back on STRING reads — out_free is invoked   */
    /* with `(out_user_data, returned_bytes)` to release the buffer  */
    /* the kernel allocated. Two pointers because the destructor may */
    /* need state (e.g. a buffer pool ticket) beyond the bytes alone */
    /* and FFI bindings cannot carry that state through closures.    */
    gn_result_t (*config_get)(void* host_ctx,
                              const char* key,
                              gn_config_value_type_t type,
                              size_t index,
                              void* out_value,
                              void** out_user_data,
                              void (**out_free)(void* user_data, void* bytes));

    /* ── Limits ──────────────────────────────────────────────────────── */
    /* Read-only borrow valid for the plugin's lifetime; see limits.md. */
    const gn_limits_t* (*limits)(void* host_ctx);

    /* ── Logging (sdk/log.h, host-api.md §11) ────────────────────── */
    /* Substruct rather than a single function pointer so the kernel  */
    /* can grow the logging surface (level fast-path, source-loc      */
    /* prefix, key-value records) without rewriting the host_api      */
    /* shape on every step. The first field of `gn_log_api_t` is its  */
    /* own `api_size`; consumers gate access to entries beyond their  */
    /* compile-time view through `GN_API_HAS(&api->log, slot)` from   */
    /* `sdk/abi.h`.                                                    */
    gn_log_api_t log;

    /* ── Transport-side notifications ────────────────────────────────── */
    /* `trust` and `role` are computed by the transport per             */
    /* `link.md` §3 and §3a; the kernel forwards both into the     */
    /* security session.                                                 */
    gn_result_t (*notify_connect)(void* host_ctx,
                                  const uint8_t remote_pk[GN_PUBLIC_KEY_BYTES],
                                  const char* uri,
                                  gn_trust_class_t trust,
                                  gn_handshake_role_t role,
                                  gn_conn_id_t* out_conn);

    /* Stream-class transports (TCP, IPC, TLS-over-TCP) deliver any   */
    /* chunk size — a single call may cross zero, one, or many        */
    /* security-frame boundaries. The kernel buffers partial bytes on */
    /* the per-conn security session (`backpressure.md` §9) and fires */
    /* the protocol layer once per complete frame; the transport      */
    /* keeps no per-call assumption about byte-to-frame correspondence. */
    gn_result_t (*notify_inbound_bytes)(void* host_ctx, gn_conn_id_t conn,
                                        const uint8_t* bytes, size_t size);

    gn_result_t (*notify_disconnect)(void* host_ctx, gn_conn_id_t conn,
                                     gn_result_t reason);

    /* ── Security registration ───────────────────────────────────────── */
    /* v1 admits at most one active provider per kernel; a second       */
    /* register_security call returns GN_ERR_LIMIT_REACHED. The         */
    /* incumbent stays active. Multi-provider per-trust-class selection  */
    /* lands with StackRegistry in v1.x. See `security-trust.md` §6.    */
    gn_result_t (*register_security)(
        void* host_ctx, const char* provider_id,
        const struct gn_security_provider_vtable_s* vtable,
        void* security_self);

    gn_result_t (*unregister_security)(void* host_ctx,
                                       const char* provider_id);

    /* ── Foreign-payload injection (see §8) ──────────────────────────── */
    gn_result_t (*inject)(void* host_ctx,
                          gn_inject_layer_t layer,
                          gn_conn_id_t source,
                          uint32_t msg_id,
                          const uint8_t* bytes,
                          size_t size);

    /* ── Handshake driver ────────────────────────────────────────────── */
    /* Initiator's first wire message is deferred from notify_connect    */
    /* to a separate kick so the transport can register its socket       */
    /* under the freshly-allocated conn_id before bytes ride out. The    */
    /* transport calls kick_handshake once that registration is done.    */
    gn_result_t (*kick_handshake)(void* host_ctx, gn_conn_id_t conn);

    /* ── Service executor (timer.md is the authoritative spec) ──────── */
    gn_result_t (*set_timer)(void* host_ctx,
                             uint32_t delay_ms,
                             gn_task_fn_t fn,
                             void* user_data,
                             gn_timer_id_t* out_id);
    gn_result_t (*cancel_timer)(void* host_ctx, gn_timer_id_t id);

    /* ── Channel subscription (conn-events.md / config.md) ──────────── */
    /* Two typed slots — one per channel — instead of a single        */
    /* `subscribe(channel, ...)` dispatcher: the kernel knows the     */
    /* payload shape per channel and the binding never has to type-  */
    /* erase. `ud_destroy` runs once with `user_data` when the        */
    /* subscription is removed, whether by `unsubscribe(id)` or by   */
    /* the kernel observing the plugin's lifetime anchor expire.     */
    /* Pass `NULL` when `user_data` carries no resources to free.    */
    gn_result_t (*subscribe_conn_state)(void* host_ctx,
                                         gn_conn_state_cb_t cb,
                                         void* user_data,
                                         void (*ud_destroy)(void*),
                                         gn_subscription_id_t* out_id);

    gn_result_t (*subscribe_config_reload)(void* host_ctx,
                                            gn_config_reload_cb_t cb,
                                            void* user_data,
                                            void (*ud_destroy)(void*),
                                            gn_subscription_id_t* out_id);

    /* `unsubscribe` is shared across both channels; the id is unique  */
    /* across them and the kernel routes the cancel internally.        */
    gn_result_t (*unsubscribe)(void* host_ctx,
                                gn_subscription_id_t id);

    gn_result_t (*for_each_connection)(void* host_ctx,
                                       gn_conn_visitor_t visitor,
                                       void* user_data);

    /* ── Backpressure publisher (backpressure.md §3) ────────────────── */
    /* Transport-only slot: the kernel routes the call into the         */
    /* connection-event channel as `BACKPRESSURE_SOFT` /                 */
    /* `BACKPRESSURE_CLEAR`. `kind` is the raw event constant from      */
    /* `sdk/conn_events.h`; `bytes` carries the current `bytes_buffered` */
    /* on the transport's write queue.                                   */
    gn_result_t (*notify_backpressure)(void* host_ctx, gn_conn_id_t conn,
                                       gn_conn_event_kind_t kind,
                                       uint64_t bytes);

    /* ── Metrics (metrics.md) ───────────────────────────────────────── */
    /* The kernel store is a flat map of monotonic UTF-8-named 64-bit  */
    /* counters. Plugins emit cross-cutting telemetry (relay forwards, */
    /* cache hits, retries) through `emit_counter` rather than spinning */
    /* up their own metrics infrastructure; an out-of-tree exporter    */
    /* plugin walks the merged set through `iterate_counters` and       */
    /* serves whatever wire format the operator picks. Counter names   */
    /* are convention-only — recommended pattern is                    */
    /* `<subsystem>.<event>.<reason>` (e.g. `relay.forward.ok`).        */
    void     (*emit_counter)(void* host_ctx, const char* name);
    uint64_t (*iterate_counters)(void* host_ctx,
                                  gn_counter_visitor_t visitor,
                                  void* user_data);

    /* ── Cooperative cancellation (plugin-lifetime.md §8) ──────────── */
    /* Non-zero once teardown for this plugin has begun. Plugins poll  */
    /* the slot from inside long-running async work and exit early so  */
    /* they drain ahead of the kernel's bounded wait.                  */
    int32_t (*is_shutdown_requested)(void* host_ctx);

    /* ── Identity primitives (identity.md §8) ──────────────────────── */
    /* The kernel holds private bytes for every key the local node    */
    /* uses; plugins drive registration, listing, deletion, and       */
    /* signing through opaque handles. A plugin never sees a          */
    /* private-key byte. `gn_key_purpose_t` and `gn_key_descriptor_t` */
    /* live in `sdk/identity.h`.                                       */
    gn_result_t (*register_local_key)(void* host_ctx,
                                       gn_key_purpose_t purpose,
                                       const char* label,
                                       gn_key_id_t* out_id);
    gn_result_t (*delete_local_key)(void* host_ctx, gn_key_id_t id);
    gn_result_t (*list_local_keys)(void* host_ctx,
                                    gn_key_descriptor_t* out_array,
                                    size_t array_cap,
                                    size_t* out_count);
    gn_result_t (*sign_local)(void* host_ctx,
                               gn_key_purpose_t purpose,
                               const uint8_t* payload, size_t size,
                               uint8_t out_sig[64]);
    gn_result_t (*sign_local_by_id)(void* host_ctx,
                                     gn_key_id_t id,
                                     const uint8_t* payload, size_t size,
                                     uint8_t out_sig[64]);

    /* ── Peer identity readers (identity.md §3, §6a) ────────────────── */
    /* After attestation pins a peer's user_pk + device_pk + handshake */
    /* hash against its mesh address, plugins read the components      */
    /* separately for user-level operations. Each slot returns         */
    /* GN_ERR_INVALID_STATE until attestation completes;               */
    /* GN_ERR_NOT_FOUND if the conn is not in the registry.            */
    gn_result_t (*get_peer_user_pk)(void* host_ctx,
                                     gn_conn_id_t conn,
                                     uint8_t out_pk[GN_PUBLIC_KEY_BYTES]);
    gn_result_t (*get_peer_device_pk)(void* host_ctx,
                                       gn_conn_id_t conn,
                                       uint8_t out_pk[GN_PUBLIC_KEY_BYTES]);
    gn_result_t (*get_handshake_hash)(void* host_ctx,
                                       gn_conn_id_t conn,
                                       uint8_t out_hash[GN_HASH_BYTES]);

    /* ── Capability TLV transport (capability-tlv.md) ────────────────── */
    /* Plugins ship identity-bearing blobs over the secured channel    */
    /* without minting a per-app msg_id. The kernel reserves `0x13`,   */
    /* prepends an 8-byte BE expires_unix_ts prefix, fans the bytes    */
    /* out to every subscriber on the receiver. Hard cap on blob      */
    /* size lives in gn_limits_t::max_capability_blob_bytes (default  */
    /* 16 KiB).                                                        */
    gn_result_t (*present_capability_blob)(void* host_ctx,
                                            gn_conn_id_t conn,
                                            const uint8_t* blob,
                                            size_t size,
                                            int64_t expires_unix_ts);
    gn_result_t (*subscribe_capability_blob)(void* host_ctx,
                                              gn_capability_blob_cb_t cb,
                                              void* user_data,
                                              void (*ud_destroy)(void*),
                                              gn_subscription_id_t* out_id);

    /* ── Identity rotation announce (identity.md §10) ────────────────── */
    /* Mints a fresh user keypair, bumps the rotation counter, signs  */
    /* a 150-byte RotationProof with the OLD user_pk, persists, then  */
    /* sends the proof on every live conn at trust >= Peer under     */
    /* msg_id 0x12. Receivers verify and advance their pin.            */
    gn_result_t (*announce_rotation)(void* host_ctx,
                                      int64_t valid_from_unix_ts);

    /* ── Reserved for future use ─────────────────────────────────────── */
    void* _reserved[8];
} host_api_t;
```

Plugins query a slot's presence through the size-prefix helpers in
`sdk/abi.h` before calling into a tail entry:

```c
if (GN_API_HAS(api, kick_handshake)) {
    api->kick_handshake(host_ctx, conn);
}
```

### 2.1 `config_get` — typed read with `(out_user_data, out_free)` pair

`config_get` reads one node out of the live config tree under a
runtime contract that bindings must respect verbatim:

- `out_value` shape is type-tagged. See `gn_config_value_type_t` in
  `sdk/types.h` for the per-type table (`int64_t*` / `int32_t*` /
  `double*` / `char**` / `size_t*`).
- `out_user_data` and `out_free` form a paired destructor handle —
  the kernel writes both on success of a `STRING` read. The plugin
  invokes `out_free(out_user_data, returned_bytes)` to release the
  buffer once it is done with the string. Both must be non-NULL for
  a `STRING` read; either one NULL returns `GN_ERR_NULL_ARG`.
- `out_user_data` and `out_free` are **forbidden** for non-`STRING`
  reads — passing either non-NULL on `INT64` / `BOOL` / `DOUBLE` /
  `ARRAY_SIZE` returns `GN_ERR_NULL_ARG`. The asymmetry keeps the
  destructor pointer's type unambiguous for FFI and prevents the
  "I always wired it just in case" pattern from leaving the pair
  dangling.
- `index` is `GN_CONFIG_NO_INDEX` for scalar reads; `INT64` and
  `STRING` accept a real array-element ordinal as well. Other
  types reject a real index with `GN_ERR_OUT_OF_RANGE`.
- An unknown `gn_config_value_type_t` enumerator returns
  `GN_ERR_INVALID_ENVELOPE` before any other validation runs.

| Condition | Result |
|---|---|
| `key == NULL` or `out_value == NULL` | `GN_ERR_NULL_ARG` |
| `STRING` read with either of `out_user_data` / `out_free` NULL, or non-`STRING` read with either non-NULL | `GN_ERR_NULL_ARG` |
| scalar read with `index != GN_CONFIG_NO_INDEX`, or array-element read with `index == GN_CONFIG_NO_INDEX` | `GN_ERR_OUT_OF_RANGE` |
| key not present in config | `GN_ERR_NOT_FOUND` |
| live value's parse type does not match `type` | `GN_ERR_INVALID_ENVELOPE` |
| `ARRAY_SIZE` query against a non-array key | `GN_ERR_INVALID_ENVELOPE` |
| `index` past array length | `GN_ERR_OUT_OF_RANGE` |
| unknown `type` enum value | `GN_ERR_INVALID_ENVELOPE` |

---

## 3. Lifetime of `host_api_t`

The kernel guarantees:

- `api` and every function pointer in it remain valid from
  `gn_plugin_init` return until `gn_plugin_shutdown` returns.
- Each individual entry is reentrant: a plugin may invoke any slot
  from any thread that owns a reference to `api`. The kernel does
  **not** serialise *across* slots — concurrent `send` and
  `register_vtable` from two threads each hold their own
  fine-grained lock and may interleave. Plugins that depend on a
  cross-slot ordering provide it themselves.
- `api->host_ctx` is opaque to the plugin; passed back unchanged.
- A plugin **must not** retain `api` past `gn_plugin_shutdown`. Posting
  a task that fires after shutdown and dereferences `api` would be a
  use-after-free.
- A slot's presence in `api_size` does **not** imply a non-null
  function pointer. Forward-looking entries that the current
  release does not fulfil are zero-initialised; consumers gate
  their call sites on `if (api->slot)` (or use the `GN_API_HAS`
  macro from `sdk/abi.h` which combines size-prefix presence with
  a null-pointer check).

Per `plugin-lifetime.md` §4, async tasks capture a weak observer of the
plugin's reference-counted handle and upgrade before using `api`.

`unregister_extension` is on `host_api_t` so plugins can withdraw
an entry without dragging the whole plugin through `gn_plugin_shutdown`
— for example, a plugin that re-registers an extension under a
different version while staying loaded calls `unregister_extension`
on the old name first. The kernel **also** auto-reaps a plugin's
extensions on shutdown via the lifetime-anchor drain
(`plugin-lifetime.md` §4), so a plugin that does not call
`unregister_extension` does not leak the entry — automatic reap is
the safety net, manual call is the explicit path.

---

## 4. What is **not** in `host_api_t`

These belong to `host_loader_api_t` (kernel-internal) and are never
reachable from a plugin:

- `_create_plugin_ctx` — kernel allocates the plugin context.
- `_load_so` / `_unload_so` — `dlopen` / `dlclose` orchestration.
- `_iterate_plugins` — kernel introspection over the plugin set.

A plugin that needs cross-plugin communication uses extensions
(`query_extension_checked`), not loader internals.

---

## 5. Error semantics

Every function pointer returns `gn_result_t`. Negative values are
errors; plugins **must** propagate or handle them. Silently dropping a
non-`GN_OK` return is a contract violation per `fsm-events.md` §4.

The kernel records every error in `metrics.host_api.<entry>.errors`
with the result code as label. This is the surface for production
alerting.

---

## 6. Forbidden inside plugin entries

Plugins **must not**:

- Block on synchronous `send` for tail responses. The kernel
  enqueues; the call returns immediately. Wait on the response
  handler.
- Call `register_*` from inside a `handle_message` dispatch. The
  handler registry is locked at that point — registration deadlocks.
  Plugins register all handlers in `gn_plugin_register`, not lazily.
- Issue calls to `api` from a thread other than the plugin's own
  io-context unless a slot is documented as cross-thread safe.

---

## 7. Cross-references

- Evolution rules: `abi-evolution.md` §3 (size-prefix), §4
  (`_reserved`).
- Init / shutdown ordering: `plugin-lifetime.md`.
- Handler registration semantics: `handler-registration.md`.
- Transport registration semantics: `link.md` §6.
- Error propagation requirements: `fsm-events.md` §4.

---

## 8. Foreign-payload injection

Bridge handlers connect external systems (MQTT, HTTP, OPC-UA, …) to
the mesh. The external system has no Ed25519 identity of its own; the
bridge — which does — re-publishes incoming foreign payloads under
its own identity through one entry tagged with the layer at which
the bytes enter the kernel:

```c
typedef enum gn_inject_layer_e {
    GN_INJECT_LAYER_MESSAGE = 0,
    GN_INJECT_LAYER_FRAME   = 1
} gn_inject_layer_t;

gn_result_t (*inject)(void* host_ctx,
                      gn_inject_layer_t layer,
                      gn_conn_id_t source,
                      uint32_t msg_id,
                      const uint8_t* bytes,
                      size_t size);
```

`GN_INJECT_LAYER_MESSAGE` builds an envelope `(sender_pk =
source.remote_pk, receiver_pk = local_identity, msg_id, bytes)` and
dispatches it through the router as if the bytes had arrived from
the source connection's link. `msg_id` must be non-zero; `size` is
bounded by `limits.max_payload_bytes`.

`GN_INJECT_LAYER_FRAME` accepts a fully formed wire-side frame, hands
it to the active protocol layer's `deframe`, and dispatches the
envelopes the deframer produces. `msg_id` is ignored; `size` is
bounded by `limits.max_frame_bytes`. Used by relay-style tunnels that
move opaque inner frames between mesh peers.

Both layers stamp `gn_message_t::conn_id = source` on every dispatched
envelope before the handler chain sees it. Conn-aware handlers
(heartbeat RTT, future per-link gates) read `env.conn_id` directly —
the bridge-source conn carries the edge identity that handlers use
for `send`/`disconnect` back at the foreign system. Producers that
synthesise envelopes outside `inject` and `notify_inbound_bytes`
leave `conn_id == GN_INVALID_ID`; per `handler-registration.md` §3a
handlers MUST tolerate that as `CONTINUE`, never `REJECT`.

Failure modes:

| Condition | Result |
|---|---|
| `source` does not refer to a known connection | `GN_ERR_NOT_FOUND` |
| `bytes == NULL && size > 0` (MESSAGE) or `bytes == NULL || size == 0` (FRAME) | `GN_ERR_NULL_ARG` |
| `size > limits.max_payload_bytes` (MESSAGE) or `size > limits.max_frame_bytes` (FRAME) | `GN_ERR_PAYLOAD_TOO_LARGE` |
| `msg_id == 0` (MESSAGE; envelope invariant per `protocol-layer.md` §2) | `GN_ERR_INVALID_ENVELOPE` |
| FRAME deframe yields no envelopes / partial input | `GN_ERR_DEFRAME_INCOMPLETE` |
| Rate budget exceeded for `source` | `GN_ERR_LIMIT_REACHED` |
| Unknown `layer` value | `GN_ERR_INVALID_ENVELOPE` |

Per-source rate limiting uses a token bucket sized at one hundred
messages per second with a burst of fifty by default; both layers
share the same bucket. The bucket key is the source connection's
`remote_pk`. The kernel creates buckets lazily; LRU eviction caps the
map at 4 096 entries so unbounded source-id growth cannot exhaust
memory.

A bridge plugin that re-publishes many foreign clients through one
source conn shares a single bucket. The kernel limit is the
**outer** guard against runaway inject; the per-source key is
`inject_rate_key(remote_pk)`, which takes the first 8 bytes of the
source conn's `remote_pk`. Bridges that fan in foreign-client
traffic must layer their own per-foreign-client rate limit on the
bridge side; the kernel neither sees nor scopes by foreign-client
identity.

A token is consumed only when the call has cleared every other gate:
argument validation, layer-specific size cap, and presence of a
protocol layer. Calls that fail with `GN_ERR_NULL_ARG`,
`GN_ERR_INVALID_ENVELOPE`, `GN_ERR_PAYLOAD_TOO_LARGE`, or
`GN_ERR_NOT_IMPLEMENTED` leave the bucket untouched; otherwise a
plugin's own bad inputs would burn through legitimate budget for the
same source.

The contract is **not** a downgrade from peer-direct delivery: the
envelope's `sender_pk` is whatever the source connection records as
the remote pk, signed metadata is unchanged, the trust class stays
that of the source connection. Bridges cannot upgrade their own
trust through the inject path.

FRAME inject does not skip the protocol layer's deframer; a malformed
frame returns the deframer's error verbatim. This rules out a class
of forged-frame attacks where a compromised plugin synthesises a
system-message envelope: the deframer rejects unknown flags and the
framing magic, and the kernel applies the same `msg_id == 0` and
payload-size limits as the regular inbound path.

Implementations live in `core/kernel/host_api_builder.cpp`; the rate
limiter primitive is `core/util/token_bucket.hpp`. The pure-C
convenience wrappers `gn_inject_external_message` and
`gn_inject_frame` in `sdk/convenience.h` expand to the corresponding
`inject(LAYER, …)` call.

### 8.1 Shippable bridge shape in v1

A bridge plugin connects an external system (MQTT, HTTP, OPC-UA,
foreign mesh) to the GoodNet mesh. v1 admits one canonical shape:

1. The foreign-protocol logic runs **out-of-process**. The bridge
   plugin owns an IPC connection to the goodnet kernel — same shape
   as any in-process plugin, but the foreign socket lives in the
   bridge's own process and the kernel never sees it.
2. The bridge calls `notify_connect` on its IPC link with
   `gn_trust_class = IntraNode` (per `security-trust.md` §3); the
   kernel admits the conn under the null security provider, whose
   mask permits `IntraNode` (`plugins/security/null/null.cpp:139`).
   No Noise handshake runs on the bridge edge.
3. For every foreign-system message the bridge wants to publish to
   the mesh, the bridge calls `inject(LAYER_MESSAGE, source =
   ipc_conn, msg_id, bytes)`. The kernel routes the envelope
   through the active protocol layer's handler chain exactly as if
   the bytes had arrived from the bridge's `remote_pk` — see §8 for
   per-conn rate limiting and `gn_message_t::conn_id` doc for the
   stamping invariant.

A second shape — bridge installs a `subscribe_data` callback on
another plugin's link conn through `sdk/extensions/link.h` composer
slots, sees foreign-protocol bytes on a shared TCP/UDP/IPC socket,
and feeds them through `inject(LAYER_FRAME)` — is reserved for v1.x.
The baseline link plugins (TCP, UDP, WS, IPC) inherit
`GN_ERR_NOT_IMPLEMENTED` defaults for the composer slots through the
`GN_LINK_PLUGIN` macro (`sdk/cpp/link_plugin.hpp:216-240`); TLS is
the sole link in v1 with explicit overrides, but those expose its
own L2 shape, not a foreign-protocol composer surface. The L1-shared
subscribe pattern lands with the relay / DHT layer.

Bridges that fan in many foreign clients through one IPC source
share a single rate-limit bucket per the §8 paragraph above; the
bridge plugin layers its own per-foreign-client limiter on top.
The kernel never sees foreign-client identity.

---

## 9. Service executor

The `set_timer` and `cancel_timer` slots route to a kernel-owned
single-thread executor reserved for plugin service tasks.
`set_timer(delay_ms = 0, …)` covers the post-to-executor pattern —
fire-and-forget work hands the kernel `delay_ms = 0` and an empty
`out_id`. They sit at the v1.x ABI tail; consumers built against
earlier prereleases must guard with `GN_API_HAS` from `sdk/abi.h`
before calling. `timer.md` is the authoritative specification:

- §2 — slot signatures and invariants
- §3 — single-thread serialisation guarantee
- §4 — lifetime safety, anchor-based dispatch, drain on plugin
  unload
- §5 — periodic work pattern (one-shot re-arm)
- §6 — resource bounds (`gn_limits_t::max_timers`,
  `max_pending_tasks`)
- §7 — error returns

A plugin **must** route its async work through these slots; private
threads outliving `gn_plugin_shutdown` violate `plugin-lifetime.md`
§9 and are not supported.

---

## 10. Cooperative cancellation

Long-running async work poll `is_shutdown_requested(host_ctx)` and
exit cooperatively when the slot returns non-zero. The slot flips on
the moment the kernel begins teardown for this plugin — before
`gn_plugin_unregister`, before pending timers are cancelled, before
the drain wait.

| Property | Specification |
|---|---|
| Producer | `core/plugin/manager` at the start of per-plugin rollback. |
| Effect | Atomic publish of the shutdown flag on the plugin's anchor. |
| Returns | 0 if shutdown not requested or context has no anchor; non-zero otherwise. |
| Concurrency | Safe to call from any thread that owns a reference to `api`. |
| Delivery | The flag latches on; once set, every subsequent call returns non-zero through the rest of the plugin's lifetime. |
| Side effects | None. The slot is a pure observation. |

The flag is **advisory**. The kernel-side gate around every async
callback already refuses dispatches that arrive after the flag was
published, so a plugin that never polls the flag is still safe — it
just consumes the kernel's bounded drain budget on shutdown. Polling
the flag is how the plugin earns the fast path: the kernel logs the
in-flight count alongside the drain timeout, so a plugin that
ignores the flag is observably the noisy one.

`plugin-lifetime.md` §8 covers the patterns: periodic timers stop
re-arming, posted multi-step tasks return without scheduling the
next step, queue-drain workers treat the flag as the loop's exit
predicate.

---

## 11. Logging without format-string trust

The `log` field of `host_api_t` is a substruct, `gn_log_api_t`,
declared in `sdk/log.h`. It carries two function pointers — the
level-filter fast path and the literal-buffer hand-off — plus the
size prefix that gates access to future additions per
`abi-evolution.md` §3a.

```c
typedef struct gn_log_api_s {
    uint32_t api_size;

    int32_t (*should_log)(void* host_ctx, gn_log_level_t level);
    void    (*emit)(void* host_ctx,
                    gn_log_level_t level,
                    const char* file, int32_t line,
                    const char* msg);

    void* _reserved[8];
} gn_log_api_t;
```

### 11.1 `should_log`

| Property | Specification |
|---|---|
| Producer | every plugin |
| Effect | none observable; pure level query against the kernel logger |
| Returns | `1` when a message at @p level would land in the live sink, `0` when it would be filtered out |
| Concurrency | safe from any thread owning a reference to `api` |
| Use | hot dispatch paths call this before formatting so a filtered-out level pays for no `snprintf` |

A plugin that skips `should_log` and formats unconditionally is
correct but wasteful — the kernel re-checks the level inside `emit`
and drops sub-threshold messages without writing.

### 11.2 `emit`

| Property | Specification |
|---|---|
| Producer | every plugin (after formatting on its own stack) |
| Effect | one log line written to the kernel's structured sink, prefixed with the calling plugin's name |
| Payload | `msg` is a NUL-terminated UTF-8 buffer the plugin formatted on its own stack; @p file/@p line carry the call-site source location, or `NULL` / `0` to omit the prefix |
| Concurrency | safe from any thread owning a reference to `api` |
| Delivery | best-effort; messages below the live level threshold are dropped without I/O |
| Truncation | the plugin's local formatter chooses the cap (the bundled `gn_log_*` macros use 2048 bytes); the kernel does not re-truncate. Plugins formatting larger messages allocate their own buffer and call `emit` directly |

Empty `msg` ("") is a valid log line and is written. NULL `msg` is
dropped silently. The kernel's only operations on the buffer are
the level filter, the plugin-name prefix, the source-location
prefix per §11.3, and forwarding to spdlog as a literal.

### 11.3 Format-string trust boundary

The kernel never invokes `vsnprintf` on plugin-supplied bytes; it
forwards `msg` to the structured logger as a literal payload. A
compromised plugin cannot smuggle `%n` writes, `%s`-without-arg
dereferences, or excessive width specifiers into kernel address
space — the kernel never parses format directives, so there is
nothing to abuse. The trust boundary sits at the plugin's stack
buffer; everything past `emit` is kernel-controlled.

Plugins format locally. `sdk/convenience.h` provides
`gn_log_<level>(api, "fmt", args…)` macros that build the message
on the plugin's stack with `snprintf`, capture `__FILE__` and
`__LINE__` at the macro expansion site, and call `emit` with the
result. C++ plugins that prefer `std::format`'s typed `{}` syntax
use the `GN_LOGF_<level>` macros from `sdk/cpp/log.hpp`, which run
`std::format_to_n` on the same 2048-byte stack buffer and feed the
result into the same `emit` slot — the trust-boundary contract is
identical.

### 11.4 Source-location detail mode

The kernel's logger renders the `file`/`line` pair through a
`%Q` flag whose verbosity is controlled by `log.source_detail_mode`
in the operator config:

| Mode | Behaviour |
|---|---|
| 0 (Auto) | TRACE/DEBUG carry full path + line; INFO and above carry basename only. Default. |
| 1 (FullPath) | every level carries the project-relative path plus `:line`. |
| 2 (BasenameWithLine) | every level carries the file basename plus `:line`. |
| 3 (BasenameOnly) | the basename, no line. Tightest format. |

The rendered path is project-relative when the build runs with
`-fmacro-prefix-map=${CMAKE_SOURCE_DIR}/=` (default in this tree)
or when `log.project_root` is set. Otherwise the formatter falls
back to the basename so a path containing the absolute build-tree
prefix never lands in the rendered line.
