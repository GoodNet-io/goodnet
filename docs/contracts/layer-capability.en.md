# Contract: Layer Capability and Topology

**Status:** active · v1
**Owner:** `core/topology/`, `sdk/topology.h`, `sdk/link.h` (`on_topology_sealed`), `sdk/security.h` (`provides_flags`), `sdk/host_api.h` (`subscribe_topology_reload`), `sdk/conn_events.h`
**Last verified:** 2026-06-14
**Stability:** v1.x (RC reshape window open until `v1.0.0`). `gn_topology_t` grew from 120 → 128 bytes in #33 (named contours); `_reserved[4]` count is frozen at 4 for the duration of RC. Post-`v1.0.0`: append-only per `abi-evolution.en.md §3`.

---

## 1. Purpose

GoodNet's four-layer stack (link → security → protocol → handlers) was
opaque to cross-layer queries. Each layer declared its own capability
flags in isolation; there was no unified picture that let a plugin ask
"what security guarantees are active above me?" or let an operator verify
"is the security contour closed for all external connections?"

The topology object solves this. It is a read-only snapshot of every
registered plugin's capability declarations, built once when the kernel
transitions to `Phase::Running`. It gives:

1. **Contour proof** — `contour_gaps` shows which trust classes lack
   E2E encryption coverage. Zero means the contour is closed.
2. **Self-governance** — link plugins receive the topology via
   `on_topology_sealed` and configure themselves accordingly (ICE
   adjusts candidate strategy; strategy plugins can read real link caps).
3. **Peer exchange** — the deterministic `fingerprint` lets two nodes
   detect stack incompatibility before exchanging application frames
   (Slice 4, `GN_SYS_MSG_CAPS`).
4. **Operator introspection** — `gn_core_get_topology()` exposes the
   full snapshot over the C ABI for tooling.

---

## 2. Topology lifecycle

### 2.1 Cold start

```
gn_core_start()
  └─ advance_to(Phase::Running)
  └─ build_topology(kernel)
        ├─ snapshot all registries under shared_lock
        ├─ sort each section by stable key (scheme / provider_id / ...)
        ├─ query link caps through extension_vtable → get_capabilities
        ├─ read security provides_flags + allowed_trust_mask
        ├─ compute SHA-256 fingerprint over sorted sections
        ├─ compute contour_gaps bitmask
        └─ call on_topology_sealed(self, &topo) on every link plugin
  └─ encode_topology_wire_blob(topo)  → TLV 0x0004 blob
  └─ kernel.set_topology_wire_blob(blob)
  └─ capability_blob_bus.subscribe(topology_caps_cb)
       topology_caps_cb → tlv_chain_.dispatch()  [W4: TlvHandlerChain, see capability-tlv.en.md §2]
         ├─ type 0x0004 handler (priority=255): topology fingerprint compare → peer_caps_verified
         └─ type 0x0005 handler (priority=255): contour fingerprint placeholder (W2)
```

`on_topology_sealed` is synchronous and fires before the kernel begins
accepting connections. The topology pointer remains valid until the next
`gn_core_reload_topology()` or `gn_core_destroy()`.

### 2.2 Reload

Hosts that register plugins dynamically (e.g. in-process plugin hot-swap)
call `gn_core_reload_topology()` after the plugin set changes. This is an
operational path, not an escape hatch.

```
gn_core_reload_topology(core)
  ├─ prev = &core->topology_->topo   (nullptr if none yet)
  ├─ new_snap = build_topology(kernel)
  ├─ encode_topology_wire_blob(*next) → new blob
  ├─ kernel.set_topology_wire_blob(blob)
  ├─ kernel.on_topology_reload().fire({prev, next})
  └─ core->topology_ = move(new_snap)
```

Subscribers registered via `host_api->subscribe_topology_reload` receive
`{prev, next}` while both snapshots are alive. After the call returns,
`prev` is destroyed. See §10 for the subscription API.

**Known gap:** the updated `topology_wire_blob_` is not pushed to existing
Transport-phase connections. They continue operating with the old fingerprint
until the next reconnect or until the caller iterates `connections().for_each()`
and sends the blob manually.

---

## 3. `sdk/topology.h` — struct layout

The structs below are **data structs**, not vtables. They carry no
`api_size` field. Growth uses `_reserved[4]` per `abi-evolution.en.md §4`.

### Entry types

| Struct | Size | Purpose |
|---|---|---|
| `gn_topo_link_entry_t` | 16 B | One registered link: scheme + `caps_flags` + `max_payload` |
| `gn_topo_security_entry_t` | 16 B | One security provider: provider_id + `allowed_trust_mask` + `provides_flags` |
| `gn_topo_protocol_entry_t` | 8 B | One protocol layer: protocol_id |
| `gn_topo_handler_entry_t` | 16 B | One (protocol_id, msg_id) pair: aggregated chain_length across all namespaces |
| `gn_topo_contour_t` | 48 B | One named packet path — full axis: trust × link × security × protocol × handler chain (see §3a) |

### `gn_topology_t` (128 bytes, reshaped in #33)

```c
typedef struct gn_topology_s {
    uint8_t  fingerprint[32];                   /* SHA-256 over sorted structural layers */
    uint32_t link_count;                        /* offset 32 */
    uint32_t security_count;                    /* offset 36 */
    uint32_t protocol_count;                    /* offset 40 */
    uint32_t handler_count;                     /* offset 44 */
    const gn_topo_link_entry_t*     links;      /* offset 48 */
    const gn_topo_security_entry_t* security;   /* offset 56 */
    const gn_topo_protocol_entry_t* protocols;  /* offset 64 */
    const gn_topo_handler_entry_t*  handlers;   /* offset 72 */
    uint32_t contour_gaps;                      /* offset 80 — bitmask, see §5 */
    uint32_t contour_count;                     /* offset 84 — promoted from implicit padding */
    const gn_topo_contour_t*        contours;   /* offset 88 — named paths, see §3a */
    void*    _reserved[4];                      /* offset 96 — MUST be zero, count frozen */
    /* sizeof = 128 */
} gn_topology_t;
```

All pointer fields are `@borrowed` from kernel-owned storage. Valid
until `gn_core_destroy()` or `gn_core_reload_topology()`.

### §3a. `gn_topo_contour_t` — named packet path

A contour is the resolved, named path that a packet travels for a specific
trust class. It is computed at `build_topology` time by resolving the cross-join:

```
(trust_class, link_scheme) → security_provider (via find_for_trust) → protocol → handler_chain
```

`find_for_trust` returns the **first** registered provider whose `allowed_trust_mask`
admits the trust class. The contour array makes the resolved winner explicit — the
entry that appears in `contours[]` IS the provider the kernel will use for that
(trust_class, link_scheme) pair. When two providers both admit the same class,
registration order determines the winner; the topology snapshot removes ambiguity.

```c
typedef struct gn_topo_contour_s {
    const char*       link_scheme;             /* offset  0 — @borrowed */
    const char*       security_provider_id;    /* offset  8 — @borrowed */
    const char*       protocol_id;             /* offset 16 — @borrowed */
    const uint32_t*   handler_msg_ids;         /* offset 24 — @borrowed; handler_count entries */
    gn_trust_class_t  trust;                   /* offset 32 — GN_TRUST_* value */
    uint32_t          security_provides_flags; /* offset 36 — GN_SEC_PROVIDES_* bitmask */
    uint32_t          handler_count;           /* offset 40 */
    uint32_t          _pad;                    /* offset 44 — explicit padding; MUST be zero */
    /* sizeof = 48 */
} gn_topo_contour_t;
```

`security_provides_flags` carries the per-path crypto profile: the same provider
may serve multiple trust classes, and both contour entries carry the same flags.
Future PQ provider: flags gain `GN_SEC_PROVIDES_PQ_SAFE` — immediately visible
per trust class in the contour array without reading the flat security entry.

`contour_gaps` (§5) is the summary: bit N set means no contour exists for
`GN_TRUST_N` with `GN_SEC_PROVIDES_E2E_ENCRYPTION`. The contour array is the
detail behind the summary.

---

## 4. Vtable slots

### Link plugin — `on_topology_sealed`

<!-- livedoc:link_vtable_slots -->
<!-- generated by tools/livedoc.py — do not edit by hand; rerun `make livedoc` to refresh -->

Link plugin vtable — **10 slots** + `4` reserved ([`sdk/link.h`](../../sdk/link.h)).

| Slot | Signature |
|---|---|
| [scheme](../../sdk/link.h#L52) | `const char * (*)(void *)` |
| [listen](../../sdk/link.h#L61) | `gn_result_t (*)(void *, const char *)` |
| [connect](../../sdk/link.h#L71) | `gn_result_t (*)(void *, const char *)` |
| [send](../../sdk/link.h#L79) | `gn_result_t (*)(void *, gn_conn_id_t, const uint8_t *, size_t)` |
| [send_batch](../../sdk/link.h#L92) | `gn_result_t (*)(void *, gn_conn_id_t, const gn_byte_span_t *, size_t)` |
| [disconnect](../../sdk/link.h#L100) | `gn_result_t (*)(void *, gn_conn_id_t)` |
| [extension_name](../../sdk/link.h#L112) | `const char * (*)(void *)` |
| [extension_vtable](../../sdk/link.h#L118) | `const void * (*)(void *)` |
| [destroy](../../sdk/link.h#L124) | `void (*)(void *)` |
| [on_topology_sealed](../../sdk/link.h#L136) | `void (*)(void *, const struct gn_topology_s *)` |
<!-- /livedoc:link_vtable_slots -->

`on_topology_sealed` is called once, synchronously inside
`build_topology`, before the kernel begins accepting connections.
The `topo` pointer is valid for the kernel's lifetime. The slot is
optional — the kernel checks `GN_API_HAS(gn_link_vtable_t, vtable, on_topology_sealed)`
before calling; plugins that do not implement it receive no callback.

### Security provider — `provides_flags`

<!-- livedoc:security_vtable_slots -->
<!-- generated by tools/livedoc.py — do not edit by hand; rerun `make livedoc` to refresh -->

Security provider vtable — **12 slots** + `4` reserved ([`sdk/security.h`](../../sdk/security.h)).

| Slot | Signature |
|---|---|
| [provider_id](../../sdk/security.h#L122) | `const char * (*)(void *)` |
| [handshake_open](../../sdk/security.h#L142) | `gn_result_t (*)(void *, gn_conn_id_t, gn_trust_class_t, gn_handshake_role_t, const uint8_t[64], const uint8_t[32], const uint8_t *, void **)` |
| [handshake_step](../../sdk/security.h#L163) | `gn_result_t (*)(void *, void *, const uint8_t *, size_t, gn_secure_buffer_t *)` |
| [handshake_complete](../../sdk/security.h#L171) | `int (*)(void *, void *)` |
| [export_transport_keys](../../sdk/security.h#L185) | `gn_result_t (*)(void *, void *, gn_handshake_keys_t *)` |
| [encrypt](../../sdk/security.h#L197) | `gn_result_t (*)(void *, void *, const uint8_t *, size_t, gn_secure_buffer_t *)` |
| [decrypt](../../sdk/security.h#L210) | `gn_result_t (*)(void *, void *, const uint8_t *, size_t, gn_secure_buffer_t *)` |
| [rekey](../../sdk/security.h#L220) | `gn_result_t (*)(void *, void *)` |
| [handshake_close](../../sdk/security.h#L225) | `void (*)(void *, void *)` |
| [destroy](../../sdk/security.h#L228) | `void (*)(void *)` |
| [allowed_trust_mask](../../sdk/security.h#L244) | `uint32_t (*)(void *)` |
| [provides_flags](../../sdk/security.h#L257) | `uint32_t (*)(void *)` |
<!-- /livedoc:security_vtable_slots -->

`provides_flags` returns a bitmask of `GN_SEC_PROVIDES_*` constants
declared in `sdk/security.h`. The kernel reads this once at
topology-build time; the result is stored in `gn_topo_security_entry_t::provides_flags`
for the snapshot's lifetime.

---

## 5. `contour_gaps` — security contour proof

`contour_gaps` is a bitmask where bit N is set when no registered
security provider covers `GN_TRUST_<N>` with
`GN_SEC_PROVIDES_E2E_ENCRYPTION`.

| Bit | Trust class | Expected at seal |
|---|---|---|
| 0 | `GN_TRUST_UNTRUSTED` | 0 — Noise covers inbound internet traffic |
| 1 | `GN_TRUST_PEER` | 0 — Noise covers peer connections |
| 2 | `GN_TRUST_LOOPBACK` | 1 — null provider; loopback needs no E2E |
| 3 | `GN_TRUST_INTRA_NODE` | 1 — null provider; intra-node needs no E2E |
| 4 | `GN_TRUST_ANONYMOUS_LOOPBACK` | 1 — local-only ingress |

A fully-correct production stack has `contour_gaps == 0b11100 == 28`.
`contour_gaps & 0x3 != 0` (bits 0 or 1 set) means an external trust
class has no E2E encryption — the contour is open and the operator
should investigate before accepting external connections.

The plaintext pass-through in `notifications.cpp` is guarded by this
invariant: inbound bytes without a security session are rejected when
`security_active && !is_local`, closing the gap.

---

## 6. `fingerprint` — deterministic peer comparison

SHA-256 over four concatenated sections, each prefixed with a domain tag:

| Tag | Section | Key order |
|---|---|---|
| `0x01` | Link entries | scheme ascending |
| `0x02` | Security entries | provider_id ascending |
| `0x03` | Protocol entries | protocol_id ascending |
| `0x04` | Handler entries | (protocol_id, msg_id) ascending |

Per section, the entry bytes are: NUL-terminated identifier string +
LE uint32 fields in struct order. The sort is over the identifying
string, not the registration order, so `fingerprint` is stable across
different plugin load sequences.

Peer exchange (Slice 4) sends the fingerprint after the Noise XX
transport phase. Nodes with identical fingerprints have matching stacks;
a mismatch surfaces which section differs before the first application
frame.

---

## 7. `GN_SEC_PROVIDES_*` flag values

Declared in `sdk/security.h`:

```c
#define GN_SEC_PROVIDES_E2E_ENCRYPTION   (1u << 0)  /* per-frame AEAD */
#define GN_SEC_PROVIDES_AUTHENTICATION   (1u << 1)  /* peer identity verified */
#define GN_SEC_PROVIDES_FORWARD_SECRECY  (1u << 2)  /* ephemeral keys */
```

| Provider | Expected `provides_flags` |
|---|---|
| `gn.security.noise` (Noise XX / IK) | `E2E_ENCRYPTION \| AUTHENTICATION \| FORWARD_SECRECY` = 7 |
| `gn.security.null` | `0` — loopback/intra-node; no session-layer crypto |

The `link_only` provider (Slice 3) also returns 0 and is admitted only
when `link.caps_flags & GN_LINK_CAP_ENCRYPTED_PATH` and operator config
has `allow_link_only_security: true`.

---

## 8. ICE self-governance example

```c
void my_ice_on_topology_sealed(void* self, const gn_topology_t* topo) {
    // If any external trust class lacks E2E, prefer TURN-TCP candidates
    // (relay adds confidentiality for the path we can't encrypt).
    const bool contour_open =
        (topo->contour_gaps & ((1u << GN_TRUST_UNTRUSTED) |
                               (1u << GN_TRUST_PEER))) != 0;
    ice_ctx(self)->prefer_turn_tcp = contour_open;
}
```

The slot is guarded with `GN_API_HAS` — ICE plugins that predate
this slot (built against an older SDK) simply receive no callback and
continue with their default candidate strategy.

---

## 9. C ABI surface

```c
/* sdk/core.h */

/* Returns borrowed pointer to current topology, or NULL before gn_core_start. */
GN_EXPORT const gn_topology_t* gn_core_get_topology(gn_core_t* core);

/* Rebuild topology from current registry state. Calls on_topology_sealed again. */
GN_EXPORT gn_result_t gn_core_reload_topology(gn_core_t* core);
```

The extension `"gn.topology"` (version `GN_EXT_TOPOLOGY_VERSION = 0x00010000`)
is reserved for a future vtable surface that plugin code can query
through `host_api->query_extension_checked` without touching `sdk/core.h`.
The extension is not registered in this slice — registering it is Slice 2b
(scheduled after peer exchange lands and the query contract is exercised
end-to-end).

---

## 10. Topology reload subscription

Declared in `sdk/conn_events.h` (`GN_SUBSCRIBE_TOPOLOGY_RELOAD = 3`,
`gn_topology_reload_cb_t`) and `sdk/host_api.h` (`subscribe_topology_reload`
slot, before `_reserved[8]`).

Any plugin type MAY subscribe to topology reload events through
`host_api_t`. The slot is optional; plugins MUST check with `GN_API_HAS`
before calling.

The kernel MUST invoke every registered callback synchronously during
`gn_core_reload_topology()`, with both `prev` and `next` valid for
the duration of each call. `prev` is `NULL` on the first reload.
After the call returns, `prev` is destroyed; plugins MUST NOT retain
either pointer.

The kernel delivers the event only. Recovery policy — closing connections,
marking contours degraded, re-exchanging capabilities — is the
plugin's responsibility.

---

## 11. Cross-references

- `abi-evolution.en.md` — RC reshape window, size-prefix rules, `_reserved` promotion.
- `security-trust.en.md` — trust class definitions, `allowed_trust_mask` gate, `provides_flags` table.
- `link.en.md §8` — link extension surface (`gn_link_api_t`, `get_capabilities`).
- `security.en.md` — Noise XX handshake, `InlineCrypto` key seeding.
- `fsm-events.en.md` — `Phase::Running` transition that triggers topology build.
- `conn-events.en.md` — `GN_SUBSCRIBE_TOPOLOGY_RELOAD`, subscription channel constants.
- `host-api.en.md` — `subscribe_topology_reload` slot, unsubscribe semantics.
