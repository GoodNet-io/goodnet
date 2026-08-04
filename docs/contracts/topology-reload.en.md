# Contract: Topology Reload

**Status:** active · v1
**Owner:** `core/kernel/core_c.cpp`, `sdk/conn_events.h`
**Last verified:** 2026-06-15
**Stability:** stable for v1.x; additive extensions gated by `GN_CONN_EVENT_TOPOLOGY_MISMATCH`.

---

## 1. What triggers a topology reload

`gn_core_reload_topology(core)` is the only operator-side entry point for a topology rebuild.
Internally it:

1. Calls `build_topology(kernel)` — recomputes fingerprint[32], contour_gaps, all four entry
   arrays from the current plugin registry state.
2. Encodes a new capability wire blob (TLV 0x0004, 44 bytes: 8-byte INT64_MAX expiry +
   type/length/fingerprint[32]).
3. Updates `kernel.topology_wire_blob_` so every subsequent handshake carries the new blob.
4. **Propagates to existing Transport-phase connections** (§2 below).
5. Fires `on_topology_reload` signal with `{prev, next}` snapshot pointers for local plugin
   subscribers (`subscribe_topology_reload`).
6. Releases the previous topology snapshot.

Plugin-side subscribers (`subscribe_topology_reload`) receive `{prev, next}` only after the
propagation loop in step 4 completes, so local state is consistent when the signal fires.

---

## 2. Propagation to existing connections

**Gap fixed in this version:** prior to this contract, `gn_core_reload_topology()` updated
the kernel's blob but did not send it to peers already in Transport phase. Those peers would
retain the stale fingerprint until the next reconnect.

**Current behaviour (`core_c.cpp:gn_core_reload_topology`):**

After updating `topology_wire_blob_`, the kernel iterates `connections().for_each()` and
calls `send_topology_blob_to_conn()` for every registered connection.
`send_topology_blob_to_conn` checks `session->phase() == SecurityPhase::Transport` internally
and silently skips Handshake-phase connections (they will receive the blob automatically on
Transport entry).

**Ordering guarantee:** every live Transport-phase connection receives the new blob
before `on_topology_reload` fires. Plugin subscribers can therefore rely on the fact that
the local topology is already consistent when they inspect `next`.

**No forced disconnect:** a mismatch does not close the connection. The kernel sets
`peer_caps_verified = false` on the `ConnectionRecord` and fires
`GN_CONN_EVENT_TOPOLOGY_MISMATCH` (§3). The embedding application decides the policy.

---

## 3. GN_CONN_EVENT_TOPOLOGY_MISMATCH

**Value:** 7 (next after `GN_CONN_EVENT_IDENTITY_ROTATED = 6`).

**When fired:** in `topology_caps_cb`, which runs when the peer's capability blob
(`msg_id = 0x13`) is received. If the peer's TLV 0x0004 fingerprint does not match the local
fingerprint, the kernel:

1. Sets `ConnectionRecord::peer_caps_verified = false`.
2. Logs a WARN: `"topology_caps: fingerprint mismatch from conn=<id> — peer stack differs"`.
3. Fires `GN_CONN_EVENT_TOPOLOGY_MISMATCH` on `on_conn_event()`.

**Payload fields** (`gn_conn_event_t`):

| Field             | Value                                                        |
|---|---|
| `kind`            | `GN_CONN_EVENT_TOPOLOGY_MISMATCH`                            |
| `conn`            | connection id of the mismatched peer                         |
| `trust`           | current trust class of the connection                        |
| `remote_pk`       | peer's Ed25519 public key                                    |
| `peer_fingerprint`| borrowed 32-byte SHA-256 from the peer's TLV; valid only for the callback duration |
| all others        | zero / NULL                                                  |

**`peer_fingerprint` lifetime:** the pointer is borrowed from the parsed TLV record on the
stack inside `topology_caps_cb`. It is valid for the duration of the subscriber callback
only. Subscribers that need to retain the fingerprint must copy it.

---

## 4. App response options

The embedding application subscribes to `GN_CONN_EVENT_TOPOLOGY_MISMATCH` via
`gn_core_on_conn_state`. Three common policies:

| Policy | Action |
|---|---|
| **Strict** | Close the connection immediately via `host_api->disconnect(conn)`. Peer must reconnect and complete a new handshake with the updated topology blob. |
| **Tolerate** | Log the mismatch. Keep the connection alive. Re-check on the next `GN_CONN_EVENT_TOPOLOGY_MISMATCH` after a local reload. |
| **Retry-reload** | Call `gn_core_reload_topology()` if the mismatch indicates the local stack is stale; then wait for the peer to send a new blob. |

The kernel makes no policy choice — it reports and records `peer_caps_verified = false`.

---

## 5. Peer-side behaviour

When a connected peer calls `gn_core_reload_topology()` on its own kernel, it sends the
new blob to this node as part of step 4. This node's `topology_caps_cb` fires, compares
fingerprints, sets `peer_caps_verified`, and fires the event if mismatched.

If this node's topology matches the peer's updated stack, `peer_caps_verified` is set to
`true` and no event fires.

---

## 6. Cross-references

- Capability TLV wire format: `capability-tlv.en.md`
- Blob encoding and fingerprint computation: `core/topology/topology_builder.cpp`
- Connection phase tracking: `core/security/session.hpp` (`SecurityPhase`)
- Event payload: `sdk/conn_events.h` (`gn_conn_event_t`, `GN_CONN_EVENT_TOPOLOGY_MISMATCH`)
- Fix implementation: `core/kernel/core_c.cpp:gn_core_reload_topology`,
  `send_topology_blob_to_conn`
