# Contract: Attestation

**Status:** active · v1
**Owner:** `core/kernel/attestation_dispatcher`, `core/identity/attestation`
**Last verified:** 2026-04-29
**Stability:** v1.x; the wire payload may grow only at the tail through
`_reserved` slot promotion.

---

## 1. Purpose

A successful Noise handshake proves both endpoints control the static
key the other side learned through the handshake itself. It does not
prove that the static key is endorsed by a long-term user identity —
a node may have rotated its device key without permission, or the
static may belong to an attacker who terminated Noise without holding
the user secret.

The attestation step closes that gap. After every security session
reaches `Transport` phase, both peers exchange a 136-byte attestation
cert (per `identity.md` §4) bound to the current session through the
channel-binding `handshake_hash`. The kernel gates the trust upgrade
`Untrusted → Peer` on a successful mutual exchange — either side that
fails to verify the other's attestation stays at `Untrusted` and the
gate refuses promotion.

The exchange rides on system msg_id `0x11` over the secured channel.
Any security provider that exports a `gn_handshake_keys_t::handshake_hash`
(per `noise-handshake.md` §2) carries the attestation flow without
modification — the dispatcher is provider-agnostic.

---

## 2. Wire payload

Total **232 bytes**. Multi-byte integers within the embedded
attestation cert are big-endian per `identity.md` §4. Layout:

| Offset | Size | Field |
|---|---|---|
| 0      | 136  | attestation cert (per `identity.md` §4) |
| 136    | 32   | binding — current session's `handshake_hash` |
| 168    | 64   | Ed25519 signature over `attestation || binding`, signed by the local device secret key |

The signature pins the cert to this session: replaying a captured
cert against a new session produces a binding mismatch and the
consumer rejects.

---

## 3. Reserved msg_id

`msg_id = 0x11` is reserved for the kernel-internal attestation
dispatcher. Plugin registration through `register_handler` against
`(any protocol_id, msg_id == 0x11)` is rejected with
`GN_ERR_INVALID_ENVELOPE` per `handler-registration.md` §2a.

The kernel intercepts envelopes carrying `msg_id == 0x11` after the
protocol layer's `deframe` step and before regular dispatch chain
lookup. Plugins do not see attestation traffic at any point.

---

## 4. Producer

Both peers, on every connection where:

- the security session has just transitioned to `Transport` phase
  (`security-trust.md` §3 timing), and
- the connection's trust class is `Untrusted` (the only class
  subject to the upgrade gate per `security-trust.md` §3),

the kernel-internal attestation dispatcher composes the 232-byte
payload:

1. Serialise the local attestation cert (per `identity.md` §4) to
   its 136-byte form.
2. Read the current session's exported `handshake_hash` from the
   security session's transport-keys block — 32 bytes.
3. Sign the concatenation `attestation || binding` with the local
   device secret key — 64-byte detached Ed25519 signature.
4. Concatenate the three; submit through the active protocol layer
   for framing; route through the security session for encryption;
   push to the transport.

`Loopback` and `IntraNode` connections skip the producer step —
their trust class is final at `notify_connect` (per
`security-trust.md` §3), and the attestation gate is not consulted.
A null-security stack on `Loopback` exchanges no attestation.

The kernel emits the producer payload automatically on phase
transition to `Transport`; plugins do not invoke this path.

---

## 5. Consumer

When `notify_inbound_bytes` produces an envelope with `msg_id == 0x11`
after the protocol layer's `deframe` step, the kernel-internal
attestation dispatcher consumes it before the regular handler chain
runs. Steps run in order; the dispatcher exits on the first failure
and the connection is closed:

1. **Size check.** Drop and disconnect if `payload_size != 232`;
   metric `attestation.bad_size`.
2. **Layout split.** Read attestation bytes `[0, 136)`, binding
   `[136, 168)`, signature `[168, 232)`.
3. **Binding match.** Drop and disconnect if `binding` differs from
   the current session's exported `handshake_hash`; metric
   `attestation.replay`.
4. **Cert parse.** Drop and disconnect if the 136-byte attestation
   does not parse per `identity.md` §4; metric
   `attestation.parse_failed`.
5. **Signature verify.** Drop and disconnect if the Ed25519
   signature does not verify against the parsed attestation's
   `device_pk` over `attestation || binding`; metric
   `attestation.bad_signature`.
6. **Cert verify.** Drop and disconnect if the cert verify
   (signature self-check against the embedded `user_pk` plus
   non-expired against the current clock) fails; metric
   `attestation.expired_or_invalid`.
7. **Identity stability.** If a prior attestation has already
   verified on this connection, compare the new `device_pk`
   against the cached one:
   - **Different** `device_pk` — drop and disconnect; metric
     `attestation.identity_change`. This catches a peer that
     swaps its device key mid-session.
   - **Same** `device_pk` — drop the envelope but leave the
     connection alive. Live re-attestation is out of scope per
     §9, and the binding match in step 3 already prevents replay
     across sessions; a same-key duplicate within one session is
     therefore noise, not an error.
8. Mark per-connection dispatcher state `their_received_valid = true`
   and cache the verified `(user_pk, device_pk)` for handler
   observation.

Step 8 runs only on the first valid attestation; subsequent
attestations with the same key skip step 8 and return.

Each consumer-step rejection maps to a `gn_drop_reason_t` enum
value declared in `sdk/types.h`:

| Step | Outcome | `gn_drop_reason_t` |
|---|---|---|
| 1 | size != 232 | `GN_DROP_ATTESTATION_BAD_SIZE` |
| 3 | binding mismatch | `GN_DROP_ATTESTATION_REPLAY` |
| 4 | cert parse failed | `GN_DROP_ATTESTATION_PARSE_FAILED` |
| 5 | signature verify failed | `GN_DROP_ATTESTATION_BAD_SIGNATURE` |
| 6 | cert expired or invalid | `GN_DROP_ATTESTATION_EXPIRED_OR_INVALID` |
| 7 | device_pk swap | `GN_DROP_ATTESTATION_IDENTITY_CHANGE` |

The dispatcher emits these as structured log fields at warn level
and passes the enum through `disconnect_on_consumer_failure`. v1
does not lift the enum to a kernel-managed counter surface; the
counter wiring lands when the cross-cutting drop-metrics design
ships (`limits.md` §5 names the same `gn_drop_reason_t` as the
intended counter key, but the surface is reserved for a future
minor release).

---

## 6. Mutual exchange and trust upgrade

The dispatcher tracks two flags per connection:

- `our_sent` — set after the producer step (§4) successfully enqueues
  the payload through the security session.
- `their_received_valid` — set after the consumer step (§5) reaches
  its mark step.

When **both** flags are true, the dispatcher promotes the connection
through `connections.upgrade_trust(conn, GN_TRUST_PEER)` and fires
`GN_CONN_EVENT_TRUST_UPGRADED` (per `conn-events.md` §2). Order is
irrelevant — concurrent send and receive on the two halves of the
duplex stream both reach the dual-flag state regardless of which
races first; the upgrade fires exactly once per connection.

The "exactly once" guarantee comes from the connection registry's
`upgrade_trust` policy gate (`security-trust.md` §3): after the
first successful promotion, every subsequent attempt returns
`GN_ERR_LIMIT_REACHED` (the gate refuses `Peer → Peer`) and the
dispatcher exits without firing a duplicate event. Concurrent
callers race through the gate, exactly one wins.

If only `our_sent` is true and the peer never sends a valid
attestation, the connection stays at `Untrusted` indefinitely.
Plugins that gate behaviour on trust class observe `Untrusted` and
apply their own policy (`security-trust.md` §7). The kernel does
not enforce a wait-time bound at v1; consumers that need bounded
waiting close the connection through `host_api->disconnect`.

---

## 7. Per-connection state lifecycle

The dispatcher allocates per-connection state on the first call to
either §4 or §5. State is released when `notify_disconnect`
invokes the dispatcher's `on_disconnect(conn)` entry directly from
the kernel thunk (per `conn-events.md` §2a) — the call runs
before the `DISCONNECTED` event publish, so subscribers never
observe stale flags during their callback.

State entries do not survive `notify_disconnect`; a fresh
connection with a previously-used numeric id (after id reuse)
starts with no state.

---

## 8. Failure semantics

Every consumer-side failure (§5 steps 1–7) results in:

1. The envelope is dropped — not forwarded to any handler.
2. The metric named in the failing step is incremented.
3. The connection is closed via `notify_disconnect(conn, reason)`
   per `conn-events.md` §2a.

The peer observes the disconnect through
`GN_CONN_EVENT_DISCONNECTED`. Subscribers apply their own retry
policy at the connection layer; the dispatcher does not retry
attestation on the closed connection.

Producer-side failures abort the §4 sequence without setting
`our_sent`. The producer may fail at any of: composing the
payload (signature error from the device key), framing through
the active protocol layer, encrypting through the security
session, looking up the active transport, or writing to the
transport. Each step logs at warn level with the connection id
and an indicative reason; no metric is emitted (the abort is
silent at the metric level — operators see a session-keyed warn
line). The connection remains at `Untrusted` and may be retried
on a fresh session.

---

## 9. Out of scope at v1

- **Wait-time bound.** A hard time limit on the wait-for-peer-
  attestation window is not enforced. A future minor release may
  add it through the kernel-side timer infrastructure.
- **Live re-attestation.** Once `their_received_valid` is set,
  additional `0x11` envelopes on the same connection are dropped
  as replay (§5 step 3 — binding still matches but the dispatcher
  treats them as duplicates). A peer that wants to swap identity
  reconnects on a fresh session.
- **Attestation chains / multi-CA.** The cert is a single
  user-key signature over the device key. Hierarchical CA
  delegation (cf. SSH certs, X.509 chains) is post-v1.

---

## 10. Cross-references

- Attestation cert format and verification: `identity.md` §4.
- Trust upgrade gate fired by §6: `security-trust.md` §3.
- Channel-binding `handshake_hash` carrier: `noise-handshake.md` §2.
- System msg_id range: `handler-registration.md` §2a.
- Per-connection event surface for state cleanup: `conn-events.md` §2a.
