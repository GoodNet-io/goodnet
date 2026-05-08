# Contract: Identity

**Status:** active · v1
**Owner:** `core/identity/`
**Last verified:** 2026-05-08
**Stability:** stable for v1.x. Mesh-address derivation, attestation
wire form, sub-key registry layout, and rotation-proof wire form
are all locked at the rc1 surface.

---

## 1. Purpose

Every GoodNet node has a 32-byte mesh address — the public key the
rest of the network uses to route to it. The address is **not**
arbitrary; it is derived from a two-component identity that
separates a long-term portable user keypair from a per-device
keypair, and a signed attestation binding the two together.

The result on the wire is one 32-byte public key. Plugins never
see the components; the kernel composes them, signs the
attestation, and exposes only the derived address through
`gn_ctx_local_pk` / `gn_ctx_remote_pk`.

---

## 2. Two-component identity

| Component | Purpose | Lifetime |
|---|---|---|
| **User keypair** (`KeyPair user`) | long-term portable identity; survives device replacement, backed up to user storage | years |
| **Device keypair** (`KeyPair device`) | per-machine identity; minted on the running node, never leaves it | months — until rotation |

Both components are Ed25519. The library treats them
symmetrically; the semantic distinction lives in storage and use,
not in cryptography.

`KeyPair` is move-only; secret bytes are zeroed on destruction so
a leaked instance does not leave key material in freed memory.
The libsodium layout — 32-byte seed prefix plus 32-byte public-key
suffix — is hidden inside the type; callers see opaque accessors.

---

## 3. Address derivation

The mesh address is HKDF-SHA256 keyed on `device_pk` alone, scoped
by a versioned salt:

```
address = HKDF(salt   = "goodnet/v1/device-address",
               input  = device_pk,
               len    = 32)
```

Properties:

- **Pure** — same `device_pk` always yields the same 32-byte
  address; different `device_pk` values produce different
  addresses under SHA-256 collision resistance.
- **Device-stable.** `user_pk` does **not** influence the mesh
  address. Rotating the user keypair leaves every live mesh
  address untouched and every live connection valid. Plugins
  reach the user-level identity through
  `host_api->get_peer_user_pk(conn)` (a separate API surface),
  not by reading bits out of the mesh address.
- **Versioned** — `kAddressDeriveSalt = "goodnet/v1/device-address"`.
  Salt deliberately differs from the legacy `goodnet/v1/address`
  so a v1-derived address (which mixed user_pk into the IKM)
  never collides with a v1-decouple address from the same
  device — peers reject the mismatch via attestation pin.
- **One-way** — given an address there is no efficient way to
  recover the device public key; rotating the device key
  produces a new address.

User-level identity rotation does not move the mesh address. The
mesh address moves only on **device replacement** — a freshly
generated `device_pk` produces a new address, and peers see the
transition as a new connection (handshake under the new address,
attestation rebinds the user_pk). Apps maintaining
**connectivity graphs by user_pk** therefore preserve all edges
through user-key rotation; they re-bind edges to a new mesh
address only on device replacement, where the move is the
desired observable.

---

## 4. Attestation

A 136-byte signed cert binds `(user_pk, device_pk, expiry)`:

| Offset | Size | Field |
|--------|------|-------|
| 0      | 32   | `user_pk`        |
| 32     | 32   | `device_pk`      |
| 64     | 8    | `expiry_unix_ts` (big-endian signed int64) |
| 72     | 64   | Ed25519 signature over the preceding 72 bytes |

The signature is produced by the user keypair over the first 72
bytes of the buffer. Verification:

1. Re-compute the signed prefix from the embedded fields.
2. `crypto_sign_verify_detached(signature, prefix, expected_user)`.
3. `expiry_unix_ts > now_unix_ts`.
4. The embedded `user_pk` matches the `expected_user` argument.

Any failure on those four checks rejects the cert; the kernel
does not promote the connection from `Untrusted` past the
attestation gate.

`Attestation::create(user, device_pk, expiry)` produces a cert;
`Attestation::verify(expected_user, now)` consumes one.

---

## 5. NodeIdentity

A running kernel holds one `NodeIdentity` for the single-tenant
case; it composes the user keypair, device keypair, attestation,
and derived address:

```cpp
class NodeIdentity {
    static Result<NodeIdentity> generate(int64_t expiry_unix_ts);
    static Result<NodeIdentity> compose(KeyPair&& user,
                                         KeyPair&& device,
                                         int64_t   expiry_unix_ts);

    const KeyPair&   user();
    const KeyPair&   device();
    const Attestation& attestation();
    const PublicKey& address();   // 32-byte derived mesh address
};
```

`generate` mints both keypairs randomly; `compose` accepts a
loaded user keypair plus a freshly minted device keypair (the
expected pattern when a long-term identity is restored from
backup on a new machine). Move-only; the secret material lives in
the kernel and never crosses the plugin boundary.

Multi-device deployments (post-1.0) compose several
`NodeIdentity` instances under one persistent user keypair —
each device produces a different address but presents the same
user component to peers, who can accept or reject per local
policy.

---

## 6. What plugins see

Plugins never see attestation bytes, never see the user keypair,
never see the device-key seed. The only identity surface they
read is the 32-byte public key returned by `gn_ctx_local_pk` and
`gn_ctx_remote_pk`. The kernel signs handshakes, verifies peer
attestations, and rotates secrets; the plugin sees only the
derived address.

A bridge plugin re-publishing foreign-system payloads through
`inject_external_message` carries the source connection's remote
pk into the envelope's `sender_pk`. This is correct behaviour —
the bridge holds no separate identity for the foreign system; the
payload is authenticated under whatever local node identity the
bridge is bound to.

---

## 6a. Identity rotation surface

The kernel exposes user-key rotation through two paths:

1. **Embedding-side `Kernel::set_node_identity(NodeIdentity)`** — the
   process owner replaces the entire identity object atomically
   through a `shared_ptr` swap on the `node_identity_` slot. Used
   by the operator binary at startup and by recovery flows that
   load a fresh identity from disk.
2. **Plugin-side `host_api->announce_rotation(valid_from)`** — a
   plugin (or app talking through the C ABI) rotates the
   user_pk while keeping the device_pk untouched. The kernel
   signs a `RotationProof`, persists the new identity, and pushes
   the proof on every live conn at trust >= Peer under msg_id
   `0x12`. Receivers verify and advance their pinned `user_pk`
   without disconnecting; full protocol in §10.

In-flight effects after a `host_api->announce_rotation`:

| Surface | Effect |
|---|---|
| Live transport connections | survive — device-derived mesh address (§3 decouple) does not move |
| `peer_pin_map[remote_pk].user_pk` on peers | advances atomically through `apply_rotation` after proof verifies |
| `GN_CONN_EVENT_IDENTITY_ROTATED` on each conn | fired so apps update connectivity-graph edges |
| Plugin-visible `gn_ctx_local_pk` (mesh address) | unchanged |
| Built-in user_pk-purpose signing (`sign_local(ASSERT)` etc) | uses the new key |
| `rotation_history_` on local identity | gains the just-signed entry |

Effects after `Kernel::set_node_identity`:

| Surface | Effect |
|---|---|
| New connections | open with the swapped device key; mesh address derived per §3 |
| Existing transport-phase connections | retain the keys they negotiated under the prior identity; the kernel does not interrupt them |
| Pending handshakes | sample `node_identity()` at handshake start; whichever value the atomic load returned wins for that session |
| Plugin-visible `gn_ctx_local_pk` | tracks the kernel's current identity at the time the dispatch context was built |

---

## 7. Sub-key registry

Beyond the built-in `(user_pk, device_pk)` pair, NodeIdentity
holds a per-purpose registry of additional Ed25519 keypairs.
Plugins drive registration and signing through host_api slots
(§8); private bytes never leave the kernel.

`gn_key_purpose_t` (`sdk/identity.h`):

| Value | Symbol | Default mapping |
|---|---|---|
| 1 | `AUTH` | device_pk (handshake) |
| 2 | `ASSERT` | user_pk (sign claims about self) |
| 3 | `KEY_AGREEMENT` | device_pk (X25519 ECDH) |
| 4 | `CAPABILITY_INVOKE` | sub-key — sign RPC requests |
| 5 | `ROTATION_SIGN` | user_pk (sign next-pk in chain) |
| 6 | `SECOND_FACTOR` | sub-key — user-level 2FA |
| 7 | `RECOVERY` | sub-key — offline backup |

Multiple sub-keys per purpose are allowed; `sign_local(purpose)`
picks the first registered match. `sign_local_by_id(id)` is the
explicit selector.

The on-disk identity file (4-byte `"GNID"` magic + version 1
+ flags + expiry + user_seed + device_seed) carries the sub-key
seeds, the rotation counter, and the rotation history. File is
`0600` and reproduces deterministically from the seed bytes.

---

## 8. Plugin-visible host_api surface

Identity-bearing slots in `host_api_t`:

| Slot | Purpose |
|---|---|
| `register_local_key(purpose, label, &id)` | mint sub-key |
| `delete_local_key(id)` | remove sub-key, zeroise |
| `list_local_keys(out_array, cap, &count)` | enumerate descriptors |
| `sign_local(purpose, payload, sig)` | sign with first matching key |
| `sign_local_by_id(id, payload, sig)` | sign with specific key |
| `get_peer_user_pk(conn, out_pk)` | peer's pinned user_pk |
| `get_peer_device_pk(conn, out_pk)` | peer's pinned device_pk |
| `get_handshake_hash(conn, out)` | noise handshake hash |
| `present_capability_blob(conn, blob, size, expires)` | ship cred |
| `subscribe_capability_blob(cb, ud, ud_destroy, &id)` | receive |
| `announce_rotation(valid_from)` | rotate user_pk |
| `unsubscribe(id)` | remove subscription |

Plugin **never** sees private bytes. `sign_local` performs the
operation in the kernel and returns the 64-byte detached
signature.

---

## 9. Reserved msg_id range

The kernel reserves `0x10..0x1F` for identity-bearing transport
under `core/kernel/system_handler_ids.hpp`:

| Id | Use | Surface |
|---|---|---|
| `0x11` | Attestation (`attestation.en.md` §3) | hard-reserved (kernel-internal) |
| `0x12` | Identity rotation announce (§7 above) | kernel-internal (intercepts) |
| `0x13` | Capability blob | kernel-internal (intercepts + bus) |
| `0x14` | User-level 2FA challenge | plugin-registerable |
| `0x15` | User-level 2FA response | plugin-registerable |

Plugins **cannot** synthesise any id in the range through the
inject boundary (`is_identity_range_msg_id` rejects). Legitimate
identity traffic flows through `host_api->send` (carrying the
originating plugin's anchor) or the dedicated typed slots
(`present_capability_blob`, `announce_rotation`).

---

## 10. Rotation continuity

When a user-key rotation happens, every live transport survives
because the mesh address is device-derived (§3 decouple). The
proof's wire format is fixed at 150 bytes:

```
0   4   magic   = "GNRX"
4   1   version = 0x01
5   1   flags   = reserved 0
6   32  new_user_pk
38  32  prev_user_pk
70  8   counter (BE64, monotonic per prev_user_pk — anti-replay)
78  8   valid_from_unix_ts (BE64, signed)
86  64  Ed25519 signature by prev_user_pk over SHA-256(0..85)
```

Sender flow (`announce_rotation` thunk):

1. Mint a fresh user keypair.
2. Bump local rotation counter.
3. Sign the proof with the **old** user keypair.
4. Persist the new identity (counter + history + sub-keys) to
   the on-disk file via `NodeIdentity::save_to_file`.
5. Send the proof on every conn at trust >= Peer under msg_id
   `0x12`.

Receiver flow (kernel-internal handler in `notify_inbound_bytes`):

1. Look up the peer's pinned `user_pk` in
   `peer_pin_map_[remote_pk]`.
2. Call `verify_rotation(payload, expected_prev_user_pk)`. The
   anti-confusion gate refuses proofs whose embedded
   `prev_user_pk` does not match the expected pin.
3. Call `ConnectionRegistry::apply_rotation(remote_pk,
   new_user_pk, counter)`. The registry rejects with
   `INVALID_ENVELOPE` when the counter does not strictly exceed
   the stored value (replay defence). On success the pin
   advances atomically.
4. Fire `GN_CONN_EVENT_IDENTITY_ROTATED` on the conn-event
   channel; the event borrows pointers to the prev / new
   user_pk and the counter through `_reserved[0..2]`.

App-level effect: subscribers update connectivity-graph edges
keyed by user_pk without observing a transport disconnect. The
device_pk and the live noise session keep running.

---

## 11. Cross-references

- TrustClass policy that gates attestation use: `security-trust.md`.
- Curve conversion (Ed25519 → X25519) for Noise DH: `plugins/security/noise/docs/handshake.md` §8.
- Connection accessors that return 32-byte public keys:
  `protocol-layer.md` §3.1.
