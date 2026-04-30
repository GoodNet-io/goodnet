# Contract: Noise Handshake

**Status:** active · v1
**Owner:** `plugins/security/noise/`
**Implements:** `gn_security_provider_vtable_t` from `sdk/security.h`
**Stability:** wire-incompatible changes require a new protocol-name suffix.

---

## 1. Purpose

This contract pins the cryptographic surface of the canonical
security provider: handshake patterns, hash function, buffer sizing,
and rekey semantics. Two Noise patterns are declared:

| Pattern | When used | Identity |
|---|---|---|
| `Noise_XX_25519_ChaChaPoly_BLAKE2b` | unknown peer, mutual auth | both sides Ed25519 keys |
| `Noise_IK_25519_ChaChaPoly_BLAKE2b` | initiator knows responder pk | both sides Ed25519, initiator preshared responder pk |

The protocol name string is the **on-wire** name; the implementation
**must** match it exactly. A name string that disagrees with the
actual hash function produces wire-incompatible peers — no external
Noise stack will interoperate.

---

## 2. Hash function

`BLAKE2b` (512-bit output, `HASHLEN = 64`) is mandatory across all three
patterns. The implementation **must**:

1. Match the protocol-name string (§1).
2. Produce 64-byte digests (`HASHLEN = 64`).
3. Pass the Noise reference test vectors for
   `Noise_XX_25519_ChaChaPoly_BLAKE2b` and
   `Noise_IK_25519_ChaChaPoly_BLAKE2b` — included in the property-test
   suite.

The choice of BLAKE2b over BLAKE2s comes from libsodium availability:
`crypto_generichash_blake2b` is the canonical primitive in our
dependency stack, BLAKE2s is not exposed. BLAKE2b is faster than BLAKE2s
on 64-bit platforms and provides a strictly larger security margin.

`HASHLEN = 64` is asserted at compile time. The cipher key size for the
ChaCha20-Poly1305 cipher is fixed at 32 bytes (`GN_CIPHER_KEY_BYTES`);
when the symmetric state derives a cipher key from a 64-byte chaining
material via `MixKey`, the first 32 bytes are taken per Noise spec §5.2.

The exposed `gn_handshake_keys_t::handshake_hash` field carries 32 bytes
for channel binding — the SDK ABI uses `GN_HASH_BYTES = 32` here, and
the plugin truncates the 64-byte `h` to its first 32 bytes on export.
Channel binding security is preserved (256-bit collision-resistance).

---

## 3. Handshake buffer sizing

The handshake state machine produces messages up to about 96 bytes
for `XX` and 80 bytes for `IK`. A fixed-size stack buffer paired with
an unbounded write call is unsafe — a peer who provokes an oversized
prologue triggers a stack-buffer overflow, an RCE-class hazard on any
public listener.

The contract: **handshake message buffers are heap-allocated and
size-bounded by the call site, not the source-code-fixed buffer
size.** The cost over a stack buffer is one allocation per handshake
message (~50 ns); negligible against the 1–10 ms the handshake
itself consumes for X25519 plus ChaCha20.

C ABI signatures **must not** accept a fixed-size output buffer
without an out-parameter for the actual length:

| Signature | Permitted |
|---|---|
| `noise_write(state, payload, payload_size, out_buf, out_cap, out_size*)` | yes — caller-provided cap, kernel-checked |
| `noise_write(state, payload, out_size)` writing into a hidden buffer | yes — opaque ownership, paired free |
| `noise_write(state, payload, out_buf)` — no cap, no out-size | **no** — unverifiable |

The first form is what we ship.

---

## 4. Rekey

Both transport ciphers (send and receive) rekey when nonce reaches
the threshold:

```
REKEY_INTERVAL = 2^60
```

Matching the WireGuard threshold. A lower interval would force rekey
on every bulk transfer and amplify any nonce-handling bug.

If `rekey()` did not reset the nonce on both ciphers atomically, two
peers running it mid-flight would diverge — sender on key `k+1`,
receiver still on `k` — and decrypt would silently fail until the
next explicit handshake.

The contract:

```
rekey():
    derive_next_keys(send_cipher, recv_cipher)
    send_cipher.nonce = 0
    recv_cipher.nonce = 0
```

Both ciphers rekey atomically with paired nonce reset.

### 4.1 Auto-trigger inside encrypt / decrypt

The provider checks the threshold inside every `encrypt` and
`decrypt` call after advancing the nonce. When either CipherState
crosses `REKEY_INTERVAL` the provider runs `rekey()` on the
`TransportState` before returning, so the next call to the same
slot sees the fresh keys and reset nonces.

Both peers reach the threshold symmetrically — every encrypt by
the local side advances the peer's recv counter by one, and the
recv counter rekeys at the same point. The two sides converge
without an out-of-band signal and without a kernel-managed
scheduler.

The `NoiseTransportRekey.SymmetricThresholdRekeyKeepsInterop`
test pushes both counters to one short of the threshold,
exchanges a frame on each direction, and asserts continued
decrypt against the fresh keys.

---

## 5. Key zeroisation

After `export_transport_keys` succeeds, the source session keys are
no longer needed. Leaving copies in memory after their purpose
expires weakens forward secrecy on every byte that outlives that
purpose.

The contract:

1. `export_transport_keys` zeroises every cipher key, nonce, and
   hash buffer in the source session after copying out.
2. After export, the source session's encrypt/decrypt entries return
   `GN_ERR_INVALID_STATE`. Reuse is rejected.
3. The inline-crypto state zeroises its own keys when destroyed.

How a language zeroises memory is internal to the binding (libsodium
`sodium_memzero` in C/C++; equivalent secure-erase primitives
elsewhere). The observable contract is that keys are not present in
process memory after the documented destruction point.

---

## 5a. `gn_handshake_keys_t` layout

The provider populates this struct in `export_transport_keys` and
zeroises its own copy on return. The caller reads the values once
to seed the transport-phase cipher state. The struct is
caller-allocated; the provider never retains a pointer past the
export call.

```c
#define GN_CIPHER_KEY_BYTES   32  /* ChaCha20 key */
#define GN_HASH_BYTES         32  /* channel-binding hash */
#define GN_PUBLIC_KEY_BYTES   32  /* peer Ed25519 public key */

typedef struct gn_handshake_keys_s {
    uint8_t  send_cipher_key[GN_CIPHER_KEY_BYTES];
    uint8_t  recv_cipher_key[GN_CIPHER_KEY_BYTES];
    uint64_t initial_send_nonce;
    uint64_t initial_recv_nonce;
    uint8_t  handshake_hash[GN_HASH_BYTES];
    uint8_t  peer_static_pk[GN_PUBLIC_KEY_BYTES];
    void*    _reserved[4];
} gn_handshake_keys_t;
```

| Field | Width | Purpose |
|---|---|---|
| `send_cipher_key` | 32 bytes | symmetric ChaCha20 key for outgoing frames |
| `recv_cipher_key` | 32 bytes | symmetric ChaCha20 key for incoming frames |
| `initial_send_nonce` | u64 | first nonce the inline-crypto path uses on send |
| `initial_recv_nonce` | u64 | first nonce the inline-crypto path expects on receive |
| `handshake_hash` | 32 bytes | channel-binding (BLAKE2b-256 over the symmetric-state `h` per §2); attestation §2 binds against this value |
| `peer_static_pk` | 32 bytes | peer's Ed25519 public key learned during handshake; the kernel uses it for routing decisions and trust upgrade |
| `_reserved[4]` | 32 bytes | NULL on init; size-prefix evolution per `abi-evolution.md` §4 |

## 6. Nonce initialisation

Inline-crypto state initialises send and receive nonces from
explicit fields in the handshake-result structure. Hard-coding the
initial value at construction would create a one-message gap between
the vtable-encrypt path (which uses the stored nonce) and the
inline-crypto path — a bug that hides on the steady state and
surfaces at rekey transitions.

The contract: every inline-crypto field that has a corresponding
`gn_handshake_keys_t::initial_*` field **must** be wired through.
If a field is always zero, it is removed from `gn_handshake_keys_t`
rather than left as unused state.

---

## 7. Wire format on the encrypted side

A Noise frame on the wire:

```
offset  size            field
------  --------------  --------------------------------------------------
  0     2               ciphertext length, big-endian uint16
  2     length - 16     ciphertext (ChaCha20-Poly1305 with associated data)
  N-16  16              authentication tag (Poly1305)
```

Length is a 16-bit unsigned because the post-decryption plaintext
(the GNET frame; see `gnet-protocol.md`) is bounded by the GNET
layer maximum. Larger payloads are pre-fragmented at the kernel
level before reaching the security layer.

The associated data is empty for v1 — the framing layer carries its
own MAC implicitly via the included header bytes inside the
ciphertext. A future v2 may introduce associated data for forward-
error-correction support; a `ver` bump in GNET (not Noise) signals
that.

---

## 8. Identity binding

The Ed25519 static keys used for Noise handshakes are the same keys
the mesh layer uses as addresses. There is no separate "transport
key" authority — `pk` is the address, the same `pk` is the Noise
static.

The address is an Ed25519 public key (32 bytes); the Noise suite
suffix `25519` denotes X25519 for Diffie-Hellman. Each side's static
key crosses curves at session initialisation — the security provider
applies the standard birational map (libsodium
`crypto_sign_ed25519_pk_to_curve25519` for the public half,
`crypto_sign_ed25519_sk_to_curve25519` for the secret half) before
the key enters the Noise state machine. The conversion is one-way and
lives inside the security provider; the kernel and handlers see only
the Ed25519 representation.

After a successful Noise handshake:

1. The transport called `host_api->notify_connect` at the moment
   the socket established, with `trust` derived from the address
   (per `transport.md` §3 — `Loopback` for `127.0.0.1`/`::1`/
   AF_UNIX, `Untrusted` for public). Trust class **stays
   `Untrusted`** when the handshake reaches the Transport phase —
   completing the cryptographic handshake proves the peer holds
   the static key but not that the kernel should treat the peer
   as a `Peer`-class participant. The promotion to `Peer` is
   gated by the attestation dual-flag protocol per
   `attestation.md` §6, which fires after both sides exchange a
   valid attestation envelope; `Loopback` and `IntraNode`
   connections never upgrade — `gn_trust_can_upgrade` in
   `sdk/trust.h` refuses any other transition.
2. The endpoint's `pk` is set to the peer's static public key,
   copied from the handshake-result structure.
3. Subsequent envelopes from this connection carry that `pk` as
   `sender_pk` (via the protocol layer's `ConnectionContext`).

Mid-flight identity change is impossible — ChaCha20-Poly1305 would
fail to authenticate any frame signed with a different static.

---

## 9. Cross-references

- TrustClass policy that gates this provider's use: `security-trust.md`.
- Frame layout that wraps Noise output: `gnet-protocol.md`.
- Handshake buffer ownership annotation: `abi-evolution.md` §6.
