# Contract: Noise Handshake

**Status:** active · v1
**Owner:** `plugins/security/noise/`
**Implements:** `ISecurityProvider` (contract TBD in `security-provider.md`)
**Last verified:** 2026-04-27
**Stability:** wire-incompatible changes require a new protocol-name suffix.

---

## 1. Purpose

This contract pins the cryptographic surface of the canonical
security provider: handshake patterns, hash function, buffer sizing,
and rekey semantics. Three Noise patterns are declared:

| Pattern | When used | Identity |
|---|---|---|
| `Noise_XX_25519_ChaChaPoly_BLAKE2s` | unknown peer, mutual auth | both sides Ed25519 keys |
| `Noise_IK_25519_ChaChaPoly_BLAKE2s` | initiator knows responder pk | both sides Ed25519, initiator preshared responder pk |
| `Noise_NK_25519_ChaChaPoly_BLAKE2s` | initiator anonymous | responder Ed25519 key only |

The protocol name string is the **on-wire** name; the implementation
**must** match it exactly. A name string that disagrees with the
actual hash function produces wire-incompatible peers — no external
Noise stack will interoperate.

---

## 2. Hash function

`BLAKE2s` (256-bit output) is mandatory across all three patterns.
The implementation **must**:

1. Match the protocol-name string (§1).
2. Produce 32-byte digests (`HASHLEN = 32`).
3. Pass the Noise reference test vectors for
   `Noise_XX_25519_ChaChaPoly_BLAKE2s` — both included in the
   property-test suite.

`HASHLEN = 32` is asserted at compile time. If a future protocol
switches to BLAKE2b-512, that creates a new suffix string (`_BLAKE2b`)
and a new plugin variant (e.g. `noise-blake2b-v1`); existing peers
continue on the BLAKE2s suite during the transition.

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

Both ciphers rekey atomically with paired nonce reset. The pre-RC
test suite includes a stress run that triggers `rekey()` on both
ends within microseconds of each other and asserts continued decrypt.

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

After a successful Noise handshake:

1. The transport calls `host_api->notify_connect` with
   `trust = GN_TRUST_PEER` per `security-trust.md` §3.
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
