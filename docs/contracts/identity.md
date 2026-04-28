# Contract: Identity

**Status:** active · v1
**Owner:** `core/identity/`
**Stability:** stable for v1.x; the wire form of an attestation
is part of the v1 mesh-address scheme and bumps the
`kAddressDeriveSalt` constant on any breaking change.

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

The mesh address is HKDF-SHA256 over the concatenation of
`user_pk || device_pk`, scoped by a versioned salt:

```
address = HKDF(salt = "goodnet/v1/address",
               input  = user_pk || device_pk,
               len    = 32)
```

Properties:

- **Pure** — same input pair always yields the same 32-byte
  address; different pairs produce different addresses under
  SHA-256 collision resistance.
- **Versioned** — `kAddressDeriveSalt = "goodnet/v1/address"`. A
  hypothetical v2 changes the salt rather than the input material
  so a v1 peer cannot mistake a v2 derivation for one of its own.
- **One-way** — given an address there is no efficient way to
  recover either component pk; rotating the device key produces a
  new address.

Address rotation under the same user keypair therefore changes the
address; this is the contract — peers must look up addresses by
key, not cache them across rotations.

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

## 7. Cross-references

- TrustClass policy that gates attestation use: `security-trust.md`.
- Ed25519 keys carried in the Noise handshake: `noise-handshake.md`.
- Connection accessors that return 32-byte public keys:
  `protocol-layer.md` §3.1.
