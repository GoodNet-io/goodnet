# Cross-implementation test vectors

This directory ships known-answer test vectors for the wire-visible
crypto and framing primitives that GoodNet bindings in other
languages (Rust, Python, JavaScript, Go) must reproduce byte-for-byte
against the C++ reference implementation.

## Source of truth

The committed JSON files are the source of truth, not the
generators. A binding author writes a consumer in their language,
loads the JSON, replays the inputs through that language's
primitives, and asserts equality against the recorded outputs.

The kernel-side consumer test (`test_vectors_consume`) runs in
`nix run .#test` and pins the vectors against the C++ reference:
when a contract bump requires regenerating a vector, the consumer
flips red until the JSON is updated. That keeps the JSON
consistently in sync with the kernel.

## Files

| File | Source contract | Generator |
|---|---|---|
| `noise_xx.json` | `plugins/security/noise/docs/handshake.md` | `gen_noise_xx.cpp` |
| `gnet_wire.json` | `plugins/protocols/gnet/docs/wire-format.md` | `gen_gnet_wire.cpp` |
| `attestation.json` | `docs/contracts/attestation.en.md` | `gen_attestation.cpp` |
| `capability_blob.json` | `docs/contracts/capability-tlv.en.md` | `gen_capability_blob.cpp` |
| `pkcs11_sign.json` | `plugins/security/pkcs11/` (synthetic — SoftHSM unavailable) | `gen_pkcs11_sign.cpp` |

Every JSON file carries a `schema` field that identifies its layout
version (e.g. `"noise-xx/v1"`). When a wire format bump is necessary,
the schema string changes alongside the new layout — a binding can
refuse to consume an unfamiliar schema version cleanly.

## File-by-file schema

### `noise_xx.json` (schema `noise-xx/v1`)

`Noise_XX_25519_ChaChaPoly_BLAKE2b` handshake driven from
deterministic seeds.

| Field | Type | Meaning |
|---|---|---|
| `protocol_name` | string | Noise protocol-name string mixed into the symmetric state |
| `prologue` | string | UTF-8 prologue mixed in immediately after `InitializeSymmetric` |
| `init_static_sk` / `init_static_pk` | hex | initiator long-term X25519 keypair |
| `resp_static_sk` / `resp_static_pk` | hex | responder long-term X25519 keypair |
| `ephemeral_prng_seed` | hex | 32-byte seed for a ChaCha20-based PRNG used to mint ephemerals |
| `handshake_msg1_e` | hex | initiator's first message bytes (just `e`) |
| `handshake_msg2_e_ee_s_es` | hex | responder's reply (`e, ee, s, es`) |
| `handshake_msg3_s_se` | hex | initiator's third message (`s, se`) |
| `handshake_hash` | hex | 64-byte BLAKE2b output, channel-binding |
| `transport_init_send_key` / `transport_init_recv_key` | hex | post-`Split` cipher keys, initiator side |
| `transport_resp_send_key` / `transport_resp_recv_key` | hex | post-`Split` cipher keys, responder side |
| `transport_msg_plaintext` | hex | first transport plaintext sent initiator → responder |
| `transport_msg_ciphertext` | hex | first transport ciphertext (under `init.send`, nonce=0) |
| `transport_msg_nonce` | integer | nonce counter for the first transport message (`0`) |
| `transport_msg_aad` | string | empty per `plugins/security/noise/docs/handshake.md` §7 |

The PRNG must be ChaCha20 keyed by the seed, counter-encoded as
little-endian 8-byte nonce, blocks of 64 bytes consumed in order
across every `randombytes_buf` request. The C++ reference
implementation lives in `deterministic_random.hpp`.

### `gnet_wire.json` (schema `gnet-wire/v1`)

GNET v1 envelope encoding plus post-Noise transport encryption.

| Field | Type | Meaning |
|---|---|---|
| `magic` | string | always `"GNET"` (4 bytes ASCII) |
| `version` | integer | always `1` |
| `prologue` | string | informational; not on the wire here |
| `local_pk` / `remote_pk` / `third_party_pk` | hex | identity pks used to construct the connection context |
| `aead_key` | hex | 32-byte ChaCha20-Poly1305 IETF key, fixed for the vectors |
| `handshake_hash` | hex | informational; not part of the AEAD input |
| `aead` | string | `"ChaCha20-Poly1305-IETF"` |
| `aead_aad` | string | empty |
| `samples[i]` | object | one per shape (system / user-baseline / large-relay) |

Each `samples[i]` carries:

| Field | Meaning |
|---|---|
| `msg_id` | the GNET `msg_id` field |
| `mode` | one of `"direct"`, `"broadcast"`, `"relay-transit"` |
| `payload` | hex application payload |
| `frame_bytes` | hex; what `GnetProtocol::frame` returns (header + conditional PKs + payload) |
| `aead_nonce_counter` | integer; encoded as 4 zero bytes + LE 8-byte counter |
| `ciphertext` | hex; `ChaCha20-Poly1305-IETF(key=aead_key, nonce=encoded, ad="", plaintext=frame_bytes)` |

### `attestation.json` (schema `attestation/v1`)

232-byte attestation payload per `docs/contracts/attestation.en.md`
§2 (msg_id `0x11`).

| Field | Meaning |
|---|---|
| `user_seed` / `device_seed` / `peer_seed` | 32-byte Ed25519 seeds (`crypto_sign_seed_keypair`) |
| `user_pk` / `device_pk` / `peer_pk` | derived 32-byte Ed25519 public keys |
| `expiry_unix_ts` | int64 expiry encoded big-endian inside the cert |
| `handshake_hash` | 32-byte channel-binding (Noise XX output truncated to 32) |
| `cert_canonical_72` | 72 bytes that the user signs: `user_pk || device_pk || expiry_be64` |
| `cert_user_signature` | 64-byte Ed25519 signature over `cert_canonical_72` under `user_sk` |
| `cert_136` | 136-byte cert: `user_pk || device_pk || expiry_be64 || cert_user_signature` |
| `device_signature` | 64-byte Ed25519 signature over `(cert_136 || handshake_hash)` under `device_sk` |
| `payload_232` | wire payload: `cert_136 || handshake_hash || device_signature` |
| `verify_cert_under_user_pk` | `true` — self-check pinned in the JSON |
| `verify_signature_under_device_pk` | `true` — self-check pinned in the JSON |

### `capability_blob.json` (schema `capability-tlv/v1`)

Capability TLV blobs per `docs/contracts/capability-tlv.en.md`
(msg_id `0x13`). Each record is
`[type:u16 BE][length:u16 BE][value:length bytes]`.

| Field | Meaning |
|---|---|
| `samples[i].tag` | identifier — `empty`, `kernel_records`, `kernel_plus_core`, `with_unknown_application_type` |
| `samples[i].records[]` | list of `{ type, type_hex, value_len, value }` |
| `samples[i].blob` | encoded blob (records concatenated, no terminator) |
| `samples[i].wire_with_prefix` | `expiry_be64 || blob` — host_api transport form |

A consumer that does not understand a record type **must** skip the
record by advancing `length` bytes; the
`with_unknown_application_type` sample exercises that path.

### `pkcs11_sign.json` (schema `pkcs11-sign/v1`, status `deferred-real-token`)

Synthetic Ed25519 sign vectors. The committed signatures are
computed by libsodium's `crypto_sign_detached`, which is
bit-for-bit identical to a real CKM_EDDSA token output per
RFC 8032 §5.1.6 (the contract the pkcs11 plugin implements).

| Field | Meaning |
|---|---|
| `mechanism` | always `"CKM_EDDSA"` |
| `status` | `"deferred-real-token"` until a SoftHSM2-backed harness in CI replays the same `key_label` / `seed` pair and asserts equality |
| `samples[i].tag` | identifier |
| `samples[i].key_label` | CKA_LABEL the kernel-side plugin uses to locate the private key |
| `samples[i].seed` | 32-byte Ed25519 seed; the equivalent of provisioning the token with `softhsm2-util --import` |
| `samples[i].public_key` | derived public key |
| `samples[i].input_bytes` / `input_size` | bytes signed |
| `samples[i].signature` / `signature_size` | 64-byte raw signature |

A binding that integrates with a real SoftHSM2 token must:

1. Provision the token with each `seed` under its `key_label`.
2. Call `C_Sign` over `input_bytes`.
3. Assert the returned 64-byte signature equals `signature`.

## Hex encoding

All byte fields in the JSON are lower-case hex with no separators
and no `0x` prefix. The C++ encoder + decoder lives in
`hex_util.hpp`; equivalent helpers in other languages must accept
the same shape.

## Regenerating

The generators are built as part of the kernel cmake project but
are NOT auto-run by `nix run .#test`. To regenerate (after a
contract bump):

```sh
cmake --build build --target gen_noise_xx \
                              gen_gnet_wire \
                              gen_attestation \
                              gen_capability_blob \
                              gen_pkcs11_sign
./build/tests/vectors/gen_noise_xx        tests/vectors/noise_xx.json
./build/tests/vectors/gen_gnet_wire       tests/vectors/gnet_wire.json
./build/tests/vectors/gen_attestation     tests/vectors/attestation.json
./build/tests/vectors/gen_capability_blob tests/vectors/capability_blob.json
./build/tests/vectors/gen_pkcs11_sign     tests/vectors/pkcs11_sign.json
```

Then re-run the consumer:

```sh
ctest --test-dir build --output-on-failure -R VectorsNoiseXX
ctest --test-dir build --output-on-failure -R VectorsGnetWire
ctest --test-dir build --output-on-failure -R VectorsAttestation
ctest --test-dir build --output-on-failure -R VectorsCapabilityBlob
ctest --test-dir build --output-on-failure -R VectorsPkcs11Sign
```

A vector that fails to round-trip indicates a divergence between
the kernel implementation and the committed JSON — investigate
which side moved and (a) bump the schema string + regenerate if
the contract changed, or (b) fix the kernel back to match.

## Deferred vectors

- **PKCS#11 real-token vectors.** The current generator uses
  libsodium as a stand-in for a real `C_Sign` call because SoftHSM2
  is not in the v1 devShell. A future revision lands SoftHSM2 in
  the devShell, provisions a slot, drives the real `C_Sign` path,
  and asserts the resulting bytes match the committed signatures.
