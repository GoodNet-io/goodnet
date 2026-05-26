# Contract: Compressed-object envelope

**Status:** active · v1
**Owner:** `plugins/handlers/zstd_decompress/` + any sender that emits
           compressed frames into a GNET connection.
**Last verified:** 2026-05-25
**Stability:** v1.x; algo byte registry is append-only.

---

## 1. Purpose

A handler may compress an application payload before injecting it onto
a connection.  The receiving end must know — without decompressing —
which algorithm was used and which msg_id the decompressed bytes should
be routed to.  This contract defines the minimal envelope that carries
both pieces of information ahead of the compressed data.

This envelope is **not** a GNET framing extension.  It is an
application-level wrapper that rides as the `payload` field of an
ordinary GNET message.  The outer GNET `msg_id` (default `0x0701`)
is the "compressed-object" sentinel; the inner envelope carries the
real routing target.

---

## 2. Wire layout

```
Offset  Len  Field           Description
------  ---  -----           -----------
0       1    algo            Algorithm identifier (see §3).
1       4    target_msg_id   Big-endian uint32.  Routing target that the
                             handler injects the decompressed bytes under.
5       N    compressed_data Algorithm-specific compressed bytes.
```

Total fixed header: **5 bytes**.

The sender:
1. Serialises the application payload (arbitrary bytes).
2. Prepends the 5-byte header (algo + target_msg_id).  The header is
   **not** part of the data that gets compressed.
3. Compresses bytes `[5:]` — only the application payload.
4. Ships the completed envelope as the GNET payload under msg_id `0x0701`.

The receiver:
1. Validates `algo` before attempting decompression.
2. Reads `target_msg_id` from bytes `[1..4]`.
3. Decompresses bytes `[5..]`.
4. Injects the decompressed result under `target_msg_id`.

---

## 3. Algo byte registry

The algo byte and the `compression-set` capability TLV (type `0x0003`,
defined in `capability-tlv.en.md` §2.3) live in the same kernel-shipped
contract namespace, but they are semantically distinct: capability-set
advertises which algorithms a peer supports (bit-shaped), the algo byte
names which algorithm a single frame is encoded with (enum-shaped).
Numeric values may coincide for kernel-shipped allocations (ZSTD = `0x01`
in both spaces) — this is allocation convention, not an inferred
invariant.  Peers operating outside the kernel-shipped allocation
re-synchronise through the capability TLV exchange, not through
assumed value equality.

| Value | Symbol                    | Algorithm |
|-------|---------------------------|-----------|
| 0x00  | —                         | Reserved (invalid; reject frame) |
| 0x01  | `GN_COMPRESS_ENV_ZSTD`    | ZSTD (RFC 8878) |
| 0x02–0xFF | —                     | Reserved for future algorithms |

New values are allocated here and in `sdk/extensions/compress.h`
(`GN_COMPRESS_ENV_*` constants).  Unknown `algo` bytes MUST be rejected
with a log warning; the frame is dropped (consumed, not forwarded).

---

## 4. Outer msg_id assignment

The outer GNET `msg_id` that triggers a decompressing handler is
**not** standardised here — it is an operator configuration concern.
The default in `zstd_decompress` is `0x0701`; operators may choose a
different id as long as they configure both sender and receiver
consistently.

Inband `target_msg_id` is rejected by `host_api->inject(LAYER_MESSAGE)`
when it falls in the identity range (`system-handlers.en.md` §2; gates
`is_reserved_system_msg_id` and `is_identity_range_msg_id` at
`core/kernel/host_api/notifications.cpp:421-424`).  A compressed-object
envelope therefore cannot be used to route a payload into heartbeat,
attestation, identity-rotation, capability-blob, or 2FA channels —
the kernel rejects the inject call before decompression is even
attempted.

---

## 5. Constants

`sdk/extensions/compress.h` exports:

```c
#define GN_COMPRESS_ENV_ZSTD      0x01u   /* algo byte */
#define GN_COMPRESS_ENV_HDR_SIZE  5u      /* bytes 0..4 */
```

`sdk/cpp/capability_tlv.hpp` exports (for capability advertisement):

```cpp
inline constexpr std::uint16_t kTlvTypeCompressionSet = 0x0003u;
inline constexpr std::uint8_t  kCompressionSetZstd    = 0x01u;
```

---

## 6. Relation to capability-tlv.en.md

The compressed-object envelope is used only after both peers have
advertised the matching algorithm bit via `present_capability_blob`
(TLV type `0x0003`, bit 0 = ZSTD).  The capability negotiation itself
is described in [`capability-tlv.en.md`](capability-tlv.en.md) §2.3.

For device bridges (`raw_inject`, `ws_inject`) the sender is not a
GoodNet peer and capability blob exchange is not applicable.  Those
bridges use config-driven compression (`zstd_compress = true`) without
the envelope; the `zstd_decompress` handler is not needed on the bridge
side.

---

## 7. Scope: GNET-shaped carriers only

This contract assumes the carrier protocol layer delivers discrete
payloads addressed by a routing `msg_id`, as the GNET protocol layer
(`plugins/protocols/gnet/`) does.  A protocol layer that delivers
byte streams, differently-keyed envelopes, or non-routed datagrams
has nothing for the envelope's `target_msg_id` field to bind to and
is out of scope for v1.  Cross-protocol compression is not a goal
of this contract; another protocol layer that wants compression
registers its own handler with its own envelope shape.

---

## 8. Cross-references

- Outer GNET frame layout: [`protocol-layer.en.md`](protocol-layer.en.md).
- Capability advertisement: [`capability-tlv.en.md`](capability-tlv.en.md).
- Algorithm extension vtable: `sdk/extensions/compress.h`.
- Reference handler: `plugins/handlers/zstd_decompress/`.
