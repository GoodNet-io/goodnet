# Contract: Capability TLV

**Status:** active · v1
**Owner:** every plugin that exchanges capability state with a peer
            (heartbeat, discovery plugins, future companion handlers)
**Last verified:** 2026-04-28
**Stability:** v1.x; type registry grows append-only.

---

## 1. Purpose

After the Noise handshake reaches the Transport phase, peers
need to learn which optional features the other side supports.
The set is open — peers gain new transport schemes, protocol
layers, and discovery handlers across releases — and shipping a
fixed bitmap means every new capability bumps a wire version.

This contract pins a **TLV-of-bitmap** format: a list of
type-length-value records where the value of each record is a
small bitmap belonging to a single capability *category*. The
type field selects the category; the bitmap inside the value is
versioned independently. New capabilities slot into existing
categories' bitmaps; new categories slot in as new types — both
extensions are wire-additive, no version bump required.

The blob is exchanged in-band over the secured GNET channel
once the handshake completes — it rides as the payload of an
application message under reserved msg_id `0x13`
(`identity.md` §9). The kernel itself does not encode or decode
the blob — plugins encode and decode it through the header-only
`sdk/cpp/capability_tlv.hpp`. Two dedicated host_api slots front
the transport:

```c
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
```

Sender-side: `present_capability_blob` prefixes the user-supplied
bytes with an 8-byte big-endian `expires_unix_ts` and ships the
result through the regular send path (kernel queue + drain +
AEAD). Hard cap on blob size:
`gn_limits_t::max_capability_blob_bytes` (default 16 KiB; 0
disables). A blob exceeding the cap returns
`GN_ERR_PAYLOAD_TOO_LARGE` and bumps
`drop.capability_blob_too_large`.

Receiver-side: the kernel intercepts msg_id `0x13` in
`notify_inbound_bytes`, parses the expiry prefix, and fans the
remaining bytes out to every subscriber via
`CapabilityBlobBus`. `ud_destroy(user_data)` runs once on
`unsubscribe(id)` or kernel teardown so plugins do not leak
their callback state.

---

## 2. Wire format

```
record := type:u16  length:u16  value:length-bytes
blob   := record record record …
```

Both `type` and `length` are big-endian. The blob is a
concatenation of records with no terminator — the consumer reads
records until the byte stream ends. A length of zero is legal and
denotes an empty value.

`length` is bounded by `gn_limits_t::max_payload_bytes` — the
record sits inside one GNET frame.

### Reserved type ranges

| Range | Owner |
|---|---|
| `0x0000 – 0x00ff` | reserved for kernel-emitted records |
| `0x0100 – 0x01ff` | _reserved_; the allocation table below holds it for future cross-cutting families |
| `0x0200 – 0x0fff` | core plugins (heartbeat, discovery, future companion handlers) |
| `0x1000 – 0x7fff` | application records |
| `0x8000 – 0xffff` | experimental, **not** to be relied on across releases |

Allocations within the kernel and core ranges land in this
contract, alphabetised by name to make merge conflicts loud.

### Initial allocations

| Type | Name | Value layout |
|---|---|---|
| `0x0000` | `transport-set` | bitmap of `1u << GN_LINK_CAP_*` for each transport scheme the peer can speak; `1u << 31` reserved |
| `0x0001` | `protocol-set` | bitmap of supported `gn.protocol.<name>` slugs in declaration order; `protocol-list` (type `0x0002`) carries the canonical ordering |
| `0x0002` | `protocol-list` | UTF-8 newline-separated list of protocol names; the index into the list is the bit position in `protocol-set` |
| `0x0100 – 0x01ff` | _reserved_ | do not allocate; the range is held for future cross-cutting families |
| `0x0200` | `heartbeat-interval-ms` | u32 big-endian; the peer's preferred PING cadence |

A consumer that receives an unknown type **must** skip the record
(advance by `length`) and continue parsing. This is what makes
the format additive: a peer that learned about a record after the
release the receiver was built against is harmless to the
receiver.

---

## 3. Encoder / decoder

The SDK ships a header-only helper at `sdk/cpp/capability_tlv.hpp`
with two free functions:

```cpp
namespace gn::sdk {

[[nodiscard]] std::expected<std::vector<std::uint8_t>, TlvError>
encode_tlv(std::span<const TlvRecord> records);

[[nodiscard]] std::expected<std::vector<TlvRecord>, TlvError>
parse_tlv(std::span<const std::uint8_t> blob);

}  // namespace gn::sdk
```

`TlvRecord` carries `{ type: u16, value: vector<uint8_t> }`.
`encode_tlv` rejects records whose `value.size()` exceeds 65535
bytes. `parse_tlv` rejects truncated input (a length that runs
past the blob) and reports the byte offset of the failed record.

Both helpers are pure functions — they touch no kernel state — so
plugins call them from any thread.

---

## 4. Empty blob is legal

A v1.0 baseline build that registers no optimiser plugins emits
an empty blob. The peer parses it as zero records and sees the
peer as supporting only the implicit baseline (every transport /
protocol / security combination both sides speak natively).

---

## 5. No size cap on the blob

The TLV blob is bounded only by the GNET frame ceiling
(`plugins/protocols/gnet/docs/wire-format.md` §3). A blob that crosses that ceiling needs
fragmentation, which the post-Noise handshake handler is welcome
to implement; the contract here scopes only the one-frame case.

---

## 6. Cross-references

- Frame layer that wraps the blob: `plugins/protocols/gnet/docs/wire-format.md`.
- Transport capability flags referenced by `transport-set`:
  `sdk/extensions/link.h` (`GN_LINK_CAP_*`).
- Limits the value size honours: `limits.md` §2
  (`max_payload_bytes`).
