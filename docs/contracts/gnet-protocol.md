# Contract: GNET Protocol — Wire Format v1

**Status:** active · v1
**Owner:** `plugins/protocols/gnet/`
**Implements:** `IProtocolLayer` per `docs/contracts/protocol-layer.md`
**Last verified:** 2026-04-27
**Stability:** wire-incompatible changes require `ver` byte bump

---

## 1. Purpose

GNET is the canonical mesh-framing implementation for GoodNet v1.x. It maps
the kernel-side `gn_message_t` envelope to and from a compact byte format on
the wire. The format prioritises:

1. **Minimal overhead** for direct connections (no PK on wire when Noise
   handshake already authenticated peers).
2. **Self-describing length** to permit streaming parsers without out-of-band
   framing.
3. **Forward-evolution** through a single `ver` byte.

GNET sits **above** the security layer — bytes processed by `frame`/`deframe`
are already plaintext (post-Noise-decrypt on inbound, pre-Noise-encrypt on
outbound).

---

## 2. Frame layout

All multi-byte integers are **big-endian**.

### 2.1 Fixed header (always 14 bytes)

```
offset  size  field        value / meaning
------  ----  -----------  ----------------------------------------------
  0      4    magic        0x47 0x4E 0x45 0x54  ('G' 'N' 'E' 'T')
  4      1    ver          0x01 for this contract
  5      1    flags        bitfield, see §2.3
  6      4    msg_id       uint32 — routing target inside receiver
 10      4    length       uint32 — total frame size including this header
                           and any conditional fields below; up to but not
                           including next frame in stream.
```

### 2.2 Conditional fields (presence determined by `flags`)

```
offset  size  field           present when
------  ----  --------------  -------------------------------------------
 14     32    sender_pk       (flags & 0x01) != 0   — EXPLICIT_SENDER
 14|46  32    receiver_pk     (flags & 0x02) != 0   — EXPLICIT_RECEIVER
```

Order is fixed: `sender_pk` precedes `receiver_pk` when both are present.

### 2.3 `flags` byte semantics

```
bit  mask   name                  meaning
---  ----   --------------------  ----------------------------------------
 0   0x01   EXPLICIT_SENDER       sender_pk present on wire (relay,
                                  inject-external, broadcast originator)
 1   0x02   EXPLICIT_RECEIVER     receiver_pk present on wire (relay
                                  forwarding, multi-tenant target)
 2   0x04   BROADCAST             receiver is ZERO; sender_pk MUST be
                                  EXPLICIT_SENDER. EXPLICIT_RECEIVER MUST
                                  be 0 — receiver is implicit.
 3   0x08   reserved              MUST be 0 in v1
 4   0x10   reserved              MUST be 0 in v1
 5   0x20   reserved              MUST be 0 in v1
 6   0x40   reserved              MUST be 0 in v1
 7   0x80   reserved              MUST be 0 in v1
```

Reserved bits set on inbound → drop frame, metric `gnet.dropped.reserved_bit`,
no connection close (forward compat).

### 2.4 Payload

```
offset                  size                  field
----------------------  --------------------  -------------------
14 + cond_pk_size       length - header_size  payload
```

Where `cond_pk_size = 32 * popcount(flags & 0x03)` and
`header_size = 14 + cond_pk_size`.

Maximum `length` per frame: `2^16 = 65536` bytes (transport MTU constraint).
Values above are kernel-rejected even though `uint32` permits more — this
matches `IProtocolLayer::max_payload_size()` returning `65536 - header_size`.

---

## 3. Three encoding modes

### 3.1 Direct (most common, smallest)

Used when connection is a peer-to-peer Noise tunnel and both endpoints know
each other's PK from the handshake.

```
flags = 0x00
total = 14 bytes header + payload
sender_pk     = ctx.remote   (filled by deframe from ConnectionContext)
receiver_pk   = ctx.local.pk (filled by deframe from ConnectionContext)
```

Overhead: **14 bytes** per frame.

### 3.2 Broadcast

Used for gossip, heartbeat, neighbour-discovery messages.

```
flags = 0x01 | 0x04 = 0x05  (EXPLICIT_SENDER | BROADCAST)
total = 14 + 32 = 46 bytes header + payload
sender_pk on wire (originator, preserved across hops)
receiver_pk     = ZERO (implicit, kernel infers from BROADCAST flag)
```

Overhead: **46 bytes** per frame.

### 3.3 Relay-transit

Used by relay-extension when the transit node forwards on behalf of another
peer. End-to-end identity preserved.

```
flags = 0x01 | 0x02 = 0x03  (EXPLICIT_SENDER | EXPLICIT_RECEIVER)
total = 14 + 32 + 32 = 78 bytes header + payload
sender_pk on wire (origin, NOT rewritten by transit)
receiver_pk on wire (final destination)
```

Overhead: **78 bytes** per frame.

---

## 4. Parser state machine

```
state DECLARED:
    accumulate bytes until 14 received
    if magic != 'GNET' → kErrDeframeCorrupt
    if ver  != 0x01    → kErrDeframeCorrupt (peer ahead of us)
    if reserved bits set → drop frame, advance, log
    compute cond_pk_size from flags
    require: BROADCAST → EXPLICIT_SENDER && !EXPLICIT_RECEIVER
    transition → READING_BODY

state READING_BODY:
    accumulate bytes until total `length` received
    populate gn_message_t:
        - copy msg_id
        - sender_pk: from wire if EXPLICIT_SENDER else ctx.remote
        - receiver_pk:
            if BROADCAST → ZERO
            elif EXPLICIT_RECEIVER → from wire
            else → ctx.local.public_key
        - payload + payload_size: remaining bytes after conditional fields
    emit envelope, advance buffer cursor by `length`
    transition → DECLARED
```

Partial frames: deframer returns `bytes_consumed = 0` until at least one
complete frame is buffered. Kernel re-feeds with concatenated bytes.

---

## 5. Design notes

A few choices in the layout above are worth flagging for plugin
authors and future format successors:

- **Replay protection lives in the security layer.** Noise AEAD
  nonces already prevent replay, so GNET carries no per-frame
  packet id of its own.
- **Wire format is plugin-private.** The 14-byte header is not part
  of `sdk/protocol.h`. Handlers see only the decoded `gn_message_t`
  envelope (`protocol-layer.md`); they cannot import GNET-specific
  types.
- **Conditional PK fields enable relay and broadcast as first-class
  modes.** A direct connection pays no overhead for identity it
  already learned from the Noise handshake.

---

## 6. Versioning policy

- `ver = 0x01` for this contract.
- Wire-incompatible changes (field reorder, magic change, length-field
  semantic change): bump to `0x02`. Kernel built for `0x01` rejects `0x02`
  frames with `kErrDeframeCorrupt` — version negotiation belongs to a
  higher layer (capability handshake post-Noise).
- Wire-additive changes via reserved bits: same `ver`, bit becomes meaningful
  in newer impl, ignored-or-warned in older impl. Reserved bits are the
  evolution channel for non-breaking additions.

---

## 7. Out of scope (v1)

- **BATCHED frames** (multiple sub-frames in one wire frame) — deferred to v2.
  Saves header overhead at cost of partial-decode complexity. Revisit when
  measurements show framing overhead matters.
- **Header authentication beyond Noise** — Noise already MACs the entire
  ciphertext. A separate header signature is unnecessary at this layer.
- **Compression flag** — payload-content concern, lives above this layer.
- **Fragmentation** — transport layer responsibility (TCP segments naturally,
  UDP fragments via separate fragmentation header in transport).

---

## 8. Cross-references

- Kernel-side envelope semantics: `protocol-layer.md`.
- Security layer (Noise) wraps GNET frames: `noise-handshake.md`.
