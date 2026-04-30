# Contract: Connection Registry

**Status:** active · v1
**Owner:** `core/registry/connection.hpp`
**Last verified:** 2026-04-27
**Stability:** v1.x

---

## 1. Purpose

Connections are reachable by three keys: numeric id, URI, and public
key. Every key must point at the same record at every observable
instant — or at none. Without coordination, three separate locks
guarding three separate indexes admit a window in which a reader
observes one populated and the others empty between insertions.

This contract specifies a single atomic operation that updates all
indexes together, and a corresponding atomic erase.

---

## 2. The C ABI surface

The kernel side of the registry is opaque to plugins. Plugins observe
records through host-API entries (`host-api.md` §2):

| Entry | Returns |
|---|---|
| `find_conn_by_pk(pk, out_conn)` | `GN_OK` and a connection id, or `GN_ERR_UNKNOWN_RECEIVER` |
| `get_endpoint(conn, out_ep)` | endpoint snapshot — pk, uri, trust, transport scheme |

These reads do not lock the kernel side. Stale reads are acceptable
(the connection may close between read and use); the C ABI returns
the most recent snapshot the kernel has published.

---

## 3. Atomic insert

The single mutation operation `insert_with_index` carries the new
record together with all three keys and updates the three indexes
under one ordered lock acquisition. The operation **fails before any
mutation** if any key would collide.

Sequencing rules:

1. Acquire the shard mutex for `id`, the URI-index mutex, and the
   pk-index mutex in a fixed total order. The fixed order is the
   only deadlock-avoidance mechanism; concurrent inserts that need
   the same triple acquire it identically.
2. Verify each index is free of the proposed key. If any is taken,
   release all locks and return `GN_ERR_LIMIT_REACHED`. No partial
   state is visible.
3. Insert the record into the shard, point the URI index at it,
   point the pk index at it.
4. Release all locks.

The registry honours `gn_limits_t::max_connections` (`limits.md` §4a):
when the live record count is already at the cap, the insert returns
`GN_ERR_LIMIT_REACHED`. The check fires twice — first before any lock
is taken (fast-path rejection), then again under the triple lock to
close the race against a concurrent inserter that may have bumped the
counter between the pre-check and the lock acquisition. On rejection
no locks remain held, no key slot is consumed, the live count stays
unchanged.

Properties:

- **All-or-nothing.** Any insert that would collide on any key fails
  before any mutation.
- **No reader-visible intermediate state.** The three locks are held
  for the duration of the mutation; readers either see the record
  under all three keys or under none.
- **Deadlock-free.** Fixed acquisition order across all callers.

---

## 4. Atomic erase

`erase_with_index` mirrors insert in reverse. Sequence:

1. Acquire the same triple of mutexes in the same order.
2. Look up the record by id in the shard. If absent, release and
   return `GN_ERR_UNKNOWN_RECEIVER`.
3. Remove from URI index, pk index, then shard.
4. Release.

`get_endpoint` returns the `gn_endpoint_t` view by value at call time
(`host-api.md` §2). The registry exposes no cache-invalidation channel
to plugins: a consumer that retains a `gn_endpoint_t` past its
originating call holds a frozen copy whose source record may have
been erased. Consumers re-call `get_endpoint` whenever the live state
matters; long-lived per-conn cached state belongs in plugin-private
storage indexed by `conn_id` and pruned on the `DISCONNECTED` event
(`conn-events.md` §2a).

The erase primitive also exposes an atomic snapshot variant
(§4a) for callers that must publish a terminal lifecycle event
whose payload reflects the just-departed record state — chiefly
`notify_disconnect` (`conn-events.md` §2a).

---

## 4a. Atomic snapshot variant — specification

**Operation.** Atomic snapshot-and-erase of a record by id,
sharing the same triple-locked critical section as the atomic
erase of §4.

**Pre-conditions.** A caller-provided `gn_conn_id_t`. No prior
lookup is required and any prior `find_*` result must not be
relied upon — the variant performs its own lookup inside the
critical section.

**Effect.** Acquires the same triple of mutexes in the same
order as §3/§4. If the record is present, captures its
`gn_endpoint_t` view (`id`, `trust`, `remote_pk`, `uri`,
`transport_scheme`) and the per-connection counters from §8
into caller-owned storage, then removes the record from all
three indexes and the counter slot. Releases.

**Outcome.** This primitive is a kernel-internal C++ method, not
a C ABI surface (the registry is opaque to plugins per §2). Two
outcomes:

| Outcome | Meaning |
|---|---|
| snapshot populated | record was present; snapshot captured; record removed from all three keys |
| no record | no record matched `id` when the critical section started; registry state unchanged; snapshot buffer left untouched |

**Snapshot ownership.** The returned snapshot owns its own copy
of the URI string and the public-key bytes — kernel-side storage
holds no reference that outlives the call. Callers may retain
the snapshot freely after the registry record is gone.

**Atomicity.** Atomic with respect to any concurrent
`insert_with_index`, `erase_with_index`, atomic-snapshot, or
indexed read on the same id: between the start of the snapshot
capture and the completion of the erase, no other observer
finds the record under any of its three keys. Readers whose
lookup completed before the critical section started return
their captured snapshot normally.

**Counter consistency.** Counter loads are sequenced after every
counter write (§8) whose mutex release happened-before the
critical section's lock acquisition. Writes that completed
before the critical section started are observed; writes that
completed afterward are not (their target slot is removed). At
v1 the `last_rtt_us` field is written only when the heartbeat
handler is loaded — if it is not, the snapshot's `last_rtt_us`
is zero.

**Cross-shard concurrency.** Concurrent atomic-snapshot calls
against ids on different shards (`id mod 16`) overlap on the
shard step; both still serialise on the global URI and pk index
mutexes for the index erase. The fixed lock order from §3
prevents deadlock across all combinations.

---

## 5. Internal sharding

The registry is internally sharded by `id mod 16` across 16 shards.
This is the largest fan-out that does not contend on shard mutex
acquisition under sustained multi-Gbps load. The number is
implementation-internal; plugins do not depend on it.

---

## 6. One id source

**Connection ids are allocated only by the kernel.** Transports do
not invent their own. Where a transport-local correlator is needed
(e.g. ICE session id during gathering), it lives in transport-private
state and is mapped to the kernel-allocated id exactly once at
`notify_connect` time.

If a transport mints its own id while the kernel dispatches on the
externally-allocated id, every send through that transport is
silently dropped because the indexes disagree. The single-source rule
removes that class of failure by construction.

The two-phase plugin activation (`plugin-lifetime.md` §5) enforces
this indirectly: only the kernel side of the host API gives out ids.

---

## 7. Pk-index lookup performance

The relay handler needs a pk lookup on the receiver to decide direct
vs gossip. The pk index is a hash table keyed by the 32-byte public
key; the lookup is O(1) average and stays sub-microsecond at 10 000
connections under stress tests. A linear walk over the connection set
would be O(N) per relay frame and would dominate cost at scale.

---

## 8. `gn_endpoint_t` layout and counters

`get_endpoint(conn, &out)` writes a caller-allocated snapshot:

```c
#define GN_ENDPOINT_URI_MAX 256

typedef struct gn_endpoint_s {
    gn_conn_id_t      conn_id;
    uint8_t           remote_pk[GN_PUBLIC_KEY_BYTES];
    gn_trust_class_t  trust;
    char              uri[GN_ENDPOINT_URI_MAX];
    char              transport_scheme[16];

    uint64_t          bytes_in;
    uint64_t          bytes_out;
    uint64_t          frames_in;
    uint64_t          frames_out;
    uint64_t          pending_queue_bytes;
    uint64_t          last_rtt_us;

    void*             _reserved[4];
} gn_endpoint_t;
```

| Field | Width / contents | Source |
|---|---|---|
| `conn_id` | u64 — same as the lookup id | registry insertion |
| `remote_pk` | 32 bytes — peer's Ed25519 public key | `notify_connect` argument |
| `trust` | enum — current trust class | live; reflects upgrade state per `security-trust.md` §3 |
| `uri` | NUL-terminated, ≤ 255 bytes | transport-supplied at `notify_connect`; longer URIs truncate at the boundary |
| `transport_scheme` | NUL-terminated, ≤ 15 bytes | scheme provided by the transport plugin (`"tcp"`, `"udp"`, `"ws"`, `"ipc"`, …) |
| `bytes_in`, `bytes_out` | u64 — atomic snapshot | producer-site atomic update |
| `frames_in`, `frames_out` | u64 — atomic snapshot | producer-site atomic update |
| `pending_queue_bytes` | u64 — atomic snapshot | maintained by the send queue (see `limits.md` §6) |
| `last_rtt_us` | u64 — atomic snapshot | written by the heartbeat handler |
| `_reserved[4]` | NULL on call | size-prefix evolution per `abi-evolution.md` §4 |

The struct is caller-allocated and held inline; the kernel writes
the URI into the buffer rather than handing back a pointer into
registry storage. Pointers inside the struct (none in v1) would
follow the same caller-frame lifetime rule.

All counters are O(1) at the producer site. Aggregation paths read
them non-blockingly; no walk of any queue is required.

---

## 9. Cross-references

- Limits driving counter bounds: `limits.md`.
- TrustClass stored in record: `security-trust.md` §7.
- Endpoint projection of the record: `host-api.md` §2 (`get_endpoint`).
