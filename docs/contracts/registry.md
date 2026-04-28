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
   return `GN_ERR_UNKNOWN`.
3. Remove from URI index, pk index, then shard.
4. Release.

The erase operation publishes a deletion-generation increment on the
`gn_endpoint_t` snapshot stream so that plugin-side cached endpoint
references can detect that they refer to a deleted record.

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

If a transport mints its own id while the orchestrator dispatches on
the externally-allocated id, every send through that transport is
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

## 8. Per-connection counters

The `gn_endpoint_t` snapshot exposes per-connection counters via the
host API:

| Counter | Source |
|---|---|
| `bytes_in`, `bytes_out` | producer-site atomic update |
| `frames_in`, `frames_out` | producer-site atomic update |
| `pending_queue_bytes` | maintained by the send queue (see `limits.md` §6) |
| `last_rtt_us` | written by the heartbeat handler |

All counters are O(1) at the producer site. Aggregation paths read
them non-blockingly; no walk of any queue is required.

---

## 9. Cross-references

- Limits driving counter bounds: `limits.md`.
- TrustClass stored in record: `security-trust.md` §7.
- Endpoint projection of the record: `host-api.md` §2 (`get_endpoint`).
