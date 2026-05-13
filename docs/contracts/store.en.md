# Contract: Store handler

**Status:** active · v1.0.0-rc1
**Owner:** `plugins/handlers/store/`
**Last verified:** 2026-05-13
**Stability:** v1.x; wire layout below is locked, the `IStore`
              backend interface may grow new methods through
              size-prefix evolution.

---

## 1. Purpose

A distributed key-value database surfaced as a system handler. The
legacy `apps/store` layer (a routing layer that doubled as a TTL'd
KV store with prefix queries, subscribe-and-notify on writes, and
multi-node sync) is brought forward as a v1 handler plugin so an
operator can let nodes publish + observe small records (peer
descriptors, service announcements, capability advertisements,
metrics) without standing up an external DB.

The handler owns a pluggable `IStore` backend (memory reference
in slice 1; sqlite + DHT + Redis planned) and a wire dispatcher
that maps the seven `STORE_*` envelope types onto the backend.
Local callers reach the same surface through the
[`gn.store`](../../sdk/extensions/store.h) extension vtable —
no wire framing, no conn-id needed.

---

## 2. Surface

### 2.1 Extension vtable

```c
gn_store_api_t* api = host_api->query_extension_checked(
    "gn.store", GN_EXT_STORE_VERSION, sizeof(gn_store_api_t));

api->put(api->ctx, "peer/alice", 11,
         pubkey, 32, /*ttl_s*/ 0, /*flags*/ 0);
```

Eight slots: `put / get / query / del / subscribe / unsubscribe /
cleanup_expired` plus the `ctx`/`_reserved` ABI footer.
`query` covers exact / prefix / since-timestamp modes through a
single entry-emitting callback.

### 2.2 Wire surface

Seven envelopes under `protocol_id = "gnet-v1"`:

| `msg_id` | Direction | Envelope |
|---|---|---|
| `0x0600` | client → server | `STORE_PUT` |
| `0x0601` | client → server | `STORE_GET` |
| `0x0602` | server → client | `STORE_RESULT` |
| `0x0603` | client → server | `STORE_DELETE` |
| `0x0604` | client → server | `STORE_SUBSCRIBE` |
| `0x0605` | server → subscriber | `STORE_NOTIFY` |
| `0x0606` | symmetric | `STORE_SYNC` |

These ids are outside the kernel-reserved `0x10..0x1F` range (see
[`system-handlers.md`](system-handlers.en.md) §2); the allocation
is inherited from the legacy `apps/store` wire layer so existing
observers keep their decoders.

---

## 3. Wire layout

All multi-byte integers are big-endian. Lengths cap at
`GN_STORE_KEY_MAX_LEN = 256` (key) and
`GN_STORE_VALUE_MAX_LEN = 65_536` (value).

### 3.1 `STORE_PUT` (`0x0600`)

| offset | size | field |
|---|---|---|
| 0 | 8 | `request_id` (caller-correlation token) |
| 8 | 8 | `ttl_s` (0 = permanent) |
| 16 | 1 | `flags` (opaque to the backend) |
| 17 | 1 | reserved (zero) |
| 18 | 2 | `key_len` (≤ 256) |
| 20 | 4 | `value_len` (≤ 65 536) |
| 24 | `key_len` | key bytes |
| 24+kl | `value_len` | value bytes |

### 3.2 `STORE_GET` (`0x0601`)

| offset | size | field |
|---|---|---|
| 0 | 8 | `request_id` |
| 8 | 1 | `query_mode` (0=exact, 1=prefix, 2=since) |
| 9 | 1 | reserved (zero) |
| 10 | 2 | `max_results` (clamped at `GN_STORE_QUERY_MAX_RESULTS = 256`) |
| 12 | 4 | reserved (zero) |
| 16 | 8 | `since_us` (μs since epoch; mode=2 only) |
| 24 | 2 | `key_len` |
| 26 | 2 | reserved (zero) |
| 28 | `key_len` | key / prefix bytes |

### 3.3 `STORE_RESULT` (`0x0602`)

| offset | size | field |
|---|---|---|
| 0 | 8 | `request_id` (echoed from the request) |
| 8 | 1 | `status` (0=ok, 1=bad-size, 2=not-found, 3=backend-error) |
| 9 | 1 | reserved (zero) |
| 10 | 2 | `entry_count` (0 for PUT/DELETE acks) |
| 12 | ... | `entry_count` × Entry record (§3.6) |

### 3.4 `STORE_DELETE` (`0x0603`)

| offset | size | field |
|---|---|---|
| 0 | 8 | `request_id` |
| 8 | 2 | `key_len` |
| 10 | 6 | reserved (zero) |
| 16 | `key_len` | key bytes |

### 3.5 `STORE_SUBSCRIBE` (`0x0604`)

Same shape as `STORE_DELETE` plus a query-mode byte:

| offset | size | field |
|---|---|---|
| 0 | 8 | `request_id` |
| 8 | 1 | `query_mode` (0=exact, 1=prefix; since is invalid) |
| 9 | 1 | reserved (zero) |
| 10 | 2 | `key_len` |
| 12 | 4 | reserved (zero) |
| 16 | `key_len` | key bytes |

### 3.6 Entry record

A single record on the wire (used by `STORE_RESULT`,
`STORE_NOTIFY`, `STORE_SYNC` payloads):

| offset | size | field |
|---|---|---|
| 0 | 8 | `timestamp_us` |
| 8 | 8 | `ttl_s` |
| 16 | 1 | `flags` |
| 17 | 1 | reserved (zero) |
| 18 | 2 | `key_len` |
| 20 | 4 | `value_len` |
| 24 | `key_len` | key bytes |
| 24+kl | `value_len` | value bytes |

### 3.7 `STORE_NOTIFY` (`0x0605`)

| offset | size | field |
|---|---|---|
| 0 | 8 | `timestamp_us` (notification dispatch time) |
| 8 | 1 | `event` (0=PUT, 1=DELETE) |
| 9 | 1 | reserved (zero) |
| 10 | ... | one Entry record (§3.6) |

### 3.8 `STORE_SYNC` (`0x0606`)

Request and reply share the header; the reply appends entries.

| offset | size | field |
|---|---|---|
| 0 | 8 | `request_id` |
| 8 | 8 | `since_us` |
| 16 | 2 | `max_results` |
| 18 | 2 | `entry_count` (0 on request; N on reply) |
| 20 | ... | `entry_count` × Entry record (§3.6) |

---

## 4. Backend contract

Each method is **synchronous and called from a single thread** —
the handler funnels every call through one mutex so the backend
sees serialised access. Backends MAY ignore their own locking.

The reference `MemoryStore` ships in-tree. Future backends:

| Backend | Persistence | Notes |
|---|---|---|
| `MemoryStore` (this slice) | none | hash-map; loses state across restart |
| `SqliteStore` (planned, slice 2) | file | prepared stmts; production reference |
| `DhtStore` (planned) | distributed | Kademlia over GoodNet itself |
| `RedisStore` (planned) | external | clustered, hot failover |

---

## 5. Behavioural rules

- **No empty keys.** `put("", ...)` returns -1 / status=bad-size.
- **Duplicate puts overwrite** with a fresh `timestamp_us` —
  `subscribe` sees a single `PUT` event.
- **TTL is wall-clock**, not steady-clock: entries cross the wire
  through SYNC and the time anchor must agree across nodes.
  Operators that need monotonic semantics use `flags` to tag
  records they post-process on read.
- **`cleanup_expired` is reactive**, not background: callers
  invoke it (typically through a kernel timer) when they want
  expired entries dropped. Slice 1 ships no automatic cleanup
  driver.
- **`get_prefix` is unordered.** The reference backend iterates
  the hash-map; future ordered backends MAY guarantee an order
  but slice-1 callers cannot rely on it.
- **Subscriptions are per-conn for wire callers**, per-cb for
  in-process callers. Wire subscriptions die with the conn
  through `PerConnMap`-style cleanup (planned, slice 2).
- **The handler is `priority = 200`** — below identity-bearing
  system handlers (240+) but above application handlers (default
  128). Adjust via plugin manifest if a node hosts a handler
  that wants STORE envelopes to land first.

---

## 6. Cross-references

- Extension ABI: [`sdk/extensions/store.h`](../../sdk/extensions/store.h)
- Reference implementation: `plugins/handlers/store/`
- Reserved-id semantics:
  [`handler-registration.md`](handler-registration.en.md) §2a +
  [`system-handlers.md`](system-handlers.en.md) §1
- Legacy origin (archived):
  `~/Desktop/projects/GoodNet_legacy/apps/store/`
