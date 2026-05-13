# Contract: DNS handler

**Status:** active · v1.0.0-rc1
**Owner:** `plugins/handlers/dns/`
**Last verified:** 2026-05-13
**Stability:** v1.x; wire layout below is locked, the `IDnsBackend`
              backend interface may grow new methods through
              size-prefix evolution.

> Not to be confused with [`hostname-resolver.md`](hostname-resolver.en.md),
> the SDK helper that rewrites `tcp://example.com:443` into an IP
> literal at connect time. That helper resolves URI hosts; this
> handler is a networked TTL'd key-value database that nodes use
> to publish + discover records. The name reflects the surface
> the legacy `goodnetd-dns` binary exposed.

---

## 1. Purpose

A distributed, TTL'd key-value database surfaced as a system
handler. Nodes publish records under string keys and other nodes
subscribe + sync them. The legacy `apps/store` layer (a routing
layer that doubled as a KV store with prefix queries, subscribe-
and-notify on writes, and multi-node sync) is brought forward as
a v1 handler plugin so an operator can let nodes publish + observe
small records — peer descriptors, service announcements,
capability advertisements, metrics — without standing up an
external DB.

The handler owns a pluggable `IDnsBackend` backend (memory
reference in slice 1; sqlite reference in slice 2; DHT + Redis
planned) and a wire dispatcher that maps the seven `DNS_*`
envelope types onto the backend. Local callers reach the same
surface through the [`gn.dns`](../../sdk/extensions/dns.h)
extension vtable — no wire framing, no conn-id needed.

---

## 2. Surface

### 2.1 Extension vtable

```c
gn_dns_api_t* api = host_api->query_extension_checked(
    "gn.dns", GN_EXT_DNS_VERSION, sizeof(gn_dns_api_t));

api->put(api->ctx, "peer/alice", 11,
         pubkey, 32, /*ttl_s*/ 0, /*flags*/ 0);
```

Eight slots: `put / get / query / del / subscribe / unsubscribe /
cleanup_expired` plus the `ctx`/`_reserved` ABI footer.
`query` covers exact / prefix / since-timestamp modes through a
single record-emitting callback.

### 2.2 Wire surface

Seven envelopes under `protocol_id = "gnet-v1"`:

| `msg_id` | Direction | Envelope |
|---|---|---|
| `0x0610` | client → server | `DNS_PUT` |
| `0x0611` | client → server | `DNS_GET` |
| `0x0612` | server → client | `DNS_RESULT` |
| `0x0613` | client → server | `DNS_DELETE` |
| `0x0614` | client → server | `DNS_SUBSCRIBE` |
| `0x0615` | server → subscriber | `DNS_NOTIFY` |
| `0x0616` | symmetric | `DNS_SYNC` |

These ids are outside the kernel-reserved `0x10..0x1F` range (see
[`system-handlers.md`](system-handlers.en.md) §2). The
`0x0610..0x0616` block sits next to the legacy `apps/store`
range (`0x0600..0x0606`) that `gn.handler.store` keeps, so a
node hosting both plugins in the same process routes traffic
unambiguously by `msg_id`.

---

## 3. Wire layout

All multi-byte integers are big-endian. Lengths cap at
`GN_DNS_KEY_MAX_LEN = 256` (key) and
`GN_DNS_VALUE_MAX_LEN = 65_536` (value).

### 3.1 `DNS_PUT` (`0x0610`)

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

### 3.2 `DNS_GET` (`0x0611`)

| offset | size | field |
|---|---|---|
| 0 | 8 | `request_id` |
| 8 | 1 | `query_mode` (0=exact, 1=prefix, 2=since) |
| 9 | 1 | reserved (zero) |
| 10 | 2 | `max_results` (clamped at `GN_DNS_QUERY_MAX_RESULTS = 256`) |
| 12 | 4 | reserved (zero) |
| 16 | 8 | `since_us` (μs since epoch; mode=2 only) |
| 24 | 2 | `key_len` |
| 26 | 2 | reserved (zero) |
| 28 | `key_len` | key / prefix bytes |

### 3.3 `DNS_RESULT` (`0x0612`)

| offset | size | field |
|---|---|---|
| 0 | 8 | `request_id` (echoed from the request) |
| 8 | 1 | `status` (0=ok, 1=bad-size, 2=not-found, 3=backend-error) |
| 9 | 1 | reserved (zero) |
| 10 | 2 | `record_count` (0 for PUT/DELETE acks) |
| 12 | ... | `record_count` × Record (§3.6) |

### 3.4 `DNS_DELETE` (`0x0613`)

| offset | size | field |
|---|---|---|
| 0 | 8 | `request_id` |
| 8 | 2 | `key_len` |
| 10 | 6 | reserved (zero) |
| 16 | `key_len` | key bytes |

### 3.5 `DNS_SUBSCRIBE` (`0x0614`)

| offset | size | field |
|---|---|---|
| 0 | 8 | `request_id` |
| 8 | 1 | `query_mode` (0=exact, 1=prefix; since is invalid) |
| 9 | 1 | reserved (zero) |
| 10 | 2 | `key_len` |
| 12 | 4 | reserved (zero) |
| 16 | `key_len` | key bytes |

### 3.6 Record

A single record on the wire (used by `DNS_RESULT`,
`DNS_NOTIFY`, `DNS_SYNC` payloads):

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

### 3.7 `DNS_NOTIFY` (`0x0615`)

| offset | size | field |
|---|---|---|
| 0 | 8 | `timestamp_us` (notification dispatch time) |
| 8 | 1 | `event` (0=PUT, 1=DELETE) |
| 9 | 1 | reserved (zero) |
| 10 | ... | one Record (§3.6) |

### 3.8 `DNS_SYNC` (`0x0616`)

Request and reply share the header; the reply appends records.

| offset | size | field |
|---|---|---|
| 0 | 8 | `request_id` |
| 8 | 8 | `since_us` |
| 16 | 2 | `max_results` |
| 18 | 2 | `record_count` (0 on request; N on reply) |
| 20 | ... | `record_count` × Record (§3.6) |

---

## 4. Backend contract

Each method is **synchronous and called from a single thread** —
the handler funnels every call through one mutex so the backend
sees serialised access. Backends MAY ignore their own locking.

The reference `MemoryDnsBackend` ships in-tree as slice 1.
`SqliteDnsBackend` lands in slice 2.

| Backend | Persistence | Notes |
|---|---|---|
| `MemoryDnsBackend` (slice 1) | none | hash-map; loses state across restart |
| `SqliteDnsBackend` (slice 2) | file | prepared stmts; production reference |
| `DhtDnsBackend` (planned) | distributed | Kademlia over GoodNet itself |
| `RedisDnsBackend` (planned) | external | clustered, hot failover |

---

## 5. Behavioural rules

- **No empty keys.** `put("", ...)` returns -1 / status=bad-size.
- **Duplicate puts overwrite** with a fresh `timestamp_us` —
  `subscribe` sees a single `PUT` event.
- **TTL is wall-clock**, not steady-clock: records cross the wire
  through `DNS_SYNC` and the time anchor must agree across nodes.
  Operators that need monotonic semantics use `flags` to tag
  records they post-process on read.
- **`cleanup_expired` is reactive**, not background: callers
  invoke it (typically through a kernel timer) when they want
  expired records dropped. The plugin ships no automatic cleanup
  driver.
- **`get_prefix` is unordered for memory, key-ordered for sqlite.**
  The memory backend iterates the hash-map; sqlite uses
  `ORDER BY key`. Callers that depend on order MUST run against
  sqlite (or a future ordered backend).
- **Subscriptions are per-conn for wire callers**, per-callback
  for in-process callers. Wire subscriptions die with the conn
  through `PerConnMap`-style cleanup (planned).
- **The handler is `priority = 200`** — below identity-bearing
  system handlers (240+) but above application handlers (default
  128). Adjust via plugin manifest if a node hosts a handler
  that wants `DNS_*` envelopes to land first.

---

## 6. Cross-references

- Extension ABI: [`sdk/extensions/dns.h`](../../sdk/extensions/dns.h)
- Reference implementation: `plugins/handlers/dns/`
- Reserved-id semantics:
  [`handler-registration.md`](handler-registration.en.md) §2a +
  [`system-handlers.md`](system-handlers.en.md) §1
- The DIFFERENT thing called "DNS":
  [`hostname-resolver.md`](hostname-resolver.en.md) — the SDK
  helper for `tcp://example.com:443` → IP-literal rewriting at
  connect time. That is a pure-function URI rewrite, not a
  network service.
- Legacy origin (archived):
  `~/Desktop/projects/GoodNet_legacy/apps/store/`
