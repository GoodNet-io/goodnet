# Contract: Configuration

**Status:** active · v1
**Owner:** `core/config/`
**Header:** `core/config/config.hpp`
**Last verified:** 2026-04-29
**Stability:** stable for v1.x; key paths land at semver-minor
boundaries with the corresponding limit / feature.

---

## 1. Purpose

Kernel-side JSON document accessed by plugins through the typed
unified `config_get(KEY, TYPE, INDEX, …)` slot in `host-api.md` §2.
One holder per running kernel. The kernel writes through
`Config::load_json(text)`; plugins read through the host-API
slots. The kernel does **not** itself touch the filesystem — the
embedding application reads the bytes off whatever source the
operator picks (disk, environment variable, network fetch) and
hands them to `load_json`. That separation lets the kernel
binary stay linkable as a library: the surrounding deployment
owns its config-source story.

The structure is flat at the top level with **dotted-path nesting**
for namespaces — `limits.max_connections` is the canonical
example; transports and handlers register their own namespaces
(`links.tls.cert_path`, `relay.dedup_capacity`) when they
begin reading from config. Plugins receive paths verbatim through
the `config_get` slot and resolve them inside the kernel;
there is no plugin-side JSON parser.

Runtime reload runs through `Kernel::reload_config(text)` and
`Kernel::reload_config_merge(overlay)`. Both are atomic-from-the-
outside: a parse failure or invariant violation rolls the kernel
state back to the prior load, propagates the new `gn_limits_t`
into kernel-owned registries through `set_limits`, and then fires
the `on_config_reload` signal. Plugins subscribe through
`host_api->subscribe(GN_SUBSCRIBE_CONFIG_RELOAD, …)` /
`unsubscribe(id)` and re-read their own knobs from inside their
callback —
the kernel's responsibility ends at the signal fire; plugins own
their state-machine response.

---

## 2. Lifecycle

| Step | Action |
|---|---|
| Kernel startup | construct `Config` with default `gn_limits_t`; empty JSON object behind it |
| Load | embedding application reads bytes off the operator's source; calls `Config::load_json(text)` |
| Auto-validate | `load_json` parses, then runs `validate_limits` on the new `gn_limits_t` before installing it. Parse failure returns `GN_ERR_INVALID_ENVELOPE`; invariant failure returns `GN_ERR_LIMIT_REACHED` with the offending key in `out_reason` (when supplied through the public `validate`). On either failure the kernel state is **rolled back** to whatever the previous successful load left — the kernel never executes against an invariant-violating limits set |
| Propagate | the embedding application (or `Kernel::set_limits`) hands the `gn_limits_t` snapshot to every kernel-owned registry that enforces a cap (timer, handler, connection, extension); `Kernel::set_limits` runs the propagation |
| Runtime queries | plugins call `host_api->config_get(key, type, GN_CONFIG_NO_INDEX, …)`; the kernel resolves the dotted path under a shared lock |

Mutation entries are `Config::load_json(text)` (wholesale replace)
and `Config::merge_json(overlay)` (RFC 7396 deep-merge). The
kernel-facing `Kernel::reload_config` / `reload_config_merge`
wrap them with the registry propagation + signal fire.

Default-constructed `Config` is usable: every key lookup returns
`GN_ERR_NOT_FOUND`, `limits()` returns the canonical defaults
from `sdk/limits.h` (the `GN_LIMITS_DEFAULT_*` macros).

---

## 3. Top-level schema

The shipping schema is the union of every section the kernel
recognises. Unknown keys are ignored at load time so a future
plugin may seed its own namespace before the kernel registers a
parser.

```jsonc
{
    "version": 1,

    // Optional. Selects the baseline gn_limits_t that the `limits`
    // block then overrides field-by-field. Three values:
    //   "server"   — canonical defaults (large memory, many conns).
    //                The unwritten default; same behaviour as before
    //                profiles landed.
    //   "embedded" — IoT / single-board: 64 conns, 8 KiB max frame,
    //                256 timers, narrowed inject limiter.
    //   "desktop"  — single-user: 512 conns, 1 KiB queue cap,
    //                between Server and Embedded.
    // Unknown / missing names fall back to "server" — operators who
    // typo a profile see the safe-default values, not a tighter set
    // that would drop traffic.
    "profile": "server",

    "limits": {
        // Connections (limits.md §2)
        "max_connections":             4096,
        "max_outbound_connections":    1024,

        // Per-connection send queue (backpressure.md §3)
        "pending_queue_bytes_high":  1048576,   //  1 MiB
        "pending_queue_bytes_low":    262144,   //  256 KiB
        "pending_queue_bytes_hard":  4194304,   //  4 MiB
        "pending_handshake_bytes":    262144,   //  256 KiB

        // Framing (gnet-protocol.md §2)
        "max_payload_bytes":            65522,
        "max_frame_bytes":              65536,

        // Handlers + relay (handler-registration.md §3)
        "max_handlers_per_msg_id":          8,
        "max_relay_ttl":                    4,

        // Plugin bounds (plugin-lifetime.md §5, plugin-manifest.md)
        "max_plugins":                     64,
        "max_extensions":                 256,

        // Service executor (timer.md §6)
        "max_timers":                    4096,
        "max_pending_tasks":              4096,
        "max_timers_per_plugin":             0, // 0 = no per-plugin sub-quota

        // Foreign-payload injection (host-api.md §8)
        "inject_rate_per_source":          100, // tokens/sec per remote_pk
        "inject_rate_burst":                50,
        "inject_rate_lru_cap":            4096,

        // Storage (sync.md, defer to v1.1 plugins)
        "max_storage_table_entries":     10000,
        "max_storage_value_bytes":       65522
    },

    // Optional. Kernel logger configuration (host-api.md §11).
    // Every field has a built-in default; an absent block leaves
    // the logger at the lazy-startup shape (stderr-only console
    // sink with the build-aware pattern).
    "log": {
        "level":               "info",      // trace/debug/info/warn/error/critical/off

        // File sink. Empty string keeps the console-only shape.
        "file":                "",
        "max_size":            10485760,    // 10 MiB rotation cap
        "max_files":           5,           // rotated history depth

        // Source-location detail (host-api.md §11.4):
        //   0 = Auto: TRACE/DEBUG full, INFO+ basename only (default)
        //   1 = FullPath:         project-relative path + line, every level
        //   2 = BasenameWithLine: basename + line, every level
        //   3 = BasenameOnly:     basename, no line
        "source_detail_mode":  0,

        // Project root prefix the %Q flag strips off __FILE__.
        // The CMake `-fmacro-prefix-map` flag already drops the
        // build-tree prefix at compile time; this knob covers the
        // out-of-tree consumer case where the working directory
        // differs from the build root.
        "project_root":        "",

        // Optional: drop the file extension from the rendered name
        // (`router.cpp` → `router`). Off by default — losing the
        // extension makes header vs. .cpp call sites
        // indistinguishable in skim-reads.
        "strip_extension":     false,

        // Pattern overrides. Empty strings keep the build-aware
        // defaults from `core/util/log.hpp::kDefaultPattern` /
        // `kDefaultFilePattern`. spdlog's standard flags apply
        // plus the custom %Q for the source-location prefix.
        "console_pattern":     "",
        "file_pattern":        ""
    }
}
```

`limits` is the only block the kernel parses; everything outside
it is opaque JSON the kernel hands back through `config_get`
without interpretation. Plugins that read from config publish
their namespace conventions in their own contract: TLS reads
`links.tls.cert_path` / `links.tls.key_path` per the
`plugins/links/tls/` README; future relay / DHT / sync
plugins will register `relay.*` / `dht.*` / `sync.*` similarly.

The embedding application is free to seed any plugin namespace
before that plugin is loaded; the kernel ignores unrecognised
top-level keys. A `version` field is conventionally `1` — the
kernel does not enforce it in v1, but operators include it so a
future v2 binary can detect the legacy shape.

### 3a. Profile re-evaluation under `merge_json`

`merge_json(overlay)` runs RFC 7396 deep-merge on the live JSON
document and **re-derives** the limits from the merged result.
That includes the `profile` field: an overlay that carries
`"profile": "<name>"` replaces the active baseline, and every
unset `limits.*` field then snaps to the new profile's defaults
rather than to the previously merged value. Operators who only
intend to nudge one limit field must omit the `profile` key from
the overlay — keeping the existing baseline in place.

```jsonc
// active document, profile = server, max_connections defaulted
{ "profile": "server" }

// overlay — switches the baseline, max_connections collapses to
// the embedded default (256), not the prior server default
{ "profile": "embedded", "limits": { "max_payload_bytes": 4096 } }
```

The kernel emits a `warn`-level log line whenever a `merge_json`
call changes the resolved profile so an operator who did not
expect the baseline shift sees the cause in the audit trail.
Wholesale `load_json` does not log the change because the
operator is replacing the document by definition.

Cross-field invariants land in `limits.md` §3 and are enforced
inside `load_json` (auto-validate). Every load that returns
`GN_OK` has passed:

- `max_outbound_connections ≤ max_connections`
- `pending_queue_bytes_low > 0`
- `pending_queue_bytes_low < pending_queue_bytes_high`
- `pending_queue_bytes_high ≤ pending_queue_bytes_hard`
- `0 < max_relay_ttl ≤ GN_LIMITS_DEFAULT_MAX_RELAY_TTL_CEIL` (8)
- `max_storage_value_bytes ≤ max_payload_bytes`
- `max_payload_bytes + 14 ≤ max_frame_bytes` (GNET fixed header)
- `inject_rate_per_source == 0 || inject_rate_burst ≥ inject_rate_per_source / 2`
- `inject_rate_per_source == 0 || inject_rate_burst > 0`

---

## 4. Read API surface

```cpp
gn_result_t Config::load_json(std::string_view json);
gn_result_t Config::validate(std::string* out_reason) const;
gn_result_t Config::get_string(std::string_view key, std::string& out) const;
gn_result_t Config::get_int64(std::string_view key, std::int64_t& out) const;
gn_limits_t Config::limits() const noexcept;
```

| Return | Meaning |
|---|---|
| `GN_OK` | found, `out` populated |
| `GN_ERR_NOT_FOUND` | key missing or path resolves to a non-leaf node |
| `GN_ERR_INVALID_ENVELOPE` | (load) JSON parse failed |
| `GN_ERR_LIMIT_REACHED` | (validate) cross-field invariant failed; `out_reason` names the field |

Plugin-facing `config_get` returns the
same codes through the C ABI. The string variant takes an `out_str`
+ `out_free` pair so the kernel hands ownership of allocated bytes
to the plugin and the plugin returns them through the matching
deallocator.

---

## 5. Thread safety

`Config` is read-mostly. Reads (`get_string`, `get_int64`,
`limits`) take a shared lock; load / reload takes an exclusive
lock. Plugins may concurrently query from any thread; one ongoing
reload blocks queries for the duration of the parse + validate
(milliseconds at v1 sizes).

Snapshots (`limits()`) are returned by value — no aliasing into
the live document, so a subsequent reload does not invalidate a
caller's local copy.

---

## 6. Source

The kernel does not itself touch the filesystem. The embedding
application reads the bytes off whatever source the operator
picks — a JSON file under `/etc/`, a Kubernetes ConfigMap, an
environment variable, a network fetch — and calls
`Config::load_json(text)` once at startup with the resulting
buffer. Plugins do not read files either; everything they need
flows through the host-API slots.

The split is deliberate: the kernel binary is linkable as a
library. A demo binary, a service supervisor, a unit-test
harness all pick their own bytes-source without dragging the
kernel into a path-handling argument.

---

## 7. Out of scope at v1

- **Runtime reload.** v1 ships a one-shot load. An application
  that needs hot reload constructs a fresh `Config`, loads,
  validates, swaps it with the running instance, and re-runs
  `Kernel::set_limits`. v1.1 will absorb the dance into a
  kernel-side `Config::reload` entry plus a plugin-facing
  reload signal channel.
- **Layered config.** Defaults → site override → per-deploy
  override merge is the embedding application's responsibility
  in v1 — the application composes the JSON document before
  calling `load_json`. v1.1 may surface a layered API if real
  deployments drive one.
- **Per-plugin schema discovery.** Plugins do not register the
  keys they read. A typo in an operator's config silently maps
  to a `GN_ERR_NOT_FOUND` and the plugin falls through to
  its built-in default — the operator gets no warning. v1.1
  adds a `reads_config` whitelist in `plugin-manifest.md` so
  the kernel logs unknown-key warnings at load time and gates
  per-section reads against the plugin's declared scope.
- **Capability gate for sensitive values.** Any loaded plugin
  can read every config-tree node; nothing in v1 prevents a
  malicious plugin from reading `links.tls.key_path`. The
  same `reads_config` mechanism above is the v1.1 fix. v1
  assumes the plugins directory is operator-controlled and
  every loaded plugin is trusted (see `plugin-manifest.md` §3).
- **Adding new value types.** The current `config_get` covers
  `INT64`, `BOOL`, `DOUBLE`, `STRING`, `ARRAY_SIZE` and indexed
  `INT64` / `STRING` array elements. Future minor releases add
  enumerators to `gn_config_value_type_t` (e.g. `BYTES`,
  `ARRAY_DOUBLE`) under the same slot — no host_api shape change.
- **Save / round-trip.** v1 is read-only. A configuration the
  embedding application built up in code is not serialisable
  back through this surface — that is the embedding's own
  responsibility.

---

## 8. Cross-references

- Limit field semantics + cross-field invariants: `limits.md`.
- Plugin-facing `config_get`: `host-api.md` §2.
- Live propagation of limits through registries:
  `Kernel::set_limits` in `core/kernel/kernel.cpp`.
- Plugin trust + integrity: `plugin-manifest.md`.
