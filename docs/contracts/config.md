# Contract: Configuration

**Status:** active · v1
**Owner:** `core/config/`
**Header:** `core/config/config.hpp`
**Stability:** stable for v1.x; key paths land at semver-minor
boundaries with the corresponding limit / feature.

---

## 1. Purpose

Kernel-side JSON document accessed by plugins through the typed
`config_get_string` / `config_get_int64` slots in `host-api.md` §2.
One holder per running kernel; loaded from disk at startup,
optionally reloaded at runtime. Plugins read; the kernel writes.

The structure is flat at the top level with **dotted-path nesting**
for namespaces — `limits.max_connections`,
`tcp.idle_timeout_s`. Plugins receive paths verbatim through the
`config_get_*` slots and resolve them inside the kernel; there is
no plugin-side JSON parser.

---

## 2. Lifecycle

| Step | Action |
|---|---|
| Kernel startup | construct `Config` with default `gn_limits_t`; empty JSON object behind it |
| Load | `Config::load_json(text)` parses the document. On success, replaces the current state; on failure, leaves the existing state unchanged |
| Validate | `Config::validate(&reason)` checks cross-field invariants from `limits.md` §3 — fails the load on first invariant violation with the offending key in `reason` |
| Runtime queries | plugins call `host_api->config_get_string(key, …)` / `config_get_int64(key, …)`; kernel resolves the dotted path under a shared lock |

The kernel exposes a `SignalChannel<ConfigReloaded>` (per
`signal-channel.md`) that fires when a future runtime-reload entry
publishes a new state; subscribers refresh their knobs in their own
callback. Until that entry lands the channel is allocated but
silent — `Config` is a one-shot load on this release.

Default-constructed `Config` is usable: every key lookup returns
`GN_ERR_UNKNOWN_RECEIVER`, `limits()` returns the canonical defaults.

---

## 3. Top-level schema

The shipping schema is the union of every section the kernel
recognises. Unknown keys are ignored at load time so a future
plugin may seed its own namespace before the kernel registers a
parser.

```jsonc
{
    "version": 1,
    "limits": {
        "max_connections":           4096,
        "max_outbound_connections":  1024,
        "max_handlers_per_msg_id":      8,
        "max_extensions":             256,
        "max_payload_bytes":        65522,
        "max_frame_bytes":          65536
        // see limits.md §2 for the full list
    }
}
```

`limits` is the only currently required block; transports register
their own namespace (`tcp`, `udp`, …) when they begin reading from
config — until then they accept the canonical defaults.

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
| `GN_ERR_UNKNOWN_RECEIVER` | key missing or path resolves to a non-leaf node |
| `GN_ERR_INVALID_ENVELOPE` | (load) JSON parse failed |
| `GN_ERR_LIMIT_REACHED` | (validate) cross-field invariant failed; `out_reason` names the field |

Plugin-facing `config_get_string` / `config_get_int64` return the
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

The default load source is a JSON document at a path provided to
the kernel binary (mechanism out of contract scope; the kernel is
linkable as a library). Plugins do not read files; everything
they need flows through the host API slots. The kernel is the
single point that touches the filesystem for config bytes.

---

## 7. Cross-references

- Limit field semantics: `limits.md`.
- Plugin-facing `config_get_*` slots: `host-api.md` §2.
- Reload notification primitive: `signal-channel.md`.
