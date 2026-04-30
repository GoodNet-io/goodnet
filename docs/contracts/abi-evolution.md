# Contract: ABI Evolution

**Status:** active · v1
**Owner:** every C ABI structure in `sdk/`
**Last verified:** 2026-04-27
**Stability:** the rules in this document do not change inside the v1.x line.

---

## 1. Purpose

The C ABI is the only stable boundary between the kernel and plugins.
Plugins are built independently, often against an older SDK header set
than the running kernel. This contract defines the rules that let new
fields and new function pointers be added without breaking
already-compiled plugins.

Two mechanisms are in use: **size-prefix** for tables of function
pointers and **`_reserved` slots** for value-type structures. Every C
ABI struct in `sdk/` follows one of the two conventions; the choice is
documented per-struct in the contract owning that struct.

---

## 2. Versioning

The SDK exposes a semantic version triple in `sdk/types.h`:

```c
#define GN_SDK_VERSION_MAJOR 1
#define GN_SDK_VERSION_MINOR 0
#define GN_SDK_VERSION_PATCH 0
```

| Component | Bumps when | Plugin compatibility |
|---|---|---|
| `MAJOR` | Field removed or repurposed; struct layout broken; semantic of an existing function changed | **breaking** — plugins must rebuild |
| `MINOR` | New struct, new function pointer appended at the end of an existing vtable, new `_reserved` slot promoted | additive — old plugins keep working |
| `PATCH` | Documentation, comments, non-binary fixes | none |

A plugin reports its build-time SDK version through:

```c
GN_PLUGIN_EXPORT void gn_plugin_sdk_version(uint32_t* major,
                                            uint32_t* minor,
                                            uint32_t* patch);
```

The kernel checks `major == kernel.major` strictly and
`kernel.minor >= plugin.minor`. A mismatch returns `GN_ERR_VERSION_MISMATCH`
from the load entry point and the plugin is rejected.

---

## 3. Size-prefix vtables

Every function-pointer table crossing the C ABI starts with a
`uint32_t api_size` as its first field. That includes `host_api_t`,
`host_loader_api_t`, and every `*_vtable_t` (transport, security
provider, handler, protocol layer, extension API). The producer
fills it with `sizeof(*table)` at producer build time. Consumers
compare against the offset of the field they want to call:

```c
typedef struct host_api_s {
    uint32_t   api_size;            /* sizeof(host_api_t) at producer build time */
    /* slots populated since v1.0 */
    int      (*send)(...);
    int      (*broadcast)(...);
    /* slot appended in a future MINOR: */
    int      (*future_slot)(...);
    /* ... */
} host_api_t;

static inline int can_call_future_slot(const host_api_t* api) {
    return api->api_size >= offsetof(host_api_t, future_slot) + sizeof(api->future_slot);
}
```

Rules:

- New entries are **appended** to the end of the struct, never inserted
  in the middle.
- Existing entries are **never** removed before a `MAJOR` bump.
- Consumers **must** check `api_size` before calling any entry that
  was added after `MINOR` 0.
- Producers populate `api_size` with `sizeof()` at build time of the
  *producer*. The consumer never trusts a hard-coded constant.
- Helper macros (`GN_API_HAS(api, field)`) live in `sdk/abi.h` to keep
  the pattern uniform across plugins.

Without size-prefix, adding a single function pointer would force every
already-compiled plugin to rebuild.

C ABI is the lowest common denominator the SDK exposes; every
supported language binding traverses this boundary. The size-prefix
rule applies regardless of where the producer was built — a binding
layer fills `api_size` at producer compile time and runs the
consumer-side `api_size >= offsetof(slot) + sizeof(slot)` guard
before any newly-introduced slot fires. Per-language helper macros
and wrappers belong to the binding's own contract, not to this one.

---

## 3a. Kernel-side validation of plugin-provided vtables

The size-prefix rule (§3) is symmetric: when a **plugin** registers
a vtable with the kernel — `gn_transport_vtable_t`,
`gn_security_provider_vtable_t`, `gn_handler_vtable_t`, and any
future plugin-provided table — the kernel is the consumer and the
plugin is the producer. The kernel validates `api_size`
defensively before invoking any slot:

```
on register_<X>(vtable):
    if vtable == NULL                        return GN_ERR_NULL_ARG
    if vtable->api_size < sizeof(min_struct) return GN_ERR_VERSION_MISMATCH
    accept; subsequent slot calls are GN_API_HAS-checked
```

`min_struct` is the minimum vtable shape the kernel knows about —
the producer's structure may be larger (newer SDK with more
slots), but never smaller (older SDK with no `api_size` would zero
the field and crash the kernel on first slot lookup). A plugin
that fails the check is rejected at registration; no partial
state survives.

Two C ABI vtables in the SDK do not pass through a kernel-side
register thunk and therefore validate consumer-side instead:

| Vtable | Why no kernel validation | Where it is validated |
|---|---|---|
| `gn_protocol_layer_vtable_t` | The kernel holds an `std::shared_ptr<gn::IProtocolLayer>` C++ wrapper rather than the C vtable; a future C-only protocol adapter performs the `api_size` check before constructing the wrapper. | producer-side until the C adapter ships; the field is populated today so adapter introduction is non-breaking |
| `gn_heartbeat_api_t` and every other extension vtable | `host_api->register_extension` stores an opaque `const void*`; the kernel cannot interpret the structure layout. | consumer-side — a plugin querying `host_api->query_extension_checked(name, version, &out)` runs `GN_API_HAS(out, slot)` before invoking any slot added after `MINOR` 0 |

---

## 4. `_reserved` slots in value-type structs

Plain data structures that the kernel passes to plugins by value or
pointer (`gn_message_t`, `gn_endpoint_t`, `gn_health_report_t`,
`gn_handshake_result_t`) do not use size-prefix. They use a fixed-count
`_reserved` array sized for likely future fields.

```c
typedef struct gn_message_s {
    uint8_t        sender_pk[32];
    uint8_t        receiver_pk[32];
    uint32_t       msg_id;
    const uint8_t* payload;
    size_t         payload_size;
    void*          _reserved[4];    /* must be NULL */
} gn_message_t;
```

Rules:

- `_reserved` is the **last** field of the struct.
- Producer **must** zero-initialise. Kernel asserts on every inbound
  copy.
- Consumer of an unfamiliar version **must** ignore unknown reserved
  contents. Reading them invites undefined behaviour.
- New fields are added by **promoting** a slot — `_reserved[0]` becomes
  `flags`, the array shrinks by one, the struct stays the same byte
  length. No size change → ABI stays binary-compatible.
- When all four slots are spent, the next addition is a `MAJOR` bump.
- Slot count is documented per struct; see the contract owning the
  struct (e.g. `protocol-layer.md` for `gn_message_t`).

Vtables grow by accumulating function pointers and need byte-level
addressability of the new entries; data structures grow by filling
pre-allocated word-sized holes that would otherwise be padding.
Mixing the two yields the worst of both — opaque growth and broken
ABI.

---

## 5. Forbidden patterns

The following ABI patterns are explicitly prohibited inside `sdk/` and
fail code review:

| Pattern | Why forbidden |
|---|---|
| Inserting a field in the **middle** of any C struct | silent layout change; older binaries read garbage |
| Removing a field from a v1.x struct | cannot warn the consumer; `MAJOR` bump only |
| Repurposing an existing field's type or semantics | same — `MAJOR` only |
| `void*` payload without explicit ownership rule | leads to dangling pointers |
| Borrowed pointers without lifetime annotation in the docstring | same |
| `#pragma pack(1)` on shared structs | misaligned-load undefined behaviour on strict-alignment platforms |
| Anonymous unions or bit-fields in shared structs | compiler-dependent layout |
| Hardcoded version numbers in comments instead of `GN_SDK_VERSION_*` | drift between source and ABI |

---

## 6. Ownership annotation in C ABI

Every C ABI function pointer or struct field that traffics in pointers
**must** carry one of the four ownership tags in its Doxygen comment:

| Tag | Meaning |
|---|---|
| `@owned` | Caller transfers ownership; receiver is responsible for `free` (via the matching `*_free` callback). |
| `@borrowed` | Pointer valid for the duration of the *synchronous* call only. Caller retains ownership. |
| `@borrowed-until-callback` | Pointer valid until the named callback fires. Used for async APIs. |
| `@in-out` | Caller allocates, receiver fills in. Caller frees afterwards. |

The Doxygen warning gate (CI) refuses to merge any entry that traffics
in pointers without one of these tags.

---

## 7. ABI test suite

`tests/abi/` houses two kinds of tests:

1. **Layout invariants.** Static assertions on struct sizes and field
   offsets; recorded per `MINOR` for regression catch.
2. **Cross-version load.** A plugin built against `GN_SDK_VERSION_MINOR
   = 0` is loaded against the head kernel and expected to succeed.
   Symmetric for newer plugin against older kernel inside the same
   `MAJOR` window.

CI runs both on every push.

---

## 8. Cross-references

- `host-api.md` — the actual public table that uses size-prefix.
- `plugin-lifetime.md` — when version negotiation runs (between init
  and register).
- `protocol-layer.md` — the `gn_message_t` envelope and its
  `_reserved[4]`.
