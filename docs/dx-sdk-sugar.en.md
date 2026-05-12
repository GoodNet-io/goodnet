# GoodNet SDK sugar — DX helpers for plugin & app authors

> Last updated 2026-05-12 (DX Tier 1 + Tier 2 landed).

This page indexes every `sdk/cpp/*.hpp` helper that exists to keep
plugin authors out of C-ABI boilerplate. Each section pins:

- What the helper does
- The pattern it replaces (before / after)
- Header to include

If you find yourself copy-pasting boilerplate across two plugins, it
probably belongs here — open an issue.

---

## Lifecycle macros

### `GN_LINK_PLUGIN(Class, "plugin_name", "version")`

Header: `<sdk/cpp/link_plugin.hpp>`

Expands to the six `gn_plugin_*` extern "C" entry points + the
optional `gn_plugin_descriptor`. Class needs `set_host_api(api)`
and the usual link-plugin methods (`listen`, `connect`, `send`,
…). See `plugins/links/tcp/plugin_entry.cpp` for a 1-line example.

### `GN_HANDLER_PLUGIN(Class, "plugin_name", "version")`

Header: `<sdk/cpp/handler_plugin.hpp>`

Same pattern for handler plugins. Class needs static
`protocol_id()` / `msg_id()` / `priority()` + instance
`handle_message(const gn_message_t&)`; optional `on_init`,
`on_shutdown`, `extension_*` (see header for the SFINAE probe).

Heartbeat plugin migrated to this macro 2026-05-12 — went from
119 LOC plugin_entry to 19 LOC.

### `GN_STRATEGY_PLUGIN(Class, "plugin_name", "version")`

Header: `<sdk/cpp/strategy_plugin.hpp>`

For `gn.strategy.*` plugins. Class needs static `extension_name()`
+ `extension_version()` + instance `pick_conn(...)`. Reference
implementation: `plugins/strategies/float_send_rtt/plugin_entry.cpp`.

---

## Connection & link composition

### `gn::sdk::LinkCarrier`

Header: `<sdk/cpp/link_carrier.hpp>`

RAII wrapper around `gn.link.<scheme>` extension vtable.
`LinkCarrier::query(api, "tcp")` returns `optional<LinkCarrier>`.
Members: `listen`, `connect`, `send`, `disconnect`, `on_data`,
`on_accept`, `listen_port`. All subscriptions auto-cleanup on
dtor.

### `gn::sdk::Connection`

Header: `<sdk/cpp/connection.hpp>`

RAII handle for a single conn id. Move-only; dtor disconnects +
unsubscribes data. Methods: `send`, `on_data`, `close`, `release`,
`id`, `valid`.

```cpp
gn::sdk::Connection conn(carrier, conn_id);
conn.on_data([](std::span<const std::uint8_t> bytes) { /* ... */ });
conn.send(payload);
// ~conn() disconnects automatically
```

### `gn::sdk::connect_to(api, "wss://h:443")`

Header: `<sdk/cpp/connect.hpp>`

Scheme dispatcher — parses URI, queries `gn.link.<scheme>`,
connects, wraps in `ConnectedSession` (owns carrier + conn). One
line replaces "query extension + cast vtable + connect + wrap".

```cpp
auto session = gn::sdk::connect_to(api, "tcp://127.0.0.1:1234");
if (!session) return GN_ERR_NOT_FOUND;
session->send(payload);
```

Variant `connect_to_err(api, uri, &err)` surfaces the underlying
`gn_result_t`. `listen_to(api, "tcp://0.0.0.0:0")` does the same
for listening sockets.

---

## Subscriptions

### `gn::sdk::Subscription`

Header: `<sdk/cpp/subscription.hpp>`

RAII handle over `host_api->subscribe_*` slots. Move-only; dtor
calls `unsubscribe`.

Two factory tiers:

**Raw channel** (delivers full event payload):
- `Subscription::on_conn_state(api, [](const gn_conn_event_t& ev){...})`
- `Subscription::on_config_reload(api, []{...})`
- `Subscription::on_capability_blob(api, [](const CapabilityBlob&){...})`

**Event-typed** (pre-filters by kind; saves the `switch (ev.kind)`):
- `Subscription::on_connected(api, [](gn_conn_id_t, const gn_conn_event_t&){...})`
- `Subscription::on_disconnected(api, [](gn_conn_id_t){...})`
- `Subscription::on_trust_upgraded(api, [](gn_conn_id_t, gn_trust_class_t){...})`
- `Subscription::on_backpressure(api, [](gn_conn_id_t, bool soft){...})`

### `gn::sdk::PerConnMap<State>`

Header: `<sdk/cpp/per_conn_map.hpp>`

State map keyed by conn id; auto-erases on `GN_CONN_EVENT_DISCONNECTED`.
Replaces hand-rolled `unordered_map + shared_mutex +
subscribe_conn_state` pattern.

---

## URI parsing

### `gn::parse_uri(uri)` / `gn::parse_uri_strict(uri, "tcp")`

Header: `<sdk/cpp/uri.hpp>`

`parse_uri` returns `optional<UriParts>` with scheme/host/port/path/
query. `parse_uri_strict` adds the scheme check inline — replaces
the `if (parts->scheme != "tcp") return GN_ERR_INVALID_ENVELOPE`
boilerplate every link plugin writes.

```cpp
// Before: 3 lines
const auto parts = parse_uri(uri);
if (!parts || parts->is_path_style()) return GN_ERR_INVALID_ENVELOPE;
if (parts->scheme != "udp") return GN_ERR_INVALID_ENVELOPE;

// After: 2 lines
const auto parts = parse_uri_strict(uri, "udp");
if (!parts || parts->is_path_style()) return GN_ERR_INVALID_ENVELOPE;
```

UDP plugin migrated 2026-05-12.

---

## Config

### `gn::sdk::config_int / config_bool / config_double / config_string`

Header: `<sdk/cpp/config.hpp>`

Typed wrappers returning `std::optional<T>`. Replaces the
`gn_config_get_<type>` macro pattern that required a pre-set
default.

```cpp
// Before
bool verify = true;  // default
gn_config_get_bool(api, "links.tls.verify_peer", &verify);

// After
const bool verify =
    gn::sdk::config_bool(api, "links.tls.verify_peer").value_or(true);
```

---

## Testing helpers

### `gn::sdk::test::wait_for(pred, timeout, tick, label)`

Header: `<sdk/cpp/test/poll.hpp>`

Spin-poll a predicate up to `timeout` ms. Drop-in replacement for
the hand-rolled `wait_for` copies in every plugin's test file.

### `gn::sdk::test::LinkStub` / `make_link_host_api(h)`

Header: `<sdk/cpp/test/stub_host.hpp>`

Shared `host_api_t` stub for link-plugin tests. Counts
`notify_connect`, `notify_inbound_bytes`, `notify_disconnect`,
`kick_handshake` calls; replaces the ~80-LOC StubHost copied into
each link plugin's test file.

### `gn::sdk::test::HandlerStub` / `make_handler_host_api(h)`

Same idea for handler-plugin tests. Captures `send` calls, scripts
`find_conn_by_pk` / `get_endpoint` via `add_peer(marker, conn, uri)`.

### `gn::sdk::test::FakeLink` / `make_fake_link_vtable(f)`

Header: `<sdk/cpp/test/fake_link.hpp>`

Reusable `gn_link_api_t` vtable for SDK-level tests (composer
plumbing, `LinkCarrier`, `Connection`). All slots wired; tracks
call counts + last-seen args through atomics.

---

## Migration index

Pieces of the codebase that adopted the sugar so far:

| File | Before | After | Helper |
|---|---|---|---|
| `plugins/handlers/heartbeat/plugin_entry.cpp` | 119 LOC | 19 LOC | `GN_HANDLER_PLUGIN` |
| `plugins/links/udp/udp.cpp` (composer_listen/connect) | 6 LOC scheme checks | 4 LOC | `parse_uri_strict` |

Outstanding migrations (good first DX tasks):
- TCP / TLS / WS / ICE → `parse_uri_strict` (1-2 lines each)
- Every plugin's `tests/StubHost` → `gn::sdk::test::LinkStub` / `HandlerStub`
- Every plugin's `wait_for` copy → `gn::sdk::test::wait_for`
- TLS / UDP source-side `gn_config_get_bool` macros → `gn::sdk::config_bool`
