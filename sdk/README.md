# sdk/

C ABI plugin boundary plus C++23 convenience wrappers. Header-only
INTERFACE target `GoodNet::sdk`; plugins link it for the include
path and never produce object files from this tree.

## Layout

C ABI core (one header per surface):

| File | Role |
|---|---|
| `types.h`        | `gn_*` POD types, error codes, drop-reason enum, fixed-size arrays |
| `host_api.h`     | Host-API the kernel hands a plugin (`subscribe`/`config_get`/`notify_*`/`inject`/`query_extension_checked`/`send`/`send_to`/`register_vtable`/...) |
| `plugin.h`       | Plugin entry-point signatures, descriptor, kind enum |
| `core.h`         | Host-embedding ABI (`gn_core_t`, `gn_core_create_*`, `gn_core_load_plugin`) |
| `link.h` / `protocol.h` / `security.h` / `handler.h` | Vtable shapes for transports, protocol layers, crypto providers, application handlers |
| `connection.h` / `conn_events.h` / `endpoint.h` | Per-connection context, event channel, peer endpoint shape |
| `identity.h` / `trust.h` | Local-key registry slots + trust-class enum + transition helpers |
| `limits.h` / `metrics.h` / `log.h` | `gn_limits_t` shape, metric counters, logging API |
| `abi.h` / `convenience.h` | Size-prefix evolution helpers (`GN_API_HAS`) + C inline helpers |
| `extensions/`   | Typed extension APIs: `dns.h`, `heartbeat.h`, `link.h`, `store.h`, `strategy.h`, `ui.h`, `ui_event.h` |
| `remote/`       | Remote-plugin wire codec (`wire.h`, `slots.h`) for subprocess-runtime plugins |

C++23 sugar layer (header-only, opt-in via `<sdk/cpp/...>`):

| File | Role |
|---|---|
| `cpp/convenience.hpp` | `gn::query_extension_typed<T>`, ergonomic message constructors, `std::span` / `std::expected` flavours |
| `cpp/types.hpp` | C++ wrappers for `gn_*` types |
| `cpp/connect.hpp` | Modern DX sugar (`connect_to`, `listen_to`) per `docs/dx-sdk-sugar.en.md` |
| `cpp/subscription.hpp` | RAII `Subscription` wrapper |
| `cpp/handler_plugin.hpp` / `cpp/link_plugin.hpp` / `cpp/strategy_plugin.hpp` | `GN_*_PLUGIN(Class, …)` macros |
| `cpp/protocol_layer.hpp` / `cpp/connection.hpp` / `cpp/handler.hpp` / `cpp/link.hpp` | C++ interface classes the plugin macros bridge through |
| `cpp/uri.hpp` / `cpp/dns.hpp` / `cpp/wire.hpp` / `cpp/endian.hpp` | RFC 3986 URI parser, DNS resolver helper, wire codec, endian helpers |
| `cpp/link_carrier.hpp` / `cpp/per_conn_map.hpp` | Composer-side LinkCarrier abstraction + per-conn state map |
| `cpp/log.hpp` / `cpp/config.hpp` / `cpp/capability_tlv.hpp` / `cpp/openssl_diag.hpp` / `cpp/token_bucket.hpp` / `cpp/remote_plugin.hpp` | Logging, config typed-read, capability TLV, OpenSSL error formatting, rate limiter, remote-plugin worker |

Versioning rules and ABI evolution policy live in
`docs/contracts/abi-evolution.en.md` — every consumer reads it before
extending the surface.

## Targets exported

- `GoodNet::sdk` — INTERFACE include path; consumers write
  `#include <sdk/types.h>` and `target_link_libraries(... PRIVATE GoodNet::sdk)`.

## Stability

ABI surface is open for reshape through the entire `v1.0.0-rcN`
cycle; the reshape window closes only on the plain `v1.0.0` tag
per `docs/contracts/abi-evolution.en.md` §3b. Post-freeze every
slot is append-only.

## License

MIT. See `sdk/LICENSE` (top-level pointer in repo `LICENSE`).
