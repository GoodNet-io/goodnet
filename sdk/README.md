# sdk/

C ABI plugin boundary plus C++23 convenience wrappers. Header-only
INTERFACE target `GoodNet::sdk`; plugins link it for the include
path and never produce object files from this tree.

## Layout

| File / dir | Role |
|---|---|
| `types.h`              | `gn_*` POD types, error codes, fixed-size arrays |
| `host_api.h`           | Host-API the kernel hands a plugin (`should_log`/`emit`/`subscribe`/`config_get`/`notify_*`/`log`/`inject`/`query_extension_checked`) |
| `plugin.h`             | `gn_plugin_init` / `gn_plugin_shutdown` entry-point signatures |
| `link.h`               | `gn_link_api_t` vtable for transports |
| `protocol.h`           | `gn_protocol_layer_vtable_t` for protocol layers |
| `security.h`           | `gn_security_provider_vtable_t` for crypto providers |
| `handler.h`            | `gn_handler_vtable_t` for application-level handlers |
| `extensions/`          | Typed extension APIs (`heartbeat.h`, `link.h` etc.) |
| `core.h`               | Host-embedding ABI (`gn_core_t`, `gn_core_create_*`, `gn_core_load_plugin`) |
| `convenience.h`        | C inline helpers (compound literals; not MSVC-portable) |
| `cpp/convenience.hpp`  | C++23 templates over the C ABI — `gn::query_extension_typed<T>`, ergonomic message constructors, `std::span` / `std::expected` flavours |
| `cpp/types.hpp`        | C++ wrappers for `gn_*` types |
| `cpp/dns.hpp`          | DNS resolver helper |
| `cpp/uri.hpp`          | RFC 3986 URI parser + `gn::is_valid_scheme` ABNF check |
| `cpp/link_plugin.hpp`  | `GN_LINK_PLUGIN(Class, "scheme")` macro |
| `abi.h`                | Size-prefix evolution helpers (`GN_API_HAS`) |
| `abi-evolution.md` etc. (in `docs/contracts/`) | Versioning rules every consumer reads before extending the surface |

## Targets exported

- `GoodNet::sdk` — INTERFACE include path; consumers write
  `#include <sdk/types.h>` and `target_link_libraries(... PRIVATE GoodNet::sdk)`.

## Stability

ABI surface is open for reshape until `v1.0.0-rc1`. Post-tag, every
slot is append-only per
[`docs/contracts/abi-evolution.md`](../docs/contracts/abi-evolution.md).

## License

MIT. See `sdk/LICENSE` (top-level pointer in repo `LICENSE`).
