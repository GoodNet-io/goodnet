# tests/

Kernel + integration test suites. Plugin-specific unit tests live
with their plugin under `plugins/<kind>/<name>/tests/` and produce
their own gtest binaries; the kernel umbrella does not link plugin
OBJECT libraries.

## Subdirectories

| Path | Binary | Role |
|---|---|---|
| `unit/`        | `goodnet_unit_tests`        | Kernel, SDK, util — every TU under `tests/unit/**/test_*.cpp` |
| `integration/` | `goodnet_integration_tests` | Cross-cutting scenarios that compose the kernel with multiple plugins (Noise-over-TCP e2e, link-extension API conformance, plugin teardown drain, backpressure under load, link teardown across all transports) |
| `abi/`         | `goodnet_abi_tests`         | C ABI binary-layout assertions; offsets and sizes pinned per `docs/contracts/abi-evolution.en.md` |
| `util/`        | (header-only)               | Cross-suite C++ helpers (e.g. `protocol_setup.hpp`, `log_capture.hpp`) |
| `livedoc/`     | pytest                      | Tests for `tools/livedoc/` writers + renderers + injection |
| `tools/`       | pytest                      | Tests for `tools/bench_compare` and other build / report tooling |
| `aggregator/`  | pytest                      | Tests for `bench/comparison/reports/*_aggregate.py` aggregators |
| `docker/`      | (scripts)                   | Multi-node integration scenarios staged under Docker Compose (e.g. `ice-3node` for TURN-relayed peer pairs) |

## Run

```sh
nix run .#test                    # Debug build + ctest
ctest --test-dir build            # inside dev shell, all suites
ctest --test-dir build -L plugin  # per-plugin binaries (when labels are set)
ctest --test-dir build -R Noise   # filter by gtest case name regex
```

Sanitiser variants: `nix run .#test-asan` and `nix run .#test-tsan`
build into `build-asan/` and `build-tsan/` respectively, with
strict `--warnings-as-errors=*` clang-tidy gating every merge.

## What lives where

- Kernel surface that does not depend on a transport — `unit/`
  (kernel/, registry/, identity/, security/, signal/, util/, plugin/, config/, abi/, sdk/).
- Cross-plugin composition or PluginManager dlopen exercises — `integration/`.
- Plugin internals (TCP / UDP / WS / IPC / TLS / ICE / QUIC, Noise,
  null, GNET, raw, heartbeat, DNS, store, float_send_rtt) — each
  plugin's own `tests/` next to its source.

## License

GPL-2.0 with Linking Exception. See top-level `LICENSE`.
