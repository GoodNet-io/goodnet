# GoodNet free-kernel showcase bench

Track Б of the bench rework — six bench sections that demonstrate
what GoodNet does **architecturally** that other p2p / RPC stacks
(`libp2p`, `iroh`, `WebRTC`, `gRPC`) cannot reproduce natively. NOT
a fair comparison track — that lives in `bench/reports/<sha>.md`
section А (`bench_real_e2e.cpp` round-trip cases pivoted side-by-
side with `libp2p-echo` and `iroh-echo`).

The reader of this report is asked «попробуй повторить» — every
acceptance row is something `libp2p` / `iroh` / `WebRTC` /
`gRPC` would need an architectural rewrite to match.

## Sections

| # | What | Surface | Status |
|---|---|---|---|
| B.1 | Multi-connect под одной identity | `ConnectionRegistry::for_each` + `host_api->send_to(peer_pk)` fallback | Works in-tree |
| B.2 | Strategy-driven carrier selection | `goodnet_float_send_rtt` plugin (in-tree OBJECT lib) | Works in-tree |
| B.3 | Provider handoff Noise→Null после handshake | `SecuritySession::_test_clear_inline_crypto` (env-gated PoC) | PoC via env-gated seam |
| B.4 | Multi-thread fanout | Kernel strand-per-conn + crypto pool | Works in-tree |
| B.5 | Carrier failover | `float_send_rtt` `CONN_DOWN` eviction + re-pick | Stand-in for Slice-9-KERNEL emit |
| B.6 | Mobility → LAN shortcut | Multi-connect + strategy + ICE-restart shape | Synthetic — C.4 netlink hook pending |

## Build

Both `GOODNET_BENCH_STRATEGIES=ON` and the `goodnet_float_send_rtt`
strategy sub-checkout under `plugins/strategies/` are required:

```sh
nix run .#setup           # fetches the strategy plugin
cmake -DGOODNET_BENCH_STRATEGIES=ON -B build
cmake --build build --target bench_showcase
```

## Run

```sh
# Standalone bench run; CSV side-channels write to /tmp/.
./build/bench/bench_showcase \
    --benchmark_min_time=2s \
    --benchmark_out=bench/reports/showcase-raw.json \
    --benchmark_out_format=json

# Aggregate into narrative markdown.
python3 bench/comparison/reports/showcase_aggregate.py \
    "$(git rev-parse --short HEAD)" \
    bench/reports/showcase-$(git rev-parse --short HEAD).md \
    bench/reports/showcase-raw.json
```

The aggregator auto-discovers CSV side-channels under
`/tmp/showcase-*.csv` (the bench prints their paths to stderr as
`[showcase] <tag> csv -> <path>` lines for operator-friendly
debugging).

## B.3 PoC disclaimer

The Noise→Null handoff in B.3 reaches into kernel-private state
through `SecuritySession::_test_clear_inline_crypto`, gated at
runtime through `GN_SHOWCASE_ALLOW_INLINE_DOWNGRADE=1`. The bench
process sets the env var from `main` so child kernels inherit. The
gate fails closed otherwise — accidentally linking the seam into a
production binary is observable through the
`tests/unit/security/test_inline_downgrade_gate.cpp` unit test,
which pins the contract.

The production-shape handoff (`SessionRegistry::downgrade_*` +
trust-class hook on connection bring-up + peer-side wire signal)
is a v1.x followup. The bench's PoC suffices to surface the
latency-step number; it is NOT a path operators should use.

## Other deferrals documented in code

* `CONN_UP`/`CONN_DOWN` auto-emit from `notify_connect` /
  `notify_disconnect` → Slice-9-KERNEL. B.5 and B.6 fire these
  manually right after `link->disconnect` / synthetic carrier
  arrival; ~10 LOC of bench code marked `XXX bench: stand-in for
  slice-9 kernel emit`. Delete when slice 9 lands.
* `RTM_NEWLINK` / `RTM_DELLINK` AF_NETLINK socket → kernel emits
  `GN_CONN_EVENT_NETWORK_CHANGE` → C.4 Network mobility. B.6
  simulates the event with a synthetic second carrier; with C.4
  the bench just listens.
* Kernel-side RTT measurement (heartbeat extension writing
  `ConnectionRecord::last_rtt_us`) → Slice-9-HEARTBEAT. B.2/B.5/B.6
  inject RTT directly through `picker.on_path_event(RTT_UPDATE)`
  in the meantime.

## Reading the report

Each section follows fixed shape:

* **Что это** — plain language summary.
* **Почему это GoodNet-only** — architectural delta vs the
  reference stacks.
* **Bench** — table of measured numbers + (where the case is
  time-series-shaped) inline ASCII spark `▁▂▃▄▅▆▇█`.
* **Acceptance** — pass/fail boolean derived from counters; the
  shape that matters most architecturally, not aggregated latency.
