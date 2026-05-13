# GoodNet

A small networking kernel with pluggable transports, security
providers, protocol layers, and handlers. Applications embed it
as a library or run the standalone daemon. The C ABI between
kernel and plugins is the only stable boundary; everything else
is composition.

The framing is Linux. The kernel does not know what TCP is, what
Noise is, what an application is. It tracks logical connections,
typed messages, public-key addresses, and registered handlers.
Every transport, every cipher, every wire format lives in a
plugin loaded through `dlopen` against a versioned C ABI.

## Quickstart

```bash
git clone https://github.com/GoodNet-io/goodnet.git
cd goodnet
nix run .#setup                # bootstrap mirrors + plugins
nix run .#build -- release     # release build with LTO → build-release/
nix run .#run -- demo          # two-node Noise-over-TCP, one message
```

Without Nix: gcc 15, libsodium, OpenSSL, asio, spdlog,
gtest, rapidcheck, CMake 3.25 — install via your package manager,
then `cmake -B build -G Ninja && cmake --build build && ctest --test-dir build`.

## What makes it different

- **Multi-path transport.** Every transport runs concurrently. A
  connection over TCP can migrate to ICE or IPC without the
  application observing the seam. Per-transport scoring picks
  the best path live.
- **Relay → direct upgrade.** Connections start through a relay
  when needed and walk themselves to a direct path within a few
  seconds, against the receiver's NAT. The application sees a
  single `conn_id` across the upgrade.
- **Plugin-first ecosystem.** Transports, security providers,
  protocol layers, and handlers are loadable shared objects
  with their own git, their own license, their own release
  cadence. The bundled set is a starting kit, not a sealed
  monolith.
- **C ABI stability across languages.** The kernel exposes one
  surface — pointer + size, no STL across the boundary — so
  bindings in Python, Rust, Go, Java land on the same
  contract. Plugins written in different languages run in the
  same process.

## How it compares

| | GoodNet | libp2p | WireGuard | Matrix |
|---|---|---|---|---|
| **Shape** | Kernel + C ABI | Library | Kernel module | Application (chat) |
| **Transports** | All concurrent (multi-path) | One per conn | UDP only | Homeserver HTTP |
| **Languages** | Any (C ABI) | Go/Rust/JS forks differ | C / kernel | Python/JS/Go |
| **NAT** | Heartbeat-observed + AutoNAT + relay → direct | Manual relay | None | Homeserver pivots |
| **Pluggable security** | Yes (Noise XX/IK, Null, TLS planned) | Yes (Noise) | No (Noise IK only) | TLS to homeserver |
| **License** | GPL-2 + linking exception (strategic), MIT (periphery) | MIT/Apache | GPL-2 | Apache |

## Performance

Reference machine: i5-1235U, loopback, ChaCha20-Poly1305 via
libsodium. Release build, median of 3 runs. Two measurement
shapes are reported separately on purpose — see
[`docs/perf/analysis.en.md`](docs/perf/analysis.en.md) §
"Measurement shape" for the full discussion.

**Real-mode** through the production stack (kernel + Noise XX
+ gnet protocol + transport plugin). What an operator-facing
`api->send()` actually pays. `RealFixture*` cases in
`bench_real_e2e`.

| Payload | TCP one-way | TCP echo RT | UDP one-way | IPC one-way | IPC echo RT |
|---|---|---|---|---|---|
| 64 B    | 22 μs / 2.3 MiB/s    | 36 μs / 2.9 MiB/s    | 18 μs / 2.8 MiB/s | 14 μs / 3.7 MiB/s    | 44 μs / 1.9 MiB/s |
| 1 KiB   | 21 μs / 35 MiB/s     | 43 μs / 35 MiB/s     | 20 μs / 38 MiB/s  | 16 μs / 51 MiB/s     | 50 μs / 32 MiB/s |
| 8 KiB   | 40 μs / 142 MiB/s    | 80 μs / 155 MiB/s    | —                 | 33 μs / 181 MiB/s    | 101 μs / 147 MiB/s |
| 32 KiB  | 135 μs / 213 MiB/s   | 245 μs / 250 MiB/s   | —                 | 118 μs / 246 MiB/s   | 319 μs / 192 MiB/s |

UDP caps at 1 KiB on the MTU floor (`udp.hpp::kDefaultMtu = 1200`).

**Parody** through the link plugin only (`LinkStub` host_api,
no security, no protocol). What the link layer alone can
deliver to a downstream that drains as fast as the socket
writes. `*Fixture/Throughput` cases.

| Plugin | @ 64 B | @ 512–1200 B | Comment |
|---|---|---|---|
| UDP    | 113 MiB/s | 0.68–1.01 GiB/s (≈ **8.7 Gb/s** @ MTU) | composer + asio strand |
| TCP    | tracked in `bench/reports/<sha>.md` | — | per-conn back-pressure already measured |

The cost decomposition between parody and real-mode is what
`bench/comparison/reports/aggregate.py` calls "the production
stack overhead": gnet framing + Noise AEAD + protocol-layer
dispatch + per-send envelope construction. On UDP @ MTU the
parody/real gap is about 4× — that gap IS the operator-facing
plugin model. See § "Free-kernel showcase" below for the things
the kernel does in exchange.

### vs WireGuard

Same machine, same kernel, same ChaCha20-Poly1305 primitive.
WireGuard is a kernel module: zero-copy data plane, single
peer = single IP tunnel, encryption pinned to one softirq CPU
per peer, no application-layer framing or routing. GoodNet is
userspace: peer identities are public keys, every send carries
a typed message envelope through a plugin pipeline. The two
pay for different things.

| Surface | Throughput | Parallelism | What it carries |
|---|---|---|---|
| `veth` loopback baseline (no crypto, `iperf3 -P 8`)              | **~80 Gb/s**  | 8 streams, kernel splice + `MSG_ZEROCOPY` | raw IP frames |
| **GoodNet UDP parody, static + LTO, 8 parallel procs, no crypto** | **~34 Gb/s** | 8 procs × 1 strand each, plugin calls inlined | raw datagrams through link plugin |
| **GoodNet UDP parody, dynamic, 8 parallel procs, no crypto**     | **~28 Gb/s**  | 8 procs × 1 strand each | raw datagrams through link plugin |
| **GoodNet UDP parody single conn, static + LTO, no crypto**      | **~8.1 Gb/s** | one asio strand, plugin calls inlined | raw datagrams through link plugin |
| **GoodNet UDP parody single conn, dynamic, no crypto**           | **~8.7 Gb/s** | one asio strand | raw datagrams through link plugin |
| **WireGuard single tunnel, kernel, with crypto**                 | **~4.9 Gb/s** | one softirq CPU pinned | IP tunnel, ChaCha20-Poly1305 per packet |
| GoodNet Noise transport (encrypt+decrypt round, single-thread)   | ~1.7 Gb/s     | one thread, libsodium ChaCha20-Poly1305 | seal + open in a tight loop, no I/O |
| **GoodNet IPC real @ 32 KiB, dynamic, with crypto**              | **~2.0 Gb/s** | one strand, single conn | typed `gn_message_t` envelopes, peer-pk addressing |
| **GoodNet TCP real @ 32 KiB, dynamic, with crypto**              | **~1.7 Gb/s** | one strand, single conn | same, over TCP loopback |

**Two reads of the table.**

*Per-connection.* WireGuard's single-tunnel ceiling (~4.9 Gb/s)
is also single-CPU: the softirq context that runs the tunnel
pins one core, encryption serialises on it. GoodNet's
single-connection-with-crypto sits at ~1.7-2.0 Gb/s through the
production stack — slower per byte because every send walks
`host_api->send()`, `gn.protocol.gnet` framing, Noise AEAD,
strand-per-conn write pump. The 2-3× gap is the cost of the
userspace plugin model on this hardware.

*Aggregate.* WireGuard's single tunnel cannot saturate more
than one CPU regardless of how many cores you give it. GoodNet's
`CryptoWorkerPool` distributes AEAD jobs across worker threads,
so multi-conn aggregate scales near-linearly. 8 parallel
no-crypto UDP processes hit **~28 Gb/s** on this 12-thread
laptop with the dynamic-plugin build (`.so` dispatched through
the `gn_link_vtable_t`); the same configuration under
`-DGOODNET_STATIC_PLUGINS=ON -DGOODNET_USE_LTO=ON` (static-linked
plugins with cross-TU LTO inlining the vtable calls into the
hot path) reaches **~34 Gb/s** — about 20 % better aggregate.
Per the legacy 4-connection inline-crypto bench in
[`docs/perf/analysis.en.md`](docs/perf/analysis.en.md), the
encrypted multi-conn path reached **19.84 Gb/s** — already 4×
the WireGuard single-tunnel ceiling, on the same machine, with
crypto.

*Crypto floor.* Pure libsodium ChaCha20-Poly1305 in a tight
loop, single-thread, encrypt+decrypt round at 64 KiB measures
~1.7 Gb/s per worker thread. The `CryptoWorkerPool` runs by
default at `hardware_concurrency()/2` workers, so the
**theoretical** pure-crypto pool ceiling on this 12-thread
laptop is ~10 Gb/s before any I/O. Add `CryptoWorkerPool::run_batch`
on a batched send pipeline and the real per-conn number sits
between the single-thread floor and that pool ceiling depending
on how many in-flight frames the conn has to amortise the strand
dispatch over.

**Why 80 Gb/s is the kernel-only ceiling.** The veth baseline
comes from `iperf3 -P 8` doing `splice()` and `MSG_ZEROCOPY` —
the kernel hands packets between network namespaces without
ever materialising a user-space buffer. Any userspace plugin
pattern pays a syscall + memcpy per `write()`. The roof for
userspace without zero-copy on this hardware is the ~34 Gb/s
the static+LTO multi-conn parody bench above already shows;
beyond that needs `io_uring` + `MSG_ZEROCOPY` on the same
pipeline (deferred work). The single-conn numbers do not benefit
from LTO because the bottleneck is the per-`send()` syscall +
asio strand hop, not plugin-boundary dispatch — those have
fixed kernel cost. LTO + static linkage pay off where the
plugin-boundary calls repeat at scale: cross-conn in the
aggregate row.

**What WireGuard does not do, at all.** It delivers raw IP
packets between two endpoints. It does not address peers by
public key in the application layer, does not route by message
id, does not let one peer have three concurrent transports
under one identity, does not migrate carriers when a mobile
device shifts networks, does not give a strategy plugin the
slot to pick a path per send. Those moves are what the
[`bench_showcase`](bench/showcase/README.md) binary
demonstrates in six sections — capabilities the kernel pays the
throughput tax above to provide. WireGuard's architecture has
no slot for any of them; libp2p / WebRTC / gRPC each only
partially overlap.

Reproduce:

```sh
# Dynamic-plugin release build (default; the noise plugin's .so
# is dlopen'd by bench_real_e2e + bench_showcase)
nix run .#build -- release

# Real-mode echo, with crypto, single conn
./build-release/bench/bench_real_e2e \
    --benchmark_filter='RealFixture' \
    --benchmark_min_time=1s --benchmark_repetitions=3

# Parody throughput, no crypto, single conn
./build-release/bench/bench_udp \
    --benchmark_filter='Throughput' \
    --benchmark_min_time=1s --benchmark_repetitions=3

# Multi-process aggregate (no-crypto upper bound, dynamic)
for i in $(seq 1 8); do
    ./build-release/bench/bench_udp \
        --benchmark_filter='Throughput/1200' \
        --benchmark_min_time=2s &
done
wait

# Static + LTO build (plugins linked into the kernel, cross-TU
# inlining of every plugin-boundary call). Tests + dlopen-based
# benches are off because the noise plugin no longer produces an
# .so. Run the same parody multi-process aggregate to read the
# LTO advantage.
cmake -B build-static-lto -DCMAKE_BUILD_TYPE=Release \
    -DGOODNET_BUILD_BENCH=ON -DGOODNET_BUILD_TESTS=OFF \
    -DGOODNET_STATIC_PLUGINS=ON -DGOODNET_USE_LTO=ON
nix develop --command cmake --build build-static-lto \
    --target bench_udp -j8

for i in $(seq 1 8); do
    ./build-static-lto/bench/bench_udp \
        --benchmark_filter='Throughput/1200' \
        --benchmark_min_time=2s &
done
wait
```

Full per-bench numbers in [`bench/reports/<sha>.md` § "А.
Comparable echo round-trip"](bench/reports/) and the
showcase report at `bench/reports/showcase-<sha>.md`.

## Architecture

The kernel is eight subsystems at the same level: connection
registry, signal bus, plugin manager, service resolver,
session registry (security state), send-queue manager,
extension registry, metrics exporter. None of them know the name
of any specific plugin. The only entry points are the SDK
contracts under [`docs/contracts/`](docs/contracts/), which the
tree treats as authoritative — contracts change first, code
catches up.

Layout:

```
core/        kernel and primitives
sdk/         public C ABI (host_api, link, security, protocol, handler, ...)
plugins/     bundled link / security / protocol / handler plugins
apps/        goodnet daemon binary, gssh, demo
examples/    bench harness, two-node demo
docs/        contracts (authoritative), architecture (narrative), operator
tests/       unit, integration, property, conformance
dist/        example operator config + systemd unit
```

Each plugin under `plugins/<kind>/<name>/` is a self-contained
unit: own `CMakeLists.txt`, own `default.nix`, own git, own
license. Loaded into the kernel via `PluginManager::load`
against an SHA-256 manifest (`/etc/goodnet/plugins.json`).

## Running as a daemon

`goodnet` is a multicall binary:

```bash
goodnet identity gen --out /etc/goodnet/identity.bin
goodnet manifest gen build/plugins/libgoodnet_*.so > plugins.json
goodnet config validate dist/example/node.json
goodnet run --config dist/example/node.json \
            --manifest plugins.json \
            --identity /etc/goodnet/identity.bin
```

A working operator setup with systemd unit and a sample
`node.json` lives under [`dist/example/`](dist/example/). The
operator guide is [`docs/operator/deployment.en.md`](docs/operator/deployment.en.md).

## Status

The tree carries release-candidate quality: every test green
under Release, ASan, and TSan on the reference machine,
contracts in `docs/contracts/` document the surface, and the
operator binary boots end-to-end from a generated identity and
a signed plugin manifest.

Wire format, public C ABI, and plugin contracts are **not** yet
frozen — RC iterations may reshape any of them in response to
integration findings. The reshape window in
[`docs/contracts/abi-evolution.en.md`](docs/contracts/abi-evolution.en.md)
§3b stays open through the rc cycle and closes only on the plain
`v1.0.0` tag without an `-rcN` suffix. The branch model is `dev`
for development, `main` for releases (between tags `main` is
quiet).

## Documentation

- [`docs/contracts/`](docs/contracts/) — authoritative
  behavioural contracts. Start with [`host-api.en.md`](docs/contracts/host-api.en.md)
  if you're embedding the kernel, [`link.en.md`](docs/contracts/link.en.md)
  if you're writing a transport plugin.
- [`docs/architecture/`](docs/architecture/) — narrative
  explanation in Russian: routing, multi-path, wire protocol.
- [`docs/operator/`](docs/operator/) — deployment, troubleshooting.
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — development workflow,
  branch model, audit pass.
- [`SECURITY.md`](SECURITY.md) — threat model, reporting channel.
- [`GOVERNANCE.md`](GOVERNANCE.md) — decision-making, contract
  amendment process.

Russian: see [`README.ru.md`](README.ru.md).

## License

GPL-2.0 with linking exception for the strategic baseline:
kernel, the bundled TCP / UDP / WS / Noise / Heartbeat plugins.
The linking exception lets out-of-tree plugins ship under any
license — the boundary is the C ABI, not the license. Periphery
plugins (raw protocol, null security, IPC link) are MIT for
ecosystem reach. The TLS plugin is Apache-2.0 for OpenSSL
compatibility.

The strategic licensing rationale is the same one Linux applied
in 1991: GPL on the kernel keeps the substrate open, the linking
exception keeps applications free. See [`LICENSE`](LICENSE) and
each plugin's `LICENSE` file.

## Benchmarks

The bench tree under [`bench/`](bench/) measures GoodNet on six
orthogonal axes (payload size, conn count, concurrency,
per-plugin, composition depth, strategy) plus a cross-implementation
comparison axis that runs each baseline (iperf3 raw TCP/UDP, socat
AF_UNIX echo, openssl s_server TLS handshake) through the same
payload matrix and surfaces UX/DX gaps via a hello-world LOC
count.

```bash
# Build the suite (opt-in)
nix develop --command cmake -B build -DGOODNET_BUILD_BENCH=ON
nix develop --command cmake --build build --target bench_tcp bench_udp \
    bench_ipc bench_tls bench_ws bench_quic bench_dtls bench_ice \
    bench_wss_over_tls bench_tcp_scale

# Stage external baselines (one-shot)
./bench/comparison/setup/01_openssl.sh
./bench/comparison/setup/02_iperf3.sh
./bench/comparison/setup/03_libuv.sh
./bench/comparison/setup/04_libssh.sh
./bench/comparison/setup/05_openssl_demos.sh

# Run everything + generate report
./bench/comparison/runners/run_all.sh
ls bench/reports/
```

Frozen reference numbers live under [`bench/reports/`](bench/reports/);
methodology + the six measurement axes are documented in
[`bench/README.md`](bench/README.md).

## Not on this tree yet

- Pre-built release binaries. Build from source through Nix or
  the standard CMake path above.
- Per-plugin GitHub repositories. The bundled plugins live
  in-tree under `plugins/`; the org repos at
  `goodnet-io/<kind>-<name>` come online when each plugin
  extracts.
- A registered domain. Documentation references the GitHub
  organisation directly.
