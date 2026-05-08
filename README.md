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
nix run .#setup            # bootstrap mirrors + plugins
nix run .#build            # release build with LTO → build-release/
nix run .#run -- demo      # two-node Noise-over-TCP, one message
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

Reference machine: i5-1235U, loopback, 16 KiB payloads, after
the AEAD batch fix in `dev`. ChaCha20-Poly1305 via libsodium.

| Scenario | Mean (5 runs) | Range |
|---|---|---|
| 1 conn, burst (1000 frames) | 7.05 Gbps | 5.1 – 9.0 |
| 1 conn, sustained (5000 frames) | 6.01 Gbps | 5.7 – 6.3 |
| 4 conns, sustained aggregate | 19.84 Gbps | 17.8 – 20.8 |
| 8 conns, burst aggregate | 20.49 Gbps | 15.8 – 30.6 |

Single connection sits at ~75 % of one core's libsodium
ChaCha throughput (`perf record`: 42 % cycles in
`chacha20_encrypt_bytes`, 30 % in `poly1305_blocks`). Multi-conn
scales because the kernel's `CryptoWorkerPool` runs AEAD jobs
in parallel across cores; each connection has its own asio
strand and per-conn drain CAS.

### vs WireGuard

Same machine, same kernel, same ChaCha20-Poly1305. WireGuard
runs through veth between two network namespaces; GoodNet runs
on loopback TCP. iperf3 vs goodnet-bench, 5 s.

| | Throughput |
|---|---|
| veth bridge (no crypto, baseline) | 80.4 Gbps |
| WireGuard single tunnel (kernel, single-thread) | 4.94 Gbps |
| **GoodNet single connection (userspace, multi-thread crypto)** | **6.01 Gbps** |
| **GoodNet 4 connections aggregate** | **19.84 Gbps** |

Notes: WireGuard's mainline data plane runs in a single softirq
context, so encryption pins one CPU. GoodNet's `CryptoWorkerPool`
distributes AEAD jobs across worker threads, which shows on this
benchmark. On a real 10 Gbps NIC, the comparison shifts —
WireGuard's zero-copy kernel path is hard to beat from
userspace. This is loopback-only evidence.

Reproduce: `nix run .#build && build-release/bin/goodnet-bench 5000 16 4`.

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

**Pre-1.0 release candidate.** Wire format, public API, and
plugin contracts are still moving. Do not pin against this tree
for production yet. The first stable surface lands on
`v1.0.0-rc1`. The branch model is `dev` for development, `main`
for releases (between tags `main` is quiet).

Sanitizer matrix: 878/878 ctest green under Release, ASan, TSan
on the reference machine. Memory hygiene: zero unsuppressed
leaks under valgrind on the integration suite.

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

## Out of scope (today)

- Pre-built release binaries — none until `v1.0.0-rc1`.
- API stability — none until `v1.0.0-rc1`.
- Per-plugin GitHub repositories — bundled plugins ship in-tree
  for now; the org repos at `goodnet-io/<kind>-<name>` come
  online after `rc1`.
- A registered domain — none, at the moment. Documentation
  references the GitHub org directly.
