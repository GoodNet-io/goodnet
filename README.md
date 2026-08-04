# GoodNet

**Linux for networks.**

A domain-specific kernel for the network layer. The address is the key — a 32-byte Ed25519 public key is the peer, not the machine. Every transport, every cipher, every protocol handler lives in a plugin over a stable C ABI. The kernel holds four registries and a dispatch loop. Everything else is yours to compose.

Runs as a Linux daemon, a `.so` loaded via FFI, a WebAssembly module in a browser, or bare-metal on a microcontroller. Same binary. Same ABI. Same guarantees.

→ [The Network Layer We Always Deserved](https://goodnet-io.github.io/the-network-layer.html) — on thirty years of the right idea in the wrong place, and what the fix looks like.

The kernel does not know what TCP is, what Noise is, what an
application is. It tracks logical connections, typed messages,
public-key addresses, and registered handlers.
Every transport, every cipher, every wire format lives in a
plugin loaded through one of three built-in runtimes — `dynamic`
(dlopen the .so), `static` (link the plugin into the kernel
binary at build time), or `remote` (spawn a subprocess worker
talking over the wire codec). The `IPluginRuntime` interface
is open: host programs that bundle a custom runtime
(WebAssembly host, FFI-over-IPC bridge, per-process sandbox)
register an instance through `PluginManager::register_runtime`
and the kernel dispatches future manifest entries through it
without touching `PluginManager` itself.

## Quickstart

```bash
git clone https://github.com/GoodNet-io/goodnet.git
cd goodnet
nix run .#setup                # bootstrap mirrors + plugins
nix run .#build -- release     # release build with LTO → build-release/
nix run .#run -- demo          # two-node Noise-over-TCP, one message
```

Without Nix: gcc 16 (x86_64-linux) / gcc 15 (other platforms), libsodium,
OpenSSL, asio, spdlog, gtest, rapidcheck, CMake 3.22 — install via your package manager,
then `cmake -B build -G Ninja && cmake --build build && ctest --test-dir build`.

LibFuzzer-driven parser harness (clang only, opt-in): see
[`docs/operator/fuzzing.en.md`](docs/operator/fuzzing.en.md).

### Local test gate and CI gating

`nix run .#setup` wires `core.hooksPath` to `.githooks/`, installing
two hooks in the clone:

- **`pre-commit`** — `clang-tidy --warnings-as-errors=*` on every
  staged C++ file plus the ABI / banlist / livedoc drift checks.
- **`pre-push`** — when the push targets `refs/heads/main`, re-runs
  the cheap CI subset locally (`tools/livedoc.py --check`, `pytest
  tests/livedoc tests/tools`, vanilla debug `ctest`) before the
  push leaves the machine. The hook is a no-op for any other branch.

Bypass once with the standard Git escape hatch when you know what
you're doing:

```bash
git commit --no-verify   # skip pre-commit for one commit
git push   --no-verify   # skip pre-push for one push
```

CI runs end-to-end on the project's self-hosted Forgejo Actions
instance ([`.forgejo/workflows/ci.yml`](.forgejo/workflows/ci.yml);
runner setup in
[`docs/operator/ci-forgejo-setup.en.md`](docs/operator/ci-forgejo-setup.en.md)).
GitHub Actions is not used. Release artefacts are built on the same
Forgejo runner on tag push and published to GitHub Releases via the
`gh` CLI ([`.forgejo/workflows/release.yml`](.forgejo/workflows/release.yml));
see "GitHub Releases publish" in the operator doc for the `GH_TOKEN`
secret setup.

| Gate                | When                                | Where             |
|---------------------|-------------------------------------|-------------------|
| `flake-check`       | every PR + push to main             | Forgejo           |
| `livedoc-check`     | every PR + push to main             | Forgejo           |
| `build-and-test`    | every PR + push to main             | Forgejo           |
| `plugin-verify`     | every PR + push to main             | Forgejo           |
| `windows-cross-build` | every PR + push to main           | Forgejo           |
| `bench-smoke`       | push to main OR PR label `bench`    | Forgejo           |
| `ice-3node`         | push to main OR PR label `ice-test` | Forgejo           |
| `fuzz-smoke`        | push to main OR PR label `fuzz`     | Forgejo           |
| `asan-smoke`        | push to main OR PR label `sanitizer` | Forgejo          |
| `tsan-smoke`        | push to main OR PR label `sanitizer` | Forgejo          |

`asan-smoke` + `tsan-smoke` previously stayed local-only; they now
run on every push to main so a race or UAF that slipped past local
dev surfaces before the next release tag. Tag a PR with `sanitizer`
when your change touches concurrency-sensitive code.

## What makes it different

- **Multi-path transport, runtime adaptive.** Every transport
  runs concurrently under one peer identity (one public key,
  three live connections through TCP + UDP + IPC at once if you
  want). A strategy plugin picks the carrier **per send** from
  live RTT samples, not at connect time. The same `conn_id`
  surface survives carrier migration: mobile device shifts from
  4G to home Wi-Fi, the LAN host candidate appears in ICE,
  strategy flips the winner, identity does not re-handshake.
  Libp2p / WebRTC / gRPC each only partially overlap on this
  axis; WireGuard has no slot for any of it.
- **Parallel crypto, scales with cores.** The
  `CryptoWorkerPool` distributes AEAD jobs across worker threads
  on every send; WireGuard's mainline data plane pins to one
  softirq CPU per peer, so its single-tunnel throughput
  saturates one core no matter how many you give it. Multi-conn
  aggregate on this 12-thread laptop hits **~60 Gb/s** parody
  (static + LTO, CPU `performance` governor), already 12× WireGuard's single-tunnel ceiling
  on the same machine, with crypto-ready architecture.
- **Relay → direct upgrade.** Connections start through a relay
  when needed and walk themselves to a direct path within a few
  seconds, against the receiver's NAT. The application sees a
  single `conn_id` across the upgrade.
- **Plugin-first ecosystem.** Transports, security providers,
  protocol layers, handlers, strategies — each is a loadable
  shared object with its own git, its own license, its own
  release cadence. The bundled set is a starting kit, not a
  sealed monolith. A `-DGOODNET_STATIC_PLUGINS=ON` build links
  every plugin straight into the kernel binary with cross-TU
  LTO for the embedded operator.
- **Runtime security provider migration.** Once Noise XX
  establishes peer-identity binding, GoodNet can swap the
  active security provider on the live connection — drop AEAD
  on a loopback connection where the trust class allows, keep
  it on the wire side. Identity-binding survives; per-frame
  seal/open evaporates. WireGuard / TLS / libp2p Noise sessions
  are monolithic: either on (every byte) or off (no auth).
- **C ABI stability across languages.** The kernel exposes one
  surface — pointer + size, no STL across the boundary — so
  bindings in Python, Rust, Go, Java land on the same
  contract. Plugins written in different languages run in the
  same process.

## How it compares

| | GoodNet | libp2p | WireGuard | Matrix |
|---|---|---|---|---|
| **Shape** | Kernel + C ABI | Library | Kernel module | Application (chat) |
| **Transports** | All concurrent (multi-path) under one identity | One per conn | UDP only | Homeserver HTTP |
| **Carrier selection** | Runtime, strategy plugin per `send()` | At connect time | None (single tunnel) | None |
| **Aggregate scaling** | Linear in cores (CryptoWorkerPool) | Per-conn | Pinned to one softirq CPU per peer | Server-bound |
| **Languages** | Any (C ABI) | Go/Rust/JS forks differ | C / kernel | Python/JS/Go |
| **NAT** | Heartbeat-observed + AutoNAT + relay → direct | Manual relay | None | Homeserver pivots |
| **Pluggable security** | Yes (Noise XX/IK, Null, TLS planned); **swappable post-handshake** | Yes (Noise) | No (Noise IK only) | TLS to homeserver |
| **Mobility** | ICE-restart on new interface, same `conn_id`, no re-handshake | None | None | Server holds session |
| **License** | GPL-2 + linking exception (strategic), MIT (periphery) | MIT/Apache | GPL-2 | Apache |

## Performance

The authoritative numbers live in [`bench/reports/`](bench/reports/) — each file is a full run with environment, exact reproduce commands, and a regression delta against the baseline. The tables below are a snapshot; check the latest report for current figures.

**A note on CPU governor:** bench reports may show `powersave` as the scaling governor. On `intel_pstate` with HWP this label is misleading — the CPU still boosts to rated max frequency under load regardless of the governor name. The `governor_note` field in each report (`intel_pstate_at_max` vs `intel_pstate_limited`) is the reliable signal. If you reproduce and see different numbers, check that field first.

Two measurement shapes are reported separately on purpose — see
[`docs/perf/analysis.en.md`](docs/perf/analysis.en.md) §
"Measurement shape" for the full discussion. Compare same-shape
rows only: `real` (production stack) vs `parody` (link layer only,
no security, no protocol) delta IS the cost of the plugin model,
not a stack quality signal.

Reference machine: i5-1235U, 12-thread, loopback, ChaCha20-Poly1305 via libsodium, static+LTO build.

**Real-mode** through the production stack (kernel + Noise XX
+ gnet protocol + transport plugin). What an operator-facing
`api->send()` actually pays. `RealFixture*` cases in
`bench_real_e2e`.

| Payload | TCP one-way | TCP echo RT | UDP one-way | IPC one-way | IPC echo RT |
|---|---|---|---|---|---|
| 64 B    | 20 μs / 3.0 MiB/s    | 39 μs / 3.2 MiB/s    | 17 μs / 3.5 MiB/s | 15 μs / 4.2 MiB/s    | 27 μs / 4.5 MiB/s |
| 1 KiB   | 19 μs / 50 MiB/s     | 43 μs / 46 MiB/s     | 19 μs / 51 MiB/s  | 16 μs / 60 MiB/s     | 32 μs / 62 MiB/s |
| 8 KiB   | 33 μs / 235 MiB/s    | 75 μs / 207 MiB/s    | —                 | 32 μs / 241 MiB/s    | 66 μs / 236 MiB/s |
| 32 KiB  | 91 μs / 344 MiB/s    | 197 μs / 317 MiB/s   | —                 | 86 μs / 362 MiB/s    | 184 μs / 340 MiB/s |

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

Full comparison table and reproduce commands: [`docs/perf/analysis.en.md`](docs/perf/analysis.en.md).

## Architecture

The kernel is a set of registries and buses at the same level, each owned
directly by `Kernel` (`core/kernel/kernel.hpp` is the source of truth). The
registries: connection, link, handler, protocol-layer, security, session
(security state), send-queue, extension, and local-identity. The buses and
dispatchers: a signal channel for connection events, a signal channel for
config reload, the attestation dispatcher, and the capability-blob bus. Plus
the router, the timer registry, and the metrics registry. None of them know
the name of any specific plugin; the `PluginManager` (under `core/plugin/`)
loads shared objects against the C ABI and names no specific plugin either.
The only entry points are the SDK contracts under
[`docs/contracts/`](docs/contracts/), which the tree treats as authoritative —
contracts change first, code catches up.

Layout:

```
core/        kernel and primitives
sdk/         public C ABI (host_api, link, security, protocol, handler, ...)
plugins/     in-tree plugin shims + test stubs (real transports, security,
             and handlers live in their own org repos — see the repo table below)
examples/    bench harness, two-node demo
docs/        contracts (authoritative), architecture (narrative), operator
tests/       unit, integration, property, conformance
dist/        example operator config + systemd unit
```

The `goodnetd` daemon binary, the `gssh` SSH tunnel, and any
other operator-facing app live in their own repos under
`GoodNet-io/` — the kernel tree stays library-only.

Each plugin under `plugins/<kind>/<name>/` is a self-contained
unit: own `CMakeLists.txt`, own `default.nix`, own git, own
license. Loaded into the kernel via `PluginManager::load`
against an SHA-256 manifest (`/etc/goodnet/plugins.json`).

## Running as a daemon

`goodnetd` is a multicall binary:

```bash
goodnetd identity gen --out /etc/goodnet/identity.bin
goodnetd manifest gen build/plugins/libgoodnet_*.so > plugins.json
goodnetd config validate dist/example/node.json
goodnetd run --config dist/example/node.json \
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

### Current release

See [`CHANGELOG.md`](CHANGELOG.md) for the full release history.

## Ecosystem repos

The kernel tree stays library-only. Operator-facing binaries,
language bridges, and each plugin live in their own GitHub repos
under [`GoodNet-io/`](https://github.com/GoodNet-io). The bundled
manifest links them together.

| Repo | Role |
|---|---|
| **[goodnet](https://github.com/GoodNet-io/goodnet)** | Kernel, SDK, bundled plugin shims. This repo. |
| **[goodnetd](https://github.com/GoodNet-io/goodnetd)** | Operator daemon + multicall CLI (`run`, `doctor`, `quickstart`, `identity import-hsm`, …). |
| **[gssh](https://github.com/GoodNet-io/gssh)** | Native SSH-2.0 server + client with peer-pubkey identity. |
| [link-tcp](https://github.com/GoodNet-io/link-tcp) · [link-udp](https://github.com/GoodNet-io/link-udp) · [link-ws](https://github.com/GoodNet-io/link-ws) · [link-tls](https://github.com/GoodNet-io/link-tls) · [link-ipc](https://github.com/GoodNet-io/link-ipc) | Single-protocol transport plugins. |
| **[link-ice](https://github.com/GoodNet-io/link-ice)** | NAT-traversal — RFC 8445 + STUN + TURN + Trickle ICE + mDNS + auto-restart. |
| [link-quic](https://github.com/GoodNet-io/link-quic) | QUIC over UDP / ICE — OpenSSL 3.6 native QUIC, composer pattern. (in progress) |
| **[security-noise](https://github.com/GoodNet-io/security-noise)** | Noise XX security provider (libsodium). |
| **[security-null](https://github.com/GoodNet-io/security-null)** | Loopback / IntraNode pass-through provider. |
| **[security-pkcs11](https://github.com/GoodNet-io/security-pkcs11)** | Hardware key store — PKCS#11 (`gn.identity.pkcs11` + `gn.security.pkcs11` dual-expose). |
| **[handler-store](https://github.com/GoodNet-io/handler-store)** | Distributed key-value store (Memory + SQLite backends, first-writer-wins ACL). |
| **[handler-dns](https://github.com/GoodNet-io/handler-dns)** | Typed RR storage on `gn.store` + three-tier resolver (local → cache → c-ares). |
| **[handler-heartbeat](https://github.com/GoodNet-io/handler-heartbeat)** | Two-way liveness + RTT measurement; feeds the strategy chain through `notify_rtt_sample`. |
| **[handler-web-api-proxy](https://github.com/GoodNet-io/handler-web-api-proxy)** | Browser-gateway handler — WS endpoint + JSON-RPC over gnet envelopes. |
| **[strategy-float-send-rtt](https://github.com/GoodNet-io/strategy-float-send-rtt)** | RTT-optimal multi-path picker (EWMA + 0.75 hysteresis + EncryptedPath tie-break). |
| **[bridges-rust](https://github.com/GoodNet-io/bridges-rust)** | Rust bindings (`goodnet-sys` + safe `goodnet` crate) with `WireSchema` trait. |
| **[bridges-python](https://github.com/GoodNet-io/bridges-python)** | Python bindings (cffi ABI mode) — `pip install`-able, no C compiler. |
| **[bridges-js](https://github.com/GoodNet-io/bridges-js)** | TypeScript/JS client for the goodnetd WS gateway. |

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
kernel, the gnet protocol layer, and the in-tree plugin shims.
The full plugin implementations (TCP / UDP / WS / ICE link,
Noise security, Heartbeat / Store / DNS handlers, TLS, QUIC,
float-send-rtt) now live in their own repos under the GoodNet-io
org, each with its own LICENSE file. The linking exception lets
out-of-tree plugins ship under any license — the boundary is the
C ABI, not the license. In-tree periphery shims (raw protocol,
null security, IPC link) are MIT for ecosystem reach.

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

Build targets, baseline scripts, frozen reference numbers, and methodology: [`bench/README.md`](bench/README.md). Numbers live under [`bench/reports/`](bench/reports/).

## Not on this tree yet

See [`docs/ROADMAP.en.md`](docs/ROADMAP.en.md).
