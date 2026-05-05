# GoodNet

A Linux-style networking framework: a small kernel, plugins for
transports, security providers, protocol layers, and handlers.
Applications embed the kernel as a library or run the standalone
daemon. The C ABI between kernel and plugins is the only stable
boundary; the rest is composition.

**Status: pre-1.0 release candidate.** Wire format, public API, and
plugin contracts are still moving. Do not pin against this tree
for production yet. The first stable surface lands on `v1.0.0-rc1`.

Russian: see [`README.ru.md`](README.ru.md).

## Build from source

The supported path is Nix. The flake pins the toolchain (gcc 15,
libsodium, OpenSSL, asio, spdlog, gtest, rapidcheck, clang-tidy 21)
so a clean clone reproduces the same binaries on any host.

```bash
git clone https://github.com/GoodNet-io/goodnet.git
cd goodnet
nix develop                     # enters pinned toolchain shell
cmake -B build -G Ninja
cmake --build build
ctest --test-dir build          # 856/856 expected on dev
```

Convenience aliases through the flake:

```bash
nix run .#               # debug build (incremental)
nix run .#build          # release build with LTO
nix run .#test           # debug build + ctest
nix run .#test-asan      # sanitizer build + ctest
nix run .#test-tsan
nix run .#demo           # two-node Noise-over-TCP quickstart
nix run .#goodnet -- version
```

Building without Nix is possible if your host already provides
gcc ≥ 15, the dependencies above, and CMake ≥ 3.25, but the flake
remains the reference setup.

## Try it

The two-node demo establishes a Noise XX handshake over loopback
TCP and exchanges one application message:

```bash
nix run .#demo
```

The bench harness measures encrypted-throughput baseline:

```bash
nix run .# -- build/bin/goodnet-bench 1000 16 1
# expected ~6 Gbps single-conn loopback on a 2024 laptop
```

## Operator CLI

`goodnet` is the daemon binary plus a few admin subcommands:

```bash
goodnet version
goodnet identity gen --out node.id
goodnet config validate dist/example/node.json
goodnet manifest gen build/plugins/libgoodnet_*.so > plugins.json
goodnet run --config dist/example/node.json \
            --manifest plugins.json \
            --identity node.id
```

A working operator setup lives under [`dist/example/`](dist/example/).

## Layout

- [`core/`](core/) — kernel
- [`sdk/`](sdk/) — public C ABI headers (host_api, security, link,
  protocol, handler, conn_events, …) plus C++ wrappers in
  `sdk/cpp/`
- [`plugins/`](plugins/) — bundled plugins (transports, security
  providers, protocol layers, handlers); each is a self-contained
  unit with its own `CMakeLists.txt` and `default.nix`
- [`apps/`](apps/) — `goodnet` daemon binary and friends
- [`examples/`](examples/) — `bench` (throughput harness) and
  `two_node` (Noise-over-TCP demo)
- [`docs/contracts/`](docs/contracts/) — every behavioural rule the
  kernel and plugins agree on; the contract changes first, then the
  code
- [`tests/`](tests/) — kernel-side unit + integration tests
- [`dist/`](dist/) — example operator config, systemd unit, migration
  notes

## Documentation

- [`docs/contracts/`](docs/contracts/) — authoritative behavioural
  contracts (start with [`host-api.md`](docs/contracts/host-api.md))
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — development workflow,
  branch model, audit pass
- [`SECURITY.md`](SECURITY.md) — threat model, reporting channel
- [`GOVERNANCE.md`](GOVERNANCE.md) — decision-making, contract
  amendment process

## License

GPL-2.0 with linking exception for the strategic baseline (kernel,
TCP / UDP / WS / Noise / Heartbeat). Periphery plugins (raw
protocol, null security, IPC link) are MIT. The TLS link is
Apache-2.0 for OpenSSL compatibility. See [`LICENSE`](LICENSE) and
per-plugin `LICENSE` files.

## Out of scope (today)

- Pre-built release binaries — none until `v1.0.0-rc1`.
- API stability — none until `v1.0.0-rc1`.
- Out-of-tree plugin distribution channel — bundled plugins only;
  per-plugin repositories land at `rc1`.
