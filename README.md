# GoodNet

A platform for distributed networking. The kernel is minimal, the brand
is the ecosystem, and a node joins by carrying a single binary and a
keypair.

## What it is

GoodNet provides a connection fabric where the address of a participant is
its public key, every byte on the wire is encrypted by default, and the
software a participant runs decides what messages mean. The platform itself
is the **kernel** plus the **SDK** — everything else is built on top by
independent plugins, each with its own license, repository, and release
cadence.

**The kernel knows four things:**

1. Logical connections — `conn_id_t`, the file descriptor of the network.
2. Typed messages — envelope of `sender_pk`, `receiver_pk`, `msg_id`, payload.
3. Public keys as addresses — Ed25519, identity is the address.
4. Handlers — userspace consumers, registered on `(protocol_id, msg_id)`.

**The kernel does not know:**

- How bits move — TCP, UDP, ICE, WebSocket, BLE, IPC are link plugins.
- How bytes are encrypted — Noise (XX / IK) is the security plugin;
  TLS sits in the link layer as a wire-byte channel.
- What an application is — chat, files, sensors, games are handlers above.
- Economics — relay payments, tokens, billing are policy, not kernel.

## What you get

The operational tax that grows with a distributed system — service mesh,
mTLS termination, GeoDNS, etcd, sidecar mesh, configmaps — collapses into
the kernel. Adding a node costs one binary and a keypair.

**Architectural directions (not implemented today):**

- **Multi-path transport.** Run TCP, UDP, WebSocket and TLS in parallel per
  connection so a path failure switches over without dropping the session.
  The single-path baseline is in the tree today; the multi-path scheduler
  is a roadmap item.
- **Directed relay → direct.** Open through a relay, upgrade to a direct
  path once both ends have discovered each other. The relay plugin and the
  discovery contract are roadmap items.
- **Address-based routing.** Public-key-as-address with logarithmic-hop
  forwarding under a DHT. The DHT plugin is a roadmap item.

These are the directions the architecture is shaped for, listed in
[docs/ROADMAP.md](docs/ROADMAP.md). What is actually shipped today
is in §"Status" below — no release tag is claimed for any of the
directions above.

## Where it fits

Built for systems where peers need **durable addresses and direct
paths** without a central broker — when a cloud round-trip is too
slow, when the broker is a trust boundary, or when there is no
operator to keep it running.

- **Self-hosted team services.** One binary per member, membership
  by public key, no DNS or VPN to administer.
- **Real-time mesh sessions.** Voice, multiplayer, sensors,
  collaborative tools where region-hopping is the bottleneck.
- **Embedded device fabrics.** Small fleets talking to each other
  and to a phone or laptop without opening ports.

The kernel does not pick a use case; the SDK and plugins do.

## Status

Pre-release. The C ABI surface is open for reshape until the
`v1.0.0-rc1` tag (`abi-evolution.md` §3b); after the tag every
slot is append-only. The kernel runs end-to-end: two processes
exchange application envelopes over a real socket through a Noise
handshake, with backpressure, config reload, connection-event
subscriptions and a dispatching router in between.

What's in the tree today:

- **Kernel:** connection / handler / link / security / extension
  registries, plugin manager (`dlopen` + size-prefix vtable + manifest
  pinning), service resolver, signal channel, hot config reload, kernel
  logger, metrics surface.
- **SDK:** C ABI plugin boundary (`gn_*` types, size-prefix vtables,
  host-API), C++23 convenience wrappers (`std::span`, `std::expected`,
  `std::format`), ABI evolution rules.
- **Crypto:** full Noise XX and IK state machines on libsodium —
  X25519, ChaCha20-Poly1305 IETF, BLAKE2b, RFC-2104 HMAC-BLAKE2b, Noise
  HKDF.
- **Link plugins (`plugins/links/`):** `tcp`, `udp`, `ipc`, `ws`, `tls`.
  Each ships as both a statically-linked archive and a dynamically-loaded
  `.so`; the operator picks per deployment.
- **Security plugins (`plugins/security/`):** `noise` (XX / IK), `null`
  (loopback / IntraNode-only).
- **Protocol layer:** GNET v1 envelope framing, statically linked into
  the kernel.
- **Reference handler (`plugins/handlers/`):** `heartbeat` — RTT
  measurement through the typed extension API.

Sanitiser matrix (ASan + UBSan, TSan) and strict clang-tidy are gates
on every merge into `main`.

Roadmap and version history: [`docs/ROADMAP.md`](docs/ROADMAP.md),
[`CHANGELOG.md`](CHANGELOG.md).

## Build

```bash
nix develop      # gcc15, boost, libsodium, spdlog, nlohmann_json, gtest
cfg && b         # cmake configure + build
t                # ctest
```

Or one-shot:

```bash
nix run .#build
nix run .#test
```

The shortest path from clone to "two endpoints exchanged a frame
over a Noise-secured TCP channel":

```bash
nix run .#demo        # two in-process kernels, real socket, real Noise
```

Sanitiser CI gates:

```bash
nix run .#test-asan   # AddressSanitizer + UBSan
nix run .#test-tsan   # ThreadSanitizer
```

## Architecture

```
┌────────────────────────────────────────────────────────────┐
│ ┄ plugins ┄  Handlers (application logic — chat, files,   │
│              relay, DHT, sync …)                          │
├────────────────────────────────────────────────────────────┤
│              Kernel — routing by (receiver_pk, msg_id)    │
│              Multi-tenant. No knowledge of wire bytes.    │
├────────────────────────────────────────────────────────────┤
│ ┄ plugin ┄   Protocol Layer (one mandatory impl)          │
│              gn_message_t envelope on the kernel side;    │
│              GNET v1 framing on the wire.                 │
├────────────────────────────────────────────────────────────┤
│ ┄ plugins ┄  Security (Noise XX / IK / …)                 │
├────────────────────────────────────────────────────────────┤
│ ┄ plugins ┄  Links (TCP, UDP, WebSocket, IPC, TLS, BLE …) │
└────────────────────────────────────────────────────────────┘

  Platform = kernel + SDK.   Plugins build independently against the SDK.
```

Foreign protocols — HTTP, MQTT, raw TCP — ride inside the payload. Their
specifications are not modified; the mesh artefact lives in exactly one
layer, the GNET frame on the wire.

## Contracts

The kernel↔plugin boundary is documented in `docs/contracts/`. Plugin
authors read these in order:

1. [`protocol-layer.md`](docs/contracts/protocol-layer.md) — envelope
   (`gn_message_t`) and `IProtocolLayer`.
2. [`host-api.md`](docs/contracts/host-api.md) — what the kernel offers
   in return.
3. [`plugin-lifetime.md`](docs/contracts/plugin-lifetime.md) — when each
   entry point is called and what each phase may do.
4. The contract for the role you are filling: `link.md`,
   `handler-registration.md`, `noise-handshake.md`, `security-trust.md`.

Code follows contracts; contracts move first.

## License

Kernel (`core/` and `plugins/protocols/gnet/`) is GPL-2.0 with a
**Linking Exception** that releases the plugin boundary from copyleft
propagation: a plugin that interfaces with the kernel only through the
stable C ABI in `sdk/` may carry any license — MIT, BSD, Apache 2.0,
proprietary — and link statically or dynamically. SDK (`sdk/`) is MIT.
Plugins are independent builds; each carries its own LICENSE file.
Bundled-tree convention: templates and common link plugins are MIT,
original implementations with no upstream analogue are Apache 2.0.
See [`LICENSE`](LICENSE) for the full text and rationale.
