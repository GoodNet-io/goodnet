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

- How bits move — TCP, UDP, ICE, WebSocket, BLE, IPC are transport plugins.
- How bytes are encrypted — Noise and TLS are security plugins.
- What an application is — chat, files, sensors, games are handlers above.
- Economics — relay payments, tokens, billing are policy, not kernel.

## What you get

The operational tax that grows with a distributed system — service mesh,
mTLS termination, GeoDNS, etcd, sidecar mesh, configmaps — collapses into
the kernel. Adding a node costs one binary and a keypair.

**Three engineering bets:**

- **Multi-path transport.** TCP + ICE + QUIC + WebSocket simultaneously per
  connection. Automatic failover under 50 ms. Each path adds a digit of
  availability — four paths reach 99.987%.
- **Directed relay → direct.** Connections start through relay, upgrade to
  a direct connection in roughly seven seconds once paths are discovered.
- **Address-based routing.** Around 4.6 hops at one million nodes;
  400 entries per routing table.

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

`v0.1.0` — bring-up release. The kernel core, the plugin C ABI,
and the canonical security crypto have landed. Real transports,
the security pipeline that drives the handshake, the NAT-traversal
stack, and the multi-path scheduler are on the [roadmap](docs/ROADMAP.md)
for v0.2.0 and beyond.

What is in v0.1.0:

- Kernel: connection registry, identity, handler/transport/extension
  registries, plugin manager (`dlopen` + size-prefix vtable), service
  resolver (Kahn topo-sort over plugin deps), signal channel, config
  loader.
- SDK: C ABI plugin boundary (`gn_*` types, vtables, host-API), C++
  convenience wrappers, ABI evolution rules.
- Crypto: full Noise XX and IK state machines on libsodium primitives —
  X25519, ChaCha20-Poly1305 IETF, BLAKE2b, RFC-2104 HMAC-BLAKE2b, Noise
  HKDF; CipherState / SymmetricState / HandshakeState / TransportState.
- Reference security plugin: `null` (loopback / debug pass-through).
- Mandatory mesh framing: GNET protocol v1, statically linked into the
  kernel.
- 304 tests passing across unit, integration, and property suites.
  ASan/UBSan/TSan wired into CI.

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
│ ┄ plugins ┄  Transports (TCP, UDP, WebSocket, IPC, BLE …) │
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
4. The contract for the role you are filling: `transport.md`,
   `handler-registration.md`, `noise-handshake.md`, `security-trust.md`.

Code follows contracts; contracts move first.

## License

Kernel (`core/` and `plugins/protocols/gnet/`) is GPL-2.0 with a
**Linking Exception** that releases the plugin boundary from copyleft
propagation: a plugin that interfaces with the kernel only through the
stable C ABI in `sdk/` may carry any license — MIT, BSD, Apache 2.0,
proprietary — and link statically or dynamically. SDK (`sdk/`) is MIT.
Plugins are independent builds; each carries its own LICENSE file.
Bundled-tree convention: templates and common transports are MIT,
original implementations with no upstream analogue are Apache 2.0.
See [`LICENSE`](LICENSE) for the full text and rationale.
