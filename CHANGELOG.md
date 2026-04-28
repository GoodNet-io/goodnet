# Changelog

All notable changes to this project. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project
uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

Phase 7 closure plus the Phase 8 baseline: real transports, an end-to-end
secured byte pipe, and the first handler. The kernel can now move
encrypted bytes between two processes over a real socket and surface
RTT through a typed extension API.

### Added

- **URI parser** — header-only `sdk/cpp/uri.hpp` with `parse_uri` /
  `uri_query_value`, plus libsodium-backed `core/util/uri_query.hpp`
  for `?peer=<hex>` decode. Contract `docs/contracts/uri.md`.
- **Kernel injection API** — `host_api->inject_external_message` and
  `inject_frame` for bridge plugins to push foreign-system payloads
  into the mesh under their own identity. Per-source token-bucket
  rate limit (`core/util/token_bucket.hpp`) with explicit `Clock`
  injection per `clock.md` §2.
- **Kernel security pipeline** — per-connection `SecuritySession` plus
  `Sessions` registry that drive the handshake from `notify_connect`
  through encrypt / decrypt at the Transport phase. `kick_handshake`
  defers the initiator's first wire message until the transport has
  registered its socket.
- **Trust upgrade** — kernel promotes `Untrusted → Peer` once a Noise
  handshake completes, gated through `gn_trust_can_upgrade` in
  `sdk/trust.h`. Downgrade paths are forbidden by contract; security
  weakening is a closure event.
- **Noise plugin** — `goodnet_security_noise` `.so` wrapping the XX +
  IK state machines, dlopen-tested through a two-session handshake.
- **Transports** — TCP (Boost.Asio strand-per-session, IPv6 dual-stack
  with `IPV6_V6ONLY=false` on `::` wildcard), IPC (AF_UNIX with
  `chmod 0700` on the parent directory before bind to close TR-C6),
  UDP (single-strand datagram, MTU-gated send, atomic batch
  precheck, `notify_disconnect` on every released peer).
- **Heartbeat handler + `gn.heartbeat` extension** — PING/PONG payload
  with timestamp echo, per-peer RTT under injected clock,
  observed-address reflection (STUN-on-the-wire) sourced from
  `host_api->get_endpoint`. Wire format big-endian; `serialize_payload`
  / `parse_payload` translate between the in-memory struct and the
  88-byte canonical layout.
- **End-to-end loopback test** — two kernels with their own
  `NodeIdentity` + `TcpTransport` + Noise provider drive a real
  Noise XX handshake over a `127.0.0.1` socket and reach Transport
  phase with matching channel-binding hashes.

### Changed

- **`flake.nix`** — drops the `cfg / cfgd / b / bd / t` shellHook
  functions in favour of `nix run .#<app>`. Every CMake workflow
  (`dev`, `build`, `test`, `test-asan`, `test-tsan`) re-enters the
  dev shell so `find_package(... CONFIG)` sees the same
  `CMAKE_PREFIX_PATH` `inputsFrom = [ goodnet-core ]` sets up.
- **TCP `connect`** rejects port 0 per `uri.md` §5; the parser still
  accepts port 0 on the listen path for ephemeral allocation.
- **`Sessions::create`** rejects a duplicate `conn` id with
  `GN_ERR_LIMIT_REACHED` instead of silently overwriting the entry.
- **Router result** is consumed at every dispatch site
  (`thunk_notify_inbound_bytes`, `inject_external_message`,
  `inject_frame`); `Rejected` and the `Dropped*` family log via the
  kernel's spdlog instead of being `(void)`-cast away.
- **clang-tidy parity** across TCP / IPC / UDP transports — mutable
  lambdas for buf-move, `size_t` literals for `kReadBufferSize`,
  destructor try/catch around `shutdown`, explicit `has_value()`
  guard before optional deref, error-code consumption on
  `set_option` / `close` / `open` via `host_api->log` when set.

### Tests

410 passing across unit, integration, scenario, and property suites
(was 304 in v0.1.0). ASan / UBSan / TSan strict-clean across the
whole tree.

## [0.1.0] — 2026-04-28

The bring-up release. The kernel skeleton, the plugin C ABI, and the
canonical security crypto are in place. Real transports and the
security pipeline that drives the handshake land in v0.2.0; see
[`docs/ROADMAP.md`](docs/ROADMAP.md).

### Added

- **Kernel** — connection registry (16-shard, three indexes by id/uri/pk),
  handler / transport / security / extension registries, identity layer
  (Ed25519 keypair, two-key HKDF address derivation, attestation,
  NodeIdentity), plugin manager (`dlopen` + size-prefix vtable evolution
  + Kahn topo-sort service resolver), typed signal channel, JSON config
  loader with schema validation.
- **SDK** — C ABI plugin boundary (`gn_message_t`, `gn_endpoint_t`,
  `host_api_t`, vtable types for handler / transport / security /
  protocol), C++ convenience wrappers, ABI evolution rules
  (`abi-evolution.md`).
- **Crypto** — full Noise XX and IK state machines on libsodium
  primitives: X25519 (`crypto_scalarmult`), ChaCha20-Poly1305 IETF AEAD,
  BLAKE2b, RFC-2104 HMAC-BLAKE2b, Noise §4.3 HKDF. CipherState,
  SymmetricState, HandshakeState (XX + IK pattern progression),
  TransportState with §4 atomic rekey.
- **Reference plugins** — null security provider (loopback /
  debug pass-through), GNET protocol v1 (mandatory mesh framing,
  statically linked into the kernel).
- **Documentation** — eleven contracts in `docs/contracts/` covering the
  ABI surface end-to-end (host-api, plugin-lifetime, registry,
  protocol-layer, gnet-protocol, transport, handler-registration,
  noise-handshake, security-trust, abi-evolution, fsm-events, clock,
  limits).
- **Tests** — 304 passing: unit (configuration, identity, crypto
  primitives, handshake state, registries, plugin manager, service
  resolver, kernel router, signal channel), integration (host_api
  chain, send loopback), scenario (round-trip, disconnect), property
  (gnet wire, gnet protocol).
- **CI/CD** — five GitHub Actions jobs on every push and PR: nix flake
  check, build + test, AddressSanitizer + UBSan, ThreadSanitizer,
  strict clang-tidy on changed files.
- **Build** — Nix flake with `nix run .#build`, `nix run .#test`,
  `nix run .#test-asan`, `nix run .#test-tsan`.

### Licensing

The kernel (`core/` and the statically-linked `plugins/protocols/gnet/`)
is **GPL-2.0 with a Linking Exception**: plugins that interface only
through the stable C ABI may carry any license — MIT, BSD, Apache 2.0,
proprietary — and link statically or dynamically. SDK (`sdk/`) is MIT.
Bundled-tree convention: templates and common transports are MIT;
original implementations with no upstream analogue are Apache 2.0.

See [`LICENSE`](LICENSE) for the full text and rationale.
