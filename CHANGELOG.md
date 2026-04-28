# Changelog

All notable changes to this project. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project
uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

Two nodes can talk: real transports, an end-to-end secured byte
pipe, and the first handler. The kernel moves encrypted bytes
between two processes over a real socket and surfaces RTT through a
typed extension API.

### Added

- **URI parser** — header-only `sdk/cpp/uri.hpp` with `parse_uri`
  and `uri_query_value`, plus libsodium-backed
  `core/util/uri_query.hpp` for `?peer=<hex>` decode. Contract
  `docs/contracts/uri.md`.
- **Kernel injection API** — `host_api->inject_external_message`
  and `inject_frame` for bridge plugins to push foreign-system
  payloads into the mesh under their own identity. Per-source
  token-bucket rate limit (`core/util/token_bucket.hpp`) with
  explicit `Clock` injection per `clock.md` §2.
- **Kernel security pipeline** — per-connection `SecuritySession`
  plus `Sessions` registry that drive the handshake from
  `notify_connect` through encrypt / decrypt at the Transport
  phase. `kick_handshake` defers the initiator's first wire
  message until the transport has registered its socket. Trust
  promotes `Untrusted → Peer` once the handshake completes,
  gated through `gn_trust_can_upgrade` in `sdk/trust.h`.
- **Noise plugin** — `goodnet_security_noise` `.so` wrapping the
  XX + IK state machines, dlopen-tested through a two-session
  handshake.
- **TCP transport** — Boost.Asio strand-per-session writes per
  `transport.md` §4 single-writer, IPv6 dual-stack with
  `IPV6_V6ONLY=false` on `::` wildcard.
- **IPC transport** — Boost.Asio `local::stream_protocol` with
  the same strand shape as TCP; `chmod 0700` on the parent
  directory before bind closes the TR-C6 TOCTOU window.
- **UDP transport** — single-strand datagram path, MTU-gated send
  with all-or-nothing `send_batch` precheck, per-source
  `RateLimiterMap` on new-conn allocation, `notify_disconnect` on
  every released peer.
- **Heartbeat handler + `gn.heartbeat` extension** — PING/PONG
  payload with timestamp echo, per-peer RTT under injected clock,
  observed-address reflection (STUN-on-the-wire) sourced from
  `host_api->get_endpoint`. 88-byte big-endian wire layout with
  explicit `serialize_payload` / `parse_payload`.
- **End-to-end loopback test** — two kernels with their own
  `NodeIdentity` plus `TcpTransport` plus the Noise provider drive
  a real Noise XX handshake over a `127.0.0.1` socket and reach
  the Transport phase with matching channel-binding hashes.
- **`nix run .#install-hooks`** — opt-in pre-commit hook that runs
  strict `clang-tidy --warnings-as-errors=*` on staged C++ files,
  mirroring the CI lint gate locally.

### Tests

410 across unit, integration, scenario, and property suites.
ASan / UBSan / TSan strict-clean.

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
