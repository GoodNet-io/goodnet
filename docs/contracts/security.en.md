# Contract: Security (umbrella)

**Status:** active · v1
**Owner:** `core/kernel`, `core/identity/`, `core/security/`,
            `core/registry/security`, `plugins/security/*`
**Last verified:** 2026-05-20
**Stability:** stable for v1.x

---

## 0. About this document

This is the umbrella contract for GoodNet's trust, identity,
attestation, and security-provider surface. The detailed wire,
storage, and registry shapes live in the per-area contracts already
on disk; this document states the threat model, names the moving
pieces, and pins the cross-references so an independent reviewer
can read one file and reconstruct the whole picture.

Where another contract already specifies a piece in depth this
document points at it rather than restating. Sections §10 and the
inline links carry the index.

---

## 1. Threat model

GoodNet's security surface defends against the following adversary
classes:

- **Untrusted network attacker.** Can observe, drop, reorder, and
  inject bytes on any public-network link the operator runs the
  kernel over. Cannot forge a Noise handshake against an unknown
  static key, cannot forge an Ed25519 signature, cannot decrypt an
  AEAD ciphertext without the session key. Sees the `Untrusted`
  trust class until the post-handshake attestation gate promotes
  the connection to `Peer`.
- **Peer impersonation attempt.** A peer that completes a Noise
  handshake under a static key it controls but does not hold a
  valid user-key attestation for. The kernel-internal attestation
  dispatcher gates the trust upgrade `Untrusted → Peer` on a
  successful mutual 232-byte exchange (per
  [attestation.en.md §6](./attestation.en.md)); a peer that fails
  the gate stays at `Untrusted` and any handler that gates on the
  trust class refuses to forward.
- **Cross-session device-key swap.** A peer that reconnects under
  the same `peer_pk` but a different `device_pk` is rejected by
  the per-peer pin in
  [registry.en.md §8a](./registry.en.md). The pin survives
  `notify_disconnect`; a swap surfaces as
  `GN_DROP_ATTESTATION_IDENTITY_CHANGE` and the connection closes
  before any handler observes the new key.
- **Replay across sessions.** Attestation envelopes carry the
  current session's `handshake_hash` as a 32-byte binding. A
  captured payload replayed against a different session fails the
  binding check (per [attestation.en.md §5](./attestation.en.md)
  step 3). Identity-rotation proofs carry a monotonic counter
  enforced by `ConnectionRegistry::apply_rotation` (per
  [identity.en.md §10](./identity.en.md)).
- **Substituted plugin binary.** The operator manifest pins
  `sha256` of every loadable plugin. A substituted `.so` between
  manifest pinning and `dlopen` fails the hash check (per
  [plugin-manifest.en.md §4](./plugin-manifest.en.md)).
- **Identity file copy.** The file-backed `LibsodiumSigner`
  default stores both seeds at `0600`. An attacker with read
  access to the identity file holds the device secret; rotation
  to an HSM-backed identity through
  [identity.en.md §12](./identity.en.md) (Phases 2–5) closes
  this gap.

### Non-goals

The kernel does **not** defend against:

- **A malicious worker the operator already trusted.** Remote
  linkage (per [remote-plugin.en.md §1a](./remote-plugin.en.md))
  spawns the worker as a plain `fork` + `execve` with no user
  namespace, no seccomp filter, no cgroup. The trust model for an
  in-process plugin and a remote worker is identical:
  operator-vetted manifest plus SHA-256 of the binary. The
  asymmetry between the two linkage modes is purely about
  address-space isolation (a crashing worker does not pull the
  kernel down), not about runtime sandboxing. Subprocess sandboxing
  is a planned extension (§9).
- **A local-process attacker with `/proc` access.** Null security
  on `Loopback` / `IntraNode` (per
  [security-trust.en.md §4](./security-trust.en.md)) is admitted
  because a local-process attacker who can read kernel memory
  through `/proc` could equally read AEAD plaintexts; the gate is
  superficial against that adversary.
- **Side channels in the underlying primitives.** Timing,
  electromagnetic, and acoustic side channels in libsodium /
  OpenSSL are out of scope. The kernel pins canonical primitives
  but does not harden them.
- **Compromised user-key bytes.** A leaked `user_sk` lets the
  holder mint attestations and rotation proofs. The kernel exposes
  no in-band revocation channel at v1 (per
  [attestation.en.md §10](./attestation.en.md)); operators rotate
  the leaked identity out of band and distribute the new `user_pk`
  to peers. The pin in `registry.en.md §8a` limits the leaked-key
  window to a single `remote_pk` value.

---

## 2. Trust-class hierarchy

The kernel records `gn_trust_class_t` on every connection. Five
values, increasing trust:

| Value | Symbol | Conveys | Upgrade issued by |
|---|---|---|---|
| 0 | `GN_TRUST_UNTRUSTED` | inbound from public internet; default | n/a — initial state |
| 1 | `GN_TRUST_PEER` | static key known + Noise handshake completed + mutual attestation verified | kernel-internal attestation dispatcher (post-handshake) |
| 2 | `GN_TRUST_LOOPBACK` | local IPC or `127.0.0.1` / `::1` | link plugin at `notify_connect` |
| 3 | `GN_TRUST_INTRA_NODE` | in-process pipe between plugins of the same kernel | link plugin at `notify_connect` |
| 4 | `GN_TRUST_ANONYMOUS_LOOPBACK` | anonymous bridge ingress on a loopback-scope carrier; zero `sender_pk` admitted | bridge plugin at `notify_connect` |

The enum lives at `sdk/types.h` and grows only by appending. Trust
is never **decreased** over a connection's lifetime; the only
admitted transition is `Untrusted → Peer`, and only when the
attestation gate validates both directions of the mutual exchange.

Where the gate runs:

- **`Peer` upgrade — kernel-side.** The
  `AttestationDispatcher` runs entirely in kernel code
  (`core/kernel/attestation_dispatcher.{hpp,cpp}`); plugins cannot
  subvert the gate by replacement or unload. See
  [attestation.en.md §11](./attestation.en.md).
- **`Loopback` / `IntraNode` — link-side.** The link plugin
  computes the trust class from observable connection properties
  (peer address scope, in-process pipe) and declares it at
  `notify_connect`. The kernel's per-component mask gate
  ([security-trust.en.md §4](./security-trust.en.md)) refuses any
  off-class transition.
- **`AnonymousLoopback` — bridge-side.** The bridge plugin
  declares the class at `notify_connect`; the router admits a
  zero `sender_pk` envelope **only** when the conn's trust class
  is `AnonymousLoopback` *and* the scheme/uri is loopback-scope
  (per [security-trust.en.md §3.5](./security-trust.en.md)).

The kernel reads the trust class once per call site and refuses
to infer it from defaults — every C ABI entry that produces or
routes a connection takes `gn_trust_class_t` as a positional
argument.

---

## 3. Security-provider extension contract

A security provider is a plugin that implements
`gn_security_provider_vtable_t` (declared in `sdk/security.h`).
Providers register at run time through:

```c
gn_result_t (*register_security)(void* host_ctx,
                                 const gn_security_provider_vtable_t* vtable,
                                 void* self);
```

Multiple providers coexist on one kernel. The `SecurityRegistry`
(`core/registry/security.{hpp,cpp}`) holds N entries keyed by
`provider_id`; a duplicate id returns `GN_ERR_LIMIT_REACHED`. A
distinct id joins the registry and the kernel's per-trust-class
lookup walks entries in registration order.

### `allowed_trust_mask` semantics

Every provider declares which trust classes it admits through the
`allowed_trust_mask` vtable slot (a bitmap of `1u << GN_TRUST_<X>`).
At `SessionRegistry::create` (`core/security/session.cpp` lines
691–704) the kernel reads the bit for the connection's `trust` and
returns `GN_ERR_INVALID_ENVELOPE` on a miss. The same envelope is
gated a second time at the protocol layer via
`IProtocolLayer::allowed_trust_mask()`
(`core/kernel/host_api/notifications.cpp:81`). The admitted set
for any stack is the intersection of the two masks intersected
with the connection's actual `trust`.

`SecurityRegistry::find_for_trust(trust)` picks the first
registered provider whose mask admits the queried class — the
mechanism by which `null` runs on `Loopback` / `IntraNode` and
`noise` runs on `Untrusted` / `Peer` in the same process without
an operator config switch. See
[security-trust.en.md §6](./security-trust.en.md).

### Extension namespace

Security providers register under the `gn.security.*` family. The
namespace is open — operators add backends without a kernel patch
— but the convention is a more specific dotted identifier:

- `gn.security.noise` — canonical Noise XX provider
  (`plugins/security/noise/`). Admits `Untrusted | Peer`. Carries
  the static key, the AEAD session, the rekey state.
- `gn.security.null` — loopback shortcut
  (`plugins/security/null/`). Admits `Loopback | IntraNode` only;
  the gate refuses any other class with no operator knob to widen
  it. See [security-trust.en.md §5](./security-trust.en.md) for
  the unreachable-on-`Untrusted` guarantee.
- `gn.security.pkcs11` — HSM-backed Noise static key
  (`plugins/security/pkcs11/`). Transport-side identity signing
  routed through a PKCS#11 token; the same `.so` dual-exposes
  `gn.identity.pkcs11` once §4 Phase 3 lands.

A provider's `provider_id` slot returns the same dotted name at
run time. The kernel does not parse the dot structure — it is a
naming convention for operators reading manifests, not a kernel
policy.

### vtable shape

The 11 slots + 4 reserved are tabulated at
[security-trust.en.md §3a](./security-trust.en.md). Lifetime and
ownership rules for every slot's parameters live in the same
section. The `api_size`-first layout admits forward-compatible
growth per `abi-evolution.en.md` §3.

---

## 4. Identity contract

Identity is the **root of the trust chain.** Every Noise handshake's
static key derives from the installed identity; every attestation's
64-byte Ed25519 signature is produced by the same identity's user
key; every rotation proof is signed by the identity's *previous*
user key. The identity surface lives at
[identity.en.md](./identity.en.md); the highlights:

- **Two-component layout.** A long-term portable user keypair
  (`user_pk`, `user_sk`) plus a per-device keypair
  (`device_pk`, `device_sk`). Both Ed25519. The mesh address is
  `HKDF-SHA256("goodnet/v1/device-address", device_pk, 32)` —
  device-derived so a user-key rotation does not move the address
  and live connections survive. See
  [identity.en.md §3](./identity.en.md).
- **Attestation cert.** 136 bytes binding `(user_pk, device_pk,
  expiry)` under a user-key signature. See
  [identity.en.md §4](./identity.en.md).
- **Sub-key registry.** Per-purpose Ed25519 keypairs minted on
  demand for `CAPABILITY_INVOKE`, `SECOND_FACTOR`, `RECOVERY`, etc.
  Private bytes never leave the kernel; plugins sign through
  `host_api->sign_local(purpose, ...)`. See
  [identity.en.md §7](./identity.en.md) +
  [identity.en.md §8](./identity.en.md).
- **Rotation.** User-key rotation is announced through
  `host_api->announce_rotation(valid_from)`; the kernel signs a
  150-byte `RotationProof` with the *previous* user key, persists
  the new identity, and pushes the proof on every conn at trust
  ≥ `Peer` under msg_id `0x12`. Receivers verify against the pinned
  `user_pk`, advance the pin atomically, and fire
  `GN_CONN_EVENT_IDENTITY_ROTATED`. See
  [identity.en.md §10](./identity.en.md).

### Roadmap — `IdentitySigner` and HSM backends

The kernel-internal signing path is a single abstraction —
`core/identity/IdentitySigner` — onto which alternative backends
register. The phased rollout (also tracked at
[identity.en.md §12](./identity.en.md)):

| Phase | Surface | Status |
|---|---|---|
| 1 (#87) | `IdentitySigner` interface + `LibsodiumSigner` default. Zero observable change; all in-kernel `crypto_sign_*` callers route through the abstraction. | in flight |
| 2 (#89) | `sdk/extensions/identity.h` + `gn_core_install_identity_from_provider(core, ext_id, key_label)`. Embedding hosts and plugins install external signers before the first attestation runs. | pending |
| 3 (#91) | `plugins/security/pkcs11/` dual-exposes `gn.identity.pkcs11` alongside the existing `gn.security.pkcs11`. Operator-recommended HSM path. | pending |
| 4 (#92) | `goodnetd identity import-hsm`, `goodnetd doctor` HSM presence, `goodnetd quickstart` HSM option. Operator-facing UX. | pending |
| 5 (#94) | `gn::sdk::Core` ctor gains `Identity::from_hsm({ext_id, key_label})` factory. Downstream apps select HSM identity declaratively. | pending |

`IdentitySigner` exposes the narrowest shape that the existing
call sites need — `sign(purpose, payload, out_sig)`,
`public_key(purpose, out_pk)`, `describe()` — so a backend (PKCS#11,
TPM, Keychain, WebAuthn) implements the interface without ever
materialising the secret bytes. The file-backed default stays as
the bootstrap path and is never removed.

The plugin-side extension vtable is
`gn_identity_signer_vtable_t` (declared in
`sdk/extensions/identity.h`); the `gn.identity.*` family is open
for additional backends — each registers under a distinct dotted
name.

---

## 5. Attestation v1 (frozen) — pointer

The attestation step closes the gap between "completed a Noise
handshake" and "endorsed by a long-term user identity". After
every security session reaches the `Transport` phase on a
connection at `Untrusted`, both peers exchange a 232-byte
attestation payload (136-byte cert + 32-byte handshake-hash
binding + 64-byte Ed25519 signature) under reserved msg_id `0x11`.
The kernel-internal `AttestationDispatcher` gates the
`Untrusted → Peer` upgrade on a successful mutual exchange.
Full wire layout, consumer steps, drop reasons, and the
exactly-once trust-upgrade rule live at
[attestation.en.md §2](./attestation.en.md) through
[attestation.en.md §8](./attestation.en.md). The format —
232 bytes, msg_id `0x11`, Ed25519 — is **frozen** per
[attestation.en.md §11](./attestation.en.md): future schemes
register under a separate `gn.security.attestation.*` extension
namespace and run alongside v1 rather than displacing it.

---

## 6. Capability TLV

Capability TLV is the declarative trust-upgrade signal that rides
alongside attestation: once the secured channel is up, peers
exchange a TLV-of-bitmap blob naming which optional features each
side supports (transport schemes, protocol layers, heartbeat
cadence, application-defined categories). The blob is encrypted
under the same Noise session and intercepted by the kernel at
msg_id `0x13`. See [capability-tlv.en.md](./capability-tlv.en.md)
for the wire format, the reserved type ranges, and the
encoder/decoder helper at `sdk/cpp/capability_tlv.hpp`. Capability
TLV records that gate behaviour on trust class read the connection's
`gn_endpoint_t::trust` rather than computing it themselves
([security-trust.en.md §7](./security-trust.en.md)).

---

## 7. Lifecycle

A security provider follows the standard plugin lifecycle. The
relevant ordering:

| Phase | Kernel call | Provider obligation |
|---|---|---|
| install | `gn_plugin_init` | allocate provider state; no threads |
| start | `gn_plugin_register` → `host_api->register_security(vtable, self)` | join the `SecurityRegistry`; the kernel's per-trust-class lookup sees the new entry on return |
| running | `handshake_open` → `handshake_step` × N → `handshake_complete` → `export_transport_keys` → `encrypt` / `decrypt` / `rekey` × M → `handshake_close` | per-conn state lives in the `void* out_state` the provider returned at `open` |
| shutdown | provider's `destroy` slot then `gn_plugin_shutdown` | zeroise key material; the per-conn handshake states are closed first via `handshake_close` |
| destroy | `dlclose` | no callback may fire after this |

`register_security` is the registration entry point per
[host-api.en.md §2](./host-api.en.md); the six-step shutdown
ordering applies per [lifecycle.en.md §4](./lifecycle.en.md).
The trust-upgrade event published when the attestation gate
fires (`GN_CONN_EVENT_TRUST_UPGRADED`) is documented at
[security-trust.en.md §3](./security-trust.en.md); subscribers
see it on the publishing thread and update their state without
disconnecting.

A second provider with a fresh `provider_id` may register at any
time after kernel `on_running`; an operator who wants
deterministic registration order pins it through plugin
`provides` / `requires` per `plugin-lifetime.en.md` §5. The
ordering matters when two providers admit the same trust class —
`find_for_trust` returns the first match.

---

## 8. Operator obligations

Before deploying a kernel build, the operator MUST verify:

1. **Manifest pinning.** Every loadable plugin (`.so` and remote
   worker binary) is listed in the operator manifest with its
   `sha256`. See
   [plugin-manifest.en.md §4](./plugin-manifest.en.md) for the
   hash-then-load ordering. Developer-mode manifests
   (`PluginManifest::empty() == true`) are for local builds only;
   production deployment requires a non-empty manifest.
2. **Identity provenance.** The static key the kernel will present
   to peers comes from one of:
   - the file-backed default at the operator-controlled path
     (`--identity` / `identity_path`; file mode `0600`);
   - an installed `gn.identity.*` extension (PKCS#11, TPM,
     Keychain, WebAuthn) configured before the first attestation
     runs (Phase 2 onward, §4).
   The operator records which source produced the live key; a
   leaked file-backed key is exploitable up to the cert's
   `expiry`.
3. **HSM slot configuration (PKCS#11).** When running with
   `gn.identity.pkcs11`, the operator pins:
   - the PKCS#11 module path,
   - the slot / token label,
   - the `CKA_LABEL` of the identity key,
   - the PIN-environment variable name (the PIN itself never lands
     in config files).
   `goodnetd identity import-hsm` (Phase 4) drives the import; the
   operator workflow lives at
   [operator/identity-hsm-setup.en.md](../operator/identity-hsm-setup.en.md).
4. **Attestation enable/disable per trust profile.** Attestation
   is automatic on every `Untrusted` connection that completes a
   Noise handshake (§5). `Loopback` and `IntraNode` connections
   skip the dispatcher path entirely. The operator's choice is
   *not* whether attestation runs — it always does on the gated
   classes — but which trust classes the security stack admits.
   A baseline-Noise stack admits `Untrusted | Peer`; a null-only
   stack admits `Loopback | IntraNode`; a dual-provider stack
   composes both.
5. **Trust-class declaration per link plugin.** Link plugins
   computing `Loopback` from address scope must use the kernel's
   loopback-scope predicate, not a string match. Bridge plugins
   that need anonymous ingress declare `AnonymousLoopback` and
   honour the loopback-only constraint
   ([security-trust.en.md §3.5](./security-trust.en.md)). A
   mis-declared class on a public-network URI is rejected by the
   gate; the operator sees `drop.trust_class_mismatch` rise.

The kernel emits structured drop metrics
([metrics.en.md §3](./metrics.en.md) `drop.*`) on every rejected
envelope; an operator watching the prefix sees rate-of-failure
without strace.

---

## 9. Open follow-ups

The following security-surface items are specified at the contract
level but not yet shipped. They are the bridge from this document
to the roadmap:

- **Subprocess sandboxing for remote workers.** Linux user
  namespaces, seccomp-bpf syscall filter, and cgroup-based
  resource ceilings around the `RemoteHost::spawn` call. The wire
  protocol itself does not change; isolation primitives wrap the
  spawn path. Tracked at
  [remote-plugin.en.md §1a](./remote-plugin.en.md) "planned
  extension". Required before a marketplace of operator-unvetted
  workers becomes a use case.
- **Identity Phase 2 — C ABI for identity providers (#89).**
  `gn_core_install_identity_from_provider(core, ext_id, key_label)`
  not yet exposed; the `IdentitySigner` interface lands at Phase 1
  (#87) but the extension-namespace dispatch is pending. Until
  Phase 2 the only installed signer is `LibsodiumSigner`.
- **Identity Phase 3 — PKCS#11 dual-expose (#91).**
  `plugins/security/pkcs11/` currently registers only
  `gn.security.pkcs11` (transport-side); the
  `gn.identity.pkcs11` extension is pending. ROADMAP "Hardware key
  store" flips fully to ✓ once Phase 3 lands.
- **Identity Phases 4–5 (#92, #94).** Operator UX
  (`goodnetd identity import-hsm`, doctor checks) and the
  `gn::sdk::Core` `Identity::from_hsm(...)` factory.
- **Identity registration handler.** A discovery handler that
  exchanges `user_pk` / `device_pk` mappings between peers on a
  schedule (cf. ROADMAP "Identity registration handler"). Today
  apps maintain their own connectivity-graph store keyed by
  `user_pk`; a kernel-side handler would standardise the format.
- **Attestation wait-time bound.** A hard time limit on the
  wait-for-peer-attestation window is not enforced
  ([attestation.en.md §9](./attestation.en.md)). A consumer that
  needs bounded waiting closes the conn via
  `host_api->disconnect`; a kernel-side timer would let the
  policy live in config.
- **Attestation chains / multi-CA.** The v1 cert is a single
  user-key signature over the device key. Hierarchical CA
  delegation (cf. SSH certs, X.509 chains) registers under a
  fresh `gn.security.attestation.*` extension and runs alongside
  v1; not in tree.
- **Revocation registry.** No in-band revocation channel at v1
  ([attestation.en.md §10](./attestation.en.md)); operators
  rotate the leaked identity out of band. A signed revocation
  list distributed alongside identity rotation is a planned
  extension.
- **Post-quantum security provider.** ML-KEM (FIPS 203) /
  ML-DSA (FIPS 204) provider once libsodium / OpenSSL ship vetted
  implementations. The Noise abstraction can host the PQ
  handshake without a wire-level change.
- **StackRegistry operator descriptors.** Operator-side cartesian
  enumeration with `requires_explicit_optin` flags and
  `name`/`allowed_for[]` fields, sketched at
  [security-trust.en.md §4](./security-trust.en.md). The shipped
  per-component gates already cover every combination the plugin
  tree can produce; the planned operator-visible layer adds
  policy on top.

---

## 10. Cross-reference index

Every other contract that touches the security surface, one bullet
each:

- [security-trust.en.md](./security-trust.en.md) — `TrustClass`
  enum and propagation, per-component mask gates, conn-id
  ownership, identity-rotation effect on trust.
- [identity.en.md](./identity.en.md) — two-component identity,
  HKDF address derivation, attestation cert layout, sub-key
  registry, rotation wire format, `IdentitySigner` roadmap.
- [attestation.en.md](./attestation.en.md) — 232-byte payload
  v1, mutual exchange, drop reasons, per-conn state lifecycle,
  inter-session device-key swap bound, frozen v1 stability.
- [capability-tlv.en.md](./capability-tlv.en.md) — declarative
  capability blob over msg_id `0x13`, reserved type ranges,
  encoder/decoder helper.
- [remote-plugin.en.md §1a](./remote-plugin.en.md) — subprocess
  trust model, manifest pinning, sandboxing as planned extension.
- [plugin-manifest.en.md](./plugin-manifest.en.md) — operator
  manifest format, `sha256` verification, hash-then-load ordering.
- [registry.en.md §8a](./registry.en.md) — per-peer `device_pk`
  pin that outlives `notify_disconnect`.
- [host-api.en.md §2](./host-api.en.md) — `register_security`,
  `present_capability_blob`, `subscribe_capability_blob`,
  `sign_local`, `announce_rotation`, `get_peer_*_pk` slots.
- [protocol-layer.en.md](./protocol-layer.en.md) —
  `IProtocolLayer::allowed_trust_mask`, connection accessors that
  return 32-byte public keys.
- [lifecycle.en.md §4](./lifecycle.en.md) — six-step shutdown
  ordering that security providers honour.
- [conn-events.en.md](./conn-events.en.md) —
  `GN_CONN_EVENT_TRUST_UPGRADED`, `GN_CONN_EVENT_IDENTITY_ROTATED`,
  `GN_CONN_EVENT_DISCONNECTED`.
- [metrics.en.md §3](./metrics.en.md) — `drop.attestation_*`,
  `drop.trust_class_mismatch`, `drop.capability_blob_too_large`
  counters.
- [handler-registration.en.md](./handler-registration.en.md) —
  reserved msg_id range `0x10..0x1F` for identity-bearing
  transport.
- [plugins/security/noise/docs/handshake.md](../../plugins/security/noise/docs/handshake.md) —
  Noise XX wire layout, exported `handshake_keys_t`, channel
  binding.
- [operator/identity-hsm-setup.en.md](../operator/identity-hsm-setup.en.md) —
  HSM-backed identity operator workflow (gated until Phase 4
  lands).
