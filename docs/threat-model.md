# Threat model

**Status:** active · v1
**Owner:** kernel + security plugins
**Last verified:** 2026-05-01
**Stability:** v1.x; the boundary between enforced and not-enforced
properties is part of the security contract and follows the same
size-prefix rules as the C ABI.

---

## 1. Adversary positions

### 1.1 Network-active

A peer on the path between two GoodNet nodes who can drop, reorder,
inject, replay, and observe ciphertext. Cannot break X25519 / Ed25519
in feasible time, cannot extract operator-controlled key material
that never leaves disk.

This is the default adversary model. The kernel and Noise pipeline
are designed against this position.

### 1.2 Misbehaving peer (post-handshake)

A correctly-handshaking remote peer who sends spurious envelopes —
malformed payloads, oversized frames, ping floods, repeated
disconnect/reconnect. The handshake binds peer pk to the
connection; the misbehaving peer is identifiable.

### 1.3 Misbehaving plugin (post-load)

A loaded plugin (passed manifest verification or developer-mode load)
that makes legitimate ABI calls with malicious arguments — wrong
config types, oversized inject payloads, kind-tag-tampered ids,
spurious unsubscribes.

### 1.4 Local privileged operator

The user running the kernel as `root` or as the dedicated service
user. Operator can alter config, replace plugins, read keys from
disk, attach a debugger. **Out of threat model** — operator owns
the system.

---

## 2. What the kernel enforces

### 2.1 Envelope authentication

Every envelope arriving at a handler carries a `sender_pk` that the
Noise handshake bound to the originating connection. A peer cannot
forge `sender_pk` without forging the handshake, which requires the
peer's static private key. `null` security plugin (loopback /
`IntraNode`-only per `security-trust.md` §4) is the explicit opt-out
for trusted-domain links.

Reference: `noise-handshake.md`, `security-trust.md` §3.

### 2.2 Replay window

Each Noise cipherstate runs a sliding 256-counter replay window per
direction (cipher-side detail in libsodium's chacha20poly1305 IETF
nonce model). A replayed frame past the window is rejected at the
security plugin's `decrypt` step before the kernel sees it.

### 2.3 Trust class

Every connection carries a `gn_trust_class_t` declared at
`notify_connect` by the link plugin and possibly upgraded once by
the security pipeline (`Untrusted → Peer` after handshake). Handler
contracts that depend on Peer-class trust gate themselves on the
`trust` field of `gn_message_t::ctx`.

Reference: `security-trust.md` §3 (one-way upgrade), §4 (loopback /
IntraNode permits null security).

### 2.4 Identity binding

The attestation dispatcher (`attestation.md`) binds peer pk to a
device pk on first attested handshake, then rejects subsequent
attestations from the same peer with a different device pk —
`GN_DROP_ATTESTATION_IDENTITY_CHANGE`. A connection-registry pin
(`registry.md` §8a) outlives the connection record so a peer that
disconnects and reconnects meets the same pin.

### 2.5 Plugin pinning

`PluginManager::set_manifest()` locks loaded plugins to a SHA-256
allowlist; `set_manifest_required(true)` makes the empty-manifest
case a hard error (`plugin-manifest.md` §7). Production deployments
ship a non-empty manifest and the strict flag; an unsigned plugin
cannot reach the kernel address space.

### 2.6 Argument validation at the C ABI

Every host-API thunk validates arguments before any state mutation
or token consumption (`host-api.md` §2.1, `host-api.md` §8). A
misbehaving plugin that passes NULL meta, an unknown enum tag, an
oversized payload, a tampered subscription id, or a kind-flipped
register id receives `GN_ERR_*` without affecting kernel state.

### 2.7 Constant-time comparisons on auth surface

Every public-key equality on the auth path runs through
`sodium_memcmp` (attestation binding match, pinned device-pk match).
A timing-side-channel attack that scoped per-byte equality is
neutralised at the kernel level.

### 2.8 Memory-zero on key teardown

Static and ephemeral Noise secrets are zeroised at handshake split
(`noise-handshake.md` §5 clause 4); TLS plugin's PEM override
buffers are zeroised before reassignment and at destructor; the
`NodeIdentity` keypair runs `wipe()` at last shared-ref drop.

---

## 3. What the kernel does **not** enforce

### 3.1 Denial of service from a peer-priviledged attacker

A peer that has completed the Noise handshake can flood the kernel
with envelopes up to the `inject_rate_per_source` token bucket and
the per-link backpressure cap. Beyond that the kernel applies
backpressure (`backpressure.md` §3) and may close the connection,
but the **resource cost up to the cap is real**. An operator who
needs harder DoS protection runs a relay plugin that throttles
by IP at L4.

### 3.2 Traffic analysis at the link layer

A network-active observer sees ciphertext lengths, timing, and the
public IP / port of every link plugin. The Noise envelope is
encrypted but its size leaks the application payload size to within
a small constant. Peer pk is **not** transmitted in the clear during
the handshake (Noise XX hides initiator pk until the third message;
IK uses a known responder pk), but the wire pattern of the handshake
itself is recognisable as Noise traffic.

### 3.3 Anonymity at the application layer

Peer pk is the address. A peer who exposes its pk to a relay or to
another mesh participant has revealed its identity. Onion-routing-
style anonymity is a relay-plugin policy concern, not a kernel
guarantee.

### 3.4 Plugin code correctness

The kernel does not analyse plugin code. A plugin author who writes
a buffer overflow in their `handle_message` reaches the kernel
address space when the kernel calls back into the plugin. The
manifest pinning prevents *unsigned* plugins from reaching the
kernel; it does not prevent a *signed buggy* plugin from compromising
the kernel.

Mitigation roadmap: per-plugin sandboxing (`feedback_plugin_deployment_modes`)
runs dynamically-loaded plugins under a default-deny capability
manifest that gates host-API calls. Statically-linked plugins
remain trusted.

### 3.5 Side channels in plugin-internal cryptography

A plugin that wires non-constant-time string compare on an auth
surface (e.g. an HMAC-based replay token in plugin-internal state)
leaks timing. The kernel can audit plugins under our signature
policy but cannot statically prove constant-time properties for
arbitrary plugin code.

### 3.6 Operator-side compromise

Disk encryption, key file permissions, terminal session security,
build-system integrity, distribution mirror verification — all
delegated to the operator. The kernel assumes the disk it was
loaded from contains the bytes the operator built or downloaded.

---

## 4. Trust class assumptions

| Class | Origin | Assumption |
|---|---|---|
| `Loopback` | AF_UNIX socket / 127.0.0.1 / ::1 | the link-layer endpoint is the same machine; OS-level isolation already applies |
| `IntraNode` | intra-process pipe | both endpoints share the same kernel and address space |
| `Untrusted` | public IP / unauthenticated peer | nothing is known about the remote until handshake completes |
| `Peer` | post-handshake | remote pk is bound; `security-trust.md` §3 one-way upgrade |

A handler that queries `gn_message_t::ctx.trust` is making a real
authorisation decision; the kernel guarantees the field reflects
the link plugin's declaration plus any handshake upgrade and never
forges the value.

---

## 5. Cryptographic primitive failure

| Primitive | Where used | Mitigation if broken |
|---|---|---|
| X25519 | Noise DH leg | Noise handshake version bump, kernel security release |
| ChaCha20-Poly1305 IETF | cipherstate | same |
| BLAKE2b | Noise HKDF, MAC | same |
| Ed25519 | static identity (`NodeIdentity`) | identity rotation campaign + kernel release |
| SHA-256 | plugin manifest hashes | manifest format bump (`plugin-manifest.md`); old hashes refused |

We commit to a security-release cadence under coordinated disclosure
(`SECURITY.md` §"Disclosure timeline"). A primitive-level break
does **not** cascade into a network-protocol redesign — the wire
envelope shape is stable, only the security-plugin interior changes.

---

## 6. Out of scope

- Multi-region CDN-style availability.
- Censorship-resistance at the transport layer (an operator running
  on hostile infrastructure relies on relays to obscure presence;
  the kernel does not steganograph).
- Quantum-resistant cryptography. The Noise patterns are classical;
  a post-quantum migration is a wire-protocol revision, not a v1
  feature.
- Formal verification of the kernel state machine. We rely on
  contract-driven testing, sanitiser CI, and audit reviews.

---

## 7. Reporting and disclosure

`SECURITY.md` covers the reporting channel, embargo timeline, and
acknowledgement policy. Threat-model revisions land through the
same channel as code: contract change, atomic merge, audit pass,
release note.
