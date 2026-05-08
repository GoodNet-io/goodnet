# Contract: Security and Trust

**Status:** active · v1
**Owner:** `core/kernel` (TrustClass propagation), `plugins/security/*`,
            `plugins/links/*` (TrustClass declaration on connect)
**Last verified:** 2026-05-08
**Stability:** v1.x; the TrustClass enum may grow only by appending values.

---

## 1. Purpose

Every connection has a trust level. Every security stack has a permitted
set of trust levels. The kernel rejects mismatches loudly at construction
time. TrustClass is an explicit ABI parameter at every call site that
produces or routes a connection — it is never inferred from defaults.

---

## 2. `TrustClass` values

```c
typedef enum gn_trust_class_e {
    GN_TRUST_UNTRUSTED  = 0,  /**< inbound connection from internet, default */
    GN_TRUST_PEER       = 1,  /**< pubkey known + Noise handshake completed */
    GN_TRUST_LOOPBACK   = 2,  /**< local IPC or 127.0.0.1 — no encryption needed */
    GN_TRUST_INTRA_NODE = 3   /**< between plugins of the same kernel; in-process */
} gn_trust_class_t;
```

The values are ordered by increasing trust. The kernel never
**decreases** trust over the lifetime of a connection — only an upgrade
after the Noise handshake completes is allowed (`Untrusted → Peer`).

---

## 3. TrustClass is an explicit parameter

Every C ABI entry that produces or routes a connection takes
`gn_trust_class_t` as a positional argument. There is no default
fallback that could let an `Untrusted` connection be classified
otherwise without source-level evidence:

```c
gn_result_t (*notify_connect)(void* host_ctx,
                              const uint8_t remote_pk[GN_PUBLIC_KEY_BYTES],
                              const char* uri,
                              gn_trust_class_t trust,
                              gn_handshake_role_t role,
                              gn_conn_id_t* out_conn);
```

The kernel allocates `*out_conn` and returns it to the transport;
the scheme is derived from the `uri://` prefix so the transport
plugin owning the scheme need not pass it explicitly. `role`
reports whether the local side initiated (outbound `connect`)
or accepted (inbound on `listen`) so the security session drives
the correct half of the asymmetric handshake pattern.

The transport plugin computes `trust` from observable connection
properties:

| Transport | Default TrustClass |
|---|---|
| TCP from public address | `Untrusted` |
| TCP from `127.0.0.1` / `::1` | `Loopback` |
| UDP from public address | `Untrusted` |
| UDP from `127.0.0.1` / `::1` | `Loopback` |
| IPC (Unix socket) | `Loopback` |
| Intra-process pipe | `IntraNode` |
| `Untrusted` after Noise handshake **and successful mutual attestation** | upgrade to `Peer` |
| `Loopback` / `IntraNode` after handshake | unchanged — gate refuses any transition off these classes |

The kernel verifies the upgrade path on every transition:

```
can_upgrade(from, to):
    if from == Untrusted and to == Peer: return true
    return from == to                          # any other change rejected
```

Promotion to `Peer` is **gated on attestation**: the kernel does
not call `upgrade_trust` when the security session reaches
`Transport`. Instead, both peers first exchange a 232-byte
attestation payload over the secured channel (per
`attestation.md`); the kernel-internal attestation dispatcher
holds the trust class at `Untrusted` until the local side has
sent and the remote side's payload has verified. A peer that
completes Noise but fails to provide a valid attestation stays
at `Untrusted`. `Loopback` and `IntraNode` connections do not
require attestation — their trust class is final at
`notify_connect` and the gate refuses any other transition
regardless.

### Link-layer authentication policy

Identity authentication is the security-pipeline's job. Link-layer
transports do not duplicate it:

- **TLS client.** Default verifies the peer certificate against the
  OpenSSL default trust store. Operators running TLS as link
  encryption beneath Noise opt out through
  `links.tls.verify_peer = false` on the kernel config; the
  Noise handshake then carries identity authentication and the
  attestation gate above promotes trust.
- **TLS server.** Anonymous-client by spec. The server presents its
  certificate and key but does not demand a client cert. Peer
  identity reaches the kernel through the Noise handshake on the
  same connection, not through mutual TLS. An operator who needs
  X.509 mutual auth as a second factor adds a `verify_peer_client`
  knob through a transport-extension; the v1 baseline does not
  ship one.
- **Plain TCP / UDP / IPC / WS.** No link-layer authentication.
  Identity is the security-pipeline's job; the transport surfaces
  the URI and trust class only.

### Bridge plugins declare `IntraNode`

A bridge plugin that re-publishes foreign-system payloads
(MQTT, HTTP, OPC-UA) into the mesh runs out-of-process and opens
an IPC link to the kernel — see `host-api.md` §8.1 for the v1
shape. The bridge's IPC conn declares `gn_trust_class = IntraNode`
on `notify_connect`; the null security provider's
`allowed_trust_mask` already permits `IntraNode`
(`plugins/security/null/null.cpp:139`), so the bridge edge runs
without a Noise handshake. No new ABI is needed — the trust class
exists, the security mask permits it, and `host-api.md` §8.1
names the canonical pattern.

A bridge that mistakenly declares `Untrusted` on its IPC link
under the canonical v1 stack (null security loaded) is rejected
synchronously: the security-mask gate at
`SessionRegistry::create` (`core/security/session.cpp:245-263`)
sees the trust-class miss against `null_allowed_trust_mask =
Loopback | IntraNode`, returns `GN_ERR_INVALID_ENVELOPE`, and
`thunk_notify_connect` erases the conn record before the bridge
returns from the call. The kernel bumps
`metrics.drop.trust_class_mismatch` so an operator watching the
counter sees the misconfiguration immediately. There is no
handshake phase, no `pending_handshake_bytes` accumulation.

The same mistake under a Noise-only stack (no null provider
loaded) succeeds at `notify_connect` — Noise admits all four
trust classes — and the foreign client then cannot drive the
Noise handshake, which is the original «stall» symptom for
mis-declared bridges in non-canonical stacks. The IntraNode
declaration above avoids both failure modes.

---

## 3a. `gn_security_provider_vtable_t` layout

A security provider implements the vtable declared in
`sdk/security.h`. The first field carries `api_size` so the kernel
gates additive evolution per `abi-evolution.md` §3.

```c
typedef struct gn_security_provider_vtable_s {
    uint32_t api_size;

    const char* (*provider_id)(void* self);

    gn_result_t (*handshake_open)(void* self,
                                  gn_conn_id_t conn,
                                  gn_trust_class_t trust,
                                  gn_handshake_role_t role,
                                  const uint8_t local_static_sk[GN_PRIVATE_KEY_BYTES],
                                  const uint8_t local_static_pk[GN_PUBLIC_KEY_BYTES],
                                  const uint8_t* remote_static_pk,
                                  void** out_state);

    gn_result_t (*handshake_step)(void* self,
                                  void* state,
                                  const uint8_t* incoming, size_t incoming_size,
                                  gn_secure_buffer_t* out_message);

    int         (*handshake_complete)(void* self, void* state);

    gn_result_t (*export_transport_keys)(void* self,
                                         void* state,
                                         gn_handshake_keys_t* out_keys);

    gn_result_t (*encrypt)(void* self,
                           void* state,
                           const uint8_t* plaintext, size_t plaintext_size,
                           gn_secure_buffer_t* out);

    gn_result_t (*decrypt)(void* self,
                           void* state,
                           const uint8_t* ciphertext, size_t ciphertext_size,
                           gn_secure_buffer_t* out);

    gn_result_t (*rekey)(void* self, void* state);

    void        (*handshake_close)(void* self, void* state);

    void        (*destroy)(void* self);

    uint32_t    (*allowed_trust_mask)(void* self);

    void* _reserved[4];
} gn_security_provider_vtable_t;
```

| Slot | Lifetime / ownership |
|---|---|
| `provider_id` | returned `const char*` outlives the plugin |
| `handshake_open`/`local_static_sk` | borrowed for the call; the provider derives its own X25519 / sign material before return |
| `handshake_open`/`out_state` | provider-allocated; kernel returns it on every subsequent call until `handshake_close` |
| `handshake_step`/`incoming` | borrowed for the call |
| `handshake_step`/`out_message` | provider-owned via `gn_secure_buffer_t`; kernel calls `out_message->free_fn(out_message->bytes)` after committing |
| `export_transport_keys`/`out_keys` | caller-allocated; provider zeroises its own copy after a successful export |
| `encrypt`/`decrypt` | `out` follows the same `gn_secure_buffer_t` ownership |
| `handshake_close` | zeroises remaining key material; subsequent encrypt/decrypt on the closed state returns `GN_ERR_INVALID_STATE` |
| `allowed_trust_mask` | bitmap of `1u << GN_TRUST_<X>` admitted by the provider; checked by the kernel on every `Sessions::create` per §4 |
| `_reserved[4]` | NULL on init; `api_size` carries the producer-build size, consumers read no further |

`gn_secure_buffer_t` (declared alongside the vtable) carries the
ownership pair for variable-length security output:

```c
typedef struct gn_secure_buffer_s {
    uint8_t* bytes;
    size_t   size;
    void  (*free_fn)(uint8_t* bytes);
} gn_secure_buffer_t;
```

## 4. Trust-class admission via per-component masks

A stack composes one transport + one security provider + one
protocol layer. v1 admits trust classes through **two independent
runtime gates** — one per component — rather than a cartesian-product
enumeration at registration:

- The active **protocol layer** declares its admitted classes via
  `IProtocolLayer::allowed_trust_mask()`. The kernel checks the bit
  for the connection's `trust` at `notify_connect`
  (`core/kernel/host_api_builder.cpp:1063-1070`); a miss returns
  `GN_ERR_INVALID_ENVELOPE` and increments the
  `drop.trust_class_mismatch` metric.
- The active **security provider** declares its admitted classes via
  `gn_security_provider_vtable_t::allowed_trust_mask`. The kernel
  checks the bit at `SessionRegistry::create`
  (`core/security/session.cpp:245-258`); a miss returns
  `GN_ERR_INVALID_ENVELOPE` and increments the same metric.

The admitted set for any stack is the intersection of the two masks
intersected with the connection's actual `trust`. The unsafe
combinations the kernel rejects today fall out of this intersection:

| Combination | How the rejection lands |
|---|---|
| `null` security with `Untrusted` | `null_allowed_trust_mask = Loopback \| IntraNode` (`plugins/security/null/null.cpp:138-140`) — security gate refuses |
| `null` security with `Peer` | same null mask — security gate refuses |
| `raw` protocol with `Untrusted` | `raw::allowed_trust_mask = Loopback \| IntraNode` (`plugins/protocols/raw/raw.cpp:109-115`) — protocol gate refuses |

The fourth common combination — `null + raw` over `Loopback` — is
admitted because both masks include `Loopback`; the threat model
excludes a local-process attacker who could equally read `/proc`.

A unified StackRegistry that enumerates the cartesian product at
admission, with `requires_explicit_optin` flags and
`name`/`allowed_for[]` descriptors, lands in v1.x. v1 ships the
per-component gates: simpler, deterministic, and already covers
every combination the v1 plugin tree can produce.

---

## 5. Null security on `Untrusted` is unreachable in v1

The v1 null security provider's `allowed_trust_mask` is
`Loopback | IntraNode` (`plugins/security/null/null.cpp:139`). The
security gate (§4) refuses any other class. There is no v1
configuration knob — JSON, env, host_api — that can widen the mask
on a loaded null provider. An operator who needs plaintext over an
untrusted link runs an external Noise/TLS terminator in front of
the kernel; the kernel sees the terminated end as a `Loopback` or
`IntraNode` link and admits null on it.

A future StackRegistry (v1.x) will introduce an explicit opt-in for
plaintext-on-untrusted as a deployment-time descriptor, so operators
can declare it in config rather than build a custom security
provider. Until then the safer path through the static masks is the
only path.

---

## 6. NullProvider lives in plugins, not core

The reference null security provider lives at
`plugins/security/null/` and ships alongside `plugins/security/noise/`.
The kernel never links a concrete security provider statically; it
acquires providers exclusively through `host_api->register_security`
from loaded plugins. `core/` contains only interface declarations.

This separation prevents the kernel from accidentally exposing a
plaintext path through pure source-level reachability.

v1 admits **at most one active security provider per kernel**. A
second `register_security` call returns `GN_ERR_LIMIT_REACHED`
(`core/registry/security.cpp:33`); the existing provider is
unaffected. Multi-provider per-trust-class selection — running a
null provider for `Loopback` traffic and Noise for `Peer` /
`Untrusted` on the same kernel — lands in v1.x via StackRegistry.

---

## 6a. Conn-id ownership gate

A link plugin holds the only legitimate path for delivering inbound
bytes, tearing down a connection, or publishing transport-level events
(backpressure, handshake kicks) for the connections it created. A
second loaded link plugin attempting any of those operations on a
foreign `gn_conn_id_t` is rejected.

The kernel enforces this at host_api entry: the connection record
carries `link_scheme`; the link registry maps each scheme to the
`lifetime_anchor` of the registering plugin; the calling plugin's
`PluginContext` carries that same anchor. Equal anchors → same
plugin. Failure surfaces as `GN_ERR_NOT_FOUND`, identical to the
shape of a missing connection id, so a probing plugin cannot use
the error code to enumerate foreign connections.

Without this gate any loaded link plugin could spoof inbound bytes
on a peer transport's connection id — feeding hostile frames into
the security session of a connection it does not own, or tearing
down its rivals' connections from outside their scheme.

In-tree fixtures construct kernels and call host_api thunks without
ever loading a plugin shared object; in that case both anchors are
null and the gate is permissive. The loader path always produces
non-null anchors, so the gate is active in production.

The gated thunks: `notify_inbound_bytes`, `notify_disconnect`,
`notify_backpressure`, `kick_handshake`. `notify_connect` is the
creation point and runs unowned.

---

## 7. Per-message TrustClass propagation

The kernel records TrustClass on every connection record and surfaces
it to handlers through the read-only `gn_endpoint_t::trust`. Handlers
that gate behaviour on trust level (relay forwarding, persistent
storage) read this field rather than computing locally — single source
of truth.

A relay handler that forwards a frame from an `Untrusted` source to a
`Peer` destination must consult `trust` on both sides and refuse the
cross-class path. The kernel does not police the cross-class flow;
that is the handler's responsibility per its registered policy.

---

## 8. Cryptographic correctness

This contract scopes TrustClass policy. The cryptographic correctness
of the security providers — Noise wire layout, hash function
consistency, buffer sizing, rekey semantics — lives in
`plugins/security/noise/docs/handshake.md`.

---

## 8a. Identity rotation under trust

User-key rotation is a kernel primitive (`identity.md` §10) that
preserves trust without an explicit policy entry on this surface:

- `mesh_address` is device-derived (`identity.md` §3 decouple), so
  a `user_pk` rotation does **not** change the address. The peer's
  `TrustClass` stays at whatever it was immediately before the
  rotation arrived (`Peer` in the typical case).
- `peer_pin_map[remote_pk].user_pk` advances atomically through
  `apply_rotation` after the kernel verifies the inbound 150-byte
  `RotationProof` against the *previously* pinned `user_pk`. The
  device_pk pin is unchanged; cross-session identity-change checks
  in §3 still gate device_pk mismatches.
- `GN_CONN_EVENT_IDENTITY_ROTATED` fires with old / new user_pk +
  counter pointers in `_reserved[0..2]`. Subscribers observe the
  event on the publishing thread and update connectivity-graph
  edges keyed by `user_pk` without disconnecting.
- Anti-replay: every pin carries a monotonic `rotation_counter`;
  `apply_rotation` rejects with `GN_ERR_INVALID_ENVELOPE` when a
  proposed counter does not strictly exceed the stored value.
  The counter persists alongside the user_pk in the on-disk
  identity file.
- A peer that returns with a different `device_pk` for the same
  `peer_pk` is **not** a rotation; it is the cross-session
  identity-change attempt §3 already disconnects on. The two
  paths are non-overlapping.

Out-of-band concerns (revocation, recovery from compromise,
witness signatures on a rotation) are app territory: the kernel
exposes the rotation primitive and the events; policy lives
above.

---

## 9. Cross-references

- Wire details for the canonical security provider:
  `plugins/security/noise/docs/handshake.md`.
- Transport-side TrustClass declaration: `link.md` §3.
- Stack registration: `host-api.md` §2 (`register_*`).
- Kernel error on a trust-class mismatch: `GN_ERR_INVALID_ENVELOPE`
  from `notify_connect` (`core/kernel/host_api_builder.cpp:1067-1068`,
  protocol-layer gate) and from `SessionRegistry::create`
  (`core/security/session.cpp:255`, security-provider gate). Both
  sites bump `metrics.drop.trust_class_mismatch` so an operator
  watching the counter sees the rate without an strace.
