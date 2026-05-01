# Contract: Security and Trust

**Status:** active · v1
**Owner:** `core/kernel` (TrustClass propagation), `plugins/security/*`,
            `plugins/links/*` (TrustClass declaration on connect)
**Last verified:** 2026-04-27
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
                              const char* scheme,
                              gn_trust_class_t trust,
                              gn_handshake_role_t role,
                              gn_conn_id_t* out_conn);
```

The kernel allocates `*out_conn` and returns it to the transport;
`role` reports whether the local side initiated (outbound `connect`)
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

## 4. Stack policy validation at construction time

A stack is `{transport, security, protocol}`. Each combination has a
declared set of permitted TrustClass values at registration. The
kernel enumerates the cartesian product on `Wire` phase and refuses
unsafe combinations **before** reaching `Running`.

The stack-policy descriptor carries:

| Field | Purpose |
|---|---|
| `name` | stable stack identifier |
| `allowed_for[]` | TrustClass values that may use this stack |
| `requires_explicit_optin` | gate for null-security stacks |

The default registry rejects:

| Combination | Reason |
|---|---|
| `null` security with TrustClass `Untrusted` | plaintext over public internet |
| `null` security with TrustClass `Peer` | keys exchanged but encryption disabled — silent downgrade |
| `raw` protocol with TrustClass `Untrusted` | no framing, no integrity |

Rejecting at config-load time, not runtime, makes the misconfiguration
visible before any traffic moves.

The fourth common combination — `null + raw` over `Loopback` — is
allowed because both endpoints are by definition the same machine; the
threat model excludes a local-process attacker who could equally read
`/proc`.

---

## 5. Explicit opt-in for null on `Untrusted`

Some users need plaintext on an untrusted link for testing or for use
behind an external Noise/TLS terminator. The contract permits it only
via explicit opt-in in the embedding configuration:

```json
{
  "stacks": {
    "test_clear": {
      "transport": "tcp",
      "security":  "null",
      "protocol":  "gnet-v1",
      "allow_null_untrusted": true
    }
  }
}
```

Without the opt-in, stack construction returns
`GN_ERR_INVALID_ENVELOPE`. The opt-in is logged at warn level on
every connect using the stack — there is no quiet plaintext path.

---

## 6. NullProvider lives in plugins, not core

The reference null security provider lives at
`plugins/security/null/` and ships alongside `plugins/security/noise/`.
The kernel never links a concrete security provider statically; it
acquires providers exclusively through `host_api->register_security`
from loaded plugins. `core/` contains only interface declarations.

This separation prevents the kernel from accidentally exposing a
plaintext path through pure source-level reachability.

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
`noise-handshake.md`.

---

## 9. Cross-references

- Wire details for the canonical security provider:
  `noise-handshake.md`.
- Transport-side TrustClass declaration: `transport.md` §3.
- Stack registration: `host-api.md` §2 (`register_*`).
- Kernel error returned for invalid stacks: `fsm-events.md` §4.
