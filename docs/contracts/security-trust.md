# Contract: Security and Trust

**Status:** active · v1
**Owner:** `core/kernel` (TrustClass propagation), `plugins/security/*`,
            `plugins/transports/*` (TrustClass declaration on connect)
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
                              gn_conn_id_t conn,
                              const gn_endpoint_t* ep,
                              const char* stack_name,
                              gn_trust_class_t trust);
```

The transport plugin computes `trust` from observable connection
properties:

| Transport | Default TrustClass |
|---|---|
| TCP from public address | `Untrusted` |
| TCP from `127.0.0.1` / `::1` | `Loopback` |
| IPC (Unix socket) | `Loopback` |
| Loopback after Noise handshake | unchanged (`Loopback` already exceeds `Peer`) |
| Public TCP after Noise handshake | upgrade to `Peer` |
| Intra-process pipe | `IntraNode` |

The kernel verifies the upgrade path on every transition:

```
can_upgrade(from, to):
    if from == Untrusted and to == Peer: return true
    return from == to                          # any other change rejected
```

---

## 4. Stack policy validation at construction time

A stack is `{transport, security, protocol}`. Each combination has a
declared set of permitted TrustClass values at registration. The
kernel enumerates the cartesian product on `Wire` phase and refuses
unsafe combinations **before** reaching `Running`.

The stack-policy descriptor (declared in `sdk/stack.h` Phase 3) carries:

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
via explicit opt-in:

```bash
goodnet --allow-null-untrusted ...
```

or in JSON config:

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

Without the flag, stack construction returns
`GN_ERR_INVALID_STACK_POLICY`. The flag is logged at warn level on
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
