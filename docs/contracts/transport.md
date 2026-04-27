# Contract: Transport Layer

**Status:** active · v1
**Owner:** `plugins/transports/*`
**Last verified:** 2026-04-27
**Stability:** v1.x; new transports plug in without changing this contract.

---

## 1. Purpose

Transports move bytes. They do not interpret payloads, do not authenticate
peers (security plugins do that), and do not route messages (the kernel
does that). The contract here pins the C ABI surface, the lifetime model,
the TrustClass declaration responsibilities, and the write-serialisation
guarantee.

The kernel multiplexes many transports concurrently — TCP, UDP, IPC, BLE,
BT, WS, ICE, future QUIC. Each implements `gn_transport_vtable_t`; the
kernel sees them as interchangeable byte movers identified by a URI scheme.

---

## 2. C ABI

Declared in `sdk/transport.h` (Phase 3). Slot list:

| Slot | Direction | Notes |
|---|---|---|
| `scheme(self)` | plugin → kernel | stable lowercase scheme name; `"tcp"`, `"udp"`, `"ws"` |
| `listen(self, uri)` | kernel → plugin | begin accepting connections matching scheme |
| `connect(self, uri)` | kernel → plugin | initiate outbound; transport calls back via `host_api->notify_connect` once handshake completes |
| `send(self, conn, bytes, size)` | kernel → plugin | bytes `@borrowed` for the call |
| `send_batch(self, conn, span_array, count)` | kernel → plugin | scatter-gather; transport may use `writev`-style internal multiplex |
| `disconnect(self, conn)` | kernel → plugin | idempotent; second call returns `GN_OK` no-op |
| `extension_name(self)` | plugin → kernel | per-transport extension surface, e.g. `"gn.tcp.transport"` |
| `extension_vtable(self)` | plugin → kernel | extension vtable for stats / runtime tweaks |
| `destroy(self)` | kernel → plugin | called once after `unregister_transport` and quiescence |

The vtable starts with `uint32_t api_size` per `abi-evolution.md` §3.

---

## 3. TrustClass declaration

The transport **must** call `host_api->notify_connect` with an explicit
`gn_trust_class_t` computed from observable connection properties per
`security-trust.md` §3:

| Connection property | Declared TrustClass |
|---|---|
| AF_UNIX socket | `Loopback` |
| Peer address `127.0.0.1` / `::1` | `Loopback` |
| Public TCP / UDP address | `Untrusted` |
| Intra-process pipe between two plugins | `IntraNode` |

After a security handshake completes, the kernel may upgrade
`Untrusted → Peer`. Transports never declare anything stronger than
`Peer`; the upgrade path is the kernel's responsibility.

A transport on a loopback path **must** declare `Loopback` regardless of
any `--allow-null-untrusted` configuration; this hint is what lets the
kernel permit `null+raw` stacks per `security-trust.md` §4.

## 3a. Handshake role declaration

The transport **must** declare a `gn_handshake_role_t` on every
`notify_connect`:

| Origin | Declared role |
|---|---|
| Outbound — transport's `connect(uri)` returned successfully | `GN_ROLE_INITIATOR` |
| Inbound — accepted on the listen socket | `GN_ROLE_RESPONDER` |

The kernel propagates this to `security_provider->handshake_open` so
the asymmetric handshake state machine drives the correct side of the
pattern. Misreporting the role is a contract violation: a Noise XX
initiator that thinks it is the responder will fail every handshake
silently and produce no actionable diagnostic.

---

## 4. Single-writer invariant on send

**At most one task may be writing to a given underlying socket at a
time.** Concurrent writes to the same socket produce interleaved bytes
on the wire; the contract serialises them so that every transport
implementation observes single-writer semantics.

What "task" means is language-specific:

- a thread, or
- an asynchronous coroutine, or
- a single-task executor / strand / actor mailbox / channel reader.

The contract is on the observable behaviour: the operating system never
sees two `send`-class syscalls for the same socket-FD overlapping. How
the language enforces it (mutex, single-task ownership, message-queue
serialisation) is internal to the implementation.

The same invariant applies to `send_batch`: the batched scatter-gather
list is one logical write; it may not interleave with other sends on
the same connection.

Reads have no such requirement; a single OS-level reader is the natural
model and no contract is needed.

---

## 5. Async lifetime through reference-counted ownership

Per `plugin-lifetime.md` §4, every async task posted by the transport
captures a weak observer of the transport's reference-counted handle
and upgrades to a strong reference before dereferencing transport
state. A failed upgrade — the last strong reference was dropped — is
a clean no-op exit. Sites that need the check:

| Site | Required |
|---|---|
| async-read completion | yes — may fire after `disconnect` was posted |
| async-write completion | yes |
| reconnect timer | yes |
| idle timer | yes |
| peer-discovery callback (BLE / BT / ICE) | yes |
| synchronous constructor / destructor | no |

The transport never captures a raw pointer to itself in an async
context. Captured strong references kept beyond the synchronous
boundary defeat the contract — they keep the transport alive past its
intended lifetime.

---

## 6. Transport registration

Transports register through `host_api->register_transport`:

```
gn_result_t register_transport(host_ctx,
                               const char* scheme,
                               const gn_transport_vtable_t* vtable,
                               void* transport_self,
                               gn_transport_id_t* out_id);
```

Rules from `host-api.md` §6 apply:

- Only inside `gn_plugin_register` (phase 5 per `plugin-lifetime.md` §2).
- `scheme` is unique across loaded transports; duplicate returns
  `GN_ERR_DUPLICATE`.
- `vtable` is `@borrowed` for the lifetime, valid until `unregister`.

A plugin may register multiple schemes through multiple calls. Pre-RC
convention is to fold IPv6 into a single `tcp` scheme — the URI carries
the address (`tcp://[::1]:9000`).

---

## 7. ConnectionContext accessors

The protocol-layer plugin reads connection state through helper
functions declared in `sdk/connection.h` (Phase 3). The C ABI surface:

| Function | Returns |
|---|---|
| `gn_ctx_local_pk(ctx)` | borrowed pointer to local node pk (32 bytes) |
| `gn_ctx_remote_pk(ctx)` | borrowed pointer to peer pk (32 bytes) |
| `gn_ctx_conn_id(ctx)` | `gn_conn_id_t` |
| `gn_ctx_trust(ctx)` | `gn_trust_class_t` |
| `gn_ctx_plugin_state(ctx)` | opaque per-plugin scratch slot |
| `gn_ctx_set_plugin_state(ctx, ptr)` | set scratch slot |

These are stable across kernel minor versions. They are the only reads
the protocol layer performs on the context.

---

## 8. Cross-references

- Plugin lifetime + liveness probe rules: `plugin-lifetime.md`.
- TrustClass policy: `security-trust.md`.
- Connection registration semantics: `registry.md`.
- Host API entries used: `host-api.md` §2.
