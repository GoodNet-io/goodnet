# Contract: Path optimizer plugins

**Status:** active · v1
**Owner:** plugins that own a single path-optimisation strategy
            (relay-driver, autonat, ICE, transport-failover, …)
**Last verified:** 2026-04-28
**Stability:** v1.x; the vtable evolves through `api_size` size-prefix
extension per `abi-evolution.md` §4.

---

## 1. Purpose

A connection's quality depends on factors the kernel cannot decide
on its own: which of several candidate transports to prefer when
the peer is reachable through more than one, whether to upgrade an
inbound TCP relay tunnel to a direct UDP-hole-punched path,
whether the peer's NAT class allows a direct path at all. Each of
these is a distinct strategy with its own measurement / decision
surface.

The contract pins one shape — the `gn.optimizer.<name>` extension —
so:

1. The kernel itself stays agnostic about which strategies exist.
   Adding a new optimiser is a `register_extension` call from a
   plugin; no kernel change.
2. Strategies compose through priority — the kernel asks every
   registered optimiser in priority order on every connection
   event and applies the first non-empty recommendation.
3. Strategy state lives in the plugin, not the kernel. Each
   optimiser owns its own measurement, hysteresis, and timer
   schedule; the kernel forwards the per-conn events the optimiser
   wants and respects the result.

Optimisers are decision plugins. They do not move bytes — moving
bytes is the transport layer's job. An optimiser's recommendation
is consumed by the `path orchestrator` and turned into a `connect()` /
`disconnect()` sequence on the kernel-managed transport.

---

## 2. Naming and registration

The extension identifier is the literal string
`"gn.optimizer." + name`, lowercase, kebab-case for the suffix.
Reserved names:

| Name | Strategy |
|---|---|
| `gn.optimizer.transport-failover` | switch transport on RTT degradation, hysteresis-bounded |
| `gn.optimizer.relay-upgrade` | promote an active relay-tunnel conn to a direct path once both peers learn each other's addresses |
| `gn.optimizer.ice` | drive ICE candidate gathering / pairing / nomination |
| `gn.optimizer.autonat` | classify the local NAT and feed the result to `relay-upgrade` |

Registration follows `host-api.md` §3 (`register_extension`):

```c
host_api->register_extension(
    host_ctx,
    "gn.optimizer.transport-failover",
    /*version=*/ GN_EXT_OPTIMIZER_VERSION,
    &vtable,
    self,
    quiescence_anchor,
    &out_id);
```

The kernel keeps the extension alive only as long as the plugin's
quiescence anchor stays alive (`plugin-lifetime.md` §4).

---

## 3. Vtable surface

```c
typedef struct gn_optimizer_api_s {
    uint32_t api_size;
    uint32_t priority;          /* lower = earlier; ties broken by
                                   registration order */

    /* @return GN_OK and fills *out when a recommendation is ready,
       GN_ERR_NOT_IMPLEMENTED when the optimiser has nothing to say
       on this conn, GN_ERR_LIMIT_REACHED when the strategy declines
       responsibility (e.g. the conn already runs the recommended
       transport). */
    gn_result_t (*recommend)(void* ctx,
                              gn_conn_id_t conn,
                              gn_optimizer_recommendation_t* out);

    /* Called for every per-conn event the optimiser declared
       interest in via the bitmask in `subscribed_events`. */
    void (*on_event)(void* ctx, const gn_conn_event_t* ev);

    uint32_t subscribed_events; /* OR of `1u << GN_CONN_EVENT_*` */

    void* _reserved[8];
} gn_optimizer_api_t;
```

`gn_optimizer_recommendation_t` carries a target transport
scheme + URI, and an `apply_strategy` enum: `Replace`, `AddPath`,
`Drop`. The kernel's `path orchestrator` decides what to do with the
recommendation; an optimiser is permitted to recommend, never to
mutate registry state directly.

Lifetime invariant: every entry in the vtable executes under the
calling plugin's quiescence anchor. A plugin that has begun
unloading drops the call silently before any optimiser code runs.

---

## 4. Event subscription model

Subscriptions ride the existing connection-event channel
(`conn-events.md` §2). An optimiser sets the bits for the events
it cares about in `subscribed_events`; the kernel publishes the
matching events through `on_event` instead of routing through
`subscribe_conn_state`. The single channel shape avoids duplicating
the lifetime / quiescence machinery.

Common subscription shapes:

| Strategy | Events |
|---|---|
| `transport-failover` | `BACKPRESSURE_SOFT`, `BACKPRESSURE_CLEAR`, `RTT_SAMPLE` |
| `relay-upgrade` | `CONNECTED`, `TRUST_UPGRADED`, `RTT_SAMPLE` |
| `ice` | `CONNECTED`, `DISCONNECTED` |

`RTT_SAMPLE` is reserved for v1.1 (`heartbeat.md` §4 emits it once
the heartbeat handler ships); current v1.0 optimisers ignore the
event until then.

---

## 5. Decision flow

```
connection event
  └── kernel publishes to subscribed optimisers
       └── optimiser updates state, may queue a follow-up timer

evaluate(conn) (called periodically + on subscribed events)
  └── for each registered optimiser in priority order:
       optimiser.recommend(conn) → recommendation
       if recommendation:
           apply via the kernel's path orchestrator
           break
```

The path orchestrator is the single mutating entrypoint to the
path-state table. Optimisers never call `connect` / `disconnect`
themselves; they always return a recommendation. A v1.0 baseline
build ships the orchestrator as a skeleton so the contract is
observable end-to-end before optimisers exist; optimiser plugins
ship incrementally and the kernel never has to know about them.

---

## 6. Cross-references

- Extension registration mechanics: `host-api.md` §3.
- Per-conn event channel: `conn-events.md`.
- Quiescence anchor: `plugin-lifetime.md` §4.
- Capability advertisement (peer-to-peer optimiser negotiation):
  `capability-tlv.md`.
- The TLV blob rides as application payload over the same secured
  GNET channel that handler messages use — it is not a separate
  frame format. `gnet-protocol.md` §6 notes the capability
  handshake as a higher-layer concern of versioning.
