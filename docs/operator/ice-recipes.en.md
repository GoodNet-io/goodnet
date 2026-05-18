# ICE config recipes

Operator-facing recipes for the `plugins/links/ice` plugin. Each
section describes one deployment shape, the knobs that shape it, and
the wire-level consequences. The full key matrix is in §10. Source of
truth: `plugins/links/ice/link_ice.cpp::apply_config()` and
`plugins/links/ice/session.hpp::IceConfig`.

All keys are read from the kernel config under the `ice.*` namespace
and react to `systemctl reload goodnetd` per the
[hot-reload](./deployment.en.md#64-hot-reload) section. TURN
credentials and the TURN transport toggles (`ice.turn_username`,
`ice.turn_password`, `ice.turn_tcp`, `ice.turn_tls`) are applied to
every entry in `ice.turn_servers` — the schema does not support per-
entry credentials today.

---

## Contents

1. [Recipe 1 — Minimal home-network deployment](#1-minimal-home-network-deployment)
2. [Recipe 2 — Behind an enterprise firewall (UDP blocked)](#2-behind-an-enterprise-firewall-udp-blocked)
3. [Recipe 3 — Multi-TURN for high availability](#3-multi-turn-for-high-availability)
4. [Recipe 4 — mDNS-only LAN (no internet bootstrap)](#4-mdns-only-lan-no-internet-bootstrap)
5. [Recipe 5 — ICE-lite server gateway](#5-ice-lite-server-gateway)
6. [Recipe 6 — Symmetric NAT punch](#6-symmetric-nat-punch)
7. [Recipe 7 — Path MTU optimisation](#7-path-mtu-optimisation)
8. [Recipe 8 — Mobile reconnect (wifi to cellular)](#8-mobile-reconnect-wifi-to-cellular)
9. [Recipe 9 — Candidate filtering](#9-candidate-filtering)
10. [Config-key matrix](#10-config-key-matrix)
11. [Cross-references](#11-cross-references)

---

## 1. Minimal home-network deployment

Default-leaning config for peer-to-peer connectivity between two
home networks. One or two public STUN bootstraps, every other knob
on its default. Approximately 80% of consumer NATs are cone-shaped;
STUN-derived server-reflexive candidates pair directly without
needing TURN.

```json
{
  "ice": {
    "stun_servers": [
      "stun.l.google.com:19302",
      "stun.cloudflare.com:3478"
    ]
  }
}
```

Notes:

- mDNS host-candidate obfuscation is off by default — host candidates
  ride the wire as raw IPs. Flip `ice.mdns_obfuscate_host_candidates`
  to `true` if peers might share interior addresses with non-trusted
  signalers.
- No TURN configured means a symmetric-NAT-to-symmetric-NAT pair will
  fail to connect. Recipe 3 covers the multi-TURN safety net.

---

## 2. Behind an enterprise firewall (UDP blocked)

Corporate egress firewalls commonly drop all UDP and allow only
outbound TCP/443. TURN-over-TLS rides 443/TCP and tunnels the STUN
framing inside a TLS record. The kernel-side `gn.link.tls` carrier
plugin must be loaded.

```json
{
  "ice": {
    "stun_servers": ["stun.l.google.com:19302"],
    "turn_servers": ["turn.example.net:443"],
    "turn_username": "operator",
    "turn_password": "REDACTED",
    "turn_tls":      1
  }
}
```

Notes:

- `ice.turn_tls = 1` takes precedence over `ice.turn_tcp` when both
  are set. Without TLS, set `ice.turn_tcp = 1` for plain TCP framing.
- The strategy chain naturally drops UDP-only candidates when the
  `gn.link.capability` extension reports UDP unusable; the relay
  candidate stays the only viable path.
- TURN credentials are global — `ice.turn_username` /
  `ice.turn_password` apply to every entry in `ice.turn_servers`.

---

## 3. Multi-TURN for high availability

Sequential fallback across a primary TURN plus one or two backups
per RFC 8445 §6.1.4. The session walks `ice.turn_servers` in order;
the first successful `ALLOCATE` becomes the relay candidate, the
remainder stay queued for failover driven by `TurnClient::is_healthy()`.

```json
{
  "ice": {
    "stun_servers": ["stun.l.google.com:19302"],
    "turn_servers": [
      "turn-primary.example.net:3478",
      "turn-backup-1.example.net:3478",
      "turn-backup-2.example.net:3478"
    ],
    "turn_username":                 "operator",
    "turn_password":                 "REDACTED",
    "turn_allocate_timeout_s":       5,
    "turn_backup_interval_s":        30,
    "turn_failover_min_interval_s":  60
  }
}
```

Notes:

- `ice.turn_allocate_timeout_s` caps the per-entry ALLOCATE attempt
  before walking to the next entry. Five seconds is the default;
  raise on links with slow handshakes.
- `ice.turn_backup_interval_s` is the cadence at which the session
  probes the next backup after the primary is active. Set to `0` to
  disable backup probing entirely (single-TURN behaviour).
- `ice.turn_failover_min_interval_s` bounds oscillation when both
  primary and backup are flapping.

---

## 4. mDNS-only LAN (no internet bootstrap)

Air-gapped clusters and developer LANs run without any public
bootstrap. Peers exchange `<uuid>.local` host candidates and resolve
them through multicast DNS on `224.0.0.251` / `FF02::FB`. Works only
for peers on the same broadcast segment.

```json
{
  "ice": {
    "stun_servers":                     [],
    "turn_servers":                     [],
    "mdns_obfuscate_host_candidates":   1,
    "mdns_resolve_timeout_ms":          5000
  }
}
```

Notes:

- The clearing-out empty arrays override the default
  `stun.l.google.com` entry. The session emits only mDNS host
  candidates.
- `ice.mdns_resolve_timeout_ms` bounds the wait for a peer's
  `<uuid>.local` name to surface on multicast DNS; expiry drops the
  pair.
- Use case: developer LANs, air-gapped clusters, kiosks. Any peer
  outside the LAN broadcast domain is unreachable in this profile.

---

## 5. ICE-lite server gateway

For an endpoint that always plays responder (media gateway, SFU,
server-side WebRTC bridge, IoT responder with a fixed public
address). A lite agent never initiates connectivity checks, never
runs consent freshness, and never drives nomination. The peer must
be a full ICE agent.

```json
{
  "ice": {
    "stun_servers": [],
    "lite_mode":    1
  }
}
```

Notes:

- Two ICE-lite peers cannot complete the FSM — neither drives
  nomination. Pair a lite gateway only with full-ICE clients.
- A lite agent is always controlled. The `controlling_` flag is
  forced false regardless of how the session was constructed.
- STUN bootstraps are typically unnecessary on a public-address
  gateway; the endpoint's own address is the host candidate.

---

## 6. Symmetric NAT punch

Symmetric NATs allocate distinct external ports for each unique
destination, defeating canonical ICE. When gather detects a
symmetric stride, the FSM probes
`(peer.ip, peer.port + stride * k)` for `k` in `1..N` alongside the
advertised peer endpoint. The remote side advertises the detection
through the `ICE_SIGNAL_FLAG_SYMMETRIC` bit on the signal envelope.

```json
{
  "ice": {
    "stun_servers": [
      "stun.l.google.com:19302",
      "stun.cloudflare.com:3478"
    ],
    "symmetric_port_prediction_enabled":  1,
    "symmetric_port_prediction_attempts": 8
  }
}
```

Notes:

- Defaults are already on (`enabled = true`, `attempts = 8`); explicit
  config here is for operators who need to override.
- Empirically converts roughly 30-50% of symmetric-to-symmetric pair
  attempts that would otherwise need TURN, against zero before. The
  exact rate depends on the ISP's port-allocation policy — predictable
  monotonic strides succeed; randomised allocations do not.
- Purely additive — every standard ICE check still runs alongside the
  predicted-port probes. Set `attempts` to `0` to disable while
  keeping the FSM in single-port mode.

---

## 7. Path MTU optimisation

RFC 8899 DPLPMTUD discovers the largest datagram size that survives
the path without fragmentation. Probes climb a ladder; the
discovered value surfaces through the `gn.link.ice.path_mtu`
extension to upper layers.

```json
{
  "ice": {
    "path_mtu":              1200,
    "pmtu_active_probing":   1,
    "pmtu_search_steps":     [1200, 1400, 1500, 4000, 9000],
    "pmtu_probe_timeout_ms": 500,
    "pmtu_probe_concurrency": 1
  }
}
```

Notes:

- All values shown are the defaults. Typical home networks converge
  to 1500 (Ethernet) after the first few probes; leave defaults.
- `ice.path_mtu` is the floor — discovery never regresses below it.
  Lower the floor on constrained mobile carriers; raise on jumbo-
  frame LANs to skip lower rungs.
- Set `ice.pmtu_active_probing = 0` to pin the effective MTU at the
  static floor (constrained paths, embedded deployments with no probe
  budget). The `gn.link.ice.path_mtu` extension still surfaces the
  static value to upper layers.
- `ice.pmtu_probe_concurrency` is capped at 16; 1 is conservative and
  matches the RFC 8899 §5.1.4 reference recommendation.

---

## 8. Mobile reconnect (wifi to cellular)

On Linux, the session opens an `AF_NETLINK / NETLINK_ROUTE` socket
and listens for `RTM_NEWLINK` / `RTM_NEWADDR` / `RTM_DELADDR` /
`RTM_DELLINK`. State transitions debounce for 300 ms before
re-gathering host candidates, so a wifi-cellular toggle does not
burn the ICE FSM through multiple restarts.

```json
{
  "ice": {
    "reactive_interface_change": 1
  }
}
```

Notes:

- Default is on. Non-Linux platforms silently no-op — the watcher
  bind fails and the session runs without interface-flap re-gather.
- The 300 ms debounce is hardcoded inside `InterfaceWatcher`. Bursts
  of netlink events inside the window collapse into a single
  re-gather.
- macOS / Windows fall through to the polling-only path today.

---

## 9. Candidate filtering

Operator-side candidate filter. `ice.candidate_filters` is an array
of string tokens. Each token OR-s one bit into the filter mask;
combinations make sense. Unknown tokens are ignored silently so
older kernels reading a newer config do not refuse to start.

| Token | Effect |
|---|---|
| `exclude-ipv4` | Drop every IPv4 candidate |
| `exclude-ipv6` | Drop every IPv6 candidate |
| `host-only`    | Keep only host candidates (no srflx, no relay) |
| `relay-only`   | Keep only relay candidates (force TURN) |

```json
{
  "ice": {
    "turn_servers":      ["turn.example.net:3478"],
    "turn_username":     "operator",
    "turn_password":     "REDACTED",
    "candidate_filters": ["relay-only", "exclude-ipv6"]
  }
}
```

Notes:

- `relay-only` + `host-only` is a contradiction — both bits drop both
  kinds, yielding zero candidates. Useful for diagnostics where you
  want a deterministic ICE failure.
- `relay-only` forces every flow through TURN — billing implication
  on metered TURN servers.

---

## 10. Config-key matrix

| Knob | Default | Range / format | Recipe |
|---|---|---|---|
| `ice.stun_servers` | `["stun.l.google.com:19302"]` | array of `host:port` or `stun:host[:port]` | 1, 2, 3, 4, 6 |
| `ice.turn_servers` | empty | array of `host:port` or `turn:host[:port]` (single string also accepted) | 2, 3, 9 |
| `ice.turn_username` | empty | string; applied to all TURN entries | 2, 3, 9 |
| `ice.turn_password` | empty | string; applied to all TURN entries | 2, 3, 9 |
| `ice.turn_tcp` | `0` | `0` / `1`; applied to all TURN entries | 2 |
| `ice.turn_tls` | `0` | `0` / `1`; precedence over `turn_tcp` | 2 |
| `ice.turn_allocate_timeout_s` | `5` | int, `(0, 600)` | 3 |
| `ice.turn_backup_interval_s` | `30` | int, `[0, 3600)`; `0` disables backup probing | 3 |
| `ice.turn_failover_min_interval_s` | `60` | int, `[0, 3600)` | 3 |
| `ice.session_timeout_s` | `10` | int, `(0, 3600)` | — |
| `ice.keepalive_interval_s` | `20` | int, `(0, 3600)` | — |
| `ice.consent_max_failures` | `3` | int, `(0, 100)` | — |
| `ice.consent_max_recovery` | `3` | int, `[0, 10]`; `0` fails on first consent loss | — |
| `ice.check_interval_ms` | `50` | int, `(0, 60000)` | — |
| `ice.path_mtu` | `1200` | int bytes, `[576, 65507]` | 7 |
| `ice.pmtu_active_probing` | `1` | `0` / `1` | 7 |
| `ice.pmtu_search_steps` | `[1200, 1400, 1500, 4000, 9000]` | array of int bytes, `[576, 65507]` | 7 |
| `ice.pmtu_probe_timeout_ms` | `500` | int, `(0, 60000)` | 7 |
| `ice.pmtu_probe_concurrency` | `1` | int, `(0, 16]` | 7 |
| `ice.aggressive_nomination` | `0` | `0` / `1`; RFC 8445 §8.1.1 | — |
| `ice.lite_mode` | `0` | `0` / `1`; RFC 8445 §2.7 | 5 |
| `ice.reactive_interface_change` | `1` | `0` / `1`; Linux only | 8 |
| `ice.symmetric_port_prediction_enabled` | `1` | `0` / `1` | 6 |
| `ice.symmetric_port_prediction_attempts` | `8` | int, `[0, 64]` | 6 |
| `ice.mdns_obfuscate_host_candidates` | `0` | `0` / `1` | 4 |
| `ice.mdns_resolve_timeout_ms` | `5000` | int, `(0, 60000)` | 4 |
| `ice.candidate_filters` | empty | array of `"exclude-ipv4"` / `"exclude-ipv6"` / `"host-only"` / `"relay-only"` | 9 |

Bounds annotation: `(a, b)` is open, `[a, b]` is closed. A value
outside the documented bound is silently rejected by
`apply_config()`; the previous value (or default) stays in effect.

---

## 11. Cross-references

- [link](../contracts/link.en.md) — kernel-side link contract that
  ICE implements.
- [deployment](./deployment.en.md) — operator deployment guide;
  §4.3 covers the multi-node mesh path where ICE rendez-vous sits.
- [config](../contracts/config.en.md) — kernel config schema; the
  `ice.*` namespace is one of several per-plugin namespaces.
- [uri](../contracts/uri.en.md) — `ice://<peer-pk-hex>` URI shape.
- `plugins/links/ice/README.md` — plugin overview, RFC coverage,
  build commands.
- `plugins/links/ice/session.hpp` — `IceConfig` field defaults.
- `plugins/links/ice/link_ice.cpp` — `apply_config()` parse path.
