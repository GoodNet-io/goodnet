# 3-node ICE integration test (Docker)

Production-shape validation for the ICE plugin: three GoodNet kernel
instances behind different NAT topologies, signalled by a fourth
"coordinator" node, with `coturn` providing STUN + TURN. Each
scenario asserts that a payload sent from peer A reaches peer B
through the candidate the ICE FSM negotiated under that NAT shape.

## Topologies

| Scenario | Peer A NAT | Peer B NAT | Expected pair | Why |
|---|---|---|---|---|
| `full_cone` | full-cone | full-cone | `srflx ↔ srflx` | both peers reflexive, STUN-only |
| `hairpin` | shared NAT | shared NAT | `host ↔ host` via hairpin | same NAT egress, NAT loops back |
| `symmetric_relay` | symmetric | full-cone | `relay ↔ srflx` | symmetric NAT defeats srflx, falls to TURN |
| `all_relay` | symmetric | symmetric | `relay ↔ relay` | both peers need TURN |
| `multi_turn_failover` | full-cone | full-cone | `relay ↔ relay`, secondary TURN | primary TURN fails mid-allocation |
| `ipv6_mdns` | full-cone, IPv6 | full-cone, IPv6 | `host(mdns) ↔ host(mdns)` | IPv6 host obfuscation |
| `restricted_mtu` | full-cone | full-cone | `srflx ↔ srflx`, MTU 900 | DPLPMTUD discovery |
| `ice_lite_gateway` | full-cone | full-cone, lite | `srflx ↔ srflx`, only A drives | lite responder |
| `port_prediction` | symmetric+stride | full-cone | `srflx ↔ srflx`, predicted port | symmetric NAT punch |
| `no_udp_fallback` | full-cone, no UDP | full-cone, no UDP | `relay-tcp ↔ relay-tcp` | UDP blocked end-to-end |
| `quic_over_ice` | full-cone | full-cone | `srflx ↔ srflx` via UDP | QUIC handshake over ICE-nominated UDP pair |

The `all_relay` row doubles as a smoke test that TURN ChannelBind
fast-path engages once both legs allocate channels.

## Layout

```
ice-3node/
├── docker-compose.yml         — base stack: STUN + TURN + signal-dir
├── peer/                      — GoodNet kernel + plugins + harness entrypoint
│   ├── Dockerfile             — alpine + nix-built static kernel + plugins
│   ├── peer.json.tmpl         — config template; envsubst at boot
│   └── run.sh                 — entrypoint: template config, boot goodnetd,
│                                publish pubkey, wait for peer, ICE-connect,
│                                write `.done` marker on first inbound byte
│                                (C++ harness binary planned)
├── stun/                      — coturn in STUN-only mode (Dockerfile)
├── turn/                      — coturn full TURN with long-term auth (Dockerfile)
├── turn-backup/               — secondary coturn behind a 500-then-200 shim
├── turn-tls/                  — coturn with TLS-TCP listener (no UDP)
├── nat-a/                     — peer A NAT (full-cone / symmetric / shared /
│                                symmetric_stride); ships a small Python
│                                stride-NAT daemon for the prediction scenario
├── nat-b/                     — peer B NAT
├── scenarios/                 — docker-compose override files per topology
│   ├── all_relay.yml
│   ├── full_cone.yml
│   ├── hairpin.yml
│   ├── ice_lite_gateway.yml
│   ├── ipv6_mdns.yml
│   ├── multi_turn_failover.yml
│   ├── no_udp_fallback.yml
│   ├── port_prediction.yml
│   ├── quic_over_ice.yml
│   ├── restricted_mtu.yml
│   └── symmetric_relay.yml
└── run_all.sh                 — orchestrate every scenario sequentially
```

## Prerequisites — NixOS hosts

The compose stack uses three docker bridges (10.10.0.0/24 = `net`,
10.20.0.0/24 = `lan_a`, 10.30.0.0/24 = `lan_b`). When `br_netfilter`
is loaded the host kernel sets `bridge-nf-call-iptables=1`, which
routes bridged IP frames through the host nftables hooks before they
reach the NAT containers. NixOS' default `inet nixos-fw forward`
chain has `policy drop` (only established/related/dnat/icmpv6 are
accepted), so docker inter-bridge UDP and ICMP are dropped at the
host hook. The container-side iptables FORWARD ACCEPT rules added in
commit `b845fa8` are necessary but **not sufficient** on a NixOS
host — `nat_a`'s FORWARD counters stay at 0 and `peer_b` cannot even
ping `nat_b`'s lan-side address.

Three operator paths, narrowest to broadest:

**(a) Surgical — `networking.firewall.extraForwardRules`** (recommended).
Accept forwarded frames only between the three subnets the compose
stack allocates; rest of the host forward policy stays at drop. A
drop-in NixOS module that does exactly this ships at
[`nixos-firewall.nix`](./nixos-firewall.nix) — add it to your flake
via `imports = [ ./tests/docker/ice-3node/nixos-firewall.nix ];`
and `sudo nixos-rebuild switch`.

```nix
{
  networking.firewall.extraForwardRules = ''
    ip saddr 10.10.0.0/24 ip daddr 10.20.0.0/24 accept
    ip saddr 10.10.0.0/24 ip daddr 10.30.0.0/24 accept
    ip saddr 10.20.0.0/24 ip daddr 10.10.0.0/24 accept
    ip saddr 10.30.0.0/24 ip daddr 10.10.0.0/24 accept
    ip saddr 10.20.0.0/24 ip daddr 10.30.0.0/24 accept
    ip saddr 10.30.0.0/24 ip daddr 10.20.0.0/24 accept
  '';
}
```

**(b) Wider — `networking.firewall.checkReversePath = false`.**
Disables the strict-RPF check that drops asymmetrically-routed
frames. Easier to remember but weakens host hardening on every
interface, not just docker bridges.

```nix
{ networking.firewall.checkReversePath = false; }
```

**(c) Broadest — disable bridge-nf-call-iptables entirely.**
Stops bridged frames from being filtered at the IP layer at all.
Removes the host firewall from docker traffic on this machine
completely; acceptable on a dedicated dev / CI box, not on a host
that also runs untrusted bridged workloads.

```nix
{ boot.kernel.sysctl."net.bridge.bridge-nf-call-iptables" = 0; }
```

### Verification

After `nixos-rebuild switch`, bring up a single scenario:

```bash
cd tests/docker/ice-3node
docker compose -f docker-compose.yml \
    -f scenarios/full_cone.yml up
```

Then inspect the NAT container's FORWARD chain:

```bash
docker exec ice-3node-nat-a-1 iptables -L FORWARD -n -v
```

If the per-rule packet counters climb above 0 once `peer_a` starts
transmitting, the host is now forwarding bridged frames correctly.
If they stay at 0, the host firewall is still dropping — re-check
that the chosen option actually applied (`sudo nft list chain inet
nixos-fw forward`).

## Runtime

```bash
cd tests/docker/ice-3node
./run_all.sh                       # iterate every scenario
docker compose -f docker-compose.yml \
    -f scenarios/full_cone.yml up  # just one
```

Each scenario logs to `./logs/<scenario>/` and exits non-zero on
failure. CI invokes `run_all.sh`; locally use `docker compose logs`
for debugging.

## Status

**This is a scaffold** — `peer/run.sh` is a placeholder entrypoint
(boots `goodnetd` + does an env-substitution pass on the config),
and the NAT-emulation networking under `nat-a/` / `nat-b/` is
stubbed. The directory + compose stack + scenario overrides
establish the contract for CI integration while the C++ harness
binary that drives the actual connect-and-write-done dance lands
iteratively. Running `run_all.sh` today brings up the topology
cleanly and reports timeout for every scenario — useful for
shape-checking the compose wiring.
