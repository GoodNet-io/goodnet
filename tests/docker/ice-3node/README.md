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
│   ├── restricted_mtu.yml
│   └── symmetric_relay.yml
└── run_all.sh                 — orchestrate every scenario sequentially
```

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
