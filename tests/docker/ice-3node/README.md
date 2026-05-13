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

The fourth scenario doubles as a smoke test that TURN ChannelBind
fast-path engages once both legs allocate channels.

## Layout

```
ice-3node/
├── docker-compose.yml         — base stack: 1 STUN + 1 TURN + 1 coordinator
├── peer/                      — GoodNet kernel + plugins + harness binary
│   ├── Dockerfile             — alpine + nix-built static kernel + harness
│   ├── harness.cpp            — minimal C++ binary (~150 LOC, see B.2)
│   └── peer.json.tmpl         — config template; envsubst at boot
├── stun/Dockerfile            — coturn in STUN-only mode
├── turn/Dockerfile            — coturn full TURN with long-term auth
├── nat-a/network.yml          — peer A NAT (full-cone / symmetric / shared)
├── nat-b/network.yml          — peer B NAT
├── scenarios/
│   ├── full_cone.sh           — compose up + harness wait + assertion
│   ├── hairpin.sh
│   ├── symmetric_relay.sh
│   └── all_relay.sh
└── run_all.sh                 — orchestrate all four scenarios sequentially
```

## Runtime

```bash
cd tests/docker/ice-3node
./run_all.sh                       # all four scenarios
./scenarios/full_cone.sh           # just one
```

Each scenario logs to `./logs/<scenario>/` and exits non-zero on
failure. CI invokes `run_all.sh`; locally use `docker compose logs`
for debugging.

## Status

**This is a scaffold** — `harness.cpp` and the NAT-emulation
networking are placeholders right now. The directory + compose file
+ scenario shell scripts establish the contract for CI integration
while the runtime binaries land iteratively.

See `~/.claude/plans/glowing-tickling-cocke.md` §B for the
roadmap.
