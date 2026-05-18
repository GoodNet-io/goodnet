# tests/docker — docker-compose-driven integration suites.
#
# Each subdirectory is a self-contained topology (NAT shapes,
# STUN/TURN, peer containers) plus a small harness binary built in
# tree. The harness binaries are dragged into the docker build
# context by the orchestrator script of each suite (see
# e.g. `ice-3node/run_all.sh`).

add_subdirectory(ice-3node)
