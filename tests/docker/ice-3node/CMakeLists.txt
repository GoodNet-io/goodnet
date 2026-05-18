# ice-3node docker integration test umbrella.
#
# Only the peer-harness binary needs a CMake target — the NAT
# emulators, STUN, TURN, and orchestration are pure shell + dockerfile
# inputs. The harness lives under `peer/` so the path the orchestrator
# copies into the docker build context is local to the Dockerfile.

add_subdirectory(peer)
