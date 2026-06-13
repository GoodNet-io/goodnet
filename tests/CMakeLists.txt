# Test trees mirror the source layout:
#   unit/          — kernel + SDK unit tests
#   integration/   — multi-component scenarios
#   stress/        — high-throughput / long-running
#   property/      — rapidcheck-driven invariants

# Subdirectories registered as suites land.
add_subdirectory(abi)
add_subdirectory(unit)
# Cross-implementation test vectors — JSON fixtures + a consumer that
# replays each input through the C++ reference and asserts byte
# equality. Binding authors (Rust, Python, JS, Go) compare against
# the committed JSON.
add_subdirectory(vectors)
# `integration/` is the slot for the goodnet-integration-tests
# repo — pulled into place by `nix run .#plugin -- install`. When
# pulled, its own `CMakeLists.txt` builds the cross-plugin suite;
# when absent (kernel-only checkout), the suite simply isn't
# registered, and the kernel build stays green.
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/integration/CMakeLists.txt")
    add_subdirectory(integration)
endif()
# `docker/` carries small harness binaries used by the
# docker-compose driven integration topologies. Each suite's
# orchestrator copies the built binary into the docker build
# context before `compose up`.
if(NOT WIN32 AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/docker/CMakeLists.txt")
    add_subdirectory(docker)
endif()
