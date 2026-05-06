# Test trees mirror the source layout:
#   unit/          — kernel + SDK unit tests
#   integration/   — multi-component scenarios
#   stress/        — high-throughput / long-running
#   property/      — rapidcheck-driven invariants

# Subdirectories registered as suites land.
add_subdirectory(abi)
add_subdirectory(unit)
# `integration/` is the slot for the goodnet-integration-tests
# repo — pulled into place by `nix run .#plugin -- install`. When
# pulled, its own `CMakeLists.txt` builds the cross-plugin suite;
# when absent (kernel-only checkout), the suite simply isn't
# registered, and the kernel build stays green.
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/integration/CMakeLists.txt")
    add_subdirectory(integration)
endif()
