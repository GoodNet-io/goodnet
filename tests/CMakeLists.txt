# Test trees mirror the source layout:
#   unit/          — kernel + SDK unit tests
#   integration/   — multi-component scenarios
#   stress/        — high-throughput / long-running
#   property/      — rapidcheck-driven invariants

# Subdirectories registered as suites land.
add_subdirectory(abi)
add_subdirectory(unit)
add_subdirectory(integration)
