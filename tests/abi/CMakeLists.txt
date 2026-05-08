# tests/abi/ — ABI invariants per `docs/contracts/abi-evolution.md` §7.
#
# Two kinds of pins:
#
#   1. Layout invariants (test_layout.c) — `_Static_assert` on every
#      public C ABI struct's `sizeof` and field `offsetof`. Compile-only,
#      no runtime test target. A future patch that reorders or resizes
#      a v1 struct fails to compile here, surfacing the ABI break before
#      merge.
#
#   2. Cross-version load (test_cross_version.cpp) — runtime gtest that
#      builds a small probe plugin against the in-tree SDK headers and
#      loads it through `PluginManager` against the same kernel binary.
#      Documents the loader's accept criteria; future patches that
#      change `gn_plugin_sdk_version` semantics or reject paths land
#      here as failing tests rather than silent rejects in production.

# ── 1. Layout invariants ─────────────────────────────────────────────
add_library(goodnet_abi_layout OBJECT
    test_layout.c
    test_core_c_layout.c
)
target_include_directories(goodnet_abi_layout
    PRIVATE
        ${CMAKE_SOURCE_DIR}
)
# C99: these files are C, not C++. No need for kernel sources or libs —
# every assertion is purely a header-driven `sizeof`/`offsetof`.
set_target_properties(goodnet_abi_layout PROPERTIES
    LINKER_LANGUAGE C
    C_STANDARD 11
    C_STANDARD_REQUIRED YES
)
# Drop the object file once compiled — the side effect we want is the
# `_Static_assert` firings during compilation, not the .o.
set_target_properties(goodnet_abi_layout PROPERTIES EXCLUDE_FROM_ALL FALSE)

# ── 2. Cross-version load (gtest) ────────────────────────────────────
add_executable(goodnet_abi_tests test_cross_version.cpp)
target_link_libraries(goodnet_abi_tests
    PRIVATE
        goodnet_kernel
        GTest::gtest_main
)
target_include_directories(goodnet_abi_tests
    PRIVATE
        ${CMAKE_SOURCE_DIR}
)
target_compile_features(goodnet_abi_tests PRIVATE cxx_std_23)
add_test(NAME abi_cross_version COMMAND goodnet_abi_tests)
