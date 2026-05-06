# Kernel + SDK unit tests.
#
# `goodnet_unit_tests` covers `core/`, `sdk/`, and the cross-cutting
# kernel surface (PluginManager, registries, util). Plugin-specific
# unit tests live with their plugin under `plugins/<kind>/<name>/tests/`
# and produce their own gtest binaries; this binary stops linking
# plugin OBJECT libraries.

include(GoogleTest)

# RapidCheck targets get patched once for the whole build by
# `goodnet_patch_rapidcheck_targets()` in the top-level CMakeLists
# (also re-exported through `GoodNetConfig.cmake` for out-of-tree
# plugin builds). The patch is idempotent so callers do not need
# to coordinate ordering.

file(GLOB_RECURSE goodnet_unit_test_sources
    CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/test_*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/*/test_*.cpp"
)

# `test_plugin_manager.cpp` dlopens the null security provider's .so
# at runtime and therefore needs the `GOODNET_NULL_PLUGIN_PATH`
# compile-time define which is only set when the plugin's CMake
# target is in the build. Loadable plugins live in their own
# repos and are pulled in on demand; if the operator did not pull
# `security-null`, drop the test from the unit suite rather than
# letting the source's `#error` guard fail the build.
if(NOT TARGET goodnet_security_null)
    list(FILTER goodnet_unit_test_sources
         EXCLUDE REGEX "test_plugin_manager\\.cpp$")
endif()

if(NOT goodnet_unit_test_sources)
    message(STATUS "tests/unit: no test_*.cpp sources found; skipping")
    return()
endif()

add_executable(goodnet_unit_tests ${goodnet_unit_test_sources})

target_link_libraries(goodnet_unit_tests
    PRIVATE
        goodnet_kernel
        GoodNet::protocol_gnet
        GTest::gtest
        GTest::gtest_main
        rapidcheck
        rapidcheck_gtest
        ${CMAKE_DL_LIBS}
)

target_compile_features(goodnet_unit_tests PRIVATE cxx_std_23)
goodnet_apply_pch(goodnet_unit_tests)

# PluginManager regression suite dlopens the null security provider .so
# to drive the load/verify/anchor paths. Force ninja to ship the .so
# before linking the test binary; the path threads through a compile-
# time define.
if(TARGET goodnet_security_null)
    add_dependencies(goodnet_unit_tests goodnet_security_null)
    target_compile_definitions(goodnet_unit_tests
        PRIVATE
            "GOODNET_NULL_PLUGIN_PATH=\"$<TARGET_FILE:goodnet_security_null>\""
    )
endif()

gtest_discover_tests(goodnet_unit_tests
    DISCOVERY_TIMEOUT 30
    PROPERTIES TIMEOUT 60
)
