# Kernel + SDK unit tests.
#
# `goodnet_unit_tests` covers `core/`, `sdk/`, and the cross-cutting
# kernel surface (PluginManager, registries, util). Plugin-specific
# unit tests live with their plugin under `plugins/<kind>/<name>/tests/`
# and produce their own gtest binaries; this binary stops linking
# plugin OBJECT libraries.

include(GoogleTest)

# RapidCheck on Nix: the cmake-config from the runtime output points
# `INTERFACE_INCLUDE_DIRECTORIES` at `${runtime}/include` which only
# exists in the `-dev` output. Patch the imported targets so the
# include path resolves to the path pkg-config reports.
pkg_check_modules(GN_RAPIDCHECK_PC IMPORTED_TARGET rapidcheck)
if(GN_RAPIDCHECK_PC_FOUND)
    set_target_properties(rapidcheck PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES "${GN_RAPIDCHECK_PC_INCLUDE_DIRS}")
    if(TARGET rapidcheck_gtest)
        set_target_properties(rapidcheck_gtest PROPERTIES
            INTERFACE_INCLUDE_DIRECTORIES "${GN_RAPIDCHECK_PC_INCLUDE_DIRS}")
    endif()
endif()

file(GLOB_RECURSE goodnet_unit_test_sources
    CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/test_*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/*/test_*.cpp"
)

if(NOT goodnet_unit_test_sources)
    message(STATUS "tests/unit: no test_*.cpp sources found; skipping")
    return()
endif()

add_executable(goodnet_unit_tests ${goodnet_unit_test_sources})

target_link_libraries(goodnet_unit_tests
    PRIVATE
        goodnet_kernel
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
