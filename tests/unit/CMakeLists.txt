# Unit tests for the kernel and SDK.
#
# All `tests/unit/**/test_*.cpp` files are compiled into a single
# `goodnet_unit_tests` executable; CTest discovers individual cases via
# `gtest_discover_tests`.

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

# CONFIGURE_DEPENDS so adding a new test_*.cpp shows up on the next
# `cmake --build` without re-running configure.
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
        GoodNet::protocol_gnet
        GoodNet::protocol_raw
        goodnet_noise_objects
        goodnet_tcp_objects
        goodnet_ipc_objects
        goodnet_udp_objects
        goodnet_ws_objects
        goodnet_tls_objects
        goodnet_heartbeat_objects
        GTest::gtest
        GTest::gtest_main
        rapidcheck
        rapidcheck_gtest
        ${CMAKE_DL_LIBS}
)

target_compile_features(goodnet_unit_tests PRIVATE cxx_std_23)

# Test seams in plugin internals (e.g. `test_set_nonces` in
# `plugins/security/noise/transport.hpp`) are gated behind the
# `GN_TEST_HOOKS` define so they cannot ship in production binaries.
# Surfacing nonce assignment in a shipped Noise CipherState would
# let a misuse trip a (key, nonce) collision and hand the attacker
# a keystream — the test build is the only context where the seams
# are reachable.
target_compile_definitions(goodnet_unit_tests PRIVATE GN_TEST_HOOKS)

# The NullProvider plugin test resolves entry symbols via dlopen at
# runtime — the .so must exist in the build tree before ctest runs.
# Adding the plugin target as a build dependency forces ninja to
# produce it before linking the test executable, and the path is
# threaded through a compile-time define so the test file knows where
# to look.
if(TARGET goodnet_security_null)
    add_dependencies(goodnet_unit_tests goodnet_security_null)
    target_compile_definitions(goodnet_unit_tests
        PRIVATE
            "GOODNET_NULL_PLUGIN_PATH=\"$<TARGET_FILE:goodnet_security_null>\""
    )
endif()

if(TARGET goodnet_security_noise)
    add_dependencies(goodnet_unit_tests goodnet_security_noise)
    target_compile_definitions(goodnet_unit_tests
        PRIVATE
            "GOODNET_NOISE_PLUGIN_PATH=\"$<TARGET_FILE:goodnet_security_noise>\""
    )
endif()

gtest_discover_tests(goodnet_unit_tests
    DISCOVERY_TIMEOUT 30
    PROPERTIES TIMEOUT 60
)
