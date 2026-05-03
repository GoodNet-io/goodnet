# Integration tests — exercise multiple kernel components together.
# Each test_*.cpp file links against the kernel and any plugins it needs
# directly (no shared umbrella binary like the unit suite, so each
# scenario can pick a focused set of dependencies).

include(GoogleTest)

file(GLOB_RECURSE goodnet_integration_test_sources
    CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/test_*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/*/test_*.cpp"
)

if(NOT goodnet_integration_test_sources)
    message(STATUS "tests/integration: no test_*.cpp sources found; skipping")
    return()
endif()

add_executable(goodnet_integration_tests ${goodnet_integration_test_sources})

target_link_libraries(goodnet_integration_tests
    PRIVATE
        GoodNet::kernel
        GoodNet::protocol_gnet
        GoodNet::sdk
        goodnet_tcp_objects
        goodnet_ws_objects
        goodnet_ipc_objects
        goodnet_tls_objects
        GTest::gtest
        GTest::gtest_main
        ${CMAKE_DL_LIBS}
)

if(TARGET OpenSSL::SSL)
    target_link_libraries(goodnet_integration_tests
        PRIVATE OpenSSL::SSL OpenSSL::Crypto)
endif()

target_compile_features(goodnet_integration_tests PRIVATE cxx_std_23)
goodnet_apply_pch(goodnet_integration_tests)

if(TARGET goodnet_security_noise)
    add_dependencies(goodnet_integration_tests goodnet_security_noise)
    target_compile_definitions(goodnet_integration_tests
        PRIVATE
            "GOODNET_NOISE_PLUGIN_PATH=\"$<TARGET_FILE:goodnet_security_noise>\""
    )
endif()

gtest_discover_tests(goodnet_integration_tests
    PROPERTIES LABELS integration
)
