# Noise security provider unit tests — Apache 2.0.
include(GoogleTest)

# Direct-link tests reach into the noise primitives (HKDF, symmetric
# state, transport ciphers) and need GN_TEST_HOOKS to invoke
# `test_set_nonces` on transport ciphers — gated so the seam is not
# reachable in shipped builds.
add_executable(test_noise
    test_noise.cpp
    test_noise_cipher_property.cpp
    test_noise_transport.cpp)
target_link_libraries(test_noise PRIVATE
    GoodNet::sdk
    goodnet_noise_objects
    PkgConfig::SODIUM
    GTest::gtest
    GTest::gtest_main
    rapidcheck
    rapidcheck_gtest)
target_compile_features(test_noise PRIVATE cxx_std_23)
target_compile_definitions(test_noise PRIVATE GN_TEST_HOOKS)
if(COMMAND goodnet_apply_pch)
    goodnet_apply_pch(test_noise)
endif()
gtest_discover_tests(test_noise
    DISCOVERY_TIMEOUT 30
    PROPERTIES TIMEOUT 60)

# dlopen-driven plugin test — entry symbols resolve at runtime from
# the .so produced by `add_plugin(goodnet_security_noise ...)`. The
# build dependency forces ninja to ship the .so before linking.
if(TARGET goodnet_security_noise)
    add_executable(test_noise_plugin test_noise_plugin.cpp)
    target_link_libraries(test_noise_plugin PRIVATE
        GoodNet::sdk
        PkgConfig::SODIUM
        GTest::gtest
        GTest::gtest_main
        ${CMAKE_DL_LIBS})
    target_compile_features(test_noise_plugin PRIVATE cxx_std_23)
    add_dependencies(test_noise_plugin goodnet_security_noise)
    target_compile_definitions(test_noise_plugin PRIVATE
        "GOODNET_NOISE_PLUGIN_PATH=\"$<TARGET_FILE:goodnet_security_noise>\"")
    if(COMMAND goodnet_apply_pch)
        goodnet_apply_pch(test_noise_plugin)
    endif()
    gtest_discover_tests(test_noise_plugin
        DISCOVERY_TIMEOUT 30
        PROPERTIES TIMEOUT 60)
endif()
