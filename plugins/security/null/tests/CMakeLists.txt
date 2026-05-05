# Null security provider unit tests — Apache 2.0.
include(GoogleTest)

# dlopen-driven test against the shipped .so. The plugin path threads
# through a compile-time define so the test resolves entry symbols at
# runtime.
if(TARGET goodnet_security_null)
    add_executable(test_null test_null.cpp)
    target_link_libraries(test_null PRIVATE
        GoodNet::sdk
        GTest::gtest
        GTest::gtest_main
        ${CMAKE_DL_LIBS})
    target_compile_features(test_null PRIVATE cxx_std_23)
    add_dependencies(test_null goodnet_security_null)
    target_compile_definitions(test_null PRIVATE
        "GOODNET_NULL_PLUGIN_PATH=\"$<TARGET_FILE:goodnet_security_null>\"")
    goodnet_apply_pch(test_null)
    gtest_discover_tests(test_null
        DISCOVERY_TIMEOUT 30
        PROPERTIES TIMEOUT 60)
endif()
