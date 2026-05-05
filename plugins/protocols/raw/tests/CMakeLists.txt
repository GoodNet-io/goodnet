# Raw protocol layer unit tests — Apache 2.0.
include(GoogleTest)

# Raw exercises `gn_ctx_*` accessors on a `gn_connection_context_s`
# constructed inline. `GoodNet::ctx_accessors` (linked transitively
# through `GoodNet::protocol_raw`) carries the C ABI bridge symbols.
add_executable(test_protocol_raw
    test_raw.cpp)
target_link_libraries(test_protocol_raw PRIVATE
    GoodNet::sdk
    GoodNet::protocol_raw
    GTest::gtest
    GTest::gtest_main)
target_compile_features(test_protocol_raw PRIVATE cxx_std_23)
if(COMMAND goodnet_apply_pch)
    goodnet_apply_pch(test_protocol_raw)
endif()
gtest_discover_tests(test_protocol_raw
    DISCOVERY_TIMEOUT 30
    PROPERTIES TIMEOUT 60)
