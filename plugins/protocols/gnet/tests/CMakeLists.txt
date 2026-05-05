# GNET protocol layer unit tests — Apache 2.0.
include(GoogleTest)

# Tests construct `gn_connection_context_s` directly and link into the
# protocol layer's `gn_ctx_*` accessors, so the kernel-side translation
# unit that defines them ships into the test binary alongside the
# protocol object library.
add_executable(test_protocol_gnet
    test_wire.cpp
    test_wire_property.cpp
    test_protocol.cpp
    test_protocol_property.cpp
    ${PROJECT_SOURCE_DIR}/core/kernel/connection_context.cpp)
target_link_libraries(test_protocol_gnet PRIVATE
    GoodNet::sdk
    GoodNet::protocol_gnet
    GTest::gtest
    GTest::gtest_main
    rapidcheck
    rapidcheck_gtest)
target_compile_features(test_protocol_gnet PRIVATE cxx_std_23)
goodnet_apply_pch(test_protocol_gnet)
gtest_discover_tests(test_protocol_gnet
    DISCOVERY_TIMEOUT 30
    PROPERTIES TIMEOUT 60)
