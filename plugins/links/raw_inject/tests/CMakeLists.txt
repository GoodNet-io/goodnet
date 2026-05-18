# raw_inject link plugin unit tests — Apache-2.0.
include(GoogleTest)

add_executable(test_raw_inject
    test_raw_inject.cpp)
target_link_libraries(test_raw_inject PRIVATE
    GoodNet::sdk
    goodnet_raw_inject_objects
    Threads::Threads
    GTest::gtest
    GTest::gtest_main)
target_compile_features(test_raw_inject PRIVATE cxx_std_23)
if(COMMAND goodnet_apply_pch)
    goodnet_apply_pch(test_raw_inject)
endif()
gtest_discover_tests(test_raw_inject
    DISCOVERY_TIMEOUT 30
    PROPERTIES TIMEOUT 60)
