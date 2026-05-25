add_executable(test_ws_inject test_ws_inject.cpp)
target_link_libraries(test_ws_inject
    PRIVATE goodnet_ws_inject_objects GTest::gtest_main)
target_compile_features(test_ws_inject PRIVATE cxx_std_23)
add_test(NAME test_ws_inject COMMAND test_ws_inject)
