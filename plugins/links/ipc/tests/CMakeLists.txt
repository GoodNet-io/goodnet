# IPC link plugin unit tests — MIT.
include(GoogleTest)

add_executable(test_ipc test_ipc.cpp)
target_link_libraries(test_ipc PRIVATE
    GoodNet::sdk
    goodnet_ipc_objects
    asio::asio
    Threads::Threads
    GTest::gtest
    GTest::gtest_main)
target_compile_features(test_ipc PRIVATE cxx_std_23)
goodnet_apply_pch(test_ipc)
gtest_discover_tests(test_ipc
    DISCOVERY_TIMEOUT 30
    PROPERTIES TIMEOUT 60)
