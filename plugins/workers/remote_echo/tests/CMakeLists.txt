# remote_echo worker — HOST_CALL slot regression suite. Spawns the
# worker over `sdk/remote/wire.h` and asserts the kernel-side
# `host_api_t` stub captures every call routed through the new slots
# (notify_connect / notify_disconnect / register_vtable /
# unregister_vtable). Mirrors `tests/unit/plugin/test_remote_host.cpp`
# in harness shape.

include(GoogleTest)

add_executable(test_remote_echo_slots test_remote_echo_slots.cpp)

target_link_libraries(test_remote_echo_slots
    PRIVATE
        goodnet_kernel
        GoodNet::sdk
        GTest::gtest
        GTest::gtest_main
        Threads::Threads
        ${CMAKE_DL_LIBS}
)

target_compile_features(test_remote_echo_slots PRIVATE cxx_std_23)

# Force the worker binary to be built before this test links, and
# thread its path through a compile-time define so ctest can find
# it from any CWD. Mirrors `tests/unit/CMakeLists.txt`.
if(TARGET remote_echo_worker)
    add_dependencies(test_remote_echo_slots remote_echo_worker)
    target_compile_definitions(test_remote_echo_slots
        PRIVATE
            "GOODNET_REMOTE_ECHO_PATH=\"$<TARGET_FILE:remote_echo_worker>\""
    )
endif()

gtest_discover_tests(test_remote_echo_slots
    DISCOVERY_TIMEOUT 30
    PROPERTIES TIMEOUT 60
)
