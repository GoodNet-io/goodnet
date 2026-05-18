# remote_slow_stub — subprocess worker that sleeps on selected
# PLUGIN_CALL slots to drive the kernel-side per-slot reply timeout
# override regression in `tests/unit/plugin/test_remote_host_timeout_override.cpp`.
# Sleep durations are sourced from GOODNET_SLOW_STUB_INIT_MS and
# GOODNET_SLOW_STUB_REGISTER_MS so the test fixture can dial the
# timing without recompiling the worker.

add_executable(remote_slow_stub_worker remote_slow_stub.cpp)
target_link_libraries(remote_slow_stub_worker
    PRIVATE GoodNet::sdk GoodNet::remote_plugin_stub
)
target_compile_features(remote_slow_stub_worker PRIVATE cxx_std_23)
set_target_properties(remote_slow_stub_worker PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/workers"
    OUTPUT_NAME remote_slow_stub
)
