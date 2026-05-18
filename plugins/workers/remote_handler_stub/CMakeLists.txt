# remote_handler_stub — subprocess worker proving the HANDLER proxy
# slot table (0x400..0x405). Implements a single-msg-id handler; the
# kernel-side integration test dispatches envelopes through
# `RemoteHost::handler_vtable_proxy`.

add_executable(remote_handler_stub_worker remote_handler_stub.cpp)
target_link_libraries(remote_handler_stub_worker
    PRIVATE GoodNet::sdk GoodNet::remote_plugin_stub
)
target_compile_features(remote_handler_stub_worker PRIVATE cxx_std_23)
set_target_properties(remote_handler_stub_worker PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/workers"
    OUTPUT_NAME remote_handler_stub
)
