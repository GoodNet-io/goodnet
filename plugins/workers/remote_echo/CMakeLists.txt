# remote_echo — minimal worker binary that proves the subprocess
# plugin round trip. Links `goodnet_remote_plugin_stub` to inherit
# the wire-protocol reader loop + synthetic host_api; the binary
# itself just supplies a `gn_link_vtable_t::send` that echoes the
# payload back through `host_api.notify_inbound_bytes`.

add_executable(remote_echo_worker remote_echo.cpp)
target_link_libraries(remote_echo_worker
    PRIVATE GoodNet::sdk GoodNet::remote_plugin_stub
)
target_compile_features(remote_echo_worker PRIVATE cxx_std_23)
set_target_properties(remote_echo_worker PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/workers"
    OUTPUT_NAME remote_echo
)
