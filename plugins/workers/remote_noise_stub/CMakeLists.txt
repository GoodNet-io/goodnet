# remote_noise_stub — subprocess worker proving the SECURITY proxy
# slot table (0x300..0x308). Implements a deterministic three-step
# handshake state machine; the kernel-side integration test drives
# it through `RemoteHost::security_vtable_proxy`.

add_executable(remote_noise_stub_worker remote_noise_stub.cpp)
target_link_libraries(remote_noise_stub_worker
    PRIVATE GoodNet::sdk GoodNet::remote_plugin_stub
)
target_compile_features(remote_noise_stub_worker PRIVATE cxx_std_23)
set_target_properties(remote_noise_stub_worker PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/workers"
    OUTPUT_NAME remote_noise_stub
)
