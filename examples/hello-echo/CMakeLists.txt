# hello-echo — minimum GoodNet client / server (SDK only).
#
# Two tiny binaries — a client that dials, sends "hello", waits for an
# echo, and a server that listens, echoes every inbound frame. Pure
# downstream consumers of the public SDK: link against `GoodNet::sdk`
# (header-only) + `GoodNet::kernel_shared` (C ABI runtime). No
# kernel-private headers, no plugin-private headers.
#
# Noise + TCP plugins are dlopen'd at runtime; paths thread in as
# compile-time strings.

add_executable(hello_echo_client client.cpp)
target_link_libraries(hello_echo_client
    PRIVATE
        GoodNet::sdk
        GoodNet::kernel_shared
        PkgConfig::SODIUM
        ${CMAKE_DL_LIBS}
)
target_compile_features(hello_echo_client PRIVATE cxx_std_23)
set_target_properties(hello_echo_client PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    OUTPUT_NAME "hello-echo-client"
)

add_executable(hello_echo_server server.cpp)
target_link_libraries(hello_echo_server
    PRIVATE
        GoodNet::sdk
        GoodNet::kernel_shared
        PkgConfig::SODIUM
        ${CMAKE_DL_LIBS}
)
target_compile_features(hello_echo_server PRIVATE cxx_std_23)
set_target_properties(hello_echo_server PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    OUTPUT_NAME "hello-echo-server"
)

if(TARGET goodnet_security_noise AND TARGET goodnet_link_tcp)
    add_dependencies(hello_echo_client goodnet_security_noise goodnet_link_tcp)
    add_dependencies(hello_echo_server goodnet_security_noise goodnet_link_tcp)
    target_compile_definitions(hello_echo_client
        PRIVATE
            "GOODNET_NOISE_PLUGIN_PATH=\"$<TARGET_FILE:goodnet_security_noise>\""
            "GOODNET_TCP_PLUGIN_PATH=\"$<TARGET_FILE:goodnet_link_tcp>\""
    )
    target_compile_definitions(hello_echo_server
        PRIVATE
            "GOODNET_NOISE_PLUGIN_PATH=\"$<TARGET_FILE:goodnet_security_noise>\""
            "GOODNET_TCP_PLUGIN_PATH=\"$<TARGET_FILE:goodnet_link_tcp>\""
    )
endif()
