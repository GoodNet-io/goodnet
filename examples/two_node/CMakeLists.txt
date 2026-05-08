# goodnet-demo — two-node Noise-over-TCP quickstart.
#
# Single-process binary that runs both ends of an encrypted handshake
# on loopback and round-trips one application message. The kernel
# noise plugin is dlopen'd at runtime; its path is threaded in as a
# compile-time string so a packaged build does not depend on the
# build tree's layout.

add_executable(goodnet_demo main.cpp)

target_link_libraries(goodnet_demo
    PRIVATE
        goodnet_kernel
        GoodNet::protocol_gnet
        goodnet_tcp_objects
        ${CMAKE_DL_LIBS}
)

target_compile_features(goodnet_demo PRIVATE cxx_std_23)

if(TARGET goodnet_security_noise)
    add_dependencies(goodnet_demo goodnet_security_noise)
    target_compile_definitions(goodnet_demo
        PRIVATE
            "GOODNET_NOISE_PLUGIN_PATH=\"$<TARGET_FILE:goodnet_security_noise>\""
    )
endif()

set_target_properties(goodnet_demo PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    OUTPUT_NAME "goodnet-demo"
)
