# goodnet-demo — two-node Noise-over-TCP quickstart.
#
# Single-process binary that runs both ends of an encrypted handshake
# on loopback and round-trips one application message. Pure downstream
# consumer of the SDK: links against `GoodNet::sdk` (header-only) and
# `GoodNet::kernel_shared` (C ABI runtime) only — no kernel-private
# headers, no in-tree `goodnet_tcp_objects`, no protocol layer target.
#
# Noise + TCP plugins are dlopen'd at runtime; their paths thread in
# as compile-time strings so a packaged build does not depend on the
# build tree's layout.

add_executable(goodnet_demo main.cpp)

target_link_libraries(goodnet_demo
    PRIVATE
        GoodNet::sdk
        GoodNet::sdk_dx
        GoodNet::kernel_shared
        PkgConfig::SODIUM
        ${CMAKE_DL_LIBS}
)
if(TARGET GoodNet::protocol_gnet)
    target_link_libraries(goodnet_demo PRIVATE GoodNet::protocol_gnet)
endif()

target_compile_features(goodnet_demo PRIVATE cxx_std_23)

if(TARGET goodnet_security_noise AND TARGET goodnet_link_tcp)
    # in-tree build: use generator expressions to point at build-tree .so files
    add_dependencies(goodnet_demo goodnet_security_noise goodnet_link_tcp)
    target_compile_definitions(goodnet_demo
        PRIVATE
            "GOODNET_NOISE_PLUGIN_PATH=\"$<TARGET_FILE:goodnet_security_noise>\""
            "GOODNET_TCP_PLUGIN_PATH=\"$<TARGET_FILE:goodnet_link_tcp>\""
    )
else()
    # standalone build: resolve plugin paths via pkg-config
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(GOODNET_NOISE REQUIRED goodnet-security-noise)
    pkg_check_modules(GOODNET_TCP   REQUIRED goodnet-link-tcp)
    target_compile_definitions(goodnet_demo
        PRIVATE
            "GOODNET_NOISE_PLUGIN_PATH=\"${GOODNET_NOISE_LIBDIR}/libgoodnet_security_noise.so\""
            "GOODNET_TCP_PLUGIN_PATH=\"${GOODNET_TCP_LIBDIR}/libgoodnet_link_tcp.so\""
    )
endif()

set_target_properties(goodnet_demo PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    OUTPUT_NAME "goodnet-demo"
)
