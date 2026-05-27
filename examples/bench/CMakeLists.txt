# goodnet-bench — throughput benchmark.
#
# Two GoodNet kernels in one process, real loopback TCP under Noise XX,
# Bob loops `host_api->send` against Alice as fast as the kernel
# accepts. Reports payload Gbps.
#
# Supported build modes:
#   in-tree (monorepo):  links goodnet_kernel + goodnet_tcp_objects directly.
#   standalone (examples/ with .goodnet/ overrides): links GoodNet::kernel
#     + GoodNet::link_tcp_static (installed by the link-tcp package).

add_executable(goodnet_bench main.cpp)

if(TARGET goodnet_kernel)
    # in-tree build — use OBJECT library so the bench does not pay for
    # the plugin entry point (plugin_entry.cpp) that the .so variant carries.
    target_link_libraries(goodnet_bench
        PRIVATE
            goodnet_kernel
            goodnet_tcp_objects
            ${CMAKE_DL_LIBS}
    )
else()
    # standalone build — use the installed static archive.
    target_link_libraries(goodnet_bench
        PRIVATE
            GoodNet::kernel
            GoodNet::link_tcp_static
            ${CMAKE_DL_LIBS}
    )
endif()

if(TARGET GoodNet::protocol_gnet)
    target_link_libraries(goodnet_bench PRIVATE GoodNet::protocol_gnet)
endif()

target_compile_features(goodnet_bench PRIVATE cxx_std_23)

# Noise plugin path resolution (first match wins):
#   1. In-tree target  — generator expression pointing at build-tree .so
#   2. CMake define    — -DGOODNET_NOISE_PLUGIN_PATH=... from the caller
#   3. Env var         — GOODNET_NOISE_PLUGIN_PATH set by the devShell
if(TARGET goodnet_security_noise)
    add_dependencies(goodnet_bench goodnet_security_noise)
    target_compile_definitions(goodnet_bench
        PRIVATE
            "GOODNET_NOISE_PLUGIN_PATH=\"$<TARGET_FILE:goodnet_security_noise>\"")
elseif(DEFINED GOODNET_NOISE_PLUGIN_PATH)
    target_compile_definitions(goodnet_bench
        PRIVATE
            "GOODNET_NOISE_PLUGIN_PATH=\"${GOODNET_NOISE_PLUGIN_PATH}\"")
elseif(DEFINED ENV{GOODNET_NOISE_PLUGIN_PATH})
    target_compile_definitions(goodnet_bench
        PRIVATE
            "GOODNET_NOISE_PLUGIN_PATH=\"$ENV{GOODNET_NOISE_PLUGIN_PATH}\"")
endif()

set_target_properties(goodnet_bench PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    OUTPUT_NAME "goodnet-bench"
)
