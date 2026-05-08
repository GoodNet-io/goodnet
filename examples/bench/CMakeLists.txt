# goodnet-bench — throughput benchmark.
#
# Two GoodNet kernels in one process, real loopback TCP under Noise XX,
# Bob loops `host_api->send` against Alice as fast as the kernel
# accepts. Reports payload Gbps. Mirrors the legacy `cli/bench.cpp`
# matrix used to land the ~11 Gbit/s reference.

add_executable(goodnet_bench main.cpp)

target_link_libraries(goodnet_bench
    PRIVATE
        goodnet_kernel
        GoodNet::protocol_gnet
        goodnet_tcp_objects
        ${CMAKE_DL_LIBS}
)

target_compile_features(goodnet_bench PRIVATE cxx_std_23)

if(TARGET goodnet_security_noise)
    add_dependencies(goodnet_bench goodnet_security_noise)
    target_compile_definitions(goodnet_bench
        PRIVATE
            "GOODNET_NOISE_PLUGIN_PATH=\"$<TARGET_FILE:goodnet_security_noise>\""
    )
endif()

set_target_properties(goodnet_bench PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    OUTPUT_NAME "goodnet-bench"
)
