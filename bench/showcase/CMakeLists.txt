# Free-kernel showcase bench (track Б of the plan).
#
# Builds `bench_showcase` — one binary with six sections
# (B.1..B.6). Links kernel + every transport's OBJECT lib + gnet
# protocol + float_send_rtt strategy directly; dlopens noise
# security at runtime (path threaded through compile-time
# `GOODNET_NOISE_PLUGIN_PATH`).
#
# Gated on `GOODNET_BENCH_STRATEGIES` because the strategy
# plugin's `_objects` target only configures when the strategies
# sub-checkout is present (mirrors `bench/CMakeLists.txt`
# treatment of `bench_float_send_rtt`).

if(NOT GOODNET_BENCH_STRATEGIES)
    message(STATUS
        "bench_showcase: skipped (GOODNET_BENCH_STRATEGIES not set; "
        "set -DGOODNET_BENCH_STRATEGIES=ON to enable, plus pull the "
        "strategy plugin sub-checkout)")
    return()
endif()

if(GOODNET_STATIC_PLUGINS)
    # bench_showcase dlopens the noise plugin's `.so` at runtime,
    # which doesn't exist under static linkage. Static builds
    # exercise the same paths through the kernel binary directly;
    # the dlopen-based showcase shape is dynamic-only.
    message(STATUS
        "bench_showcase: skipped (GOODNET_STATIC_PLUGINS=ON; the "
        "showcase dlopens noise at runtime, only the dynamic-plugin "
        "build configuration produces the required .so)")
    return()
endif()

if(NOT TARGET goodnet_float_send_rtt_objects)
    message(STATUS
        "bench_showcase: skipped (goodnet_float_send_rtt_objects "
        "target missing — plugin sub-checkout not present)")
    return()
endif()

if(NOT TARGET goodnet_security_noise
   OR NOT TARGET goodnet_tcp_objects
   OR NOT TARGET goodnet_udp_objects
   OR NOT TARGET goodnet_ipc_objects)
    message(STATUS
        "bench_showcase: skipped (one of the required plugin targets "
        "is missing: goodnet_security_noise / goodnet_tcp_objects / "
        "goodnet_udp_objects / goodnet_ipc_objects)")
    return()
endif()

add_executable(bench_showcase bench_showcase.cpp)
target_link_libraries(bench_showcase PRIVATE
    goodnet_bench_harness
    goodnet_kernel
    GoodNet::protocol_gnet
    goodnet_tcp_objects
    goodnet_udp_objects
    goodnet_ipc_objects
    goodnet_float_send_rtt_objects
    OpenSSL::Crypto
    PkgConfig::SODIUM
    benchmark::benchmark
    ${CMAKE_DL_LIBS}
)
add_dependencies(bench_showcase goodnet_security_noise)
target_compile_definitions(bench_showcase PRIVATE
    "GOODNET_NOISE_PLUGIN_PATH=\"$<TARGET_FILE:goodnet_security_noise>\""
)
target_include_directories(bench_showcase PRIVATE
    ${CMAKE_SOURCE_DIR})
set_target_properties(bench_showcase PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bench"
)
