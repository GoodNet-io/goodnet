# Comprehensive benchmark suite.
#
# Measures three axes:
#   1. Per-plugin throughput / latency / handshake time
#      (bench_<scheme>.cpp under bench/plugins)
#   2. Composition depth — stacks like TLS-over-TCP, Noise-over-QUIC
#      (bench/composition)
#   3. Cross-implementation comparison vs mature solutions
#      (bench/comparison) so the report can surface UX/DX gaps
#      relative to libwebrtc, OpenSSL, etc.
#
# Each binary registers benchmarks with google-benchmark; the umbrella
# `goodnet_bench` target chains them so `nix run .#bench` runs every
# scenario and feeds the JSON output into `bench/reports/`.

find_package(benchmark REQUIRED)

# ── Common harness ─────────────────────────────────────────────────
add_library(goodnet_bench_harness STATIC
    bench_harness.cpp
)
target_include_directories(goodnet_bench_harness PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}
)
target_link_libraries(goodnet_bench_harness PUBLIC
    GoodNet::sdk
    asio::asio
    Threads::Threads
    benchmark::benchmark
)
target_compile_features(goodnet_bench_harness PUBLIC cxx_std_23)

# ── Per-plugin benchmarks ──────────────────────────────────────────
function(goodnet_add_bench name source plugin_obj)
    add_executable(${name} ${source})
    target_link_libraries(${name} PRIVATE
        goodnet_bench_harness
        ${plugin_obj}
        OpenSSL::Crypto
        PkgConfig::SODIUM
        benchmark::benchmark_main
    )
    set_target_properties(${name} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bench"
    )
endfunction()

if(TARGET goodnet_tcp_objects)
    goodnet_add_bench(bench_tcp plugins/bench_tcp.cpp goodnet_tcp_objects)
endif()

if(TARGET goodnet_udp_objects)
    goodnet_add_bench(bench_udp plugins/bench_udp.cpp goodnet_udp_objects)
endif()

# Composition + comparison benches arrive in follow-ups; the harness
# library is the foundation. Per-plugin TCP / UDP land first as the
# canonical templates the rest copy.
