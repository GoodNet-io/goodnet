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

if(TARGET goodnet_ipc_objects)
    goodnet_add_bench(bench_ipc plugins/bench_ipc.cpp goodnet_ipc_objects)
endif()

# TLS bench rides over a TCP carrier so its target links both objects.
# OpenSSL is pulled in through the TLS plugin's transitive deps.
if(TARGET goodnet_tls_objects AND TARGET goodnet_tcp_objects)
    add_executable(bench_tls plugins/bench_tls.cpp)
    target_link_libraries(bench_tls PRIVATE
        goodnet_bench_harness
        goodnet_tls_objects
        goodnet_tcp_objects
        OpenSSL::SSL
        OpenSSL::Crypto
        PkgConfig::SODIUM
        benchmark::benchmark_main
    )
    set_target_properties(bench_tls PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bench"
    )
endif()

# QUIC / WS / DTLS / ICE benches follow the same pattern as TLS once
# the rest of the comprehensive matrix lands. Composition stacks
# (Noise-over-QUIC, WSS-over-TLS) layer N+1 plugins behind their own
# bench binaries so the report can decompose per-layer overhead.

# Cross-implementation comparison binaries live under bench/comparison/
# but ship as shell scripts wrapping curl / openssl s_client / etc.
# rather than C++ — see bench/comparison/README.md for the harness
# layout that drives both GoodNet and reference stacks through the
# same payload matrix.
