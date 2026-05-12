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
    goodnet_add_bench(bench_tcp_scale plugins/bench_tcp_scale.cpp
                       goodnet_tcp_objects)
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

if(TARGET goodnet_ws_objects AND TARGET goodnet_tcp_objects)
    add_executable(bench_ws plugins/bench_ws.cpp)
    target_link_libraries(bench_ws PRIVATE
        goodnet_bench_harness
        goodnet_ws_objects
        goodnet_tcp_objects
        OpenSSL::Crypto
        PkgConfig::SODIUM
        benchmark::benchmark_main
    )
    set_target_properties(bench_ws PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bench"
    )
endif()

if(TARGET goodnet_quic_objects AND TARGET goodnet_udp_objects)
    add_executable(bench_quic plugins/bench_quic.cpp)
    target_link_libraries(bench_quic PRIVATE
        goodnet_bench_harness
        goodnet_quic_objects
        goodnet_udp_objects
        OpenSSL::SSL
        OpenSSL::Crypto
        PkgConfig::SODIUM
        benchmark::benchmark_main
    )
    set_target_properties(bench_quic PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bench"
    )
endif()

if(TARGET goodnet_tls_objects AND TARGET goodnet_udp_objects)
    add_executable(bench_dtls plugins/bench_dtls.cpp)
    target_link_libraries(bench_dtls PRIVATE
        goodnet_bench_harness
        goodnet_tls_objects
        goodnet_udp_objects
        OpenSSL::SSL
        OpenSSL::Crypto
        PkgConfig::SODIUM
        benchmark::benchmark_main
    )
    set_target_properties(bench_dtls PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bench"
    )
endif()

if(TARGET goodnet_ice_objects AND TARGET goodnet_udp_objects)
    add_executable(bench_ice plugins/bench_ice.cpp)
    target_link_libraries(bench_ice PRIVATE
        goodnet_bench_harness
        goodnet_ice_objects
        goodnet_udp_objects
        OpenSSL::Crypto
        PkgConfig::SODIUM
        benchmark::benchmark_main
    )
    set_target_properties(bench_ice PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bench"
    )
endif()

# Composition stacks — depth-3 WSS-over-TLS-over-TCP measures the
# overhead of stacking three composer plugins versus the per-layer
# numbers from bench_tcp / bench_tls / bench_ws.
if(TARGET goodnet_ws_objects AND TARGET goodnet_tls_objects
   AND TARGET goodnet_tcp_objects)
    add_executable(bench_wss_over_tls composition/bench_wss_over_tls.cpp)
    target_link_libraries(bench_wss_over_tls PRIVATE
        goodnet_bench_harness
        goodnet_ws_objects
        goodnet_tls_objects
        goodnet_tcp_objects
        OpenSSL::SSL
        OpenSSL::Crypto
        PkgConfig::SODIUM
        benchmark::benchmark_main
    )
    set_target_properties(bench_wss_over_tls PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bench"
    )
endif()

# Noise pattern handshake + transport AEAD benches — direct against
# the noise plugin's HandshakeState/CipherState. No sockets,
# isolates pure crypto cost (handshake DH + HKDF + AEAD).
if(TARGET goodnet_noise_objects)
    add_executable(bench_noise composition/bench_noise.cpp)
    target_link_libraries(bench_noise PRIVATE
        goodnet_bench_harness
        goodnet_noise_objects
        OpenSSL::Crypto
        PkgConfig::SODIUM
        benchmark::benchmark_main
    )
    target_include_directories(bench_noise PRIVATE
        ${CMAKE_SOURCE_DIR}/plugins/security/noise)
    set_target_properties(bench_noise PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bench"
    )
endif()

# Strategy plugin bench — picker dispatch overhead under varying
# candidate-set size. The float_send_rtt plugin lives outside the
# kernel tree (its own git repo under plugins/strategies/), so the
# bench is opt-in via GOODNET_BENCH_STRATEGIES so a tree without
# the plugin sub-checkout doesn't fail configure.
if(GOODNET_BENCH_STRATEGIES AND TARGET goodnet_float_send_rtt_objects)
    add_executable(bench_float_send_rtt strategy/bench_float_send_rtt.cpp)
    target_link_libraries(bench_float_send_rtt PRIVATE
        goodnet_bench_harness
        goodnet_float_send_rtt_objects
        benchmark::benchmark_main
    )
    set_target_properties(bench_float_send_rtt PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bench"
    )
endif()

# Cross-implementation comparison binaries live under bench/comparison/
# but ship as shell scripts wrapping curl / openssl s_client / etc.
# rather than C++ — see bench/comparison/README.md for the harness
# layout that drives both GoodNet and reference stacks through the
# same payload matrix.
