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

# Failover policies — drives `IceSession` directly so the bench
# can exercise the consent-loss + restart dispatch path. Needs the
# ICE plugin's private session headers, so the include path picks
# the plugin source tree explicitly.
# Sustained-burn — a 60-second TCP run that surfaces long-tail
# behaviour (thermal throttle, allocator slowdown, conn-state leak)
# the 0.3-second windows of the other benches cannot reach.
if(TARGET goodnet_tcp_objects)
    add_executable(bench_sustained plugins/bench_sustained.cpp)
    target_link_libraries(bench_sustained PRIVATE
        goodnet_bench_harness
        goodnet_tcp_objects
        OpenSSL::Crypto
        PkgConfig::SODIUM
        benchmark::benchmark_main
    )
    set_target_properties(bench_sustained PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bench"
    )
endif()

if(TARGET goodnet_ice_objects)
    add_executable(bench_failover plugins/bench_failover.cpp)
    target_link_libraries(bench_failover PRIVATE
        goodnet_bench_harness
        goodnet_ice_objects
        OpenSSL::Crypto
        PkgConfig::SODIUM
        benchmark::benchmark_main
    )
    target_include_directories(bench_failover PRIVATE
        ${CMAKE_SOURCE_DIR}
    )
    # LTO on the bench target's link line confuses the LTO inliner —
    # `goodnet_ice_objects` linked directly as object files (not a
    # static lib) makes the LTO plugin lose track of cross-TU
    # references inside session.cpp / turn.cpp. Disable LTO for this
    # bench specifically; the regression sensitivity we care about
    # here is dispatch / mutex / atomic cost, not crypto inlining.
    set_target_properties(bench_failover PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bench"
        INTERPROCEDURAL_OPTIMIZATION OFF
    )
endif()

# Subprocess plugin runtime — wire-proxy round-trip cost. Drives
# the LINK / HANDLER / SECURITY proxies through the same kernel-
# side RemoteHost the production runtime uses, with the in-tree
# worker stubs (`remote_echo`, `remote_handler_stub`,
# `remote_noise_stub`) as the worker process binaries. Each worker
# target is built independently; missing any of them disables the
# corresponding fixture set in the bench at runtime (the macro
# guards refuse to compile without all three paths defined).
if(TARGET remote_echo_worker
   AND TARGET remote_handler_stub_worker
   AND TARGET remote_noise_stub_worker)
    add_executable(bench_subprocess plugins/bench_subprocess.cpp)
    target_link_libraries(bench_subprocess PRIVATE
        goodnet_bench_harness
        goodnet_kernel
        OpenSSL::Crypto
        PkgConfig::SODIUM
        benchmark::benchmark_main
        ${CMAKE_DL_LIBS}
    )
    add_dependencies(bench_subprocess
        remote_echo_worker
        remote_handler_stub_worker
        remote_noise_stub_worker
    )
    target_compile_definitions(bench_subprocess PRIVATE
        "GOODNET_REMOTE_ECHO_PATH=\"$<TARGET_FILE:remote_echo_worker>\""
        "GOODNET_REMOTE_HANDLER_STUB_PATH=\"$<TARGET_FILE:remote_handler_stub_worker>\""
        "GOODNET_REMOTE_NOISE_STUB_PATH=\"$<TARGET_FILE:remote_noise_stub_worker>\""
    )
    set_target_properties(bench_subprocess PROPERTIES
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

# ── Real-mode (production-shape) bench (A.2) ──────────────────────────
#
# Boots a real `gn::core::Kernel` + production plugins (gnet protocol
# layer linked statically + Noise security via dlopen + a transport
# plugin via OBJECT lib) and measures the operator-facing
# `host_api->send` round-trip. The Noise security provider keeps the
# shared-object loading path the kernel uses in production; every
# other piece links statically so the bench binary owns its own
# kernel instance per process.
if(NOT GOODNET_STATIC_PLUGINS
   AND TARGET goodnet_tcp_objects
   AND TARGET goodnet_udp_objects
   AND TARGET goodnet_ipc_objects
   AND TARGET goodnet_security_noise)
    # The bench dlopens the noise plugin's `.so` at runtime — that
    # target doesn't produce a shared object under GOODNET_STATIC_PLUGINS
    # (everything is linked into the kernel binary instead). Skip the
    # bench entirely in static builds; the static plugin layout is
    # exercised by the regular kernel binary via `goodnet run`.
    add_executable(bench_handler_registry
        plugins/bench_handler_registry.cpp)
    target_link_libraries(bench_handler_registry PRIVATE
        goodnet_bench_harness
        goodnet_kernel
        goodnet_tcp_objects
        OpenSSL::Crypto
        PkgConfig::SODIUM
        benchmark::benchmark_main
        ${CMAKE_DL_LIBS}
    )
    if(TARGET GoodNet::protocol_gnet)
        target_link_libraries(bench_handler_registry PRIVATE GoodNet::protocol_gnet)
    endif()
    add_dependencies(bench_handler_registry goodnet_security_noise)
    target_compile_definitions(bench_handler_registry PRIVATE
        "GOODNET_NOISE_PLUGIN_PATH=\"$<TARGET_FILE:goodnet_security_noise>\""
    )
    set_target_properties(bench_handler_registry PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bench"
    )

    add_executable(bench_real_e2e plugins/bench_real_e2e.cpp)
    target_link_libraries(bench_real_e2e PRIVATE
        goodnet_bench_harness
        goodnet_kernel
        goodnet_tcp_objects
        goodnet_udp_objects
        goodnet_ipc_objects
        OpenSSL::Crypto
        PkgConfig::SODIUM
        benchmark::benchmark_main
        ${CMAKE_DL_LIBS}
    )
    if(TARGET GoodNet::protocol_gnet)
        target_link_libraries(bench_real_e2e PRIVATE GoodNet::protocol_gnet)
    endif()
    add_dependencies(bench_real_e2e goodnet_security_noise)
    target_compile_definitions(bench_real_e2e PRIVATE
        "GOODNET_NOISE_PLUGIN_PATH=\"$<TARGET_FILE:goodnet_security_noise>\""
    )
    set_target_properties(bench_real_e2e PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bench"
    )
endif()

# Cross-implementation comparison binaries live under bench/comparison/
# but ship as shell scripts wrapping curl / openssl s_client / etc.
# rather than C++ — see bench/comparison/README.md for the harness
# layout that drives both GoodNet and reference stacks through the
# same payload matrix.

# ── Free-kernel showcase bench ────────────────────────────────────────
#
# Demonstrates GoodNet-distinctive moves no other stack can reproduce:
# multi-connect under one identity, runtime strategy-driven carrier
# pick, post-handshake provider handoff PoC, multi-thread fanout,
# carrier failover, mobility LAN shortcut. Drives the inline-crypto
# downgrade seam (`SecuritySession::_test_clear_inline_crypto`,
# compile-gated through `GOODNET_BENCH_SHOWCASE`); the subdirectory
# is also gated through `GOODNET_BENCH_STRATEGIES` for the strategy-
# plugin sub-checkout.
add_subdirectory(showcase)
