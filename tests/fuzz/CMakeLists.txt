# LibFuzzer harness for kernel-side parsers exposed to untrusted bytes.
#
# Activates only when the configure is driven by clang — gcc has no
# libFuzzer runtime. A `CheckCXXCompilerFlag` probe gates the targets
# behind a single STATUS message so a gcc-driven configure stays green.
#
# Targets bind directly to per-plugin OBJECT libs (`goodnet_ice_objects`,
# `goodnet_ws_objects`, `goodnet_protocol_gnet`) so the fuzzer link
# does not pull in the SHARED plugin entry, the kernel runtime, or
# any of the asio / sodium side effects that the plugin .so requires
# at load time.

include(CheckCXXSourceCompiles)

# Probe for libFuzzer end-to-end: compiles AND links a TU that
# defines `LLVMFuzzerTestOneInput`. `-fsanitize=fuzzer` must be on
# both the compile and link command line for the link to resolve
# the SanitizerCoverage runtime symbols, so the probe sets both
# `CMAKE_REQUIRED_FLAGS` and `CMAKE_REQUIRED_LINK_OPTIONS`.
set(CMAKE_REQUIRED_FLAGS         "-fsanitize=fuzzer")
set(CMAKE_REQUIRED_LINK_OPTIONS  "-fsanitize=fuzzer")
check_cxx_source_compiles([[
    #include <cstddef>
    #include <cstdint>
    extern "C" int LLVMFuzzerTestOneInput(const uint8_t*, size_t) {
        return 0;
    }
]] GOODNET_HAVE_LIBFUZZER)
unset(CMAKE_REQUIRED_FLAGS)
unset(CMAKE_REQUIRED_LINK_OPTIONS)

if(NOT GOODNET_HAVE_LIBFUZZER)
    message(STATUS "  Fuzz harness      : skipped (clang required for libFuzzer)")
    return()
endif()

message(STATUS "  Fuzz harness      : building (libFuzzer + ASan + UBSan)")

# Sanitiser stack for the fuzz binaries. ASan catches OOB / UAF;
# UBSan catches signed overflow, alignment, enum-range violations
# that the parsers may surface only under hostile input.
set(_goodnet_fuzz_sanitisers "fuzzer,address,undefined")

# Helper: define one fuzz target. `NAME` is the executable name,
# `SOURCE` the entry .cpp, remaining args are link dependencies.
function(goodnet_add_fuzz_target NAME SOURCE)
    add_executable(${NAME} ${SOURCE})
    target_compile_options(${NAME} PRIVATE
        -fsanitize=${_goodnet_fuzz_sanitisers}
        -fno-omit-frame-pointer
        -g
        -O1)
    target_link_options(${NAME} PRIVATE
        -fsanitize=${_goodnet_fuzz_sanitisers})
    target_link_libraries(${NAME} PRIVATE ${ARGN})
    target_include_directories(${NAME} PRIVATE
        ${CMAKE_SOURCE_DIR})
    set_target_properties(${NAME} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}")
endfunction()

# ── fuzz_stun ────────────────────────────────────────────────────────────
# Exercises `gn::link::ice::parse_stun` against arbitrary byte
# sequences. Goal: no UB / no abort on hostile STUN inputs.
if(TARGET goodnet_ice_objects)
    goodnet_add_fuzz_target(fuzz_stun fuzz_stun.cpp goodnet_ice_objects)
endif()

# ── fuzz_gnet_deframe ────────────────────────────────────────────────────
# Exercises `gn::plugins::gnet::wire::parse_header` — the first
# parser the kernel runs against decrypted bytes from the wire.
if(TARGET goodnet_protocol_gnet)
    goodnet_add_fuzz_target(fuzz_gnet_deframe fuzz_gnet_deframe.cpp goodnet_protocol_gnet)
endif()

# ── fuzz_ws_frame ────────────────────────────────────────────────────────
# Exercises `gn::link::ws::wire::parse_frame_header`. The parser is
# header-only inline, so no plugin object link is required — the
# fuzz translation unit pulls the implementation through the header.
goodnet_add_fuzz_target(fuzz_ws_frame fuzz_ws_frame.cpp)

# ── fuzz_mdns_dns ────────────────────────────────────────────────────────
# Exercises `gn::link::ice::parse_dns_message`, the mDNS wire-level
# parser. Pointer loops and oversize labels are the obvious targets.
if(TARGET goodnet_ice_objects)
    goodnet_add_fuzz_target(fuzz_mdns_dns fuzz_mdns_dns.cpp goodnet_ice_objects)
endif()
