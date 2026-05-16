cmake_minimum_required(VERSION 3.22)

project(GoodNet
        VERSION       1.0.0
        DESCRIPTION   "Network kernel and SDK"
        LANGUAGES     CXX C)

# Pre-release suffix appended to PROJECT_VERSION wherever the full
# string is published (CLI banner, package metadata, Nix derivation).
# CMake's `project(... VERSION ...)` is strictly numeric; the rc tail
# rides separately. Drop to empty when cutting `v1.0.0` final.
set(GOODNET_VERSION_SUFFIX "-rc3" CACHE STRING "Pre-release suffix (e.g. -rc3); empty for stable")
set(GOODNET_VERSION_FULL "${PROJECT_VERSION}${GOODNET_VERSION_SUFFIX}")

# ── Project settings ─────────────────────────────────────────────────────────
set(CMAKE_CXX_STANDARD          23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS         OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS  ON)

# Skip C++ module scanning. CMake 3.28+ probes every translation unit
# for `import` / `module` directives by default; we use only headers
# and the resulting `-fmodules-ts` / `-fdeps-format=p1689r5` GCC flags
# trip clang-tidy when it parses `compile_commands.json`.
set(CMAKE_CXX_SCAN_FOR_MODULES OFF)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

add_compile_options(
    -Wall -Wextra -Wpedantic
    -Wshadow -Wconversion -Wnon-virtual-dtor -Woverloaded-virtual
    -Wno-unused-parameter
    # Strip the absolute build-tree prefix from `__FILE__` so log
    # output and assertion messages carry repo-relative paths
    # (`core/util/log.hpp:42`) instead of the full filesystem
    # location of the source tree.
    "-fmacro-prefix-map=${CMAKE_SOURCE_DIR}/=")

# mingw defaults `off_t` to 32-bit. `core/plugin/plugin_manifest.cpp`
# static-asserts `sizeof(off_t) >= 8` so the manifest fd-digest path
# works on >2 GiB plugin binaries. `_FILE_OFFSET_BITS=64` lifts the
# typedef to 64-bit across the platform headers.
if(WIN32)
    add_compile_definitions(_FILE_OFFSET_BITS=64)
endif()

# spdlog compile-time level ceiling. Release strips TRACE and DEBUG
# call sites entirely; Debug compiles every level. The ceiling is
# read by the SPDLOG_LOGGER_* macros at the call site, so the
# stripped levels do not even produce dead branches in the binary.
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    add_compile_definitions(SPDLOG_ACTIVE_LEVEL=SPDLOG_LEVEL_INFO)
else()
    add_compile_definitions(SPDLOG_ACTIVE_LEVEL=SPDLOG_LEVEL_TRACE)
endif()

# Plugin-author build helper. Defines `add_plugin(NAME sources...)`.
# In-tree iteration: visibility stays open so unit tests link plugin
# objects directly. The flag flips to FALSE for out-of-tree consumers
# loading the helper through `find_package(GoodNet)`.
set(_GOODNET_IN_TREE TRUE CACHE INTERNAL
    "Building plugins in-tree alongside the kernel")
include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/AddPlugin.cmake")
# Precompiled-header umbrella. Defines `goodnet_apply_pch(target)`.
include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/Pch.cmake")

# ── Options ──────────────────────────────────────────────────────────────────
# This build covers the platform — kernel + SDK + the mandatory mesh-framing
# protocol (GNET). Other plugins are independent projects that depend on the
# installed SDK. The bundled-plugins option iterates plugins/ for in-tree
# development convenience; production builds package each plugin separately.
option(GOODNET_BUILD_TESTS            "Build unit + integration tests"   ON)
option(GOODNET_BUILD_EXAMPLES         "Build example apps"               OFF)
option(GOODNET_BUILD_BENCH            "Build the comprehensive bench suite (bench/)" OFF)
option(GOODNET_BUILD_BUNDLED_PLUGINS  "Iterate plugins/ during in-tree builds" ON)
# Compiles the bench-only `_test_clear_inline_crypto` seam into the
# kernel. The seam is a guarded entrypoint that zeroes the inline
# AEAD counters so `bench_showcase` §B.3 can model the post-handshake
# Noise→Null handoff path. Default OFF — production binaries do not
# carry the seam at all; the method always returns
# `GN_ERR_INVALID_STATE` when the macro is undefined.
option(GOODNET_BENCH_SHOWCASE         "Compile the inline-crypto downgrade seam for bench_showcase" OFF)
if(GOODNET_BENCH_SHOWCASE)
    add_compile_definitions(GOODNET_BENCH_SHOWCASE)
endif()

# Build-acceleration toggles. Defaults pick the right path per build
# type: Release gets LTO + `-O3`, every type gets the mold linker + a
# precompiled-header umbrella for the asio / spdlog / fmt block that
# would otherwise be re-parsed once per translation unit.
set(_goodnet_lto_default OFF)
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    set(_goodnet_lto_default ON)
endif()
option(GOODNET_USE_LTO  "Link-time optimization (Release default ON)" ${_goodnet_lto_default})
option(GOODNET_USE_PCH  "Precompile <asio.hpp> + spdlog + fmt umbrella" ON)
option(GOODNET_USE_MOLD "Use mold linker if available"                  ON)

# Release strips the implicit `-O2` GCC default for `-O3`. Sanitizer
# builds set their own `-O1 -g` per `nix/sanitize.nix`; Debug stays
# unoptimised so stack traces remain readable.
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    add_compile_options(-O3)
endif()

# `mold` is the single biggest link-time win for a multi-target build
# like this one (kernel + 8 plugins + 3 test binaries). Auto-detect at
# configure time; absence is silent — the default ld stays in use.
if(GOODNET_USE_MOLD)
    find_program(GOODNET_MOLD_BIN mold)
    if(GOODNET_MOLD_BIN)
        add_link_options(-fuse-ld=mold)
    endif()
endif()

# IPO / LTO across translation units. Only fires for Release —
# Debug / sanitizer trees are unaffected even when a stale option
# value persists in `CMakeCache.txt` from a prior Release configure.
# `check_ipo_supported` guards against compilers that decline so the
# build survives an unexpected toolchain.
if(GOODNET_USE_LTO AND CMAKE_BUILD_TYPE STREQUAL "Release")
    include(CheckIPOSupported)
    check_ipo_supported(RESULT _goodnet_ipo_ok OUTPUT _goodnet_ipo_msg)
    if(_goodnet_ipo_ok)
        set(CMAKE_INTERPROCEDURAL_OPTIMIZATION ON)
        # LTO-companion: tell GCC/Clang that internal calls within
        # a shared library are not subject to ELF symbol interposition,
        # so the optimiser may inline and devirtualise across TUs that
        # land in the same `.so` (kernel objects → libgoodnet_kernel.a;
        # plugin objects → libgoodnet_<name>.so). The PLT indirection
        # for `gn_*` exports stays — only the kernel's intra-library
        # calls collapse. Visibility scope-narrowing is set per-target
        # in `cmake/AddPlugin.cmake` (CXX_VISIBILITY_PRESET hidden)
        # so test binaries keep the default visibility they need to
        # link against gtest's libstdc++ surface.
        if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
            add_compile_options(-fno-semantic-interposition)
        endif()
    else()
        message(STATUS "  LTO requested but compiler declined: ${_goodnet_ipo_msg}")
    endif()
endif()

# ── Dependencies ─────────────────────────────────────────────────────────────
# Standalone Asio is the same library as Boost.Asio without the Boost
# umbrella — Christopher Kohlhoff maintains both in lockstep. Keeping
# only the standalone variant trims the dependency closure (no
# Boost.System, Boost.Thread, Boost.Atomic) and stays header-only.
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)
find_package(spdlog REQUIRED)
find_package(fmt    REQUIRED)
find_package(nlohmann_json REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED IMPORTED_TARGET libsodium)
# OpenSSL is consumed by TLS/QUIC/WS/ICE plugins. On Windows mingw
# cross-builds we skip those plugins (see plugins/CMakeLists.txt),
# so OpenSSL itself is optional at the root level. Linux configures
# always discover it — the plugins fail at link if it's missing.
if(WIN32)
    find_package(OpenSSL)
else()
    find_package(OpenSSL REQUIRED)
endif()
# Standalone Asio ships only a pkg-config file in nixpkgs; wrap it
# into an alias `asio::asio` so target_link_libraries reads the same
# as if the library shipped a CMake config. ASIO_STANDALONE switches
# the headers off the Boost umbrella.
pkg_check_modules(ASIO REQUIRED IMPORTED_TARGET asio)
add_library(asio::asio INTERFACE IMPORTED)
target_link_libraries(asio::asio INTERFACE PkgConfig::ASIO)
target_compile_definitions(asio::asio INTERFACE ASIO_STANDALONE)

# ── Test framework discovery ─────────────────────────────────────────────────
# Hoisted before plugin/test subdirectories so per-plugin
# `tests/CMakeLists.txt` files (added under each plugin's umbrella when
# GOODNET_BUILD_TESTS is on) can reference GTest::gtest and the rapidcheck
# imported targets directly.
if(GOODNET_BUILD_TESTS)
    enable_testing()
    find_package(GTest      REQUIRED)
    find_package(rapidcheck REQUIRED)
    include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/GoodNetTesting.cmake")
    goodnet_patch_rapidcheck_targets()
endif()

# ── Platform: SDK + kernel ───────────────────────────────────────────────────
add_subdirectory(sdk)
add_subdirectory(core)

# Mandatory mesh-framing plugin lives in plugins/protocols/gnet/ but is
# statically linked into the kernel binary. Added directly so the kernel
# build does not depend on GOODNET_BUILD_BUNDLED_PLUGINS.
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/plugins/protocols/gnet/CMakeLists.txt")
    add_subdirectory(plugins/protocols/gnet)
endif()

# Raw protocol — alternative layer for simulation harnesses, PCAP replay,
# foreign-protocol passthrough. Built unconditionally so tests can link
# it; production kernel builds with `gnet-v1` linked.
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/plugins/protocols/raw/CMakeLists.txt")
    add_subdirectory(plugins/protocols/raw)
endif()

# ── Bundled plugins (development convenience) ────────────────────────────────
# Production: each plugin is a separate build/derivation, depends on the
# installed SDK via find_package(GoodNet REQUIRED).
if(GOODNET_BUILD_BUNDLED_PLUGINS)
    add_subdirectory(plugins)
endif()

# ── Operator-side language bindings ──────────────────────────────────────────
# `bridges/cpp/` lives in its own git (mirror `bridges-cpp.git`); when
# present, surface its INTERFACE target plus its smoke tests through the
# kernel build, so `nix run .#test` exercises the binding alongside the
# rest of the platform.
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/bridges/cpp/CMakeLists.txt")
    add_subdirectory(bridges/cpp)
endif()

# ── Operator-facing apps ─────────────────────────────────────────────────────
option(GOODNET_BUILD_APPS "Build operator-facing CLI binaries (apps/)" ON)
if(GOODNET_BUILD_APPS AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/apps/CMakeLists.txt")
    add_subdirectory(apps)
endif()

# ── Static-plugin registry (`-DGOODNET_STATIC_PLUGINS=ON`) ───────────────────
# Wire every bundled plugin's OBJECT lib + suffix-named entry symbols
# into the kernel binary. The helper generates `static_plugins.cpp`,
# excludes the empty-default registry TU, and links every passed
# plugin target via PRIVATE so downstream consumers still get the
# dynamic-linkage contract from `find_package(GoodNet)`.
#
# Globally surface the option to the C++ preprocessor so kernel and
# apps code (notably `apps/goodnetd/subcommands/run.cpp`) can switch
# to `PluginManager::load_static()` at compile time. The macros in
# `sdk/plugin.h` are guarded on both this define AND
# `GN_PLUGIN_STATIC_NAME` — defining only the former at the kernel
# scope keeps the suffix rename limited to plugin TUs.
if(GOODNET_STATIC_PLUGINS)
    add_compile_definitions(GOODNET_STATIC_PLUGINS=1)
endif()

if(GOODNET_STATIC_PLUGINS)
    include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/StaticPlugins.cmake")

    set(_goodnet_static_plugin_list "")
    foreach(_p IN ITEMS
            goodnet_security_null
            goodnet_security_noise
            goodnet_link_ipc
            goodnet_link_tcp
            goodnet_link_udp
            goodnet_link_tls
            goodnet_link_ws
            goodnet_link_ice
            goodnet_link_quic
            goodnet_handler_heartbeat
            goodnet_strategy_float_send_rtt)
        if(TARGET ${_p})
            list(APPEND _goodnet_static_plugin_list ${_p})
        endif()
    endforeach()

    if(_goodnet_static_plugin_list)
        # Bundle the registry + plugin objects into the kernel
        # static archive. Targeting `goodnet_kernel` directly
        # (the STATIC variant) — `target_sources($<TARGET_OBJECTS
        # :p>)` resolves at the archive step, so the plugin .o
        # files actually land in `libgoodnet_kernel.a`. Targeting
        # `goodnet_kernel_objects` (OBJECT) drops the TARGET_OBJECTS
        # generator expression silently. Same registry then reaches
        # apps/goodnet (links kernel), find_package consumers like
        # Solas (link kernel), and in-process operator UIs.
        # `gn_core_init` walks the registry via
        # `PluginManager::load_static` automatically under the
        # GOODNET_STATIC_PLUGINS compile gate.
        goodnet_register_static_plugins(goodnet_kernel
            ${_goodnet_static_plugin_list})

        # Plugin-side PUBLIC link deps that aren't already on
        # `goodnet_kernel_objects`'s link line. Bundling the
        # plugin .o files via TARGET_OBJECTS doesn't carry the
        # INTERFACE_LINK_LIBRARIES; the bundled symbols compile
        # but the final link of a consumer (apps/goodnet, Solas)
        # fails with unresolved references unless the host
        # archive itself surfaces the requirement. Listed plugins
        # opt in here by name; new plugins with unique link deps
        # extend the block.
        find_package(OpenSSL QUIET)
        if(TARGET goodnet_link_tls AND TARGET OpenSSL::SSL)
            target_link_libraries(goodnet_kernel PUBLIC
                OpenSSL::SSL OpenSSL::Crypto)
        endif()

        # `goodnet_kernel_shared` is currently built from the same
        # OBJECT lib without the per-plugin TARGET_OBJECTS bundling
        # — operator UIs that need static plugins in a shared
        # variant should adjust the recipe; in-tree apps/goodnet
        # and find_package consumers go through the STATIC variant.
        message(STATUS
            "  Static plugins    : ${_goodnet_static_plugin_list}")
    endif()
endif()

# ── Examples & tests ─────────────────────────────────────────────────────────
if(GOODNET_BUILD_EXAMPLES AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/examples/CMakeLists.txt")
    add_subdirectory(examples)
endif()

if(GOODNET_BUILD_TESTS)
    add_subdirectory(tests)
endif()

# ── Benchmark suite ──────────────────────────────────────────────────────────
# Opt-in via GOODNET_BUILD_BENCH. Pulls google-benchmark from the dev
# shell; the suite covers per-plugin throughput / latency / handshake,
# composition depth, and live comparisons vs mature solutions for the
# UX / DX gap analysis the bench report exports.
if(GOODNET_BUILD_BENCH AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/bench/CMakeLists.txt")
    add_subdirectory(bench)
endif()

# ── Install / find_package(GoodNet) support ──────────────────────────────────
# Plugins outside this repository import GoodNet through:
#
#     find_package(GoodNet REQUIRED)
#     add_library(my_plugin SHARED my_plugin.cpp)
#     target_link_libraries(my_plugin PRIVATE GoodNet::sdk)
#
# The kernel target (`GoodNet::kernel`) is for hosts that embed the
# kernel; plugins do not link against it.
include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

set(GOODNET_CMAKE_DIR "${CMAKE_INSTALL_LIBDIR}/cmake/GoodNet")

install(EXPORT GoodNetTargets
        FILE        GoodNetTargets.cmake
        NAMESPACE   GoodNet::
        DESTINATION "${GOODNET_CMAKE_DIR}")

configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/GoodNetConfig.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/GoodNetConfig.cmake"
    INSTALL_DESTINATION "${GOODNET_CMAKE_DIR}")

write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/GoodNetConfigVersion.cmake"
    VERSION       "${PROJECT_VERSION}"
    COMPATIBILITY SameMajorVersion)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/GoodNetConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/GoodNetConfigVersion.cmake"
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/AddPlugin.cmake"
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/GoodNetTesting.cmake"
    DESTINATION "${GOODNET_CMAKE_DIR}")

# ── Summary ──────────────────────────────────────────────────────────────────
message(STATUS "")
message(STATUS "GoodNet ${PROJECT_VERSION}")
message(STATUS "  Build type        : ${CMAKE_BUILD_TYPE}")
message(STATUS "  Compiler          : ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "  C++ standard      : ${CMAKE_CXX_STANDARD}")
message(STATUS "  Tests             : ${GOODNET_BUILD_TESTS}")
message(STATUS "  Examples          : ${GOODNET_BUILD_EXAMPLES}")
message(STATUS "  Bundled plugins   : ${GOODNET_BUILD_BUNDLED_PLUGINS}")
if(CMAKE_INTERPROCEDURAL_OPTIMIZATION)
    message(STATUS "  LTO               : ON (Release IPO)")
elseif(GOODNET_USE_LTO)
    message(STATUS "  LTO               : requested but inactive (build type ${CMAKE_BUILD_TYPE})")
else()
    message(STATUS "  LTO               : OFF")
endif()
message(STATUS "  PCH               : ${GOODNET_USE_PCH}")
if(GOODNET_USE_MOLD AND GOODNET_MOLD_BIN)
    message(STATUS "  Linker            : mold (${GOODNET_MOLD_BIN})")
elseif(GOODNET_USE_MOLD)
    message(STATUS "  Linker            : default (mold not found on PATH)")
else()
    message(STATUS "  Linker            : default")
endif()
message(STATUS "")
