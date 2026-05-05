cmake_minimum_required(VERSION 3.22)

project(GoodNet
        VERSION       0.1.0
        DESCRIPTION   "Network kernel and SDK"
        LANGUAGES     CXX C)

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
option(GOODNET_BUILD_BUNDLED_PLUGINS  "Iterate plugins/ during in-tree builds" ON)

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
find_package(OpenSSL REQUIRED)
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

# ── Operator-facing apps ─────────────────────────────────────────────────────
option(GOODNET_BUILD_APPS "Build operator-facing CLI binaries (apps/)" ON)
if(GOODNET_BUILD_APPS AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/apps/CMakeLists.txt")
    add_subdirectory(apps)
endif()

# ── Examples & tests ─────────────────────────────────────────────────────────
if(GOODNET_BUILD_EXAMPLES AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/examples/CMakeLists.txt")
    add_subdirectory(examples)
endif()

if(GOODNET_BUILD_TESTS)
    add_subdirectory(tests)
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
