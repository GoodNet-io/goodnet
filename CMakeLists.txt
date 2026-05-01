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
include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/AddPlugin.cmake")

# ── Options ──────────────────────────────────────────────────────────────────
# This build covers the platform — kernel + SDK + the mandatory mesh-framing
# protocol (GNET). Other plugins are independent projects that depend on the
# installed SDK. The bundled-plugins option iterates plugins/ for in-tree
# development convenience; production builds package each plugin separately.
option(GOODNET_BUILD_TESTS            "Build unit + integration tests"   ON)
option(GOODNET_BUILD_EXAMPLES         "Build example apps"               OFF)
option(GOODNET_BUILD_BUNDLED_PLUGINS  "Iterate plugins/ during in-tree builds" ON)
option(GOODNET_USE_LTO                "Link-time optimization (Release)" OFF)

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

# ── Examples & tests ─────────────────────────────────────────────────────────
if(GOODNET_BUILD_EXAMPLES AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/examples/CMakeLists.txt")
    add_subdirectory(examples)
endif()

if(GOODNET_BUILD_TESTS)
    enable_testing()
    find_package(GTest      REQUIRED)
    find_package(rapidcheck REQUIRED)
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
message(STATUS "  LTO               : ${GOODNET_USE_LTO}")
message(STATUS "")
