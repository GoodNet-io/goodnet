cmake_minimum_required(VERSION 3.28)

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

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

add_compile_options(
    -Wall -Wextra -Wpedantic
    -Wshadow -Wconversion -Wnon-virtual-dtor -Woverloaded-virtual
    -Wno-unused-parameter
)

# ── Options ──────────────────────────────────────────────────────────────────
# This build covers the platform — kernel + SDK + the mandatory mesh-framing
# protocol (GNET). Other plugins are independent projects that depend on the
# installed SDK. The bundled-plugins option iterates plugins/ for in-tree
# development convenience; production builds package each plugin separately.
option(GOODNET_BUILD_TESTS            "Build unit + integration tests"   ON)
option(GOODNET_BUILD_EXAMPLES         "Build example apps"               ON)
option(GOODNET_BUILD_BUNDLED_PLUGINS  "Iterate plugins/ during in-tree builds" OFF)
option(GOODNET_USE_LTO                "Link-time optimization (Release)" OFF)

# ── Dependencies ─────────────────────────────────────────────────────────────
# Boost.System is header-only since Boost 1.69; we only need a real
# library link for Boost.Thread. The CMake-config split in newer Boost
# packagings can omit the system shim, so request only what we link.
set(Boost_NO_BOOST_CMAKE ON)
find_package(Boost REQUIRED COMPONENTS thread)
find_package(spdlog REQUIRED)
find_package(fmt    REQUIRED)
find_package(nlohmann_json REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED IMPORTED_TARGET libsodium)

# ── Platform: SDK + kernel ───────────────────────────────────────────────────
add_subdirectory(sdk)
add_subdirectory(core)

# Mandatory mesh-framing plugin lives in plugins/protocols/gnet/ but is
# statically linked into the kernel binary. Added directly so the kernel
# build does not depend on GOODNET_BUILD_BUNDLED_PLUGINS.
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/plugins/protocols/gnet/CMakeLists.txt")
    add_subdirectory(plugins/protocols/gnet)
endif()

# ── Bundled plugins (development convenience) ────────────────────────────────
# Production: each plugin is a separate build/derivation, depends on the
# installed SDK via find_package(GoodNet REQUIRED).
if(GOODNET_BUILD_BUNDLED_PLUGINS)
    add_subdirectory(plugins)
endif()

# ── Examples & tests ─────────────────────────────────────────────────────────
if(GOODNET_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

if(GOODNET_BUILD_TESTS)
    enable_testing()
    find_package(GTest      REQUIRED)
    find_package(rapidcheck REQUIRED)
    add_subdirectory(tests)
endif()

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
