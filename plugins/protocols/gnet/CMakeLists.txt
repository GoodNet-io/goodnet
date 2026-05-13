cmake_minimum_required(VERSION 3.22)

if(NOT TARGET GoodNet::sdk)
    project(goodnet_protocol_gnet
        VERSION   1.0.0
        LANGUAGES CXX)
    find_package(GoodNet REQUIRED)
    include(CTest)
    if(BUILD_TESTING)
        find_package(GTest      REQUIRED)
        find_package(rapidcheck QUIET)
        set(GOODNET_BUILD_TESTS ON)
    endif()
endif()

# GNET — canonical mesh-framing implementation. Statically linked
# into the kernel binary; the source still lives here under plugins/
# so the kernel/plugin separation is structural, not implementation-
# detail.

add_library(goodnet_protocol_gnet STATIC
    wire.cpp
    protocol.cpp
)
add_library(GoodNet::protocol_gnet ALIAS goodnet_protocol_gnet)

target_include_directories(goodnet_protocol_gnet PUBLIC
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>"
    "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}>"
)

target_link_libraries(goodnet_protocol_gnet
    PUBLIC
        GoodNet::sdk
        GoodNet::ctx_accessors
)
# protocol.cpp / wire.cpp consume only `core/util/endian.hpp` from
# the kernel tree, reachable through the PUBLIC include directories
# entry above (PROJECT_SOURCE_DIR covers core/). Linking
# `GoodNet::kernel` would route consumers back through the kernel
# graph and prevent the install-tree shape below from being a
# decoupled add-on.

target_compile_features(goodnet_protocol_gnet PUBLIC cxx_std_23)

# Export under the `GoodNet::protocol_gnet` alias name (matches the
# in-tree alias above so consumers using `find_package(GoodNet)`
# spell the dependency identically to a source-tree subdirectory
# build).
set_target_properties(goodnet_protocol_gnet PROPERTIES
    EXPORT_NAME protocol_gnet)

# Install the static archive alongside the kernel archives.
# `gn_core_init` references `GnetProtocol::vtable`; without this
# install, `find_package(GoodNet)` consumers that link only
# `GoodNet::kernel` see unresolved-vtable at link time. The plugin's
# archive lands next to libgoodnet_kernel.a so consumers add a
# single `GoodNet::protocol_gnet` link line and the symbol resolves.
install(TARGETS goodnet_protocol_gnet
    EXPORT GoodNetTargets
    ARCHIVE)

if(GOODNET_BUILD_TESTS)
    add_subdirectory(tests)
endif()
