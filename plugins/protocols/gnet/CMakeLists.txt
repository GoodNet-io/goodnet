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
    PRIVATE
        GoodNet::kernel
)

target_compile_features(goodnet_protocol_gnet PUBLIC cxx_std_23)

if(GOODNET_BUILD_TESTS)
    add_subdirectory(tests)
endif()
