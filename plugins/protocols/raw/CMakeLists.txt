cmake_minimum_required(VERSION 3.22)

if(NOT TARGET GoodNet::sdk)
    project(goodnet_protocol_raw
        VERSION   0.1.0
        LANGUAGES CXX)
    find_package(GoodNet REQUIRED)
    include(CTest)
    if(BUILD_TESTING)
        find_package(GTest      REQUIRED)
        find_package(rapidcheck QUIET)
        set(GOODNET_BUILD_TESTS ON)
    endif()
endif()

# Raw protocol — opaque-payload protocol layer.
# Build-time alternative to `gnet-v1` for simulation harnesses,
# PCAP replay, and foreign-protocol passthrough scenarios. STATIC
# library + OBJECT lib for in-tree tests, mirroring the gnet shape.

add_library(goodnet_protocol_raw STATIC
    raw.cpp
)
add_library(GoodNet::protocol_raw ALIAS goodnet_protocol_raw)

target_include_directories(goodnet_protocol_raw PUBLIC
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>"
    "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}>"
)

target_link_libraries(goodnet_protocol_raw
    PUBLIC
        GoodNet::sdk
        GoodNet::ctx_accessors
)

target_compile_features(goodnet_protocol_raw PUBLIC cxx_std_23)
target_compile_options(goodnet_protocol_raw PRIVATE
    -Wall -Wextra -Wpedantic -Wno-unused-parameter)
set_target_properties(goodnet_protocol_raw PROPERTIES
    POSITION_INDEPENDENT_CODE ON)

if(GOODNET_BUILD_TESTS)
    add_subdirectory(tests)
endif()
