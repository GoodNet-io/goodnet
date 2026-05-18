cmake_minimum_required(VERSION 3.22)

if(NOT TARGET GoodNet::sdk)
    project(goodnet_link_raw_inject
        VERSION   1.0.0
        LANGUAGES CXX)
    find_package(GoodNet REQUIRED)
    include(CTest)
    if(BUILD_TESTING)
        find_package(GTest      REQUIRED)
        find_package(rapidcheck QUIET)
        goodnet_patch_rapidcheck_targets()
        set(GOODNET_BUILD_TESTS ON)
    endif()
endif()

# Apache-2.0 — the raw-inject bridge follows the same licence as the
# other transport-adjacent plugins (noise/quic/tls).
# OBJECT lib for in-tree tests + SHARED plugin entry that the kernel
# loads through `dlopen`.

add_library(goodnet_raw_inject_objects OBJECT
    raw_inject.cpp
)
target_link_libraries(goodnet_raw_inject_objects
    PUBLIC GoodNet::sdk Threads::Threads)
target_compile_features(goodnet_raw_inject_objects PUBLIC cxx_std_23)
target_compile_options(goodnet_raw_inject_objects PRIVATE
    -Wall -Wextra -Wpedantic -Wno-unused-parameter)
target_include_directories(goodnet_raw_inject_objects PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR})
set_target_properties(goodnet_raw_inject_objects PROPERTIES
    POSITION_INDEPENDENT_CODE ON)

add_plugin(goodnet_link_raw_inject
    plugin_entry.cpp
)
target_link_libraries(goodnet_link_raw_inject
    PRIVATE goodnet_raw_inject_objects Threads::Threads)

if(GOODNET_BUILD_TESTS)
    add_subdirectory(tests)
endif()
