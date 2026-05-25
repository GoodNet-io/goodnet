cmake_minimum_required(VERSION 3.22)

if(NOT TARGET GoodNet::sdk)
    project(goodnet_link_ws_inject
        VERSION   0.1.0
        LANGUAGES CXX)
    find_package(GoodNet REQUIRED)
    include(CTest)
    if(BUILD_TESTING)
        find_package(GTest REQUIRED)
        set(GOODNET_BUILD_TESTS ON)
    endif()
endif()

add_library(goodnet_ws_inject_objects OBJECT
    ws_inject.cpp
)
target_link_libraries(goodnet_ws_inject_objects
    PUBLIC GoodNet::sdk Threads::Threads)
target_compile_features(goodnet_ws_inject_objects PUBLIC cxx_std_23)
target_compile_options(goodnet_ws_inject_objects PRIVATE
    -Wall -Wextra -Wpedantic -Wno-unused-parameter)
target_include_directories(goodnet_ws_inject_objects PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR})
set_target_properties(goodnet_ws_inject_objects PROPERTIES
    POSITION_INDEPENDENT_CODE ON)

add_plugin(goodnet_link_ws_inject
    plugin_entry.cpp
)
target_link_libraries(goodnet_link_ws_inject
    PRIVATE goodnet_ws_inject_objects Threads::Threads)

if(GOODNET_BUILD_TESTS)
    add_subdirectory(tests)
endif()
