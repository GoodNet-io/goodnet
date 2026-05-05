# Heartbeat handler — Apache 2.0 (real implementation, no upstream
# analogue per LICENSE convention).
#
# OBJECT library carries the C++ class for in-tree tests; the
# `goodnet_handler_heartbeat.so` plugin entry registers the handler
# + the `gn.heartbeat` extension through the host_api.

add_library(goodnet_heartbeat_objects OBJECT
    heartbeat.cpp
)
target_link_libraries(goodnet_heartbeat_objects PUBLIC GoodNet::sdk)
target_compile_features(goodnet_heartbeat_objects PUBLIC cxx_std_23)
target_compile_options(goodnet_heartbeat_objects PRIVATE
    -Wall -Wextra -Wpedantic -Wno-unused-parameter)
target_include_directories(goodnet_heartbeat_objects PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR})
set_target_properties(goodnet_heartbeat_objects PROPERTIES
    POSITION_INDEPENDENT_CODE ON)

add_plugin(goodnet_handler_heartbeat
    plugin_entry.cpp
)
target_link_libraries(goodnet_handler_heartbeat
    PRIVATE goodnet_heartbeat_objects)

if(GOODNET_BUILD_TESTS)
    add_subdirectory(tests)
endif()
