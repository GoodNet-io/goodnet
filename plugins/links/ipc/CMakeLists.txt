# IPC transport plugin — MIT (common transports per LICENSE convention).
# OBJECT lib for in-tree tests + SHARED plugin entry.

add_library(goodnet_ipc_objects OBJECT
    ipc.cpp
)
target_link_libraries(goodnet_ipc_objects PUBLIC GoodNet::sdk asio::asio Threads::Threads)
target_compile_features(goodnet_ipc_objects PUBLIC cxx_std_23)
target_compile_options(goodnet_ipc_objects PRIVATE
    -Wall -Wextra -Wpedantic -Wno-unused-parameter)
target_include_directories(goodnet_ipc_objects PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR})
set_target_properties(goodnet_ipc_objects PROPERTIES
    POSITION_INDEPENDENT_CODE ON)

add_plugin(goodnet_link_ipc
    plugin_entry.cpp
)
target_link_libraries(goodnet_link_ipc
    PRIVATE goodnet_ipc_objects asio::asio Threads::Threads)

if(GOODNET_BUILD_TESTS)
    add_subdirectory(tests)
endif()
