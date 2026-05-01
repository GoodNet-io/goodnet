# TCP transport plugin — MIT (common transports per LICENSE convention).
# Two artefacts share the source: an OBJECT library so unit tests link
# the C++ class directly, and a SHARED plugin via add_plugin() that the
# kernel's PluginManager loads through dlopen.

add_library(goodnet_tcp_objects OBJECT
    tcp.cpp
)
target_link_libraries(goodnet_tcp_objects PUBLIC GoodNet::sdk asio::asio Threads::Threads)
target_compile_features(goodnet_tcp_objects PUBLIC cxx_std_23)
target_compile_options(goodnet_tcp_objects PRIVATE
    -Wall -Wextra -Wpedantic -Wno-unused-parameter)
target_include_directories(goodnet_tcp_objects PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR})
set_target_properties(goodnet_tcp_objects PROPERTIES
    POSITION_INDEPENDENT_CODE ON)

add_plugin(goodnet_link_tcp
    plugin_entry.cpp
)
target_link_libraries(goodnet_link_tcp
    PRIVATE goodnet_tcp_objects asio::asio Threads::Threads)
