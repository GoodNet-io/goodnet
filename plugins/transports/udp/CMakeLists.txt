# UDP transport plugin — MIT (common transports per LICENSE convention).
# OBJECT lib for in-tree tests + SHARED plugin entry.

add_library(goodnet_udp_objects OBJECT
    udp.cpp
)
target_link_libraries(goodnet_udp_objects PUBLIC GoodNet::sdk asio::asio Threads::Threads)
target_compile_features(goodnet_udp_objects PUBLIC cxx_std_23)
target_compile_options(goodnet_udp_objects PRIVATE
    -Wall -Wextra -Wpedantic -Wno-unused-parameter)
target_include_directories(goodnet_udp_objects PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR})
set_target_properties(goodnet_udp_objects PROPERTIES
    POSITION_INDEPENDENT_CODE ON)

add_plugin(goodnet_transport_udp
    plugin_entry.cpp
)
target_link_libraries(goodnet_transport_udp
    PRIVATE goodnet_udp_objects asio::asio Threads::Threads)
