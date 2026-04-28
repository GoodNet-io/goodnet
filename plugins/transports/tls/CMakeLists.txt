# TLS transport plugin — Apache 2.0 (original implementation).
# OBJECT lib for in-tree tests + SHARED plugin entry. Links OpenSSL
# transitively through Asio's <asio/ssl.hpp> headers.

add_library(goodnet_tls_objects OBJECT
    tls.cpp
)
target_link_libraries(goodnet_tls_objects PUBLIC
    GoodNet::sdk asio::asio Threads::Threads
    OpenSSL::SSL OpenSSL::Crypto)
target_compile_features(goodnet_tls_objects PUBLIC cxx_std_23)
target_compile_options(goodnet_tls_objects PRIVATE
    -Wall -Wextra -Wpedantic -Wno-unused-parameter)
target_include_directories(goodnet_tls_objects PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR})
set_target_properties(goodnet_tls_objects PROPERTIES
    POSITION_INDEPENDENT_CODE ON)

add_plugin(goodnet_transport_tls
    plugin_entry.cpp
)
target_link_libraries(goodnet_transport_tls
    PRIVATE goodnet_tls_objects asio::asio Threads::Threads
            OpenSSL::SSL OpenSSL::Crypto)
