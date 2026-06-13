cmake_minimum_required(VERSION 3.22)

if(NOT TARGET GoodNet::sdk)
    project(goodnet-examples VERSION 1.0.0 LANGUAGES CXX)
    find_package(GoodNet REQUIRED)
    # TCP static lib + headers — exported by the link-tcp plugin package.
    # Absent in kernel-only builds; bench guards on GoodNet::link_tcp_static.
    find_package(GoodNetLinkTcp QUIET)
    include(CTest)
    if(BUILD_TESTING)
        find_package(GTest REQUIRED)
    endif()
endif()

# two_node and hello-echo: public SDK only — always buildable standalone.
add_subdirectory(two_node)
add_subdirectory(hello-echo)

# bench: links kernel + TCP directly; requires both targets.
if(TARGET GoodNet::kernel AND (TARGET goodnet_tcp_objects OR TARGET GoodNet::link_tcp_static))
    add_subdirectory(bench)
endif()
