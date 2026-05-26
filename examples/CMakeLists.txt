cmake_minimum_required(VERSION 3.22)

if(NOT TARGET GoodNet::sdk)
    project(goodnet-examples VERSION 1.0.0 LANGUAGES CXX)
    find_package(GoodNet REQUIRED)
    include(CTest)
    if(BUILD_TESTING)
        find_package(GTest REQUIRED)
    endif()
endif()

# two_node and hello-echo: public SDK only — always buildable standalone.
add_subdirectory(two_node)
add_subdirectory(hello-echo)

# bench: uses kernel-internal headers — only built when in-tree
# (TARGET GoodNet::kernel is only defined inside the monorepo build).
if(TARGET GoodNet::kernel)
    add_subdirectory(bench)
endif()
