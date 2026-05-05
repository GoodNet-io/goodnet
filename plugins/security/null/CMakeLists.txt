cmake_minimum_required(VERSION 3.22)

if(NOT TARGET GoodNet::sdk)
    project(goodnet_security_null
        VERSION   0.1.0
        LANGUAGES CXX)
    find_package(GoodNet REQUIRED)
    goodnet_standalone_plugin_includes()
    include(CTest)
    if(BUILD_TESTING)
        find_package(GTest      REQUIRED)
        find_package(rapidcheck QUIET)
        goodnet_patch_rapidcheck_targets()
        set(GOODNET_BUILD_TESTS ON)
    endif()
endif()

# Null security provider — loopback / debug pass-through. Per
# `security-trust.md` §4-§5 only permitted on Loopback / IntraNode
# trust classes by default; production deployments do not load this
# plugin.

add_plugin(goodnet_security_null
    null.cpp
)

if(GOODNET_BUILD_TESTS)
    add_subdirectory(tests)
endif()
