# apps/ — operator-facing CLI binaries.
#
# - `goodnet`: BusyBox-style multicall covering the v1 operator
#   surface (config validation, plugin hashing, manifest generation,
#   version reporting, identity gen|show, run).
# - `goodnet-ssh`: single binary with three operational modes
#   (wrap / bridge / listen) for tunnelling openssh through a
#   GoodNet kernel.

add_subdirectory(goodnet)

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/goodnet-ssh/CMakeLists.txt")
    add_subdirectory(goodnet-ssh)
endif()
