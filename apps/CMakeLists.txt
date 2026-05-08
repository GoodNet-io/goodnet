# apps/ — operator-facing CLI binaries.
#
# - `goodnet`: BusyBox-style multicall covering the v1 operator
#   surface (config validation, plugin hashing, manifest generation,
#   version reporting, identity gen|show, run).
# - `gssh`: single binary with three operational modes
#   (wrap / bridge / listen) for tunnelling openssh through a
#   GoodNet kernel.

add_subdirectory(goodnet)

# `gssh` consumes the operator-side C++ binding `GoodNet::cpp`
# from `bridges/cpp/`. The kernel-only sub-flake builds without
# the bridges checkout, so the target is absent in that context;
# guarding on the alias keeps that build green and lights the
# binary up automatically once `bridges/cpp/` is wired in.
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/gssh/CMakeLists.txt"
        AND TARGET GoodNet::cpp)
    add_subdirectory(gssh)
endif()
