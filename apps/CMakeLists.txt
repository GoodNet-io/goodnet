# apps/ — operator-facing CLI binaries.
#
# - `goodnetd`: BusyBox-style multicall covering the v1 operator
#   surface (config validation, plugin hashing, manifest generation,
#   version reporting, identity gen|show, run). Renamed from the
#   pre-rc4 `goodnet` binary so the daemon name matches the Linux
#   convention (systemd, dockerd, sshd) and frees the
#   `goodnet-io/goodnet` namespace for the kernel repo itself.
# - `gssh`: single binary with three operational modes
#   (wrap / bridge / listen) for tunnelling openssh through a
#   GoodNet kernel.

add_subdirectory(goodnetd)

# `gssh` consumes the operator-side C++ binding `GoodNet::cpp`
# from `bridges/cpp/`. The kernel-only sub-flake builds without
# the bridges checkout, so the target is absent in that context;
# guarding on the alias keeps that build green and lights the
# binary up automatically once `bridges/cpp/` is wired in.
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/gssh/CMakeLists.txt"
        AND TARGET GoodNet::cpp)
    add_subdirectory(gssh)
endif()
