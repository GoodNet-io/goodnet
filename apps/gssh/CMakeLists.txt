# gssh — single binary, three operational modes (wrap / bridge /
# listen). Modeled on openssh's shared-source `ssh` + `sshd` split: one
# tree, two utilities, separated by argv. The wrap mode is the
# user-facing convenience that execs into openssh with a ProxyCommand
# re-entering the same binary in bridge mode. The listen mode is the
# server-side daemon, intended to run under systemd.
#
# License: MIT. The kernel headers are GPL-2 + linking-exception, the
# bridges/cpp wrapper is MIT, the SDK is MIT — none of those licences
# propagate into a binary that links against them, so this app stays
# permissively licensed for downstream operators.

add_executable(gssh
    main.cpp
    mode_wrap.cpp
    mode_bridge.cpp
    mode_listen.cpp
    identity.cpp
    peers.cpp
    pipe.cpp
)

target_include_directories(gssh
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
)

target_compile_features(gssh PRIVATE cxx_std_23)

# Linkage:
#   - `goodnet_kernel` carries the C ABI surface AND the kernel C++
#     types (`Kernel`, `PluginManager`, `Phase`) the bridge / listen
#     modes need for persistent identity loading. The C bridge
#     (`bridges/cpp/core.hpp`) does not surface identity persistence
#     in v1.0 — the kernel internals are the only path until a future
#     SDK release adds `gn_core_load_identity_from_file`.
#   - `GoodNet::cpp` pulls in the bridges/cpp INTERFACE library for
#     RAII helpers we may use opportunistically (`Subscription`).
#   - `GoodNet::protocol_gnet` is the canonical mesh-framing layer;
#     statically linked because every bridge mode invocation needs
#     it before plugin loading runs.
target_link_libraries(gssh
    PRIVATE
        goodnet_kernel
        GoodNet::cpp
        GoodNet::protocol_gnet
        nlohmann_json::nlohmann_json
)

target_compile_definitions(gssh
    PRIVATE
        GOODNET_SSH_VERSION="0.1.0"
)

set_target_properties(gssh PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    OUTPUT_NAME "gssh"
)

# Operator-visible binary lands at `<prefix>/bin/gssh` so the
# wrap mode's ProxyCommand re-execs into the same path it was
# invoked with.
install(TARGETS gssh RUNTIME DESTINATION bin)
