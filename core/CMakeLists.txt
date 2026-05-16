# Kernel — minimal, plugin-driven, public-key addressed.
#
# Compiled once as a position-independent OBJECT library; emitted as
# both a STATIC archive (for hosts that link the kernel into their
# own binary) and a SHARED `.so` (for hosts that link the C ABI in
# `sdk/core.h` at runtime — Rust / Python / Go bindings, scripting
# embeds, hot-reload tools).

set(_goodnet_kernel_sources
    config/config.cpp
    identity/keypair.cpp
    identity/derive.cpp
    identity/attestation.cpp
    identity/node_identity.cpp
    identity/sub_key_registry.cpp
    identity/rotation.cpp
    kernel/capability_blob.cpp
    registry/connection.cpp
    registry/extension.cpp
    registry/handler.cpp
    registry/security.cpp
    registry/link.cpp
    registry/protocol_layer.cpp
    registry/send_queue.cpp
    security/session.cpp
    security/inline_crypto.cpp
    crypto/crypto_worker_pool.cpp
    kernel/router.cpp
    kernel/kernel.cpp
    kernel/core_c.cpp
    kernel/host_api_builder.cpp
    kernel/host_api/internal.cpp
    kernel/host_api/messaging.cpp
    kernel/host_api/identity.cpp
    kernel/host_api/control.cpp
    kernel/host_api/notifications.cpp
    kernel/service_resolver.cpp
    kernel/timer_registry.cpp
    kernel/attestation_dispatcher.cpp
    kernel/metrics_registry.cpp
    plugin/plugin_manager.cpp
    plugin/plugin_manifest.cpp
    plugin/wire_codec.cpp
    plugin/remote_host.cpp
    # Static-registry stub. Dynamic builds keep this empty array; the
    # static-linkage build replaces this TU with a generated one via
    # `cmake/StaticPlugins.cmake`.
    plugin/static_registry_default.cpp
    util/log.cpp
    util/log_config.cpp
)

# C ABI accessors for `gn_connection_context_t`. Lives separately so
# protocol-layer plugins (gnet, raw, future custom layers) link the
# accessors without dragging the entire kernel; `find_package(GoodNet)`
# exports `GoodNet::ctx_accessors` for out-of-tree consumers.
add_library(goodnet_ctx_accessors STATIC kernel/connection_context.cpp)
target_link_libraries(goodnet_ctx_accessors PUBLIC GoodNet::sdk)
target_include_directories(goodnet_ctx_accessors PUBLIC
    "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}>"
    "$<INSTALL_INTERFACE:include/goodnet>"
)
set_target_properties(goodnet_ctx_accessors PROPERTIES
    POSITION_INDEPENDENT_CODE ON
    EXPORT_NAME ctx_accessors
)
add_library(GoodNet::ctx_accessors ALIAS goodnet_ctx_accessors)
goodnet_apply_pch(goodnet_ctx_accessors)

add_library(goodnet_kernel_objects OBJECT ${_goodnet_kernel_sources})
set_target_properties(goodnet_kernel_objects PROPERTIES
    POSITION_INDEPENDENT_CODE ON
)

target_include_directories(goodnet_kernel_objects PUBLIC
    "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}>"
    "$<INSTALL_INTERFACE:include/goodnet>"
)

target_link_libraries(goodnet_kernel_objects
    PUBLIC
        GoodNet::sdk
        GoodNet::ctx_accessors
        Threads::Threads
        asio::asio
        spdlog::spdlog
        fmt::fmt
        nlohmann_json::nlohmann_json
        PkgConfig::SODIUM
        ${CMAKE_DL_LIBS}
)

# Windows: asio's IOCP backend needs `ws2_32` (WSAStartup/Cleanup,
# socket()/closesocket()) and `mswsock` (TransmitFile, AcceptEx).
# Without explicit links the linker errors on `__imp_WSAStartup`
# etc. PUBLIC so downstream binaries (the goodnet CLI) inherit
# the link line.
if(WIN32)
    target_link_libraries(goodnet_kernel_objects PUBLIC ws2_32 mswsock)
endif()

target_compile_features(goodnet_kernel_objects PUBLIC cxx_std_23)

# Precompiled-header umbrella for the asio / spdlog / fmt block plus
# the C++23 stdlib slices the kernel reaches everywhere. Single
# biggest clean-build win per `cmake/Pch.cmake`.
goodnet_apply_pch(goodnet_kernel_objects)

# ── STATIC variant ───────────────────────────────────────────────────────────
# Default for hosts that embed GoodNet through `find_package(GoodNet REQUIRED)`
# and link the kernel into their own binary at compile time.

add_library(goodnet_kernel STATIC $<TARGET_OBJECTS:goodnet_kernel_objects>)
target_link_libraries(goodnet_kernel PUBLIC goodnet_kernel_objects)
add_library(GoodNet::kernel ALIAS goodnet_kernel)
set_target_properties(goodnet_kernel PROPERTIES EXPORT_NAME kernel)

# ── SHARED variant ───────────────────────────────────────────────────────────
# For hosts that load the C ABI in `sdk/core.h` at runtime — non-C++
# bindings, scripting embeds, hot-reload tools. Same OBJECT library
# under the hood; one compile, two link variants.
#
# Windows: the SHARED .dll wants every referenced symbol resolved at
# link time, including `GnetProtocol::vtable` defined in
# `goodnet_protocol_gnet`. On the static-plugin Windows build the
# .dll has no consumer (the goodnet.exe binary links the STATIC
# kernel + protocol_gnet archive directly) — skip it so the link
# stage stays tractable. The shared-kernel hot-reload story is a
# Linux-only convenience today; Windows hot-reload waits on a
# proper named-pipe IPC port.
if(NOT WIN32)
    add_library(goodnet_kernel_shared SHARED $<TARGET_OBJECTS:goodnet_kernel_objects>)
    target_link_libraries(goodnet_kernel_shared PUBLIC goodnet_kernel_objects)
    set_target_properties(goodnet_kernel_shared PROPERTIES
        EXPORT_NAME  kernel_shared
        OUTPUT_NAME  goodnet_kernel
    )
    add_library(GoodNet::kernel_shared ALIAS goodnet_kernel_shared)

    install(TARGETS goodnet_kernel goodnet_kernel_shared goodnet_kernel_objects
                    goodnet_ctx_accessors
        EXPORT GoodNetTargets
        ARCHIVE
        LIBRARY
    )
else()
    install(TARGETS goodnet_kernel goodnet_kernel_objects
                    goodnet_ctx_accessors
        EXPORT GoodNetTargets
        ARCHIVE
    )
endif()

install(
    DIRECTORY   "${CMAKE_CURRENT_SOURCE_DIR}/"
    DESTINATION "include/goodnet/core"
    FILES_MATCHING
        PATTERN "*.h"
        PATTERN "*.hpp"
        PATTERN "CMakeLists.txt" EXCLUDE
)
