# Kernel — minimal, plugin-driven, public-key addressed.

add_library(goodnet_kernel STATIC
    config/config.cpp
    identity/keypair.cpp
    identity/derive.cpp
    identity/attestation.cpp
    identity/node_identity.cpp
    registry/connection.cpp
    registry/extension.cpp
    registry/handler.cpp
    registry/security.cpp
    registry/link.cpp
    security/session.cpp
    kernel/router.cpp
    kernel/kernel.cpp
    kernel/connection_context.cpp
    kernel/host_api_builder.cpp
    kernel/service_resolver.cpp
    kernel/timer_registry.cpp
    kernel/attestation_dispatcher.cpp
    kernel/metrics_registry.cpp
    plugin/plugin_manager.cpp
    plugin/plugin_manifest.cpp
    util/log.cpp
)
add_library(GoodNet::kernel ALIAS goodnet_kernel)
set_target_properties(goodnet_kernel PROPERTIES EXPORT_NAME kernel)

target_include_directories(goodnet_kernel PUBLIC
    "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}>"
    "$<INSTALL_INTERFACE:include/goodnet>"
)

target_link_libraries(goodnet_kernel
    PUBLIC
        GoodNet::sdk
        Threads::Threads
        asio::asio
        spdlog::spdlog
        fmt::fmt
        nlohmann_json::nlohmann_json
        PkgConfig::SODIUM
        ${CMAKE_DL_LIBS}
)

target_compile_features(goodnet_kernel PUBLIC cxx_std_23)

# Precompiled-header umbrella for the asio / spdlog / fmt block plus
# the C++23 stdlib slices the kernel reaches everywhere. Single
# biggest clean-build win per `cmake/Pch.cmake`.
goodnet_apply_pch(goodnet_kernel)

# ── Install ──────────────────────────────────────────────────────────────────
# Hosts that embed GoodNet through `find_package(GoodNet REQUIRED)` link
# against `GoodNet::kernel`. Plugins outside this tree usually need only
# `GoodNet::sdk`; the kernel target is for the host binary that owns the
# kernel instance.
install(TARGETS goodnet_kernel EXPORT GoodNetTargets ARCHIVE)

install(
    DIRECTORY   "${CMAKE_CURRENT_SOURCE_DIR}/"
    DESTINATION "include/goodnet/core"
    FILES_MATCHING
        PATTERN "*.h"
        PATTERN "*.hpp"
        PATTERN "CMakeLists.txt" EXCLUDE
)
