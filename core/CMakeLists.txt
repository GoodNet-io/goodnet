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
    registry/transport.cpp
    security/session.cpp
    kernel/router.cpp
    kernel/kernel.cpp
    kernel/connection_context.cpp
    kernel/host_api_builder.cpp
    kernel/service_resolver.cpp
    kernel/timer_registry.cpp
    kernel/attestation_dispatcher.cpp
    plugin/plugin_manager.cpp
    plugin/plugin_manifest.cpp
)
add_library(GoodNet::kernel ALIAS goodnet_kernel)

target_include_directories(goodnet_kernel PUBLIC
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>"
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
