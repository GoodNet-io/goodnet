# Kernel — minimal, plugin-driven, public-key addressed.

add_library(goodnet_kernel STATIC
    util/placeholder.cpp
    config/config.cpp
    registry/connection.cpp
    registry/extension.cpp
    registry/handler.cpp
    registry/transport.cpp
    kernel/router.cpp
    kernel/kernel.cpp
    kernel/connection_context.cpp
    kernel/host_api_builder.cpp
    kernel/service_resolver.cpp
)
add_library(GoodNet::kernel ALIAS goodnet_kernel)

target_include_directories(goodnet_kernel PUBLIC
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>"
)

target_link_libraries(goodnet_kernel
    PUBLIC
        GoodNet::sdk
        Boost::thread
        spdlog::spdlog
        fmt::fmt
        nlohmann_json::nlohmann_json
        PkgConfig::SODIUM
)

target_compile_features(goodnet_kernel PUBLIC cxx_std_23)
