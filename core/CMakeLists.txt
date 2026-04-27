# Kernel — minimal, plugin-driven, public-key addressed.

add_library(goodnet_kernel STATIC
    util/placeholder.cpp
)
add_library(GoodNet::kernel ALIAS goodnet_kernel)

target_include_directories(goodnet_kernel PUBLIC
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>"
)

target_link_libraries(goodnet_kernel
    PUBLIC
        GoodNet::sdk
        Boost::system
        Boost::thread
        spdlog::spdlog
        fmt::fmt
        nlohmann_json::nlohmann_json
        PkgConfig::SODIUM
)

target_compile_features(goodnet_kernel PUBLIC cxx_std_23)
