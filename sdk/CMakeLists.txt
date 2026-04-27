# SDK is the public boundary: C ABI headers and C++ wrappers.
# Header-only INTERFACE target — consumers link without producing object files.

add_library(goodnet_sdk INTERFACE)
add_library(GoodNet::sdk ALIAS goodnet_sdk)

target_include_directories(goodnet_sdk INTERFACE
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>"
    "$<INSTALL_INTERFACE:include>"
)

target_compile_features(goodnet_sdk INTERFACE cxx_std_23)
