# SDK is the public boundary: C ABI headers and C++ wrappers.
# Header-only INTERFACE target — consumers link without producing object files.
#
# Include style: paths are namespaced under sdk/, so kernel and plugins
# write `#include <sdk/types.h>` and `#include <sdk/cpp/handler.hpp>`.

add_library(goodnet_sdk INTERFACE)
add_library(GoodNet::sdk ALIAS goodnet_sdk)
set_target_properties(goodnet_sdk PROPERTIES EXPORT_NAME sdk)

target_include_directories(goodnet_sdk INTERFACE
    "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}>"
    "$<INSTALL_INTERFACE:include>"
)

target_compile_features(goodnet_sdk INTERFACE cxx_std_23)
