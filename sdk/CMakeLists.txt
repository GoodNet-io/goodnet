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

# ── Install ──────────────────────────────────────────────────────────────────
# `find_package(GoodNet REQUIRED)` after `make install` exposes
# `GoodNet::sdk` as the C ABI header-only target. Plugins outside this tree
# link against it, never against the kernel — the kernel side stays MIT/GPL
# split per the linker exception in the top-level LICENSE.
install(TARGETS goodnet_sdk EXPORT GoodNetTargets)

install(
    DIRECTORY   "${CMAKE_CURRENT_SOURCE_DIR}/"
    DESTINATION "include/sdk"
    FILES_MATCHING
        PATTERN "*.h"
        PATTERN "*.hpp"
        PATTERN "CMakeLists.txt" EXCLUDE
)
