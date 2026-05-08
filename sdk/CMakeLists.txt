# SDK is the public boundary: C ABI headers and C++ wrappers.
# Header-only INTERFACE target — consumers link without producing object files.
#
# In-tree code writes `#include <sdk/types.h>` against the source tree
# (BUILD_INTERFACE is `${PROJECT_SOURCE_DIR}`). Out-of-tree plugins
# consume the same headers under the FHS-friendly install layout
# `<prefix>/include/goodnet/sdk/types.h` and write
# `#include <goodnet/sdk/types.h>` so the plain `sdk/` prefix on the
# installed FS does not collide with unrelated SDK packages.

add_library(goodnet_sdk INTERFACE)
add_library(GoodNet::sdk ALIAS goodnet_sdk)
set_target_properties(goodnet_sdk PROPERTIES EXPORT_NAME sdk)

target_include_directories(goodnet_sdk INTERFACE
    "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}>"
    "$<INSTALL_INTERFACE:include/goodnet>"
)

target_compile_features(goodnet_sdk INTERFACE cxx_std_23)

# ── Install ──────────────────────────────────────────────────────────────────
# `find_package(GoodNet REQUIRED)` after `make install` exposes
# `GoodNet::sdk` as the C ABI header-only target. Plugins outside this tree
# link against it, never against the kernel — the kernel side stays GPL
# with the linker exception per the top-level LICENSE.
install(TARGETS goodnet_sdk EXPORT GoodNetTargets)

install(
    DIRECTORY   "${CMAKE_CURRENT_SOURCE_DIR}/"
    DESTINATION "include/goodnet/sdk"
    FILES_MATCHING
        PATTERN "*.h"
        PATTERN "*.hpp"
        PATTERN "CMakeLists.txt" EXCLUDE
)
