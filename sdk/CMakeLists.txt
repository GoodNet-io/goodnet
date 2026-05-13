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

# ── Subprocess plugin worker stub ────────────────────────────────────────────
# Static library a worker binary links to inherit the wire-protocol
# reader loop + synthetic host_api. Mirrors the kernel-side
# `core/plugin/remote_host.cpp` from the worker side. Reuses the CBOR
# codec by adding `core/plugin/wire_codec.cpp` as a source — the same
# code compiles into the kernel and the worker stub.
add_library(goodnet_remote_plugin_stub STATIC
    cpp/remote_plugin.cpp
    "${PROJECT_SOURCE_DIR}/core/plugin/wire_codec.cpp"
)
add_library(GoodNet::remote_plugin_stub ALIAS goodnet_remote_plugin_stub)
set_target_properties(goodnet_remote_plugin_stub PROPERTIES
    POSITION_INDEPENDENT_CODE ON
    EXPORT_NAME remote_plugin_stub
)
target_include_directories(goodnet_remote_plugin_stub PUBLIC
    "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}>"
    "$<INSTALL_INTERFACE:include/goodnet>"
)
target_link_libraries(goodnet_remote_plugin_stub PUBLIC GoodNet::sdk)
target_compile_features(goodnet_remote_plugin_stub PUBLIC cxx_std_23)

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
