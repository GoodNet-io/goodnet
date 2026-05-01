# Plugins are independent builds. Each plugin has its own CMakeLists,
# its own license, and — in production — its own Nix derivation. The
# kernel binary loads them at runtime through the stable C ABI.
#
# Bundled in-tree plugins under this directory use the `add_plugin()`
# macro from `cmake/AddPlugin.cmake` (auto-included from the root
# CMakeLists). A typical bundled plugin's CMakeLists is one line:
#
#     add_plugin(my_handler my_handler.cpp helpers.cpp)
#
# The macro covers SHARED-by-default with PREFIX/visibility/warnings/
# size-flags/SDK link, and switches to OBJECT under
# `-DGOODNET_STATIC_PLUGINS=ON` for embedded or test builds.
#
# This file is iterated only when the root option
# `GOODNET_BUILD_BUNDLED_PLUGINS` is ON, as a development convenience.
# Outside that flag, plugins build standalone via:
#
#     find_package(GoodNet REQUIRED)
#     # ... include plugins/helper.cmake or define the target manually
#
# The mandatory mesh-framing plugin (plugins/protocols/gnet) is added
# directly from the root CMakeLists; it links statically into the
# kernel binary and is not a `dlopen`-able plugin.

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/security/null/CMakeLists.txt")
    add_subdirectory(security/null)
endif()

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/security/noise/CMakeLists.txt")
    add_subdirectory(security/noise)
endif()

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/links/tcp/CMakeLists.txt")
    add_subdirectory(links/tcp)
endif()

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/handlers/heartbeat/CMakeLists.txt")
    add_subdirectory(handlers/heartbeat)
endif()

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/links/ipc/CMakeLists.txt")
    add_subdirectory(links/ipc)
endif()

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/links/udp/CMakeLists.txt")
    add_subdirectory(links/udp)
endif()

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/links/ws/CMakeLists.txt")
    add_subdirectory(links/ws)
endif()

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/links/tls/CMakeLists.txt")
    add_subdirectory(links/tls)
endif()
