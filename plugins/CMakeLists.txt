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

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/handlers/store/CMakeLists.txt")
    add_subdirectory(handlers/store)
endif()

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/links/ipc/CMakeLists.txt")
    add_subdirectory(links/ipc)
endif()

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/links/udp/CMakeLists.txt")
    add_subdirectory(links/udp)
endif()

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/links/tls/CMakeLists.txt")
    add_subdirectory(links/tls)
endif()

# WS comes after TLS so the WS test fixture's optional `wss://` slice
# can see `goodnet_tls_objects` as a CMake target at conditional time.
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/links/ws/CMakeLists.txt")
    add_subdirectory(links/ws)
endif()

# ICE before QUIC so that QUIC's `test_quic` fixture (which now
# integrates an `IceCarrierBridge` for the `quic://<peer-pk-hex>`
# route per Q.1) sees `goodnet_ice_objects` at conditional time.
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/links/ice/CMakeLists.txt")
    add_subdirectory(links/ice)
endif()

# QUIC requires OpenSSL 3.5+ for OSSL_QUIC_*_method; the build will
# fail at compile time on older OpenSSL — kept after udp/tls/ice so
# its composer test fixture can see all three carrier object libraries.
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/links/quic/CMakeLists.txt")
    add_subdirectory(links/quic)
endif()

# Strategy plugins consume `sdk/extensions/strategy.h` (Слайс 9-SDK).
# FloatSendRtt is the reference implementation — picks min-RTT
# conn with hysteresis. Added after every L1 link so its tests can
# build synthetic candidate sets representing real link surfaces.
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/strategies/float_send_rtt/CMakeLists.txt")
    add_subdirectory(strategies/float_send_rtt)
endif()

# Subprocess workers — separate executables (not `.so` plugins) that
# the kernel spawns over `sdk/remote/wire.h`. Tracked under
# `plugins/workers/` so they ride the same `add_subdirectory` walk as
# in-tree dlopen plugins. The `remote_echo` proof binary ships in-tree
# so the kernel↔worker round trip has a stable integration smoke
# without pulling a separate repo. Real workers live in their own gits
# the same way handlers/links/security plugins do.
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/workers/CMakeLists.txt")
    add_subdirectory(workers)
endif()
