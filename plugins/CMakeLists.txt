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
# The gnet mesh-framing protocol (plugins/protocols/gnet) has been
# extracted to GoodNet-io/protocol-gnet; it is consumed as an
# external plugin and is not bundled in this tree.
#
# Windows MVP (mingw cross-build) currently skips plugins that need
# OpenSSL mingw (TLS, QUIC, WS) or rely on POSIX-only resolver
# subsystems (handler/dns via c-ares). ICE and store/strategies stay
# off the first cut until their CI smoke is wired. The lean Windows
# bundle is kernel + Noise + Null + TCP + UDP + IPC + Heartbeat;
# the rest will lift in a follow-up cut once each plugin's mingw
# build is verified.
set(_GOODNET_WINDOWS_SKIP FALSE)
if(WIN32)
    set(_GOODNET_WINDOWS_SKIP TRUE)
endif()

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/security/null/CMakeLists.txt")
    add_subdirectory(security/null)
endif()

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/security/noise/CMakeLists.txt")
    add_subdirectory(security/noise)
endif()

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/security/pkcs11/CMakeLists.txt")
    # PKCS#11 plugin needs `p11-kit-1` (pkg-config); skip silently
    # when the devShell / sysroot doesn't carry it so vanilla `nix
    # develop` shells (which don't pull p11-kit yet) still configure.
    find_package(PkgConfig QUIET)
    if(PKG_CONFIG_FOUND)
        pkg_check_modules(_GOODNET_HAVE_P11_KIT QUIET p11-kit-1)
    endif()
    if(_GOODNET_HAVE_P11_KIT_FOUND)
        add_subdirectory(security/pkcs11)
    else()
        message(STATUS "Skipping plugins/security/pkcs11: p11-kit-1 not found")
    endif()
endif()

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/links/tcp/CMakeLists.txt")
    add_subdirectory(links/tcp)
endif()

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/handlers/heartbeat/CMakeLists.txt")
    add_subdirectory(handlers/heartbeat)
endif()

if(NOT _GOODNET_WINDOWS_SKIP
   AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/handlers/store/CMakeLists.txt")
    add_subdirectory(handlers/store)
endif()

if(NOT _GOODNET_WINDOWS_SKIP
   AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/handlers/dns/CMakeLists.txt")
    add_subdirectory(handlers/dns)
endif()

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/handlers/web_api_proxy/CMakeLists.txt")
    add_subdirectory(handlers/web_api_proxy)
endif()

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/links/ipc/CMakeLists.txt")
    add_subdirectory(links/ipc)
endif()

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/links/raw_inject/CMakeLists.txt")
    # raw_inject plugin needs `libzstd` (pkg-config); skip silently
    # when the kernel's base devShell / sysroot doesn't carry it so
    # top-level unified development builds still configure.
    find_package(PkgConfig QUIET)
    if(PKG_CONFIG_FOUND)
        pkg_check_modules(_GOODNET_HAVE_ZSTD QUIET libzstd)
    endif()
    if(_GOODNET_HAVE_ZSTD_FOUND)
        add_subdirectory(links/raw_inject)
    else()
        message(STATUS "Skipping plugins/links/raw_inject: libzstd not found")
    endif()
endif()

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/links/udp/CMakeLists.txt")
    add_subdirectory(links/udp)
endif()

if(NOT _GOODNET_WINDOWS_SKIP
   AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/links/tls/CMakeLists.txt")
    add_subdirectory(links/tls)
endif()

# WS comes after TLS so the WS test fixture's optional `wss://` slice
# can see `goodnet_tls_objects` as a CMake target at conditional time.
if(NOT _GOODNET_WINDOWS_SKIP
   AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/links/ws/CMakeLists.txt")
    add_subdirectory(links/ws)
endif()

# ws_inject after ws: composes over gn.link.ws carrier.
if(NOT _GOODNET_WINDOWS_SKIP
   AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/links/ws_inject/CMakeLists.txt")
    add_subdirectory(links/ws_inject)
endif()

# ICE before QUIC so that QUIC's `test_quic` fixture (which now
# integrates an `IceCarrierBridge` for the `quic://<peer-pk-hex>`
# route per Q.1) sees `goodnet_ice_objects` at conditional time.
if(NOT _GOODNET_WINDOWS_SKIP
   AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/links/ice/CMakeLists.txt")
    add_subdirectory(links/ice)
endif()

# QUIC requires OpenSSL 3.6+ for OSSL_QUIC_*_method + SSL_new_listener
# (the server side landed in 3.6 — see plugins/links/quic/CMakeLists.txt
# for the exact API set the plugin uses); the build fails at compile
# time on older OpenSSL. Kept after udp/tls/ice so its composer test
# fixture can see all three carrier object libraries.
if(NOT _GOODNET_WINDOWS_SKIP
   AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/links/quic/CMakeLists.txt")
    add_subdirectory(links/quic)
endif()

# PortMap surfaces the `gn.link.portmap` extension (NAT-PMP / PCP /
# UPnP IGD) consumed by ICE before host-candidate gathering. Added
# before strategies so the in-tree ICE composer fixture can resolve
# the extension at conditional time when the integration tests link
# it.
if(NOT _GOODNET_WINDOWS_SKIP
   AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/links/portmap/CMakeLists.txt")
    add_subdirectory(links/portmap)
endif()

# Strategy plugins consume `sdk/extensions/strategy.h`.
# FloatSendRtt is the reference implementation — picks min-RTT
# conn with hysteresis. Added after every L1 link so its tests can
# build synthetic candidate sets representing real link surfaces.
if(NOT _GOODNET_WINDOWS_SKIP
   AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/strategies/float_send_rtt/CMakeLists.txt")
    add_subdirectory(strategies/float_send_rtt)
endif()

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/protocols/gnet/CMakeLists.txt")
    add_subdirectory(protocols/gnet)
endif()

# Subprocess workers — separate executables (not `.so` plugins) that
# the kernel spawns over `sdk/remote/wire.h`. Tracked under
# `plugins/workers/` so they ride the same `add_subdirectory` walk as
# in-tree dlopen plugins. The `remote_echo` proof binary ships in-tree
# so the kernel↔worker round trip has a stable integration smoke
# without pulling a separate repo. Real workers live in their own gits
# the same way handlers/links/security plugins do.
if(NOT _GOODNET_WINDOWS_SKIP
   AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/workers/CMakeLists.txt")
    add_subdirectory(workers)
endif()
