# Plugins are independent builds. Each plugin has its own CMakeLists,
# its own license, and — in production — its own Nix derivation. The
# kernel binary loads them at runtime through the stable C ABI.
#
# This file is iterated only when the root option GOODNET_BUILD_BUNDLED_PLUGINS
# is ON, as a development convenience. Outside that flag, plugins build
# standalone via:
#
#     find_package(GoodNet REQUIRED)
#     # ... implements ITransport / IHandler / ISecurityProvider / etc.
#
# The mandatory mesh-framing plugin (plugins/protocols/gnet) is added
# directly from the root CMakeLists because the kernel statically links
# it and ships it as part of the platform binary.

# Subdirectories are registered as bundled plugins land:
#
#   if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/transports/tcp/CMakeLists.txt")
#       add_subdirectory(transports/tcp)
#   endif()
#   ... etc.
