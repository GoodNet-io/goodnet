/// @file   core/plugin/static_registry_default.cpp
/// @brief  Empty static-plugin registry used by dynamic-linkage
///         builds. `-DGOODNET_STATIC_PLUGINS=ON` swaps this TU out
///         for the generated `static_plugins.cpp` (see
///         `cmake/StaticPlugins.cmake`), which fills the array with
///         each bundled plugin's entry pointers.

#include <core/plugin/static_registry.hpp>

extern "C" const gn_plugin_static_entry_t gn_plugin_static_registry[] = {
    { /* sentinel */ nullptr, nullptr, nullptr, nullptr,
      nullptr, nullptr, nullptr },
};
