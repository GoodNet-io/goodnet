/// @file   core/plugin/static_registry.hpp
/// @brief  Registry table for plugins linked statically into the
///         kernel binary (`-DGOODNET_STATIC_PLUGINS=ON`).
///
/// Under static linkage every bundled plugin's entry symbols are
/// suffixed with the plugin's stem (`gn_plugin_init_link_tcp`,
/// `gn_plugin_init_handler_heartbeat`, …) so they don't collide at
/// link time. The CMake helper `goodnet_register_static_plugins`
/// (`cmake/StaticPlugins.cmake`) generates a translation unit
/// `static_plugins.cpp` that gathers each plugin's entry pointers
/// into the array declared here.
///
/// The array is plain C ABI on purpose — the suffixed entry names
/// stay reachable from Python ctypes / Rust FFI / Zig bindings
/// that embed the kernel statically; the cross-language plugin
/// promise survives both linkage modes.

#pragma once

#include <sdk/host_api.h>
#include <sdk/plugin.h>
#include <sdk/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/// One row in the static registry. Mirrors the five entry-point
/// signatures from `sdk/plugin.h` plus the optional descriptor.
/// A row with `name == NULL` is the sentinel.
typedef struct gn_plugin_static_entry_s {
    const char* name;          /**< plugin stem ("link_tcp", etc.) */
    void  (*sdk_version)(uint32_t* major, uint32_t* minor,
                         uint32_t* patch);
    gn_result_t (*init)(const host_api_t* api, void** out_self);
    gn_result_t (*reg)(void* self);
    gn_result_t (*unreg)(void* self);
    void  (*shutdown)(void* self);
    const gn_plugin_descriptor_t* (*descriptor)(void);
} gn_plugin_static_entry_t;

/// Null-terminated registry of every statically-linked plugin.
/// Defined by the generated `static_plugins.cpp` when the build is
/// configured with `-DGOODNET_STATIC_PLUGINS=ON`; otherwise the
/// dynamic-linkage build provides a weak empty stub below so the
/// kernel can probe the array unconditionally.
extern const gn_plugin_static_entry_t gn_plugin_static_registry[];

#ifdef __cplusplus
} // extern "C"
#endif
