/**
 * @file   sdk/plugin.h
 * @brief  Plugin entry-point declarations.
 *
 * Every plugin shared object exports five C symbols, all with the
 * `gn_` prefix. The kernel resolves them by name at `dlopen` time;
 * missing symbols cause the plugin to be rejected before any state
 * is constructed.
 *
 * See `docs/contracts/plugin-lifetime.en.md`.
 */
#ifndef GOODNET_SDK_PLUGIN_H
#define GOODNET_SDK_PLUGIN_H

#include <stdint.h>

#include <sdk/types.h>
#include <sdk/abi.h>
#include <sdk/host_api.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Entry points ────────────────────────────────────────────────────────── */

/**
 * @brief Report the build-time SDK version triple. No side effects.
 *
 * Phase: 3 (version check).
 *
 * The kernel rejects the plugin if @p major does not equal the kernel's
 * SDK major, or if @p minor exceeds the kernel's minor.
 */
GN_PLUGIN_EXPORT void gn_plugin_sdk_version(uint32_t* out_major,
                                            uint32_t* out_minor,
                                            uint32_t* out_patch);

/**
 * @brief Construct internal state.
 *
 * Phase: 4 (init_all). Plugin allocates buffers, parses config, and
 * sets up internal state. **Must not** call any `host_api->register_*`
 * here — registration happens in @ref gn_plugin_register.
 *
 * @param api      @borrowed; valid until @ref gn_plugin_shutdown
 *                 returns. The kernel-supplied pointer carries
 *                 `api->host_ctx` already set; the plugin retains the
 *                 single `api*` pointer and reads `api->host_ctx`
 *                 wherever a vtable entry needs it.
 * @param out_self plugin-allocated state handle returned to the kernel.
 *
 * @return GN_OK on success; the kernel calls @ref gn_plugin_shutdown
 *         on failure to release any partial state.
 */
GN_PLUGIN_EXPORT gn_result_t gn_plugin_init(const host_api_t* api,
                                            void** out_self);

/**
 * @brief Install vtables into the kernel dispatch tables.
 *
 * Phase: 5 (register_all). Atomic with sibling plugins: if any
 * sibling fails, every successfully-registered descriptor is
 * `unregister`-ed before the kernel rolls back to phase 4 cleanup.
 */
GN_PLUGIN_EXPORT gn_result_t gn_plugin_register(void* self);

/**
 * @brief Remove every registration done in @ref gn_plugin_register.
 *
 * Phase: 8 (unregister_all). Mirror of register; the kernel calls this
 * before quiescence wait, so dispatchers in flight may still resolve
 * a handler whose `unregister` returned. After quiescence the kernel
 * calls @ref gn_plugin_shutdown.
 */
GN_PLUGIN_EXPORT gn_result_t gn_plugin_unregister(void* self);

/**
 * @brief Release plugin-owned resources.
 *
 * Phase: 9 (shutdown_all). After return the plugin **must not** call
 * `host_api`. The kernel may call `dlclose` on the shared object
 * immediately afterwards.
 */
GN_PLUGIN_EXPORT void gn_plugin_shutdown(void* self);

/* ── Plugin descriptor ───────────────────────────────────────────────────── */

/**
 * @brief Plugin role declared in the descriptor.
 *
 * The kernel splits its host-API surface by role: only `Transport`
 * plugins may invoke the loader-side `notify_connect` /
 * `notify_inbound_bytes` / `notify_disconnect` / `kick_handshake`
 * entries; calls from other roles are rejected. `Unknown` is
 * permissive (treated as no-gate) for backward-compat with plugins
 * built against the v1.1 descriptor that did not carry the field.
 */
typedef enum gn_plugin_kind_e {
    GN_PLUGIN_KIND_UNKNOWN   = 0,
    GN_PLUGIN_KIND_LINK = 1,
    GN_PLUGIN_KIND_HANDLER   = 2,
    GN_PLUGIN_KIND_SECURITY  = 3,
    GN_PLUGIN_KIND_PROTOCOL  = 4,
    GN_PLUGIN_KIND_BRIDGE    = 5
} gn_plugin_kind_t;

/**
 * @brief Static metadata declared inside the plugin shared object.
 *
 * Read by the kernel through a sixth, optional, exported symbol
 * `gn_plugin_descriptor`. When present, it lets the kernel order load
 * by service-graph dependencies and decide hot-reload eligibility
 * before constructing any state.
 */
typedef struct gn_plugin_descriptor_s {
    const char* name;             /**< stable identifier; e.g. `"libgoodnet_tcp"` */
    const char* version;          /**< human-readable, e.g. `"0.1.0"` */

    int hot_reload_safe;          /**< 1 if `unregister`/`shutdown`/`init` cycle is supported */

    /** Null-terminated arrays of extension names this plugin requires/provides. */
    const char* const* ext_requires;
    const char* const* ext_provides;

    /** Plugin role; gates loader-side host_api entries. */
    gn_plugin_kind_t kind;

    void* _reserved[4];
} gn_plugin_descriptor_t;

/**
 * @brief Optional accessor for static plugin metadata.
 *
 * Kernel resolves this symbol after `gn_plugin_sdk_version` and uses
 * the returned pointer to drive the dependency toposort.
 */
GN_PLUGIN_EXPORT const gn_plugin_descriptor_t* gn_plugin_descriptor(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* GOODNET_SDK_PLUGIN_H */
