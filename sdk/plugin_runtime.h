/**
 * @file   sdk/plugin_runtime.h
 * @brief  C ABI for registering an external plugin runtime kind.
 *
 * Mirrors the kernel-private `IPluginRuntime` C++ interface in
 * `core/plugin/runtimes/`. A host that wants to load plugins under a
 * new linkage kind (e.g. `wasm-plugin`, `wasmtime-sandbox`, `ebpf`,
 * `jvm-bridge`) implements the vtable below and registers it once via
 * `gn_core_register_runtime` from `sdk/core.h`.
 *
 * The kernel ships built-in runtimes under the reserved kinds
 * `"static"`, `"dynamic"`, and `"remote"`. Custom kinds layer on top
 * without touching kernel source — the same dispatch path
 * (`PluginManager::open_one` → `runtime->load` → init → register →
 * unregister → close) runs against the C-vtable adapter just as it
 * does against the built-in C++ runtimes.
 *
 * The vtable shape is `api_size`-versioned per
 * `docs/contracts/abi-evolution.en.md` §3. New thunks can be appended
 * without breaking existing host registrations; older hosts pass a
 * smaller `api_size` and the kernel skips the trailing thunks.
 *
 * Thread model: every vtable thunk is called from the kernel thread
 * that issued the corresponding `PluginManager` method. The runtime
 * itself must be thread-safe on its own internal state — concurrent
 * `gn_core_load_plugins_batch` calls dispatch into the same vtable
 * from multiple manager threads.
 */
#ifndef GOODNET_SDK_PLUGIN_RUNTIME_H
#define GOODNET_SDK_PLUGIN_RUNTIME_H

#include <stddef.h>
#include <stdint.h>

#include <sdk/abi.h>
#include <sdk/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Opaque handle ───────────────────────────────────────────────────────── */

/**
 * @brief Opaque per-plugin handle minted by a custom runtime.
 *
 * The runtime returns a unique non-zero `gn_plugin_instance_t` from
 * its `register_plugin` thunk; the kernel hands the same value back
 * when calling `unregister` so the runtime can address the right
 * plugin from its own bookkeeping. The handle is opaque to the
 * kernel — any non-zero `uint32_t` the runtime can map back to its
 * internal record works.
 *
 * Lifetime: from `register_plugin` thunk return until the matching
 * `unregister` thunk call returns. The kernel never dereferences the
 * value; it only stores and replays it.
 */
typedef uint32_t gn_plugin_instance_t;

/** Sentinel for "no instance" — returned on load failure. */
#define GN_PLUGIN_INSTANCE_INVALID ((gn_plugin_instance_t)0)

/* ── Vtable ─────────────────────────────────────────────────────────────── */

/**
 * @brief Vtable a custom runtime exposes to the kernel.
 *
 * Begins with `api_size` for size-prefix evolution per
 * `abi-evolution.en.md` §3. The kernel reads up to `api_size` bytes
 * from the vtable, ignoring fields beyond; a newer SDK that appends
 * a thunk leaves older host registrations working without recompile.
 *
 * Every method receives the `void* ctx` that the host handed to
 * `gn_core_register_runtime`. The runtime owns the lifetime of `ctx`;
 * the kernel never dereferences it.
 *
 * @par Mapping onto the kernel's `IPluginRuntime`
 * The C++-side interface has six lifecycle methods (load, init,
 * register_plugin, unregister, shutdown, close). The C ABI collapses
 * them to four for the foreign-runtime case: load / init /
 * register_plugin become the single `register_plugin` thunk because a
 * non-`dlopen` runtime (Wasm, sandbox bridge, JVM proxy) has no
 * meaningful distinction between «open the artefact» and «activate
 * its handlers»; unregister / shutdown / close collapse into the
 * single `unregister` thunk for the same reason. Built-in runtimes
 * (`DynamicRuntime`, `StaticRuntime`, `RemoteRuntime`) keep the
 * fine-grained split because their underlying mechanisms (dlopen,
 * subprocess) need it.
 */
typedef struct gn_plugin_runtime_vtable_s {
    /** sizeof(gn_plugin_runtime_vtable_t) at producer build time. */
    size_t api_size;

    /**
     * @brief Runtime-level setup. Called once when the kernel
     *        registers this vtable through `gn_core_register_runtime`.
     *
     * Optional — pass NULL to skip. A non-`GN_OK` return rolls back
     * the registration; the kernel does not retain the vtable in
     * that case.
     */
    gn_result_t (*init)(void* ctx);

    /**
     * @brief Load a single plugin manifest entry under this runtime.
     *
     * @param ctx          The `ctx` passed to `gn_core_register_runtime`.
     * @param entry_name   @borrowed canonical plugin name from the
     *                     manifest entry. NUL-terminated; the kernel
     *                     does not retain the pointer past return.
     * @param entry_path   @borrowed resource reference. File path for
     *                     dynamic, `static://<name>` label for static,
     *                     URI for remote, JS callback id for
     *                     `wasm-plugin`, etc.
     * @param out_instance Out-parameter — the runtime writes a unique
     *                     non-zero `gn_plugin_instance_t` it can use
     *                     to address the plugin from its own state on
     *                     subsequent `unregister` calls. Leave at
     *                     `GN_PLUGIN_INSTANCE_INVALID` on failure.
     *
     * @return `GN_OK` on success; any error code on failure (the
     *         kernel surfaces it through the manager's load
     *         diagnostic).
     */
    gn_result_t (*register_plugin)(void*                  ctx,
                                   const char*            entry_name,
                                   const char*            entry_path,
                                   gn_plugin_instance_t*  out_instance);

    /**
     * @brief Unload a previously-registered plugin. The handle is the
     *        value the runtime returned from `register_plugin`.
     *
     * Called once during the kernel's teardown chain
     * (`PluginManager::rollback` or `unload(name)`). Best-effort — the
     * kernel does not require a `GN_OK` to continue teardown, but the
     * value surfaces through diagnostics.
     */
    gn_result_t (*unregister)(void*                ctx,
                              gn_plugin_instance_t instance);

    /**
     * @brief Runtime-level teardown. Called once when the kernel is
     *        shutting down or this runtime is being unregistered.
     *        The runtime should release any global resources here.
     *
     * Optional — pass NULL to skip.
     */
    gn_result_t (*shutdown)(void* ctx);
} gn_plugin_runtime_vtable_t;

GN_VTABLE_API_SIZE_FIRST(gn_plugin_runtime_vtable_t);

/**
 * @brief Minimum `api_size` the kernel accepts on `gn_core_register_runtime`.
 *
 * The kernel reads at least the `api_size` field plus the four base
 * thunks (`init`, `register_plugin`, `unregister`, `shutdown`); a
 * smaller value means the vtable is older than any kernel that ships
 * this header and the registration fails with
 * `GN_ERR_VERSION_MISMATCH`.
 */
#define GN_PLUGIN_RUNTIME_VTABLE_MIN_SIZE \
    (offsetof(gn_plugin_runtime_vtable_t, shutdown) + \
     sizeof(((gn_plugin_runtime_vtable_t*)0)->shutdown))

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* GOODNET_SDK_PLUGIN_RUNTIME_H */
