/**
 * @file   sdk/abi.h
 * @brief  ABI evolution helpers for the C plugin boundary.
 *
 * Macros and inline helpers that let plugins introspect a host vtable
 * for size-prefix evolution per `docs/contracts/abi-evolution.md`.
 */
#ifndef GOODNET_SDK_ABI_H
#define GOODNET_SDK_ABI_H

#include <stddef.h>

#include <sdk/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Plugin entry-point export macro ─────────────────────────────────────── */

/**
 * @brief Marks a symbol for export from a plugin shared object.
 *
 * Required on every `gn_plugin_*` entry. The kernel resolves these symbols
 * by name at `dlopen` time; missing or differently-named symbols cause the
 * plugin to be rejected before any state is constructed.
 */
#if defined(_WIN32)
  #define GN_PLUGIN_EXPORT __declspec(dllexport)
#elif defined(__GNUC__) || defined(__clang__)
  #define GN_PLUGIN_EXPORT __attribute__((visibility("default")))
#else
  #define GN_PLUGIN_EXPORT
#endif

/* ── Size-prefix vtable introspection ────────────────────────────────────── */

/**
 * @brief True when @p api is large enough to carry @p field.
 *
 * Vtables in the host-API family begin with `uint32_t api_size = sizeof(*api)`
 * at the producer's build time. A consumer compiled against a newer SDK that
 * adds a slot uses `GN_API_HAS` to gate calls into entries that the running
 * kernel may not implement.
 *
 * Usage:
 * @code
 *   if (GN_API_HAS(api, pin_handler)) {
 *       api->pin_handler(host_ctx, conn, handler_id);
 *   }
 * @endcode
 */
#define GN_API_HAS(api, field) \
    ((api) != NULL && \
     (api)->api_size >= (offsetof(__typeof__(*(api)), field) + sizeof((api)->field)))

/**
 * @brief Compile-time guard that @p T begins with `uint32_t api_size`.
 *
 * Every C ABI vtable in `sdk/` carries `api_size` as its first field
 * so a consumer can read the size byte-precisely without knowing the
 * rest of the struct's layout (`abi-evolution.md` §3). Place this at
 * file scope immediately after the struct's typedef so a rebase that
 * accidentally moves another field above `api_size` fails to compile.
 */
#ifdef __cplusplus
  #define GN_VTABLE_API_SIZE_FIRST(T) \
      static_assert(offsetof(T, api_size) == 0, \
                    #T " must begin with `uint32_t api_size` per abi-evolution.md §3")
#else
  #define GN_VTABLE_API_SIZE_FIRST(T) \
      _Static_assert(offsetof(T, api_size) == 0, \
                     #T " must begin with `uint32_t api_size` per abi-evolution.md §3")
#endif

/* ── Version comparison helpers ──────────────────────────────────────────── */

/**
 * @brief Pack the SDK version triple into a single uint32_t for ordered
 *        comparison.
 */
static inline uint32_t gn_version_pack(uint32_t major, uint32_t minor, uint32_t patch) {
    return (major << 24) | ((minor & 0xff) << 16) | (patch & 0xffff);
}

/**
 * @brief Returns nonzero if a plugin built at @p plugin_major.@p plugin_minor
 *        is loadable by a kernel at @p kernel_major.@p kernel_minor.
 *
 * Rule: major must match exactly; kernel minor must be >= plugin minor.
 * Patch is ignored.
 */
static inline int gn_version_compatible(uint32_t plugin_major, uint32_t plugin_minor,
                                        uint32_t kernel_major, uint32_t kernel_minor) {
    return plugin_major == kernel_major && kernel_minor >= plugin_minor;
}

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* GOODNET_SDK_ABI_H */
