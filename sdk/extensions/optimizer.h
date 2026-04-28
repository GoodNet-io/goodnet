/**
 * @file   sdk/extensions/optimizer.h
 * @brief  Path-optimiser plugin extension surface.
 *
 * Plugins that own a single path-optimisation strategy
 * (transport-failover, relay-upgrade, ICE, autonat, …) register a
 * `gn_optimizer_api_t` vtable under
 * `"gn.optimizer." + name`. The kernel's `PathManager` walks every
 * registered optimiser in priority order on each connection event
 * and applies the first non-empty recommendation. Per
 * `docs/contracts/optimizer.md`.
 */
#ifndef GOODNET_SDK_EXTENSIONS_OPTIMIZER_H
#define GOODNET_SDK_EXTENSIONS_OPTIMIZER_H

#include <stddef.h>
#include <stdint.h>

#include <sdk/conn_events.h>
#include <sdk/endpoint.h>
#include <sdk/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Naming convention prefix. The full extension identifier is
 *        `"gn.optimizer." + name`, lowercase, kebab-case suffix.
 */
#define GN_EXT_OPTIMIZER_PREFIX "gn.optimizer."

/** v1.0.0 — initial release. */
#define GN_EXT_OPTIMIZER_VERSION 0x00010000u

/**
 * @brief How the kernel applies a recommendation produced by
 *        `gn_optimizer_api_t::recommend`.
 */
typedef enum gn_optimizer_strategy_e {
    /** Replace the current connection's transport with the new one;
        graceful drain on the old socket, fresh handshake on the new. */
    GN_OPT_REPLACE  = 0,
    /** Add the recommended transport as a parallel path; the
        `PathManager` may steer subsequent sends across both. */
    GN_OPT_ADD_PATH = 1,
    /** Drop the current connection. Used by autonat / ICE when the
        peer is concluded unreachable across every candidate path. */
    GN_OPT_DROP     = 2,
} gn_optimizer_strategy_t;

/**
 * @brief Recommendation produced by an optimiser. Filled by
 *        `recommend`; consumed by the kernel's `PathManager`.
 */
typedef struct gn_optimizer_recommendation_s {
    gn_optimizer_strategy_t strategy;
    /** Target URI for `Replace` / `AddPath`; ignored for `Drop`. The
        URI must be canonicalised per `uri.md` §4. */
    char target_uri[GN_ENDPOINT_URI_MAX];
    /** Target transport scheme for `Replace` / `AddPath`. The kernel
        resolves the vtable through `find_by_scheme` per
        `transport.md` §6. */
    char target_scheme[16];

    uint64_t _reserved[8];
} gn_optimizer_recommendation_t;

/**
 * @brief Optimiser vtable. One per registered strategy.
 *
 * `priority` is consulted at registration time only; the kernel
 * caches the priority alongside the vtable. Lower priority runs
 * earlier; ties broken by registration order.
 *
 * Lifetime: every entry executes under the calling plugin's
 * quiescence anchor (`plugin-lifetime.md` §4); a plugin that has
 * begun unloading sees `recommend` and `on_event` dropped silently.
 */
typedef struct gn_optimizer_api_s {
    uint32_t api_size;
    uint32_t priority;

    /**
     * @brief Produce a recommendation for @p conn.
     *
     * @return @ref GN_OK on a populated @p out;
     *         @ref GN_ERR_NOT_IMPLEMENTED when the optimiser has
     *         nothing to say on this connection;
     *         @ref GN_ERR_LIMIT_REACHED when the strategy declines
     *         responsibility (e.g. the conn already runs the
     *         recommended transport).
     */
    gn_result_t (*recommend)(void* ctx,
                              gn_conn_id_t conn,
                              gn_optimizer_recommendation_t* out);

    /**
     * @brief Receive a per-conn event the optimiser subscribed to.
     *        @p ev is borrowed for the duration of the call; the
     *        optimiser must copy if it needs to retain past return.
     */
    void (*on_event)(void* ctx, const gn_conn_event_t* ev);

    /**
     * @brief Bitmask of `1u << GN_CONN_EVENT_*` values the optimiser
     *        wants on `on_event`. Read once at registration, treated
     *        as static for the optimiser's lifetime.
     */
    uint32_t subscribed_events;

    void* _reserved[8];
} gn_optimizer_api_t;

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* GOODNET_SDK_EXTENSIONS_OPTIMIZER_H */
