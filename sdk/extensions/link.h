/**
 * @file   sdk/extensions/link.h
 * @brief  Per-link extension surface: `gn.link.<scheme>`.
 *
 * Links register a typed extension vtable under
 * `gn.link.<scheme>` (e.g. `gn.link.tcp`,
 * `gn.link.udp`, `gn.link.ipc`) so other plugins can
 *
 *   1. snapshot per-link counters (`get_stats`),
 *   2. read static capabilities (`get_capabilities`) without parsing
 *      strings or hard-coding scheme assumptions, and
 *   3. compose layer-2 links on top of layer-1 ones —
 *      WSS-over-TCP, ICE-over-UDP, relay-tunnel-over-anything.
 *
 * The composition slots (`listen`, `connect`, `send`, `send_batch`,
 * `subscribe_data`, `unsubscribe_data`, `close`) are the same shape
 * across every scheme; that uniformity is what lets a generic L2
 * link target an arbitrary L1 without scheme-aware glue.
 *
 * See `docs/contracts/link.md` §8 for the registration model and
 * the per-link `<scheme>.h` headers for capability flag values
 * specific to a scheme.
 */
#ifndef GOODNET_SDK_EXTENSIONS_LINK_H
#define GOODNET_SDK_EXTENSIONS_LINK_H

#include <stddef.h>
#include <stdint.h>

#include <sdk/link.h>
#include <sdk/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Naming convention prefix. The full extension identifier is
 *        `"gn.link." + scheme`, lowercase.
 */
#define GN_EXT_LINK_PREFIX "gn.link."

/** v1.0.0 — initial release. */
#define GN_EXT_LINK_VERSION 0x00010000u

/**
 * @brief Capability flags, ORed into `gn_link_caps_t::flags`.
 *
 * `Stream` means the link delivers an unframed byte stream and
 * the consumer must impose its own message boundaries (TCP, IPC).
 * `Datagram` means the OS preserves each `send` as a separate
 * delivery (UDP).
 *
 * `Reliable` and `Ordered` describe the OS-level guarantees, not the
 * end-to-end ones the security layer adds.
 *
 * `EncryptedPath` is the link asserting it carries already-
 * encrypted bytes (e.g. a TLS terminator). `LocalOnly` is the
 * link refusing to bind a public address regardless of URI
 * (loopback, AF_UNIX).
 */
#define GN_LINK_CAP_STREAM         (1u << 0)
#define GN_LINK_CAP_DATAGRAM       (1u << 1)
#define GN_LINK_CAP_RELIABLE       (1u << 2)
#define GN_LINK_CAP_ORDERED        (1u << 3)
#define GN_LINK_CAP_ENCRYPTED_PATH (1u << 4)
#define GN_LINK_CAP_LOCAL_ONLY     (1u << 5)

/**
 * @brief Static capability descriptor. Stable for the lifetime of the
 *        link plugin; the kernel may snapshot once at register time.
 */
typedef struct gn_link_caps_s {
    uint32_t flags;          /**< OR of `GN_LINK_CAP_*` */
    uint32_t max_payload;    /**< soft MTU in bytes; 0 = unlimited */
    uint64_t _reserved[4];   /**< MUST be zero; see `abi-evolution.md` §4 */
} gn_link_caps_t;

/**
 * @brief Aggregate counters. All values are monotonic over the
 *        link's lifetime; rollover is handled by the consumer.
 */
typedef struct gn_link_stats_s {
    uint64_t bytes_in;
    uint64_t bytes_out;
    uint64_t frames_in;
    uint64_t frames_out;
    uint64_t active_connections;
    uint64_t _reserved[4];   /**< MUST be zero; see `abi-evolution.md` §4 */
} gn_link_stats_t;

/**
 * @brief Receive-side callback for composer plugins.
 *
 * Called by the L1 link when bytes arrive on a connection a
 * composer subscribed to via @ref gn_link_api_t::subscribe_data.
 * `bytes` is `@borrowed` for the duration of the call; the composer
 * must copy if it needs to retain past return.
 */
typedef void (*gn_link_data_cb_t)(
    void*          user_data,
    gn_conn_id_t   conn,
    const uint8_t* bytes,
    size_t         size);

/**
 * @brief Vtable surfaced under `gn.link.<scheme>`.
 *
 * `ctx` is the plugin's `self` pointer; every entry takes it as the
 * first argument. Versioned with @ref GN_EXT_LINK_VERSION.
 *
 * Slots split into three groups by maturity in v1.x:
 *
 *   * **Steady** — `get_stats`, `get_capabilities`, `send`,
 *     `send_batch`, `close`. Implemented by every baseline link
 *     (TCP, IPC, UDP) against the kernel-managed connection set.
 *
 *   * **Composer** — `listen`, `connect`, `subscribe_data`,
 *     `unsubscribe_data`. Reserved for layer-2 composition where the
 *     composer plugin owns the conn lifecycle independent of the
 *     kernel's `notify_connect` flow. Baseline links return
 *     `GN_ERR_NOT_IMPLEMENTED` until the corresponding L2 link
 *     (WSS, TLS, ICE) lands and the contract is exercised end-to-end.
 *
 * Implementations always provide every slot to keep the C ABI table
 * shape stable; an unimplemented slot returns `GN_ERR_NOT_IMPLEMENTED`
 * rather than presenting a NULL pointer.
 */
typedef struct gn_link_api_s {
    uint32_t api_size;          /**< sizeof(gn_link_api_t) at producer build time */

    /* ── Steady slots ───────────────────────────────────────────── */

    /**
     * @brief Snapshot per-link counters into @p out.
     *
     * @param out @borrowed caller-allocated; the plugin writes the
     *            counter snapshot.
     * @return @ref GN_OK on success, @ref GN_ERR_NULL_ARG when
     *         @p ctx or @p out is NULL.
     */
    gn_result_t (*get_stats)(void* ctx, gn_link_stats_t* out);

    /**
     * @brief Read static capability flags into @p out. Values stable
     *        for the plugin's lifetime; safe to cache.
     *
     * @param out @borrowed caller-allocated.
     */
    gn_result_t (*get_capabilities)(void* ctx, gn_link_caps_t* out);

    /**
     * @brief Send bytes on @p conn. Same shape as the kernel-facing
     *        `gn_link_vtable_t::send`; intended for composer
     *        plugins that have a kernel `gn_conn_id_t` in hand.
     *
     * Single-writer invariant per `link.md` §4 applies.
     *
     * @param bytes @borrowed for the duration of the call.
     */
    gn_result_t (*send)(void* ctx, gn_conn_id_t conn,
                        const uint8_t* bytes, size_t size);

    /**
     * @brief Scatter-gather send. Single-writer invariant covers the
     *        whole batch; `link.md` §4.
     *
     * @param batch @borrowed array of byte spans for the duration
     *              of the call; each span's bytes are also @borrowed.
     */
    gn_result_t (*send_batch)(void* ctx, gn_conn_id_t conn,
                              const gn_byte_span_t* batch, size_t count);

    /**
     * @brief Close @p conn. Idempotent; second call returns
     *        @ref GN_OK no-op. @p hard requests an immediate close
     *        without graceful drain (RST on TCP); 0 = graceful.
     */
    gn_result_t (*close)(void* ctx, gn_conn_id_t conn, int hard);

    /* ── Composer slots ─────────────────────────────────────────── */

    /**
     * @brief Begin accepting connections matching @p uri without
     *        threading them through the kernel `notify_connect`
     *        pipeline. Used by composer plugins (WSS, TLS) that
     *        manage connection state at L2.
     *
     * Returns @ref GN_ERR_NOT_IMPLEMENTED on baseline links in
     * v1.0.x — see contract `link.md` §8.
     *
     * @param uri @borrowed for the duration of the call.
     */
    gn_result_t (*listen)(void* ctx, const char* uri);

    /**
     * @brief Initiate an L1 connection bypassing the kernel
     *        `notify_connect` pipeline. Out-parameter receives the
     *        L1 handle the composer hands to subsequent
     *        `send`/`subscribe_data`/`close` calls.
     *
     * @param uri      @borrowed for the duration of the call.
     * @param out_conn @borrowed caller-allocated; the plugin writes
     *                 the L1 handle on success.
     */
    gn_result_t (*connect)(void* ctx, const char* uri,
                           gn_conn_id_t* out_conn);

    /**
     * @brief Install a receive callback for @p conn. Re-subscribing
     *        replaces the prior callback. @p user_data is passed
     *        unchanged on every callback invocation.
     *
     * @param cb        @borrowed function pointer; the plugin keeps
     *                  it alive until `unsubscribe_data` returns.
     * @param user_data @borrowed by the plugin under the same
     *                  lifetime as @p cb; pass-through to every
     *                  callback invocation.
     */
    gn_result_t (*subscribe_data)(void* ctx, gn_conn_id_t conn,
                                  gn_link_data_cb_t cb,
                                  void* user_data);

    /**
     * @brief Remove the subscription installed by @ref subscribe_data.
     *        Returns @ref GN_OK no-op when no subscription was active.
     */
    gn_result_t (*unsubscribe_data)(void* ctx, gn_conn_id_t conn);

    /**
     * @brief Plugin self pointer. Pass-through to every slot's first
     *        argument. Set by the producing plugin before
     *        `register_extension`.
     */
    void* ctx;

    void* _reserved[4];      /**< MUST be zero; see `abi-evolution.md` §4 */
} gn_link_api_t;

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* GOODNET_SDK_EXTENSIONS_LINK_H */
