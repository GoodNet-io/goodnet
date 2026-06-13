// SPDX-License-Identifier: MIT
/**
 * @file   sdk/extensions/compress.h
 * @brief  gn.compress extension — algorithm-agnostic compression services.
 *
 * Plugins query this extension to compress or decompress byte buffers
 * without a direct dependency on any algorithm library:
 *
 *   gn_compress_api_t vtable = {};
 *   gn_result_t rc = query_extension_checked(api, GN_COMPRESS_EXT,
 *                        GN_COMPRESS_API_VERSION, &vtable);
 *   if (rc == GN_OK) {
 *       uint8_t out[vtable.compress_bound(&vtable, in_sz)];
 *       size_t out_sz = 0;
 *       vtable.compress(&vtable, in, in_sz, out, sizeof(out), &out_sz, 3);
 *   }
 *
 * Capability advertisement: after notify_connect, present a capability
 * blob containing TLV type GN_TLV_COMPRESSION_SET with a bitmask of
 * supported algorithms (GN_COMPRESS_ALGO_ZSTD = 0x01). Both peers must
 * advertise the same bit before enabling compression on the connection.
 * See capability-tlv.en.md §2.3 and sdk/cpp/capability_tlv.hpp.
 */
#ifndef GOODNET_SDK_EXTENSIONS_COMPRESS_H
#define GOODNET_SDK_EXTENSIONS_COMPRESS_H

#include <stddef.h>
#include <stdint.h>

#include <sdk/abi.h>
#include <sdk/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Stable extension identifier. Unchanged across minor releases. */
#define GN_COMPRESS_EXT             "gn.compress"
/** v1.0.0 — initial release. */
#define GN_COMPRESS_API_VERSION     0x00010000u

/**
 * @brief TLV type for compression capability advertisement.
 *
 * Value: one-byte bitmask of @ref GN_COMPRESS_ALGO_ZSTD flags.
 * Exchange via `present_capability_blob` / `subscribe_capability_blob`
 * (msg_id 0x13). See `capability-tlv.en.md` §2.3.
 */
#define GN_TLV_COMPRESSION_SET      0x0003u

/**
 * @brief Algorithm flags for the @ref GN_TLV_COMPRESSION_SET bitmask.
 *
 * Both peers must advertise the same bit before a compression algorithm
 * is enabled on the connection.
 */
#define GN_COMPRESS_ALGO_ZSTD       0x01u  /**< ZSTD algorithm supported */

/**
 * @defgroup compress_env Compressed-object envelope (compressed-object.en.md §2)
 *
 * Layout of the 5-byte header that precedes compressed data when the
 * "inband" routing mode is in use:
 *
 *   [0]     algo byte (GN_COMPRESS_ENV_*)
 *   [1..4]  target msg_id (big-endian uint32)
 *   [5..]   algorithm-specific compressed bytes (never compressed together
 *           with the header — the header is always uncompressed)
 *
 * The header is parsed from the raw GNET payload BEFORE decompression.
 * @{
 */
/** Algo byte: ZSTD (RFC 8878). Matches bit 0 of GN_COMPRESS_ALGO_ZSTD. */
#define GN_COMPRESS_ENV_ZSTD        0x01u
/** Total byte length of the compressed-object envelope header. */
#define GN_COMPRESS_ENV_HDR_SIZE    5u
/** @} */

/**
 * @brief Vtable surfaced as the `gn.compress` extension.
 *
 * The `ctx` field is the provider's `self` pointer; every entry takes
 * it as its first argument. Versioned with @ref GN_COMPRESS_API_VERSION.
 *
 * Begins with `api_size` for size-prefix evolution per
 * `abi-evolution.en.md` §3. Consumers query the extension through
 * `host_api->query_extension_checked` which validates `api_size`
 * against the consumer's compile-time minimum before any slot fires.
 *
 * All function pointers are non-NULL when the extension is registered.
 */
typedef struct gn_compress_api_s {
    uint32_t api_size;          /**< sizeof(gn_compress_api_t) at producer build time */

    /**
     * @brief Compress @p in_sz bytes from @p in into @p out.
     *
     * Caller allocates @p out with capacity @p out_cap bytes (at least
     * `compress_bound(ctx, in_sz)`). On success writes the compressed
     * byte count to @p out_sz.
     *
     * @param level  Algorithm-specific effort level; 0 = provider
     *               default, positive = more compression, negative =
     *               faster (ZSTD convention).
     *
     * @return @ref GN_OK on success.
     * @return @ref GN_ERR_OUTPUT_TOO_SMALL when @p out_cap is less than
     *         `compress_bound(ctx, in_sz)`; caller may retry with a
     *         larger buffer.
     */
    gn_result_t (*compress)(void*          ctx,
                             const uint8_t* in,
                             size_t         in_sz,
                             uint8_t*       out,
                             size_t         out_cap,
                             size_t*        out_sz,
                             int            level);

    /**
     * @brief Upper bound on compressed output for an input of @p in_sz bytes.
     *
     * Use the returned size to allocate the buffer passed to @ref compress.
     * The bound is conservative — actual compressed size is always ≤ this.
     */
    size_t      (*compress_bound)(void* ctx, size_t in_sz);

    /**
     * @brief Decompress @p in_sz bytes from @p in into @p out.
     *
     * Caller allocates @p out with capacity @p out_cap bytes. On
     * success writes the decompressed byte count to @p out_sz.
     *
     * @return @ref GN_OK on success.
     * @return @ref GN_ERR_OUTPUT_TOO_SMALL when @p out_cap is too small
     *         to hold the decompressed data; caller may retry with a
     *         larger buffer.
     * @return @ref GN_ERR_INVALID_ENVELOPE when @p in contains data
     *         that is not a valid compressed frame.
     */
    gn_result_t (*decompress)(void*          ctx,
                               const uint8_t* in,
                               size_t         in_sz,
                               uint8_t*       out,
                               size_t         out_cap,
                               size_t*        out_sz);

    /**
     * @brief Plugin self pointer. Pass-through to every slot's first
     *        argument. Set by the producing plugin before
     *        `register_extension`.
     */
    void* ctx;

    void* _reserved[4];      /**< MUST be zero; see `abi-evolution.en.md` §4 */
} gn_compress_api_t;

GN_VTABLE_API_SIZE_FIRST(gn_compress_api_t);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* GOODNET_SDK_EXTENSIONS_COMPRESS_H */
