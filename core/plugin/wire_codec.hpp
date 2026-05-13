/// @file   core/plugin/wire_codec.hpp
/// @brief  Minimal CBOR encoder/decoder for the subprocess plugin
///         wire protocol pinned in `sdk/remote/wire.h`.
///
/// CBOR subset:
///   • major 0 (unsigned int), major 1 (negative int)   → u64/i64
///   • major 2 (byte string), major 3 (text string)     → spans
///   • major 4 (array header), major 5 (map header)     → headers only
///   • major 7 simple: 20 (false), 21 (true), 22 (null) → bool/null
///
/// Out of scope: floats, indefinite-length sequences, tags. Workers
/// that need richer encodings cross the boundary with bytestrings
/// (major 2) and decode language-side.
///
/// The codec stays in-kernel (no third-party dependency). The wire
/// format is documented in `docs/contracts/remote-plugin.en.md` §5
/// — that markdown file is the binding spec; this header is the
/// implementation contract.
///
/// Errors return `GN_ERR_OUT_OF_RANGE` for malformed input (the
/// closest match in `sdk/types.h` to "CBOR decode failure"); the
/// reader's `pos` is left at the offending byte so a caller can
/// emit a useful diagnostic.

#pragma once

#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

#include <sdk/types.h>

namespace gn::core::wire {

/// Append-only CBOR writer. Callers reuse a single `std::vector` to
/// build a frame payload, then ship it through `RemoteHost::write_frame`.
void encode_u64(std::vector<std::uint8_t>& out, std::uint64_t v);

/// Two's-complement encoding: non-negative values go through
/// `encode_u64`; negative values use major 1 with magnitude `-1 - v`.
void encode_i64(std::vector<std::uint8_t>& out, std::int64_t v);

void encode_bytes(std::vector<std::uint8_t>& out,
                  std::span<const std::uint8_t> data);

void encode_text(std::vector<std::uint8_t>& out, std::string_view s);

/// CBOR array header — the caller appends `n` items afterwards. The
/// codec does not validate item count against the header.
void encode_array_header(std::vector<std::uint8_t>& out, std::size_t n);

/// CBOR map header — the caller appends `n` key-value pairs (so 2*n
/// items total) afterwards. Same lack of structural validation.
void encode_map_header(std::vector<std::uint8_t>& out, std::size_t n);

void encode_bool(std::vector<std::uint8_t>& out, bool v);
void encode_null(std::vector<std::uint8_t>& out);

/// Stateful reader. `pos` advances on every successful decode; on
/// failure the caller can inspect `pos` to find the offending byte.
struct Reader {
    std::span<const std::uint8_t> buf;
    std::size_t pos{0};
};

[[nodiscard]] gn_result_t decode_u64(Reader& r, std::uint64_t& out);
[[nodiscard]] gn_result_t decode_i64(Reader& r, std::int64_t& out);

/// On success `out` points into `r.buf` — the view is valid as long
/// as the input buffer outlives it. Zero allocation in decode.
[[nodiscard]] gn_result_t decode_bytes(Reader& r,
                                       std::span<const std::uint8_t>& out);
[[nodiscard]] gn_result_t decode_text(Reader& r, std::string_view& out);

[[nodiscard]] gn_result_t decode_array_header(Reader& r, std::size_t& n);
[[nodiscard]] gn_result_t decode_map_header(Reader& r, std::size_t& n);

[[nodiscard]] gn_result_t decode_bool(Reader& r, bool& out);
[[nodiscard]] gn_result_t decode_null(Reader& r);

/// Peek the major type of the next item without advancing `pos`.
/// Returns `GN_ERR_OUT_OF_RANGE` when the buffer is exhausted.
/// Useful for HOST_REPLY decoders that need to distinguish a
/// success array from an error map without dual-decoding.
[[nodiscard]] gn_result_t peek_major_type(const Reader& r,
                                          std::uint8_t& major);

}  // namespace gn::core::wire
