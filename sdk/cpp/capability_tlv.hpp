// SPDX-License-Identifier: MIT
/// @file   sdk/cpp/capability_tlv.hpp
/// @brief  Header-only TLV encoder / decoder for the post-Noise
///         capability handshake. Per `docs/contracts/capability-tlv.en.md`.
///
/// Wire format: a sequence of `[type:u16 BE][length:u16 BE][value...]`
/// records with no terminator. The consumer reads records until the
/// byte stream ends. Records of unknown type are skipped — every
/// extension stays additive.

#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <vector>

namespace gn::sdk {

/// One TLV record. The encoder validates `value.size() <= 0xffff` and
/// rejects oversized inputs before touching the output buffer.
struct TlvRecord {
    std::uint16_t             type;
    std::vector<std::uint8_t> value;
};

/// Reason an encode / parse call could not complete. The `offset`
/// field on parse errors carries the byte position of the failed
/// record so callers can log it.
struct TlvError {
    enum class Kind {
        ValueTooLarge,   ///< encode: a record's value > 0xffff bytes
        Truncated,       ///< parse: a length field runs past the blob
    };
    Kind         kind;
    std::size_t  offset;
    std::string  message;
};

/// Encode @p records to a flat byte blob in declaration order. Each
/// record contributes `4 + value.size()` bytes. Returns the encoded
/// blob, or `TlvError::ValueTooLarge` when one of the values is too
/// large to fit a 16-bit length field.
[[nodiscard]] inline std::expected<std::vector<std::uint8_t>, TlvError>
encode_tlv(std::span<const TlvRecord> records) {
    std::size_t total = 0;
    for (const auto& r : records) {
        if (r.value.size() > 0xffffu) {
            return std::unexpected(TlvError{
                TlvError::Kind::ValueTooLarge,
                /*offset=*/total,
                "tlv value exceeds 65535 bytes"});
        }
        total += 4 + r.value.size();
    }

    std::vector<std::uint8_t> out;
    out.reserve(total);
    for (const auto& r : records) {
        out.push_back(static_cast<std::uint8_t>((r.type >> 8) & 0xffu));
        out.push_back(static_cast<std::uint8_t>(r.type & 0xffu));
        const auto len = static_cast<std::uint16_t>(r.value.size());
        out.push_back(static_cast<std::uint8_t>((len >> 8) & 0xffu));
        out.push_back(static_cast<std::uint8_t>(len & 0xffu));
        out.insert(out.end(), r.value.begin(), r.value.end());
    }
    return out;
}

/// Parse @p blob into the contained record sequence. A blob that ends
/// mid-record (a truncated `length` or a length that runs past the
/// remaining bytes) yields `TlvError::Truncated` with the offset of
/// the failed record. Empty input parses to an empty vector.
[[nodiscard]] inline std::expected<std::vector<TlvRecord>, TlvError>
parse_tlv(std::span<const std::uint8_t> blob) {
    std::vector<TlvRecord> out;
    std::size_t            pos = 0;
    while (pos < blob.size()) {
        if (blob.size() - pos < 4) {
            return std::unexpected(TlvError{
                TlvError::Kind::Truncated, pos,
                "header runs past blob end"});
        }
        const std::uint16_t type =
            static_cast<std::uint16_t>(blob[pos] << 8 |
                                        blob[pos + 1]);
        const std::uint16_t length =
            static_cast<std::uint16_t>(blob[pos + 2] << 8 |
                                        blob[pos + 3]);
        const std::size_t value_off = pos + 4;
        if (blob.size() - value_off < length) {
            return std::unexpected(TlvError{
                TlvError::Kind::Truncated, pos,
                "value runs past blob end"});
        }
        using diff_t = std::ptrdiff_t;
        TlvRecord rec;
        rec.type = type;
        rec.value.assign(
            blob.begin() + static_cast<diff_t>(value_off),
            blob.begin() + static_cast<diff_t>(value_off + length));
        out.push_back(std::move(rec));
        pos = value_off + length;
    }
    return out;
}

}  // namespace gn::sdk
