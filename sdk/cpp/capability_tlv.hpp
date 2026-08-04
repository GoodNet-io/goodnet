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

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <span>
#include <string>
#include <unordered_map>
#include <vector>

#include <sdk/cpp/endian.hpp>
#include <sdk/handler.h>
#include <sdk/types.h>

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
        const std::uint16_t type   = gn::endian::read_be_ptr<std::uint16_t>(
                                         blob.data() + pos);
        const std::uint16_t length = gn::endian::read_be_ptr<std::uint16_t>(
                                         blob.data() + pos + 2);
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

/// TLV type for compression capability advertisement (capability-tlv.en.md §2.3).
/// Value: one-byte bitmask. Exchange via present_capability_blob after connect.
inline constexpr std::uint16_t kTlvTypeCompressionSet = 0x0003u;
/// Bit 0 of compression-set value: ZSTD algorithm supported.
inline constexpr std::uint8_t  kCompressionSetZstd    = 0x01u;

/// TLV type for topology fingerprint exchange (layer-capability.en.md §6).
/// Value: exactly 32 bytes — SHA-256 over sorted structural layers.
/// Sent automatically after Noise XX reaches Transport phase.
/// Peer fingerprint mismatch logs the diff and sets peer_caps_verified=false.
inline constexpr std::uint16_t kTlvTypeTopologyFingerprint = 0x0004u;

/// TLV type for contour fingerprint exchange (layer-capability.en.md §7).
/// Value: exactly 32 bytes. Sent by the kernel after contour seal. W2 placeholder.
inline constexpr std::uint16_t kTlvTypeContourFingerprint = 0x0005u;

/// Per-type priority-ordered TLV dispatch — second level below msg_id dispatch.
/// Kernel registers at priority 255 for topology types (0x0004, 0x0005).
/// Plugins register for capability types (0x0200+).
class TlvHandlerChain {
public:
    using HandlerFn = std::function<gn_propagation_t(gn_conn_id_t, const TlvRecord&)>;

    void register_handler(std::uint16_t type, std::uint8_t priority, HandlerFn fn) {
        auto& v = handlers_[type];
        v.push_back({priority, std::move(fn)});
        std::stable_sort(v.begin(), v.end(),
            [](const Entry& a, const Entry& b) noexcept { return a.priority > b.priority; });
    }

    void dispatch(gn_conn_id_t conn, std::span<const TlvRecord> records) const {
        for (const auto& rec : records) {
            const auto it = handlers_.find(rec.type);
            if (it == handlers_.end()) continue;
            for (const auto& e : it->second) {
                if (e.fn(conn, rec) == GN_PROPAGATION_CONSUMED) break;
            }
        }
    }

    void clear() noexcept { handlers_.clear(); }

private:
    struct Entry { std::uint8_t priority; HandlerFn fn; };
    std::unordered_map<std::uint16_t, std::vector<Entry>> handlers_;
};

}  // namespace gn::sdk
