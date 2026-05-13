/// @file   core/plugin/wire_codec.cpp
/// @brief  Implementation of the minimal CBOR subset declared in
///         `wire_codec.hpp`. See that header for the supported
///         subset and `docs/contracts/remote-plugin.en.md` §5 for
///         the binding spec.

#include <core/plugin/wire_codec.hpp>

#include <cstring>
#include <limits>

namespace gn::core::wire {

namespace {

constexpr std::uint8_t kMajorShift     = 5;
constexpr std::uint8_t kMinorMask      = 0x1F;

constexpr std::uint8_t kMajorUInt      = 0;
constexpr std::uint8_t kMajorNegInt    = 1;
constexpr std::uint8_t kMajorByteStr   = 2;
constexpr std::uint8_t kMajorTextStr   = 3;
constexpr std::uint8_t kMajorArray     = 4;
constexpr std::uint8_t kMajorMap       = 5;
constexpr std::uint8_t kMajorSimple    = 7;

constexpr std::uint8_t kSimpleFalse    = 20;
constexpr std::uint8_t kSimpleTrue     = 21;
constexpr std::uint8_t kSimpleNull     = 22;

constexpr std::uint8_t kAdditional1B   = 24;
constexpr std::uint8_t kAdditional2B   = 25;
constexpr std::uint8_t kAdditional4B   = 26;
constexpr std::uint8_t kAdditional8B   = 27;

inline std::uint8_t make_initial(std::uint8_t major,
                                 std::uint8_t additional) noexcept {
    return static_cast<std::uint8_t>((major << kMajorShift) |
                                     (additional & kMinorMask));
}

void emit_head(std::vector<std::uint8_t>& out,
               std::uint8_t major,
               std::uint64_t v) {
    if (v <= 23) {
        out.push_back(make_initial(major, static_cast<std::uint8_t>(v)));
        return;
    }
    if (v <= std::numeric_limits<std::uint8_t>::max()) {
        out.push_back(make_initial(major, kAdditional1B));
        out.push_back(static_cast<std::uint8_t>(v));
        return;
    }
    if (v <= std::numeric_limits<std::uint16_t>::max()) {
        out.push_back(make_initial(major, kAdditional2B));
        out.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFF));
        out.push_back(static_cast<std::uint8_t>(v & 0xFF));
        return;
    }
    if (v <= std::numeric_limits<std::uint32_t>::max()) {
        out.push_back(make_initial(major, kAdditional4B));
        for (int shift = 24; shift >= 0; shift -= 8) {
            out.push_back(static_cast<std::uint8_t>((v >> shift) & 0xFF));
        }
        return;
    }
    out.push_back(make_initial(major, kAdditional8B));
    for (int shift = 56; shift >= 0; shift -= 8) {
        out.push_back(static_cast<std::uint8_t>((v >> shift) & 0xFF));
    }
}

[[nodiscard]] gn_result_t read_head(Reader& r,
                                    std::uint8_t& major,
                                    std::uint64_t& value) noexcept {
    if (r.pos >= r.buf.size()) {
        return GN_ERR_OUT_OF_RANGE;
    }
    const std::uint8_t initial = r.buf[r.pos];
    const std::uint8_t additional = initial & kMinorMask;
    major = static_cast<std::uint8_t>(initial >> kMajorShift);
    std::size_t need = 1;
    if (additional < 24) {
        value = additional;
    } else if (additional == kAdditional1B) {
        need = 2;
    } else if (additional == kAdditional2B) {
        need = 3;
    } else if (additional == kAdditional4B) {
        need = 5;
    } else if (additional == kAdditional8B) {
        need = 9;
    } else {
        return GN_ERR_OUT_OF_RANGE;
    }
    if (r.buf.size() - r.pos < need) {
        return GN_ERR_OUT_OF_RANGE;
    }
    if (additional >= kAdditional1B) {
        value = 0;
        for (std::size_t i = 1; i < need; ++i) {
            value = (value << 8) | r.buf[r.pos + i];
        }
    }
    r.pos += need;
    return GN_OK;
}

}  // namespace

// ── Encoders ────────────────────────────────────────────────────────────

void encode_u64(std::vector<std::uint8_t>& out, std::uint64_t v) {
    emit_head(out, kMajorUInt, v);
}

void encode_i64(std::vector<std::uint8_t>& out, std::int64_t v) {
    if (v >= 0) {
        emit_head(out, kMajorUInt, static_cast<std::uint64_t>(v));
    } else {
        // CBOR negative-int magnitude is `-1 - v`. Compute via the
        // unsigned trick to avoid INT64_MIN overflow.
        const std::uint64_t mag =
            static_cast<std::uint64_t>(-(v + 1));
        emit_head(out, kMajorNegInt, mag);
    }
}

void encode_bytes(std::vector<std::uint8_t>& out,
                  std::span<const std::uint8_t> data) {
    emit_head(out, kMajorByteStr, data.size());
    out.insert(out.end(), data.begin(), data.end());
}

void encode_text(std::vector<std::uint8_t>& out, std::string_view s) {
    emit_head(out, kMajorTextStr, s.size());
    out.insert(out.end(),
               reinterpret_cast<const std::uint8_t*>(s.data()),
               reinterpret_cast<const std::uint8_t*>(s.data() + s.size()));
}

void encode_array_header(std::vector<std::uint8_t>& out, std::size_t n) {
    emit_head(out, kMajorArray, n);
}

void encode_map_header(std::vector<std::uint8_t>& out, std::size_t n) {
    emit_head(out, kMajorMap, n);
}

void encode_bool(std::vector<std::uint8_t>& out, bool v) {
    out.push_back(make_initial(kMajorSimple,
                                v ? kSimpleTrue : kSimpleFalse));
}

void encode_null(std::vector<std::uint8_t>& out) {
    out.push_back(make_initial(kMajorSimple, kSimpleNull));
}

// ── Decoders ────────────────────────────────────────────────────────────

gn_result_t decode_u64(Reader& r, std::uint64_t& out) {
    std::uint8_t major = 0;
    std::uint64_t value = 0;
    if (auto rc = read_head(r, major, value); rc != GN_OK) {
        return rc;
    }
    if (major != kMajorUInt) {
        return GN_ERR_OUT_OF_RANGE;
    }
    out = value;
    return GN_OK;
}

gn_result_t decode_i64(Reader& r, std::int64_t& out) {
    std::uint8_t major = 0;
    std::uint64_t value = 0;
    if (auto rc = read_head(r, major, value); rc != GN_OK) {
        return rc;
    }
    if (major == kMajorUInt) {
        if (value > static_cast<std::uint64_t>(
                        std::numeric_limits<std::int64_t>::max())) {
            return GN_ERR_OUT_OF_RANGE;
        }
        out = static_cast<std::int64_t>(value);
        return GN_OK;
    }
    if (major == kMajorNegInt) {
        // Mirror of the encoder: negative value is `-1 - magnitude`.
        // Cap magnitude so `out` stays in range for int64_t.
        if (value > static_cast<std::uint64_t>(
                        std::numeric_limits<std::int64_t>::max())) {
            return GN_ERR_OUT_OF_RANGE;
        }
        out = -1 - static_cast<std::int64_t>(value);
        return GN_OK;
    }
    return GN_ERR_OUT_OF_RANGE;
}

gn_result_t decode_bytes(Reader& r,
                         std::span<const std::uint8_t>& out) {
    std::uint8_t major = 0;
    std::uint64_t length = 0;
    if (auto rc = read_head(r, major, length); rc != GN_OK) {
        return rc;
    }
    if (major != kMajorByteStr) {
        return GN_ERR_OUT_OF_RANGE;
    }
    if (length > r.buf.size() - r.pos) {
        return GN_ERR_OUT_OF_RANGE;
    }
    out = r.buf.subspan(r.pos, static_cast<std::size_t>(length));
    r.pos += static_cast<std::size_t>(length);
    return GN_OK;
}

gn_result_t decode_text(Reader& r, std::string_view& out) {
    std::uint8_t major = 0;
    std::uint64_t length = 0;
    if (auto rc = read_head(r, major, length); rc != GN_OK) {
        return rc;
    }
    if (major != kMajorTextStr) {
        return GN_ERR_OUT_OF_RANGE;
    }
    if (length > r.buf.size() - r.pos) {
        return GN_ERR_OUT_OF_RANGE;
    }
    out = std::string_view(
        reinterpret_cast<const char*>(r.buf.data() + r.pos),
        static_cast<std::size_t>(length));
    r.pos += static_cast<std::size_t>(length);
    return GN_OK;
}

gn_result_t decode_array_header(Reader& r, std::size_t& n) {
    std::uint8_t major = 0;
    std::uint64_t value = 0;
    if (auto rc = read_head(r, major, value); rc != GN_OK) {
        return rc;
    }
    if (major != kMajorArray) {
        return GN_ERR_OUT_OF_RANGE;
    }
    n = static_cast<std::size_t>(value);
    return GN_OK;
}

gn_result_t decode_map_header(Reader& r, std::size_t& n) {
    std::uint8_t major = 0;
    std::uint64_t value = 0;
    if (auto rc = read_head(r, major, value); rc != GN_OK) {
        return rc;
    }
    if (major != kMajorMap) {
        return GN_ERR_OUT_OF_RANGE;
    }
    n = static_cast<std::size_t>(value);
    return GN_OK;
}

gn_result_t decode_bool(Reader& r, bool& out) {
    std::uint8_t major = 0;
    std::uint64_t value = 0;
    if (auto rc = read_head(r, major, value); rc != GN_OK) {
        return rc;
    }
    if (major != kMajorSimple) {
        return GN_ERR_OUT_OF_RANGE;
    }
    if (value == kSimpleFalse) { out = false; return GN_OK; }
    if (value == kSimpleTrue)  { out = true;  return GN_OK; }
    return GN_ERR_OUT_OF_RANGE;
}

gn_result_t decode_null(Reader& r) {
    std::uint8_t major = 0;
    std::uint64_t value = 0;
    if (auto rc = read_head(r, major, value); rc != GN_OK) {
        return rc;
    }
    if (major != kMajorSimple || value != kSimpleNull) {
        return GN_ERR_OUT_OF_RANGE;
    }
    return GN_OK;
}

gn_result_t peek_major_type(const Reader& r, std::uint8_t& major) {
    if (r.pos >= r.buf.size()) {
        return GN_ERR_OUT_OF_RANGE;
    }
    major = static_cast<std::uint8_t>(r.buf[r.pos] >> kMajorShift);
    return GN_OK;
}

}  // namespace gn::core::wire
