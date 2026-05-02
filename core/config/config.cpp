/// @file   core/config/config.cpp
/// @brief  Implementation of the kernel Config holder.

#include "config.hpp"

#include <cstdio>
#include <fstream>
#include <mutex>
#include <sstream>

#include <core/util/log.hpp>

namespace gn::core {

namespace {

/// Read a uint32_t field from a JSON object, falling back to @p def
/// on a missing field, on a non-integer value, on a negative number,
/// or on a value that overflows the uint32_t range. The range checks
/// run at the int64 level so a JSON literal of e.g. `2^33` is
/// rejected here rather than thrown out of `nlohmann::json::get`.
std::uint32_t pick_u32(const nlohmann::json& obj, const char* field, std::uint32_t def) {
    auto it = obj.find(field);
    if (it == obj.end() || !it->is_number_integer()) return def;
    const std::int64_t v = it->get<std::int64_t>();
    if (v < 0 || v > static_cast<std::int64_t>(UINT32_MAX)) return def;
    return static_cast<std::uint32_t>(v);
}

std::uint64_t pick_u64(const nlohmann::json& obj, const char* field, std::uint64_t def) {
    auto it = obj.find(field);
    if (it == obj.end() || !it->is_number_integer()) return def;
    /// `nlohmann::json` stores an integer as `int64_t`; a value that
    /// overflows that range is parsed as a float and `is_number_integer`
    /// returns false. Negative values reach us only via the int path
    /// and must reject — uint64_t fields are inherently non-negative.
    const std::int64_t v = it->get<std::int64_t>();
    if (v < 0) return def;
    return static_cast<std::uint64_t>(v);
}

gn_limits_t server_profile() noexcept {
    /// Canonical defaults from `sdk/limits.h`. Matches the
    /// historical hard-coded values the kernel held inline before
    /// the profile system landed.
    gn_limits_t L{};
    L.max_connections             = GN_LIMITS_DEFAULT_MAX_CONNECTIONS;
    L.max_outbound_connections    = GN_LIMITS_DEFAULT_MAX_OUTBOUND_CONNECTIONS;
    L.pending_queue_bytes_high    = GN_LIMITS_DEFAULT_PENDING_QUEUE_BYTES_HIGH;
    L.pending_queue_bytes_low     = GN_LIMITS_DEFAULT_PENDING_QUEUE_BYTES_LOW;
    L.pending_queue_bytes_hard    = GN_LIMITS_DEFAULT_PENDING_QUEUE_BYTES_HARD;
    L.max_frame_bytes             = GN_LIMITS_DEFAULT_MAX_FRAME_BYTES;
    L.max_payload_bytes           = GN_LIMITS_DEFAULT_MAX_FRAME_BYTES - 14u;
    L.max_handlers_per_msg_id     = GN_LIMITS_DEFAULT_MAX_HANDLERS_PER_MSG_ID;
    L.max_relay_ttl               = GN_LIMITS_DEFAULT_MAX_RELAY_TTL;
    L.max_plugins                 = GN_LIMITS_DEFAULT_MAX_PLUGINS;
    L.max_extensions              = GN_LIMITS_DEFAULT_MAX_EXTENSIONS;
    L.max_timers                  = GN_LIMITS_DEFAULT_MAX_TIMERS;
    L.max_pending_tasks           = GN_LIMITS_DEFAULT_MAX_PENDING_TASKS;
    L.pending_handshake_bytes     = GN_LIMITS_DEFAULT_PENDING_HANDSHAKE_BYTES;
    L.max_storage_table_entries   = GN_LIMITS_DEFAULT_MAX_STORAGE_TABLE_ENTRIES;
    L.max_storage_value_bytes     = L.max_payload_bytes;
    L.inject_rate_per_source      = GN_LIMITS_DEFAULT_INJECT_RATE_PER_SOURCE;
    L.inject_rate_burst           = GN_LIMITS_DEFAULT_INJECT_RATE_BURST;
    L.inject_rate_lru_cap         = GN_LIMITS_DEFAULT_INJECT_RATE_LRU_CAP;
    return L;
}

/// Resource-constrained profile for IoT / single-board deploys.
/// 64-conn ceiling, 8 KiB max frame (low-MTU radio links), small
/// timer pool, narrowed inject limiter so a single peer cannot
/// monopolise the device's tiny budget. Embedded operators tune
/// further from this baseline through the JSON `limits` block.
gn_limits_t embedded_profile() noexcept {
    gn_limits_t L = server_profile();
    L.max_connections             = 64;
    L.max_outbound_connections    = 16;
    L.pending_queue_bytes_high    = 64u  * 1024;       //  64 KiB
    L.pending_queue_bytes_low     = 16u  * 1024;       //  16 KiB
    L.pending_queue_bytes_hard    = 256u * 1024;       // 256 KiB
    L.max_frame_bytes             = 8u   * 1024;       //   8 KiB
    L.max_payload_bytes           = L.max_frame_bytes - 14u;
    L.max_handlers_per_msg_id     = 4;
    L.max_relay_ttl               = 2;
    L.max_plugins                 = 8;
    L.max_extensions              = 32;
    L.max_timers                  = 256;
    L.max_pending_tasks           = 256;
    L.pending_handshake_bytes     = 32u  * 1024;       //  32 KiB
    L.max_storage_value_bytes     = L.max_payload_bytes;
    L.inject_rate_per_source      = 10;
    L.inject_rate_burst           = 8;
    L.inject_rate_lru_cap         = 64;
    return L;
}

/// Single-user / workstation profile. Sits between Embedded and
/// Server: enough headroom for active development and casual
/// peer-to-peer use, without the per-process memory budget the
/// Server profile assumes.
gn_limits_t desktop_profile() noexcept {
    gn_limits_t L = server_profile();
    L.max_connections             = 512;
    L.max_outbound_connections    = 128;
    L.pending_queue_bytes_high    = 256u * 1024;       // 256 KiB
    L.pending_queue_bytes_low     = 64u  * 1024;       //  64 KiB
    L.pending_queue_bytes_hard    = 1u   * 1024 * 1024; //  1 MiB
    L.max_plugins                 = 32;
    L.max_extensions              = 128;
    L.max_timers                  = 1024;
    L.max_pending_tasks           = 1024;
    return L;
}

gn_limits_t default_limits() noexcept { return server_profile(); }

} // namespace

Config::Config() : json_(nlohmann::json::object()), limits_(default_limits()) {}

Config::Profile Config::parse_profile_name(std::string_view name) noexcept {
    if (name == "embedded") return Profile::Embedded;
    if (name == "desktop")  return Profile::Desktop;
    /// Unknown / missing names fall back to the safe default. An
    /// operator who typoed their profile sees the canonical
    /// values, not a tighter set that would drop traffic.
    return Profile::Server;
}

gn_limits_t Config::profile_defaults(Profile profile) noexcept {
    switch (profile) {
        case Profile::Embedded: return embedded_profile();
        case Profile::Desktop:  return desktop_profile();
        case Profile::Server:   return server_profile();
    }
    return server_profile();
}

gn_limits_t Config::parse_limits(const nlohmann::json& root) {
    /// Profile selects the baseline; the `limits` block overrides
    /// individual fields on top. Operators write either:
    ///   `{"profile": "embedded"}` — pure profile, no overrides
    ///   `{"limits": {"max_connections": 256}}` — server baseline
    ///   `{"profile": "embedded", "limits": {"max_timers": 512}}`
    ///       — embedded baseline + a single override
    Profile profile = Profile::Server;
    if (auto p = root.find("profile"); p != root.end() && p->is_string()) {
        profile = parse_profile_name(p->get<std::string>());
    }
    gn_limits_t L = profile_defaults(profile);
    auto it = root.find("limits");
    if (it == root.end() || !it->is_object()) return L;
    const auto& obj = *it;
#define GN_PICK_U32(field) L.field = pick_u32(obj, #field, L.field)
#define GN_PICK_U64(field) L.field = pick_u64(obj, #field, L.field)
    GN_PICK_U32(max_connections);
    GN_PICK_U32(max_outbound_connections);
    GN_PICK_U32(pending_queue_bytes_high);
    GN_PICK_U32(pending_queue_bytes_low);
    GN_PICK_U32(pending_queue_bytes_hard);
    GN_PICK_U32(max_frame_bytes);
    GN_PICK_U32(max_payload_bytes);
    GN_PICK_U32(max_handlers_per_msg_id);
    GN_PICK_U32(max_relay_ttl);
    GN_PICK_U32(max_plugins);
    GN_PICK_U32(max_extensions);
    GN_PICK_U32(pending_handshake_bytes);
    GN_PICK_U64(max_storage_table_entries);
    GN_PICK_U64(max_storage_value_bytes);
    GN_PICK_U32(max_timers);
    GN_PICK_U32(max_pending_tasks);
    GN_PICK_U32(max_timers_per_plugin);
    GN_PICK_U32(inject_rate_per_source);
    GN_PICK_U32(inject_rate_burst);
    GN_PICK_U32(inject_rate_lru_cap);
#undef GN_PICK_U32
#undef GN_PICK_U64
    return L;
}

gn_result_t Config::load_json(std::string_view json) {
    nlohmann::json parsed;
    try {
        /// nlohmann's `parse` accepts `(begin, end, callback,
        /// allow_exceptions, ignore_comments)`. The trailing flag
        /// strips `//` and `/* */` comments before structure
        /// validation — operators annotate config files routinely
        /// and a comment-strict parser is hostile to that.
        parsed = nlohmann::json::parse(
            json.begin(), json.end(),
            /*cb*/ nullptr,
            /*allow_exceptions*/ true,
            /*ignore_comments*/ true);
    } catch (const nlohmann::json::parse_error&) {
        return GN_ERR_INVALID_ENVELOPE;
    }
    if (!parsed.is_object()) return GN_ERR_INVALID_ENVELOPE;

    auto new_limits = parse_limits(parsed);

    /// Cross-field validation runs here, on the *new* limits the
    /// load is about to install — failure rolls the kernel state
    /// back to whatever the previous `load_json` left, so an
    /// operator who pushed a malformed config never sees the kernel
    /// running on it. The legacy split (`load_json` accepts → caller
    /// invokes `validate` → caller decides whether to recover) was
    /// brittle: nothing inside the kernel guaranteed the call.
    if (auto rc = validate_limits(new_limits, nullptr); rc != GN_OK) {
        return rc;
    }

    std::unique_lock lock(mu_);
    json_   = std::move(parsed);
    limits_ = new_limits;
    return GN_OK;
}

gn_result_t Config::validate(std::string* out_reason) const {
    std::shared_lock lock(mu_);
    return validate_limits(limits_, out_reason);
}

gn_result_t Config::validate_limits(const gn_limits_t& L,
                                     std::string* out_reason) {
    auto note = [&](const char* msg) {
        if (out_reason) *out_reason = msg;
    };

    if (L.max_outbound_connections > L.max_connections) {
        note("limits.max_outbound_connections > limits.max_connections");
        return GN_ERR_LIMIT_REACHED;
    }
    if (L.pending_queue_bytes_low == 0) {
        /// `low == 0` makes the falling-edge `BACKPRESSURE_CLEAR`
        /// publisher in every transport unable to fire — `post >= 0`
        /// is always true, so subscribers stay paused forever after
        /// the first `BACKPRESSURE_SOFT`. Per `backpressure.md` §3
        /// the threshold is positive.
        note("limits.pending_queue_bytes_low must be > 0");
        return GN_ERR_LIMIT_REACHED;
    }
    if (L.pending_queue_bytes_low >= L.pending_queue_bytes_high) {
        note("limits.pending_queue_bytes_low >= pending_queue_bytes_high");
        return GN_ERR_LIMIT_REACHED;
    }
    if (L.pending_queue_bytes_high > L.pending_queue_bytes_hard) {
        note("limits.pending_queue_bytes_high > pending_queue_bytes_hard");
        return GN_ERR_LIMIT_REACHED;
    }
    if (L.max_relay_ttl == 0 ||
        L.max_relay_ttl > GN_LIMITS_DEFAULT_MAX_RELAY_TTL_CEIL) {
        note("limits.max_relay_ttl out of range");
        return GN_ERR_LIMIT_REACHED;
    }
    if (L.max_storage_value_bytes > L.max_payload_bytes) {
        note("limits.max_storage_value_bytes > max_payload_bytes");
        return GN_ERR_LIMIT_REACHED;
    }
    /// `limits.md §3` invariant: a payload plus the fixed 14-byte
    /// GNET header must fit in one wire frame; otherwise a max-size
    /// payload accepted at the inject path produces a frame that
    /// the deframer rejects.
    constexpr std::uint32_t kGnetFixedHeaderBytes = 14;
    if (L.max_payload_bytes >
        L.max_frame_bytes - kGnetFixedHeaderBytes) {
        note("limits.max_payload_bytes + 14 > max_frame_bytes");
        return GN_ERR_LIMIT_REACHED;
    }
    /// Inject rate limiter: burst must cover at least half a second
    /// of refill so a momentary spike never starves the legitimate
    /// caller. With `rate=0` the bucket never refills (a valid
    /// "drain only" choice for tests) so the rate>0 guard is the
    /// right gate.
    if (L.inject_rate_per_source != 0 &&
        L.inject_rate_burst <
            (L.inject_rate_per_source + 1) / 2) {
        note("limits.inject_rate_burst < inject_rate_per_source / 2");
        return GN_ERR_LIMIT_REACHED;
    }
    if (L.inject_rate_per_source != 0 && L.inject_rate_burst == 0) {
        note("limits.inject_rate_burst must be > 0 when rate > 0");
        return GN_ERR_LIMIT_REACHED;
    }
    return GN_OK;
}

std::optional<nlohmann::json> Config::resolve(std::string_view dotted_key) const {
    std::shared_lock lock(mu_);
    const nlohmann::json* node = &json_;

    std::size_t start = 0;
    while (start <= dotted_key.size()) {
        std::size_t end = dotted_key.find('.', start);
        std::string_view seg = dotted_key.substr(
            start, end == std::string_view::npos ? std::string_view::npos : end - start);
        if (seg.empty()) return std::nullopt;
        if (!node->is_object()) return std::nullopt;
        auto it = node->find(std::string{seg});
        if (it == node->end()) return std::nullopt;
        if (end == std::string_view::npos) {
            return *it;
        }
        node = &(*it);
        start = end + 1;
    }
    return std::nullopt;
}

gn_result_t Config::get_string(std::string_view key, std::string& out) const {
    auto found = resolve(key);
    if (!found) return GN_ERR_NOT_FOUND;
    if (!found->is_string()) return GN_ERR_INVALID_ENVELOPE;
    out = found->get<std::string>();
    return GN_OK;
}

gn_result_t Config::get_int64(std::string_view key, std::int64_t& out) const {
    auto found = resolve(key);
    if (!found) return GN_ERR_NOT_FOUND;
    if (!found->is_number_integer()) return GN_ERR_INVALID_ENVELOPE;
    out = found->get<std::int64_t>();
    return GN_OK;
}

gn_result_t Config::get_bool(std::string_view key, bool& out) const {
    auto found = resolve(key);
    if (!found) return GN_ERR_NOT_FOUND;
    if (!found->is_boolean()) return GN_ERR_INVALID_ENVELOPE;
    out = found->get<bool>();
    return GN_OK;
}

gn_result_t Config::get_double(std::string_view key, double& out) const {
    auto found = resolve(key);
    if (!found) return GN_ERR_NOT_FOUND;
    /// Accept both integer and float literals — `is_number()` is
    /// the union check. Operators reach the same knob whether they
    /// write `1` or `1.0`, and the SDK consumer always sees a
    /// `double` regardless of the source-side spelling.
    if (!found->is_number()) return GN_ERR_INVALID_ENVELOPE;
    out = found->get<double>();
    return GN_OK;
}

gn_result_t Config::get_array_size(std::string_view key,
                                    std::size_t&     out) const {
    auto found = resolve(key);
    if (!found) return GN_ERR_NOT_FOUND;
    if (!found->is_array()) return GN_ERR_INVALID_ENVELOPE;
    out = found->size();
    return GN_OK;
}

gn_result_t Config::get_array_string(std::string_view key,
                                      std::size_t      index,
                                      std::string&     out) const {
    auto found = resolve(key);
    if (!found) return GN_ERR_NOT_FOUND;
    if (!found->is_array()) return GN_ERR_INVALID_ENVELOPE;
    if (index >= found->size()) return GN_ERR_OUT_OF_RANGE;
    const auto& element = (*found)[index];
    if (!element.is_string()) return GN_ERR_INVALID_ENVELOPE;
    out = element.get<std::string>();
    return GN_OK;
}

gn_result_t Config::get_array_int64(std::string_view key,
                                     std::size_t      index,
                                     std::int64_t&    out) const {
    auto found = resolve(key);
    if (!found) return GN_ERR_NOT_FOUND;
    if (!found->is_array()) return GN_ERR_INVALID_ENVELOPE;
    if (index >= found->size()) return GN_ERR_OUT_OF_RANGE;
    const auto& element = (*found)[index];
    if (!element.is_number_integer()) return GN_ERR_INVALID_ENVELOPE;
    out = element.get<std::int64_t>();
    return GN_OK;
}

gn_limits_t Config::limits() const noexcept {
    std::shared_lock lock(mu_);
    return limits_;
}

std::string Config::dump(int indent) const {
    std::shared_lock lock(mu_);
    return json_.dump(indent);
}

gn_result_t Config::merge_json(std::string_view overlay) {
    nlohmann::json patch;
    try {
        patch = nlohmann::json::parse(
            overlay.begin(), overlay.end(),
            /*cb*/ nullptr,
            /*allow_exceptions*/ true,
            /*ignore_comments*/ true);
    } catch (const nlohmann::json::parse_error&) {
        return GN_ERR_INVALID_ENVELOPE;
    }
    if (!patch.is_object()) return GN_ERR_INVALID_ENVELOPE;

    /// Build the merged document outside the lock so the parse +
    /// validate + limits-build cycle does not block readers. The
    /// `merge_patch` runs RFC 7396 deep-merge semantics: nested
    /// objects merge field-by-field, scalars and arrays replace
    /// the matching key wholesale.
    nlohmann::json merged;
    nlohmann::json prior;
    {
        std::shared_lock lock(mu_);
        merged = json_;
        prior  = json_;
    }
    merged.merge_patch(patch);

    auto new_limits = parse_limits(merged);
    if (auto rc = validate_limits(new_limits, nullptr); rc != GN_OK) {
        return rc;
    }

    /// Profile re-evaluation per `config.md` §3a — an overlay that
    /// carries `profile` switches the baseline that the limits
    /// derive from. Surface the change at warn level so an
    /// operator who only meant to nudge one field sees the
    /// baseline shift in the audit trail.
    const auto extract_profile = [](const nlohmann::json& doc) -> std::string {
        if (auto p = doc.find("profile"); p != doc.end() && p->is_string()) {
            return p->get<std::string>();
        }
        return "server";
    };
    const std::string prior_profile  = extract_profile(prior);
    const std::string merged_profile = extract_profile(merged);
    if (prior_profile != merged_profile) {
        SPDLOG_LOGGER_WARN(::gn::log::kernel().get(),
            "config.merge_json: profile changed '{}' -> '{}'; every "
            "limits.* field that the overlay does not set snaps to "
            "the new baseline (config.md §3a)",
            prior_profile, merged_profile);
    }

    std::unique_lock lock(mu_);
    json_   = std::move(merged);
    limits_ = new_limits;
    return GN_OK;
}

gn_result_t Config::load_file(const std::string& path) {
    /// Stream the file in once, hand the buffer to `load_json`.
    /// `std::ifstream` translation of file-open failure to a
    /// `fail()` flag avoids the throw-on-fail noise of the
    /// `exceptions(badbit)` configuration; the explicit `is_open`
    /// branch surfaces the missing-file case cleanly.
    std::ifstream in(path, std::ios::binary);
    if (!in.is_open()) {
        return GN_ERR_NOT_FOUND;
    }
    std::ostringstream buf;
    buf << in.rdbuf();
    if (in.bad()) {
        return GN_ERR_NOT_FOUND;
    }
    return load_json(buf.str());
}

} // namespace gn::core
