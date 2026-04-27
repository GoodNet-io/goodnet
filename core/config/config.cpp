/// @file   core/config/config.cpp
/// @brief  Implementation of the kernel Config holder.

#include "config.hpp"

#include <mutex>

namespace gn::core {

namespace {

/// Read a uint32_t field from a JSON object, falling back to @p def
/// when the field is missing or not a number.
std::uint32_t pick_u32(const nlohmann::json& obj, const char* field, std::uint32_t def) {
    auto it = obj.find(field);
    if (it == obj.end() || !it->is_number_integer()) return def;
    return it->get<std::uint32_t>();
}

std::uint64_t pick_u64(const nlohmann::json& obj, const char* field, std::uint64_t def) {
    auto it = obj.find(field);
    if (it == obj.end() || !it->is_number_integer()) return def;
    return it->get<std::uint64_t>();
}

gn_limits_t default_limits() noexcept {
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
    L.max_storage_table_entries   = GN_LIMITS_DEFAULT_MAX_STORAGE_TABLE_ENTRIES;
    L.max_storage_value_bytes     = L.max_payload_bytes;
    return L;
}

} // namespace

Config::Config() : json_(nlohmann::json::object()), limits_(default_limits()) {}

gn_limits_t Config::parse_limits(const nlohmann::json& root) {
    gn_limits_t L = default_limits();
    auto it = root.find("limits");
    if (it == root.end() || !it->is_object()) return L;
    const auto& obj = *it;
    L.max_connections           = pick_u32(obj, "max_connections",          L.max_connections);
    L.max_outbound_connections  = pick_u32(obj, "max_outbound_connections", L.max_outbound_connections);
    L.pending_queue_bytes_high  = pick_u32(obj, "pending_queue_bytes_high", L.pending_queue_bytes_high);
    L.pending_queue_bytes_low   = pick_u32(obj, "pending_queue_bytes_low",  L.pending_queue_bytes_low);
    L.pending_queue_bytes_hard  = pick_u32(obj, "pending_queue_bytes_hard", L.pending_queue_bytes_hard);
    L.max_frame_bytes           = pick_u32(obj, "max_frame_bytes",          L.max_frame_bytes);
    L.max_payload_bytes         = pick_u32(obj, "max_payload_bytes",        L.max_payload_bytes);
    L.max_handlers_per_msg_id   = pick_u32(obj, "max_handlers_per_msg_id",  L.max_handlers_per_msg_id);
    L.max_relay_ttl             = pick_u32(obj, "max_relay_ttl",            L.max_relay_ttl);
    L.max_plugins               = pick_u32(obj, "max_plugins",              L.max_plugins);
    L.max_extensions            = pick_u32(obj, "max_extensions",           L.max_extensions);
    L.max_storage_table_entries = pick_u64(obj, "max_storage_table_entries", L.max_storage_table_entries);
    L.max_storage_value_bytes   = pick_u64(obj, "max_storage_value_bytes",   L.max_storage_value_bytes);
    return L;
}

gn_result_t Config::load_json(std::string_view json) {
    nlohmann::json parsed;
    try {
        parsed = nlohmann::json::parse(json);
    } catch (const nlohmann::json::parse_error&) {
        return GN_ERR_INVALID_ENVELOPE;
    }
    if (!parsed.is_object()) return GN_ERR_INVALID_ENVELOPE;

    auto new_limits = parse_limits(parsed);

    std::unique_lock lock(mu_);
    json_   = std::move(parsed);
    limits_ = new_limits;
    return GN_OK;
}

gn_result_t Config::validate(std::string* out_reason) const {
    std::shared_lock lock(mu_);
    auto note = [&](const char* msg) {
        if (out_reason) *out_reason = msg;
    };

    if (limits_.max_outbound_connections > limits_.max_connections) {
        note("limits.max_outbound_connections > limits.max_connections");
        return GN_ERR_LIMIT_REACHED;
    }
    if (limits_.pending_queue_bytes_low >= limits_.pending_queue_bytes_high) {
        note("limits.pending_queue_bytes_low >= pending_queue_bytes_high");
        return GN_ERR_LIMIT_REACHED;
    }
    if (limits_.pending_queue_bytes_high > limits_.pending_queue_bytes_hard) {
        note("limits.pending_queue_bytes_high > pending_queue_bytes_hard");
        return GN_ERR_LIMIT_REACHED;
    }
    if (limits_.max_relay_ttl == 0 ||
        limits_.max_relay_ttl > GN_LIMITS_DEFAULT_MAX_RELAY_TTL_CEIL) {
        note("limits.max_relay_ttl out of range");
        return GN_ERR_LIMIT_REACHED;
    }
    if (limits_.max_storage_value_bytes > limits_.max_payload_bytes) {
        note("limits.max_storage_value_bytes > max_payload_bytes");
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
    if (!found) return GN_ERR_UNKNOWN_RECEIVER;
    if (!found->is_string()) return GN_ERR_INVALID_ENVELOPE;
    out = found->get<std::string>();
    return GN_OK;
}

gn_result_t Config::get_int64(std::string_view key, std::int64_t& out) const {
    auto found = resolve(key);
    if (!found) return GN_ERR_UNKNOWN_RECEIVER;
    if (!found->is_number_integer()) return GN_ERR_INVALID_ENVELOPE;
    out = found->get<std::int64_t>();
    return GN_OK;
}

gn_limits_t Config::limits() const noexcept {
    std::shared_lock lock(mu_);
    return limits_;
}

} // namespace gn::core
