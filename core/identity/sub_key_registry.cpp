/// @file   core/identity/sub_key_registry.cpp

#include "sub_key_registry.hpp"

#include <algorithm>
#include <cstring>
#include <utility>

namespace gn::core::identity {

gn_key_id_t SubKeyRegistry::insert(gn_key_purpose_t purpose,
                                    KeyPair&&        kp,
                                    std::string_view label,
                                    std::int64_t     created_unix_ts) {
    const auto id = encode_key_id(purpose, next_counter_++);
    SubKeyEntry e;
    e.id              = id;
    e.purpose         = purpose;
    e.kp              = std::move(kp);
    e.label.assign(label);
    e.created_unix_ts = created_unix_ts;
    entries_.push_back(std::move(e));
    return id;
}

bool SubKeyRegistry::erase(gn_key_id_t id) {
    auto it = std::find_if(entries_.begin(), entries_.end(),
                            [id](const SubKeyEntry& e) { return e.id == id; });
    if (it == entries_.end()) return false;
    /// `KeyPair` destructor zeroises the seed; the entry move
    /// from `entries_.back()` into the hole is safe because the
    /// trailing element is then popped.
    if (it != entries_.end() - 1) {
        *it = std::move(entries_.back());
    }
    entries_.pop_back();
    return true;
}

void SubKeyRegistry::snapshot(gn_key_descriptor_t* out,
                               std::size_t cap,
                               std::size_t* out_count) const {
    if (out_count) *out_count = entries_.size();
    if (!out || cap == 0) return;

    const std::size_t n = std::min(cap, entries_.size());
    for (std::size_t i = 0; i < n; ++i) {
        const auto& e = entries_[i];
        gn_key_descriptor_t& d = out[i];
        std::memset(&d, 0, sizeof(d));
        d.api_size        = sizeof(d);
        d.id              = e.id;
        d.purpose         = e.purpose;
        d.created_unix_ts = e.created_unix_ts;
        std::memcpy(d.public_key, e.kp.public_key().data(), GN_PUBLIC_KEY_BYTES);
        const auto label_n = std::min<std::size_t>(e.label.size(), sizeof(d.label) - 1);
        std::memcpy(d.label, e.label.data(), label_n);
        d.label[label_n] = '\0';
    }
}

const KeyPair* SubKeyRegistry::find_first_of_purpose(
    gn_key_purpose_t purpose) const noexcept {
    for (const auto& e : entries_) {
        if (e.purpose == purpose) return &e.kp;
    }
    return nullptr;
}

const KeyPair* SubKeyRegistry::find_by_id(gn_key_id_t id) const noexcept {
    for (const auto& e : entries_) {
        if (e.id == id) return &e.kp;
    }
    return nullptr;
}

} // namespace gn::core::identity
