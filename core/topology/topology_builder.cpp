/// @file   core/topology/topology_builder.cpp

#include "topology_builder.hpp"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

#include <sodium.h>

#include <sdk/extensions/link.h>
#include <sdk/security.h>
#include <sdk/topology.h>
#include <sdk/trust.h>

#include <core/kernel/kernel.hpp>
#include <core/kernel/safe_invoke.hpp>
#include <core/registry/handler.hpp>
#include <core/registry/link.hpp>
#include <core/registry/protocol_layer.hpp>
#include <core/registry/security.hpp>

namespace gn::core::topology {

namespace {

// Append a LE-encoded uint32 to the running SHA-256 state.
void sha_u32(crypto_hash_sha256_state& st, std::uint32_t v) noexcept {
    const uint8_t b[4] = {
        static_cast<uint8_t>(v),
        static_cast<uint8_t>(v >> 8),
        static_cast<uint8_t>(v >> 16),
        static_cast<uint8_t>(v >> 24),
    };
    crypto_hash_sha256_update(&st, b, sizeof(b));
}

// Append a NUL-terminated string to the running SHA-256 state.
void sha_str(crypto_hash_sha256_state& st, const char* s) noexcept {
    if (s) {
        crypto_hash_sha256_update(&st,
            reinterpret_cast<const unsigned char*>(s), std::strlen(s) + 1);
    } else {
        const uint8_t nul = 0;
        crypto_hash_sha256_update(&st, &nul, 1);
    }
}

void compute_fingerprint(TopologySnapshot* snap) noexcept {
    crypto_hash_sha256_state st;
    crypto_hash_sha256_init(&st);

    // Section 0x01: links (already sorted by scheme)
    const uint8_t tag_link = 0x01;
    crypto_hash_sha256_update(&st, &tag_link, 1);
    for (const auto& e : snap->link_entries) {
        sha_str(st, e.scheme);
        sha_u32(st, e.caps_flags);
        sha_u32(st, e.max_payload);
    }

    // Section 0x02: security (already sorted by provider_id)
    const uint8_t tag_sec = 0x02;
    crypto_hash_sha256_update(&st, &tag_sec, 1);
    for (const auto& e : snap->sec_entries) {
        sha_str(st, e.provider_id);
        sha_u32(st, e.allowed_trust_mask);
        sha_u32(st, e.provides_flags);
    }

    // Section 0x03: protocols (already sorted by protocol_id)
    const uint8_t tag_proto = 0x03;
    crypto_hash_sha256_update(&st, &tag_proto, 1);
    for (const auto& e : snap->proto_entries) {
        sha_str(st, e.protocol_id);
    }

    // Section 0x04: handlers (already sorted by (protocol_id, msg_id))
    const uint8_t tag_hdlr = 0x04;
    crypto_hash_sha256_update(&st, &tag_hdlr, 1);
    for (const auto& e : snap->handler_entries) {
        sha_str(st, e.protocol_id);
        sha_u32(st, e.msg_id);
        sha_u32(st, e.chain_length);
    }

    crypto_hash_sha256_final(&st,
        reinterpret_cast<unsigned char*>(snap->topo.fingerprint));
}

} // namespace

std::unique_ptr<TopologySnapshot> build_topology(gn::core::Kernel& kernel) {
    auto snap = std::make_unique<TopologySnapshot>();

    // ── 1. Link entries ────────────────────────────────────────────────
    auto links = kernel.links().snapshot();
    std::sort(links.begin(), links.end(),
        [](const LinkEntry& a, const LinkEntry& b) {
            return a.scheme < b.scheme;
        });

    snap->link_scheme_storage.reserve(links.size());
    for (const auto& le : links) {
        snap->link_scheme_storage.push_back(le.scheme);
    }

    snap->link_entries.reserve(links.size());
    for (std::size_t i = 0; i < links.size(); ++i) {
        const auto& le = links[i];
        gn_topo_link_entry_t entry{};
        entry.scheme = snap->link_scheme_storage[i].c_str();

        // Query link capabilities via the gn.link.<scheme> extension vtable.
        if (le.vtable && le.vtable->extension_vtable) {
            const auto* raw = le.vtable->extension_vtable(le.self);
            if (raw) {
                const auto* lapi = static_cast<const gn_link_api_t*>(raw);
                if (GN_API_HAS(gn_link_api_t, lapi, get_capabilities) &&
                    lapi->get_capabilities) {
                    gn_link_caps_t caps{};
                    if (lapi->get_capabilities(lapi->ctx, &caps) == GN_OK) {
                        entry.caps_flags  = caps.flags;
                        entry.max_payload = caps.max_payload;
                    }
                }
            }
        }
        snap->link_entries.push_back(entry);
    }

    // ── 2. Security entries ────────────────────────────────────────────
    auto sec = kernel.security().snapshot();
    std::sort(sec.begin(), sec.end(),
        [](const SecurityEntry& a, const SecurityEntry& b) {
            return a.provider_id < b.provider_id;
        });

    snap->sec_id_storage.reserve(sec.size());
    for (const auto& se : sec) {
        snap->sec_id_storage.push_back(se.provider_id);
    }

    snap->sec_entries.reserve(sec.size());
    for (std::size_t i = 0; i < sec.size(); ++i) {
        gn_topo_security_entry_t entry{};
        entry.provider_id        = snap->sec_id_storage[i].c_str();
        entry.allowed_trust_mask = sec[i].trust_mask();
        entry.provides_flags     = sec[i].provides_flags();
        snap->sec_entries.push_back(entry);
    }

    // ── 3. Protocol entries ────────────────────────────────────────────
    auto protos = kernel.protocol_layers().snapshot();
    std::sort(protos.begin(), protos.end(),
        [](const ProtocolLayerEntry& a, const ProtocolLayerEntry& b) {
            return a.protocol_id < b.protocol_id;
        });

    snap->proto_id_storage.reserve(protos.size());
    for (const auto& pe : protos) {
        snap->proto_id_storage.push_back(pe.protocol_id);
    }

    snap->proto_entries.reserve(protos.size());
    for (std::size_t i = 0; i < protos.size(); ++i) {
        gn_topo_protocol_entry_t entry{};
        entry.protocol_id = snap->proto_id_storage[i].c_str();
        snap->proto_entries.push_back(entry);
    }

    // ── 4. Handler pairs ───────────────────────────────────────────────
    auto pairs = kernel.handlers().enumerate_pairs();
    // enumerate_pairs returns sorted by (protocol_id, msg_id) already.
    // Re-sort for guaranteed order (sort is stable anyway).
    std::sort(pairs.begin(), pairs.end(),
        [](const HandlerRegistry::HandlerPairInfo& a,
           const HandlerRegistry::HandlerPairInfo& b) {
            if (a.protocol_id != b.protocol_id) return a.protocol_id < b.protocol_id;
            return a.msg_id < b.msg_id;
        });

    snap->handler_proto_id_storage.reserve(pairs.size());
    for (const auto& hp : pairs) {
        snap->handler_proto_id_storage.push_back(hp.protocol_id);
    }

    snap->handler_entries.reserve(pairs.size());
    for (std::size_t i = 0; i < pairs.size(); ++i) {
        gn_topo_handler_entry_t entry{};
        entry.protocol_id  = snap->handler_proto_id_storage[i].c_str();
        entry.msg_id       = pairs[i].msg_id;
        entry.chain_length = static_cast<std::uint32_t>(pairs[i].chain_length);
        snap->handler_entries.push_back(entry);
    }

    // ── 5. Wire up view struct ─────────────────────────────────────────
    auto& topo          = snap->topo;
    topo.link_count     = static_cast<std::uint32_t>(snap->link_entries.size());
    topo.security_count = static_cast<std::uint32_t>(snap->sec_entries.size());
    topo.protocol_count = static_cast<std::uint32_t>(snap->proto_entries.size());
    topo.handler_count  = static_cast<std::uint32_t>(snap->handler_entries.size());
    topo.links          = snap->link_entries.empty()    ? nullptr : snap->link_entries.data();
    topo.security       = snap->sec_entries.empty()     ? nullptr : snap->sec_entries.data();
    topo.protocols      = snap->proto_entries.empty()   ? nullptr : snap->proto_entries.data();
    topo.handlers       = snap->handler_entries.empty() ? nullptr : snap->handler_entries.data();

    // ── 6. Contour gaps ────────────────────────────────────────────────
    // LINK_ENCRYPTED trust class is covered when any link advertises
    // ENCRYPTED_PATH AND a security provider allows that trust class
    // (the link-only provider, provides_flags=0 but link layer has crypto).
    const bool any_encrypted_link = [&]() {
        for (const auto& le : snap->link_entries) {
            if (le.caps_flags & GN_LINK_CAP_ENCRYPTED_PATH) return true;
        }
        return false;
    }();

    std::uint32_t gaps = 0;
    for (unsigned t = 0; t <= static_cast<unsigned>(GN_TRUST_LINK_ENCRYPTED); ++t) {
        const std::uint32_t class_bit = 1u << t;
        bool covered = false;
        if (t == static_cast<unsigned>(GN_TRUST_LINK_ENCRYPTED)) {
            // Covered when link layer provides encryption and a provider
            // (link-only) is registered for this trust class.
            if (any_encrypted_link) {
                for (const auto& se : snap->sec_entries) {
                    if (se.allowed_trust_mask & class_bit) {
                        covered = true;
                        break;
                    }
                }
            }
        } else {
            for (const auto& se : snap->sec_entries) {
                if ((se.provides_flags & GN_SEC_PROVIDES_E2E_ENCRYPTION) &&
                    (se.allowed_trust_mask & class_bit)) {
                    covered = true;
                    break;
                }
            }
        }
        if (!covered) gaps |= class_bit;
    }
    topo.contour_gaps = gaps;

    // ── 7. Fingerprint ─────────────────────────────────────────────────
    compute_fingerprint(snap.get());

    // ── 8. Notify link plugins ─────────────────────────────────────────
    for (const auto& le : links) {
        if (!le.vtable) continue;
        if (!GN_API_HAS(gn_link_vtable_t, le.vtable, on_topology_sealed)) continue;
        if (!le.vtable->on_topology_sealed) continue;
        safe_call_void("link.on_topology_sealed",
            le.vtable->on_topology_sealed, le.self, &topo);
    }

    return snap;
}

std::vector<std::uint8_t> encode_topology_wire_blob(const gn_topology_t& topo) {
    // [8-byte BE expiry = INT64_MAX] [TLV: type=0x0004 len=32 value=fingerprint]
    constexpr std::size_t kFpLen = 32;
    std::vector<std::uint8_t> out;
    out.reserve(8 + 4 + kFpLen);

    // expiry = INT64_MAX (valid for kernel lifetime)
    constexpr std::uint64_t kExpiry = static_cast<std::uint64_t>(INT64_MAX);
    for (int i = 7; i >= 0; --i)
        out.push_back(static_cast<std::uint8_t>((kExpiry >> (i * 8)) & 0xFFu));

    // TLV header: type=0x0004, length=32
    out.push_back(0x00); out.push_back(0x04); // type BE
    out.push_back(0x00); out.push_back(0x20); // length = 32 BE

    // fingerprint value
    out.insert(out.end(), topo.fingerprint, topo.fingerprint + kFpLen);
    return out;
}

} // namespace gn::core::topology
