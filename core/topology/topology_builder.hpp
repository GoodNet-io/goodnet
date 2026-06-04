/// @file   core/topology/topology_builder.hpp
/// @brief  Kernel topology snapshot builder.
///
/// `build_topology` reads all registry snapshots, sorts entries
/// deterministically, computes the SHA-256 fingerprint, and calls
/// `on_topology_sealed` on every registered link plugin.

#pragma once

#include <memory>
#include <string>
#include <vector>

#include <sdk/topology.h>

namespace gn::core {
class Kernel;
}

namespace gn::core::topology {

/// Owning store for a topology snapshot.
///
/// `topo` is the C-ABI view struct; all its pointer fields point into
/// the storage vectors below. The struct is stable as long as the
/// `TopologySnapshot` object is alive — no reallocation happens after
/// `build_topology` returns.
struct TopologySnapshot {
    // String storage — c_str() pointers inside entry structs point here.
    std::vector<std::string> link_scheme_storage;
    std::vector<std::string> sec_id_storage;
    std::vector<std::string> proto_id_storage;
    std::vector<std::string> handler_proto_id_storage;

    // C-struct entry arrays.
    std::vector<gn_topo_link_entry_t>      link_entries;
    std::vector<gn_topo_security_entry_t>  sec_entries;
    std::vector<gn_topo_protocol_entry_t>  proto_entries;
    std::vector<gn_topo_handler_entry_t>   handler_entries;

    // View struct with borrowed pointers into the vectors above.
    gn_topology_t topo{};
};

/// Build a topology snapshot from the current kernel registry state.
///
/// Snapshots all registries, sorts entries deterministically, queries
/// link capabilities through `extension_vtable`, computes the SHA-256
/// fingerprint, fills `contour_gaps`, and calls `on_topology_sealed`
/// on every registered link plugin (guarded with GN_API_HAS).
///
/// Called once by `gn_core_start` and again on explicit
/// `gn_core_reload_topology`.
[[nodiscard]] std::unique_ptr<TopologySnapshot> build_topology(gn::core::Kernel& kernel);

/// Encode the topology fingerprint as a capability wire blob:
///   [8-byte BE expiry = INT64_MAX] [TLV 0x0004: fingerprint[32]]
///
/// The result is ready to pass to the send path (frame + encrypt + send)
/// with msg_id = kCapabilityBlobMsgId (0x13). expiry = INT64_MAX signals
/// that the fingerprint is valid for the kernel's lifetime.
[[nodiscard]] std::vector<std::uint8_t>
encode_topology_wire_blob(const gn_topology_t& topo);

} // namespace gn::core::topology
