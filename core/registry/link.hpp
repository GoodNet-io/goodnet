/// @file   core/registry/link.hpp
/// @brief  Scheme → transport vtable lookup.
///
/// Per `host-api.md` §6 a scheme is unique across loaded transports.
/// `register_link` rejects duplicates with `GN_ERR_DUPLICATE`.
/// Lookups are O(1) under a shared mutex; concurrent senders do not
/// contend on writers when no transport is being (un)registered.

#pragma once

#include <atomic>
#include <cstdint>
#include <memory>
#include <optional>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <unordered_map>

#include <sdk/link.h>
#include <sdk/types.h>

namespace gn::core {

/// One row in the transport registry. Holds the plugin-supplied
/// vtable and the opaque self pointer that goes back as the first
/// argument to every vtable call.
struct LinkEntry {
    gn_link_id_t            id              = GN_INVALID_ID;
    std::string                  scheme;
    const gn_link_vtable_t* vtable          = nullptr;
    void*                        self            = nullptr;

    /// Same shape as `HandlerEntry::lifetime_anchor`. Snapshots
    /// returned by `find_by_*` value-copy the anchor so the transport
    /// stays mapped while the caller is dereferencing the vtable
    /// pointer.
    std::shared_ptr<void>        lifetime_anchor;
};

class LinkRegistry {
public:
    LinkRegistry()                                    = default;
    LinkRegistry(const LinkRegistry&)            = delete;
    LinkRegistry& operator=(const LinkRegistry&) = delete;

    /// Register a transport for @p scheme. Fails with
    /// `GN_ERR_LIMIT_REACHED` if the scheme is already taken.
    /// @p lifetime_anchor mirrors `HandlerRegistry::register_handler`.
    [[nodiscard]] gn_result_t register_link(std::string_view scheme,
                                                 const gn_link_vtable_t* vtable,
                                                 void* self,
                                                 gn_link_id_t* out_id,
                                                 std::shared_ptr<void> lifetime_anchor = {}) noexcept;

    [[nodiscard]] gn_result_t unregister_link(gn_link_id_t id) noexcept;

    /// Find the transport entry matching @p scheme. Returns a value
    /// snapshot so the lookup releases the lock before the caller
    /// dereferences vtable / self.
    [[nodiscard]] std::optional<LinkEntry> find_by_scheme(std::string_view scheme) const;

    /// Find by allocated id; useful for unregister and metric paths.
    [[nodiscard]] std::optional<LinkEntry> find_by_id(gn_link_id_t id) const;

    [[nodiscard]] std::size_t size() const noexcept;

private:
    mutable std::shared_mutex                       mu_;
    std::unordered_map<std::string, LinkEntry> by_scheme_;
    std::unordered_map<gn_link_id_t, std::string> by_id_;

    std::atomic<gn_link_id_t> next_id_{1};
};

} // namespace gn::core
