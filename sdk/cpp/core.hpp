// SPDX-License-Identifier: Apache-2.0
/// @file   sdk/cpp/core.hpp
/// @brief  RAII wrapper around the `gn_core_t*` lifecycle.
///
/// The C ABI in `sdk/core.h` is intentionally flat: every step of
/// the create → init → load_plugins → start sequence is a separate
/// entry, every step can fail, every step needs the same
/// `gn_core_destroy` cleanup on failure. After the public-ABI
/// rewrite that landed in `e8aec77`, a hello-echo client carried
/// ten-plus lines of lifecycle boilerplate before its first
/// `connect_to` call.
///
/// `gn::sdk::Core` collapses that into one constructor. The default
/// ctor reads identity + manifest paths from the XDG config dir,
/// installs the identity, walks `init`, loads every plugin the
/// manifest lists, and runs `start`. Each failure path throws
/// `gn::sdk::Error` with a hint string so the caller does not have
/// to dig into `gn_result_t` documentation. The destructor stops
/// and destroys the kernel.
///
/// @code
/// gn::sdk::Core core;
/// auto session = core.connect_to("tcp://127.0.0.1:9100");
/// (void)session.send(payload);
/// @endcode
///
/// For tests or hosts that ship their own pinned identity / config,
/// construct via `Core{Options{...}}` and pass explicit paths.
///
/// The class is move-only; copy makes no sense (a `gn_core_t*` is
/// not refcounted).

#pragma once

#include <array>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <sdk/core.h>
#include <sdk/cpp/connect.hpp>
#include <sdk/cpp/subscription.hpp>
#include <sdk/host_api.h>
#include <sdk/types.h>

namespace gn::sdk {

/// Move-only RAII handle around a `gn_core_subscribe` token. The
/// dtor calls `gn_core_unsubscribe` and frees the captured
/// callback. Returned by `Core::subscribe`.
class MessageSubscription {
public:
    /// Callback shape. Receives the connection id the envelope
    /// came in on (so echo-style servers can reply on the same
    /// conn) plus the payload bytes. The msg id is implicit in the
    /// subscription filter.
    using Callback =
        std::function<void(gn_conn_id_t, std::span<const std::uint8_t>)>;

    /// Type-erased storage for the kernel's `user_data` block. The
    /// implementation lives in `core.cpp`; the header only sees the
    /// custom deleter signature so the unique_ptr lays out.
    using HolderDeleter = void (*)(void*);

    MessageSubscription() noexcept
        : holder_(nullptr, +[](void*){}) {}

    MessageSubscription(gn_core_t* core,
                        std::uint64_t token,
                        void* holder,
                        HolderDeleter deleter) noexcept
        : core_(core), token_(token), holder_(holder, deleter) {}

    MessageSubscription(const MessageSubscription&)            = delete;
    MessageSubscription& operator=(const MessageSubscription&) = delete;

    MessageSubscription(MessageSubscription&& o) noexcept
        : core_(o.core_),
          token_(o.token_),
          holder_(std::move(o.holder_)) {
        o.core_  = nullptr;
        o.token_ = 0;
    }
    MessageSubscription& operator=(MessageSubscription&& o) noexcept {
        if (this != &o) {
            release();
            core_   = o.core_;
            token_  = o.token_;
            holder_ = std::move(o.holder_);
            o.core_  = nullptr;
            o.token_ = 0;
        }
        return *this;
    }
    ~MessageSubscription() noexcept { release(); }

    [[nodiscard]] bool          valid() const noexcept {
        return token_ != 0 && core_ != nullptr;
    }
    [[nodiscard]] std::uint64_t token() const noexcept { return token_; }

private:
    void release() noexcept;

    gn_core_t*    core_  = nullptr;
    std::uint64_t token_ = 0;
    /// Type-erased holder for the kernel's `user_data` block — the
    /// `Callback` + the conn-id filter. Owned by this subscription
    /// so the kernel's pointer stays valid for the whole lifetime.
    std::unique_ptr<void, HolderDeleter> holder_;
};

class Core {
public:
    /// Per-`Core` configuration. Default-constructed values resolve
    /// against `$XDG_CONFIG_HOME/goodnet` (or `$HOME/.config/goodnet`
    /// when `XDG_CONFIG_HOME` is unset). The argument-less ctor
    /// fills this struct from the environment and forwards.
    struct PluginEntry {
        std::filesystem::path path;
        std::array<std::uint8_t, 32> sha256{};  // zero-filled = "compute it"
    };

    struct Options {
        /// Path to a `NodeIdentity::save_to_file` blob. When empty
        /// the kernel mints a fresh identity inside `gn_core_init`.
        std::filesystem::path identity_path;

        /// Path to a `plugins`-array manifest per
        /// `docs/contracts/plugin-manifest.en.md`. When empty no
        /// plugins are loaded through the manifest path — but the
        /// `plugins` vector below still applies. Useful for kernel-
        /// only tests.
        std::filesystem::path manifest_path;

        /// Pre-computed plugin set. Each entry's SHA-256 is sent
        /// straight to `gn_core_load_plugins_batch`; a zero-filled
        /// digest signals "compute over the file at .path on the
        /// fly", which is what tests / demos want when they already
        /// have a build-tree path. Concatenated with
        /// `manifest_path`-loaded entries when both are set.
        std::vector<PluginEntry> plugins;

        /// JSON config text handed to `gn_core_reload_config_json`
        /// before `gn_core_init`. Defaults to `"{}"`.
        std::string config_json{"{}"};
    };

    /// XDG-default ctor:
    ///   * identity   = `$XDG_CONFIG_HOME/goodnet/identity.bin`
    ///                  (skipped if the file does not exist — the
    ///                   kernel mints fresh)
    ///   * manifest   = `$XDG_CONFIG_HOME/goodnet/manifest.json`
    ///                  (skipped if absent)
    ///   * config     = `GOODNET_CONFIG_JSON` env or `"{}"`
    /// Throws `Error` on any kernel failure.
    Core();

    /// Explicit ctor: caller pins every path. The ctor body walks
    /// `gn_core_create` → `reload_config_json` (if non-empty) →
    /// `install_identity_from_file` (if set) → `gn_core_init` →
    /// `load_plugins_batch` (if a manifest is set) → `gn_core_start`.
    /// Each failure path throws `Error` carrying the step name and
    /// an actionable hint.
    explicit Core(Options opts);

    Core(const Core&)            = delete;
    Core& operator=(const Core&) = delete;
    Core(Core&& other) noexcept;
    Core& operator=(Core&& other) noexcept;

    /// Stops and destroys the kernel. No-op on a moved-from
    /// instance.
    ~Core();

    /// Escape hatch for `host_api_t`-shaped helpers (subscription
    /// constructors, extension queries, etc.). The returned table
    /// is owned by the kernel.
    [[nodiscard]] host_api_t* host_api() noexcept {
        // host_api_t* (non-const) is what every subscribe / send
        // helper expects; the C ABI hands back a const pointer to
        // the kernel-owned vtable, which is the same instance.
        return const_cast<host_api_t*>(api_);
    }

    /// Raw kernel handle for the few entries that do not have a
    /// C++-side wrapper yet (`gn_core_get_stats`, `gn_core_broadcast`,
    /// etc.).
    [[nodiscard]] gn_core_t* raw() noexcept { return core_; }

    /// Read the local node's Ed25519 public key. Throws `Error` if
    /// the kernel has no identity — should not happen after a
    /// successful ctor.
    struct PubKey {
        std::uint8_t bytes[GN_PUBLIC_KEY_BYTES]{};
    };
    [[nodiscard]] PubKey pubkey() const;

    /// One-call dial: parses the URI scheme, queries the matching
    /// `gn.link.<scheme>` extension, and returns a `ConnectedSession`
    /// that owns the carrier + conn id. Throws `Error` on failure.
    [[nodiscard]] ConnectedSession connect_to(std::string_view uri);

    /// One-call bind. Returns the listener carrier; caller installs
    /// `on_accept` to react to inbound connections. Throws on
    /// failure.
    [[nodiscard]] LinkCarrier listen_to(std::string_view uri);

    /// Subscribe to inbound messages on @p msg for connection @p conn.
    /// Returns a `MessageSubscription` whose dtor cancels the
    /// subscription. Throws `Error` on registration failure.
    [[nodiscard]] MessageSubscription subscribe(
        gn_conn_id_t conn,
        std::uint32_t msg,
        MessageSubscription::Callback cb);

    /// Send @p payload on connection @p conn under message id
    /// @p msg. Pass-through to `gn_core_send_to`. Throws `Error` on
    /// failure.
    void send_to(gn_conn_id_t conn,
                  std::uint32_t msg,
                  std::span<const std::uint8_t> payload);

    /// Block until `gn_core_stop` fires. Useful as the main-thread
    /// idle wait in single-threaded hosts. The dtor will not block
    /// — call `wait()` explicitly when you want to hold the thread.
    void wait();

private:
    gn_core_t*        core_ = nullptr;
    const host_api_t* api_  = nullptr;
};

}  // namespace gn::sdk
