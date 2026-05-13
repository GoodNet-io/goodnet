/// @file   core/plugin/remote_host.hpp
/// @brief  Kernel-side spawner + framing driver for subprocess
///         plugins. Mirrors the dlopen path's two-phase activation
///         over the wire protocol pinned in `sdk/remote/wire.h`.
///
/// One `RemoteHost` instance owns one worker process: the spawn
/// socketpair, the reader thread, the pending-request correlator,
/// the synthetic vtables registered on behalf of the worker. The
/// kernel reaches the worker the same way it reaches an in-process
/// plugin — `call_init / call_register / call_unregister /
/// call_shutdown` — except every entry-point invocation becomes a
/// `GN_WIRE_PLUGIN_CALL` frame that the worker's stub library
/// dispatches into the real plugin code on its side.
///
/// Worker callbacks back into `host_api_t` arrive as
/// `GN_WIRE_HOST_CALL` frames; the reader thread decodes the slot
/// id (`sdk/remote/slots.h`), invokes the corresponding slot on the
/// real `host_api_t` the kernel built for this plugin, then writes
/// a `GN_WIRE_HOST_REPLY` back.

#pragma once

#include <atomic>
#include <cstdint>
#include <future>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <vector>

#include <sys/types.h>

#include <sdk/host_api.h>
#include <sdk/plugin.h>
#include <sdk/types.h>

namespace gn::core {

struct PluginContext;

/// Spawn + drive a single worker subprocess over `sdk/remote/wire.h`.
///
/// Lifetime invariants:
///   • `spawn` is called once per instance. It performs HELLO /
///     HELLO_ACK before returning; subsequent calls fail.
///   • The reader thread is created inside `spawn` and stays live
///     until `terminate()` (or destructor) joins it.
///   • All public call methods are safe to call from the kernel's
///     dispatcher threads — they serialise writes through a mutex.
///   • The synthesised link vtable (returned by `link_vtable_proxy`)
///     issues `PLUGIN_CALL` frames; the worker side dispatches them
///     into the worker-provided real vtable.
class RemoteHost {
public:
    RemoteHost() = default;
    ~RemoteHost();

    RemoteHost(const RemoteHost&)            = delete;
    RemoteHost& operator=(const RemoteHost&) = delete;

    /// Spawn a worker subprocess at @p worker_path with @p args.
    /// The kernel side keeps @p kernel_host_api as the real
    /// `host_api_t` that `HOST_CALL` frames dispatch into.
    /// Returns `GN_OK` after the HELLO/HELLO_ACK handshake completes;
    /// any failure (fork, socketpair, HELLO timeout, SDK major
    /// mismatch) returns the corresponding code and leaves the
    /// instance in a non-spawned state.
    [[nodiscard]] gn_result_t spawn(const std::string& worker_path,
                                    std::span<const std::string> args,
                                    PluginContext& ctx,
                                    host_api_t kernel_host_api,
                                    std::string& diagnostic);

    /// Issue `PLUGIN_CALL` for the four lifecycle entry-points.
    /// Mirror semantics of the dlopen path; @p out_self_handle
    /// receives the worker-side `self` opaque (a u64 encoded as
    /// `void*` for storage parity).
    [[nodiscard]] gn_result_t call_init(void** out_self_handle);
    [[nodiscard]] gn_result_t call_register(std::uint64_t self_handle);
    [[nodiscard]] gn_result_t call_unregister(std::uint64_t self_handle);
    void call_shutdown(std::uint64_t self_handle);

    /// Send `GN_WIRE_GOODBYE`, join the reader thread, reap the
    /// child. Idempotent. Called from the destructor too.
    void terminate() noexcept;

    /// Descriptor reported by the worker in its HELLO frame. The
    /// returned pointer is owned by this `RemoteHost`; valid until
    /// `terminate()` runs.
    [[nodiscard]] const gn_plugin_descriptor_t* descriptor() const noexcept {
        return &descriptor_;
    }

    /// Synthetic link vtable wired to the worker's link plugin via
    /// the wire. The worker reports its kind in HELLO; non-link
    /// kinds return nullptr. Slot count matches the in-process
    /// `gn_link_vtable_t`; every slot writes a `PLUGIN_CALL`,
    /// awaits the matching `PLUGIN_REPLY`, and returns the decoded
    /// `gn_result_t`. The vtable's `self` field is the synthetic
    /// `self_handle` returned by `call_init`.
    [[nodiscard]] const gn_link_vtable_t* link_vtable_proxy() noexcept;

    /// Timeout for a single `PLUGIN_CALL` round trip. Default 5s.
    /// Tests override to enforce timeout coverage.
    void set_reply_timeout(std::chrono::milliseconds t) noexcept {
        reply_timeout_ = t;
    }

    /// Number of completed round-trip `PLUGIN_CALL` exchanges.
    /// Tests assert non-zero to confirm the wire is live.
    [[nodiscard]] std::size_t round_trips() const noexcept {
        return round_trips_.load(std::memory_order_relaxed);
    }

    using PayloadVec = std::vector<std::uint8_t>;

    /// Result of a single PLUGIN_CALL: flags from the reply header
    /// (`GN_WIRE_FLAG_ERROR` bit communicates error) and the CBOR
    /// payload bytes. Public so the synthesised link vtable's
    /// per-slot thunks (defined in the .cpp's anonymous namespace)
    /// can construct one and pass it through `round_trip_for_proxy`.
    struct ReplyResult {
        std::uint32_t flags{0};
        PayloadVec    payload;
    };

    /// Public bridge for the synthesised vtable thunks. Wraps the
    /// private `round_trip_` so callers outside the class can route
    /// PLUGIN_CALL through the wire. Identical contract.
    [[nodiscard]] gn_result_t round_trip_for_proxy(std::uint32_t slot_id,
                                                    const PayloadVec& args,
                                                    ReplyResult& out) {
        return round_trip_(slot_id, args, out);
    }

    /// Public read of the worker's self_handle so the proxy thunks
    /// can echo it on every PLUGIN_CALL.
    [[nodiscard]] std::uint64_t worker_self_handle_for_proxy() const noexcept {
        return worker_self_handle_;
    }

private:

    /// Reader-thread main: spin on `read_frame_`, dispatch by kind.
    void reader_loop_();

    /// Read exactly N bytes from `fd_` into @p out. Returns false on
    /// EOF / error / shutdown — the reader treats any false as a
    /// terminal condition.
    [[nodiscard]] bool read_exact_(std::uint8_t* out, std::size_t n);

    /// Write a header+payload pair in a single `writev` syscall so
    /// the reader on the other side never sees a torn frame. Mutex-
    /// guarded; the reader thread also writes (HOST_REPLY).
    [[nodiscard]] gn_result_t write_frame_(std::uint32_t kind,
                                           std::uint32_t request_id,
                                           std::uint32_t flags,
                                           std::span<const std::uint8_t> payload);

    /// Marshal a PLUGIN_CALL, wait for its reply, return the result.
    [[nodiscard]] gn_result_t round_trip_(std::uint32_t slot_id,
                                          const PayloadVec& args,
                                          ReplyResult& out);

    /// Dispatch a HOST_CALL frame the reader just decoded.
    void handle_host_call_(std::uint32_t request_id,
                            std::span<const std::uint8_t> payload);

    /// Satisfy a pending future with a reply.
    void deliver_reply_(std::uint32_t request_id,
                         std::uint32_t flags,
                         std::span<const std::uint8_t> payload);

    /// Reader-thread shutdown helper — drain every pending future
    /// with an error reply so the calling thread does not block
    /// forever on a dead worker.
    void fail_pending_(gn_result_t code, const char* message) noexcept;

    /// Encode an error reply payload: CBOR map `{ "code": <i64>,
    /// "message": <text> }`. Used by `handle_host_call_` when a
    /// host slot returns a non-OK result.
    static void encode_error_(PayloadVec& out, gn_result_t code,
                              std::string_view message);

    int                              fd_{-1};
    ::pid_t                          pid_{-1};
    std::thread                      reader_;
    std::atomic<bool>                stopping_{false};
    std::atomic<bool>                spawned_{false};
    std::mutex                       write_mu_;
    std::atomic<std::uint32_t>       next_request_id_{1};
    std::atomic<std::size_t>         round_trips_{0};
    std::chrono::milliseconds        reply_timeout_{std::chrono::seconds{5}};

    PluginContext*                   ctx_{nullptr};
    host_api_t                       kernel_host_api_{};
    gn_plugin_descriptor_t           descriptor_{};
    std::string                      descriptor_name_storage_;
    std::string                      descriptor_version_storage_;
    gn_plugin_kind_t                 worker_kind_{GN_PLUGIN_KIND_UNKNOWN};
    std::uint64_t                    worker_self_handle_{0};

    struct Pending {
        std::promise<ReplyResult>    result;
    };
    std::mutex                       pending_mu_;
    std::unordered_map<std::uint32_t, Pending> pending_;

    std::unique_ptr<gn_link_vtable_t> link_vtable_storage_;

    /// Packed id returned by `host_api.register_vtable` when the
    /// kernel publishes the link proxy on behalf of a remote link
    /// worker. Captured during `call_register` and replayed through
    /// `unregister_vtable` during `call_unregister` so the link
    /// registry sees a tidy register/unregister pair.
    std::uint64_t registered_link_id_{0};
};

}  // namespace gn::core
