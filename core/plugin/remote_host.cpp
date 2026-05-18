/// @file   core/plugin/remote_host.cpp
/// @brief  Implementation of `RemoteHost`. See `remote_host.hpp`
///         for the contract and `docs/contracts/remote-plugin.en.md`
///         for the wire protocol.

#include <core/plugin/remote_host.hpp>

#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <utility>

#include <sdk/link.h>
#include <sdk/remote/slots.h>
#include <sdk/remote/wire.h>

#include <core/kernel/plugin_context.hpp>
#include <core/plugin/wire_codec.hpp>

#if defined(_WIN32)

// Windows subprocess host: stub. The POSIX implementation below
// (socketpair + fork + execve + writev + waitpid) maps to Win32
// CreateProcess + named-pipe pair + OVERLAPPED I/O — that port is
// tracked separately. Until then `RemoteHost::spawn` reports
// `GN_ERR_NOT_IMPLEMENTED` so `PluginManager` falls back from
// `kind: remote` plugins gracefully; `manifest` and `static` plugin
// modes remain fully functional on Windows.
namespace gn::core {

RemoteHost::~RemoteHost() = default;

gn_result_t RemoteHost::spawn(const std::string&,
                              std::span<const std::string>,
                              PluginContext&,
                              host_api_t,
                              std::string& diagnostic) {
    diagnostic = "RemoteHost::spawn: subprocess plugin runtime is "
                 "POSIX-only; Windows port pending";
    return GN_ERR_NOT_IMPLEMENTED;
}

gn_result_t RemoteHost::call_init(void** out)              { if (out) *out = nullptr; return GN_ERR_NOT_IMPLEMENTED; }
gn_result_t RemoteHost::call_register(std::uint64_t)       { return GN_ERR_NOT_IMPLEMENTED; }
gn_result_t RemoteHost::call_unregister(std::uint64_t)     { return GN_ERR_NOT_IMPLEMENTED; }
void        RemoteHost::call_shutdown(std::uint64_t)       {}
void        RemoteHost::terminate() noexcept               {}

const gn_link_vtable_t* RemoteHost::link_vtable_proxy() noexcept { return nullptr; }
const gn_security_provider_vtable_t* RemoteHost::security_vtable_proxy() noexcept { return nullptr; }
const gn_handler_vtable_t* RemoteHost::handler_vtable_proxy() noexcept { return nullptr; }

void RemoteHost::reader_loop_()                                                       {}
bool RemoteHost::read_exact_(std::uint8_t*, std::size_t)                              { return false; }
gn_result_t RemoteHost::write_frame_(std::uint32_t, std::uint32_t, std::uint32_t,
                                     std::span<const std::uint8_t>)                  { return GN_ERR_NOT_IMPLEMENTED; }
gn_result_t RemoteHost::round_trip_(std::uint32_t, const PayloadVec&, ReplyResult&)  { return GN_ERR_NOT_IMPLEMENTED; }
void RemoteHost::handle_host_call_(std::uint32_t, std::span<const std::uint8_t>)     {}
void RemoteHost::deliver_reply_(std::uint32_t, std::uint32_t,
                                 std::span<const std::uint8_t>)                       {}
void RemoteHost::fail_pending_(gn_result_t, const char*) noexcept                    {}
void RemoteHost::encode_error_(PayloadVec&, gn_result_t, std::string_view)           {}

void RemoteHost::set_reply_timeout_for_slot(std::uint16_t slot_id,
                                            std::chrono::milliseconds t) {
    std::lock_guard<std::mutex> lk(timeout_overrides_mu_);
    timeout_overrides_[slot_id] = t;
}

void RemoteHost::clear_reply_timeout_overrides() {
    std::lock_guard<std::mutex> lk(timeout_overrides_mu_);
    timeout_overrides_.clear();
}

}  // namespace gn::core

#else  // POSIX path

#include <fcntl.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

extern "C" char** environ;

namespace gn::core {

namespace {

constexpr int kWorkerSocketFd = 3;

// Read the four-uint32 little-endian header into the typed struct.
void parse_header(const std::uint8_t buf[16],
                  gn_wire_frame_t& out) noexcept {
    std::memcpy(&out.kind,         buf + 0,  4);
    std::memcpy(&out.request_id,   buf + 4,  4);
    std::memcpy(&out.payload_size, buf + 8,  4);
    std::memcpy(&out.flags,        buf + 12, 4);
}

void serialise_header(const gn_wire_frame_t& f,
                      std::uint8_t out[16]) noexcept {
    std::memcpy(out + 0,  &f.kind,         4);
    std::memcpy(out + 4,  &f.request_id,   4);
    std::memcpy(out + 8,  &f.payload_size, 4);
    std::memcpy(out + 12, &f.flags,        4);
}

}  // namespace

RemoteHost::~RemoteHost() {
    terminate();
}

gn_result_t RemoteHost::spawn(const std::string& worker_path,
                              std::span<const std::string> args,
                              PluginContext& ctx,
                              host_api_t kernel_host_api,
                              std::string& diagnostic) {
    if (spawned_.load(std::memory_order_acquire)) {
        diagnostic = "RemoteHost::spawn called twice";
        return GN_ERR_INVALID_STATE;
    }

    // Writing to a closed peer raises SIGPIPE by default. The
    // RemoteHost survives transient worker death by ignoring it and
    // surfacing EPIPE through the normal error path. Idempotent.
    static const bool sigpipe_ignored = []() {
        struct ::sigaction sa{};
        sa.sa_handler = SIG_IGN;
        ::sigemptyset(&sa.sa_mask);
        ::sigaction(SIGPIPE, &sa, nullptr);
        return true;
    }();
    (void)sigpipe_ignored;

    int fds[2];
    if (::socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) {
        diagnostic = "socketpair failed: ";
        diagnostic += std::strerror(errno);
        return GN_ERR_INTERNAL;
    }

    ::pid_t pid = ::fork();
    if (pid < 0) {
        const int saved = errno;
        ::close(fds[0]);
        ::close(fds[1]);
        diagnostic = "fork failed: ";
        diagnostic += std::strerror(saved);
        return GN_ERR_INTERNAL;
    }

    if (pid == 0) {
        // Child: parent end goes away; child end is moved to fd 3 so
        // every worker has a stable fd to find the kernel on.
        ::close(fds[0]);
        if (fds[1] != kWorkerSocketFd) {
            if (::dup2(fds[1], kWorkerSocketFd) < 0) {
                _exit(127);
            }
            ::close(fds[1]);
        }
        // Build argv. argv[0] is the worker path; remainder mirrors
        // `args` verbatim.
        std::vector<char*> argv;
        argv.reserve(args.size() + 2);
        argv.push_back(const_cast<char*>(worker_path.c_str()));
        for (const auto& a : args) {
            argv.push_back(const_cast<char*>(a.c_str()));
        }
        argv.push_back(nullptr);
        ::execve(worker_path.c_str(), argv.data(), environ);
        // execve only returns on failure.
        _exit(127);
    }

    // Parent: keep our end, close the worker end.
    ::close(fds[1]);
    fd_  = fds[0];
    pid_ = pid;
    ctx_ = &ctx;
    kernel_host_api_ = kernel_host_api;

    // Start the reader thread up-front; the reader handles the
    // HELLO frame for us.
    std::promise<ReplyResult> hello_promise;
    auto hello_future = hello_promise.get_future();
    {
        std::lock_guard<std::mutex> lk(pending_mu_);
        pending_.emplace(0u, Pending{std::move(hello_promise)});
    }

    spawned_.store(true, std::memory_order_release);
    reader_ = std::thread([this] { reader_loop_(); });

    // Wait for HELLO (request_id=0).
    if (hello_future.wait_for(reply_timeout_) != std::future_status::ready) {
        diagnostic = "worker did not send HELLO within timeout";
        terminate();
        return GN_ERR_INVALID_STATE;
    }
    ReplyResult hello = hello_future.get();
    if (hello.flags & GN_WIRE_FLAG_ERROR) {
        diagnostic = "worker HELLO carried error flag";
        terminate();
        return GN_ERR_INVALID_STATE;
    }

    // Decode HELLO payload: map { "sdk": [maj, min, pat],
    //                            "name": "...",
    //                            "kind": <int>,
    //                            "pid": <u64> (optional) }
    wire::Reader r{hello.payload, 0};
    std::size_t map_n = 0;
    if (wire::decode_map_header(r, map_n) != GN_OK) {
        diagnostic = "HELLO payload is not a CBOR map";
        terminate();
        return GN_ERR_OUT_OF_RANGE;
    }
    std::uint32_t maj = 0, mn = 0, pt = 0;
    std::string name;
    gn_plugin_kind_t kind = GN_PLUGIN_KIND_UNKNOWN;
    bool saw_sdk = false;
    bool saw_name = false;
    for (std::size_t i = 0; i < map_n; ++i) {
        std::string_view key;
        if (wire::decode_text(r, key) != GN_OK) {
            diagnostic = "HELLO map key is not text";
            terminate();
            return GN_ERR_OUT_OF_RANGE;
        }
        if (key == "sdk") {
            std::size_t arr_n = 0;
            if (wire::decode_array_header(r, arr_n) != GN_OK || arr_n != 3) {
                diagnostic = "HELLO sdk array malformed";
                terminate();
                return GN_ERR_OUT_OF_RANGE;
            }
            std::uint64_t v = 0;
            if (wire::decode_u64(r, v) != GN_OK) { terminate(); return GN_ERR_OUT_OF_RANGE; }
            maj = static_cast<std::uint32_t>(v);
            if (wire::decode_u64(r, v) != GN_OK) { terminate(); return GN_ERR_OUT_OF_RANGE; }
            mn = static_cast<std::uint32_t>(v);
            if (wire::decode_u64(r, v) != GN_OK) { terminate(); return GN_ERR_OUT_OF_RANGE; }
            pt = static_cast<std::uint32_t>(v);
            saw_sdk = true;
        } else if (key == "name") {
            std::string_view nv;
            if (wire::decode_text(r, nv) != GN_OK) {
                diagnostic = "HELLO name is not text";
                terminate();
                return GN_ERR_OUT_OF_RANGE;
            }
            name.assign(nv);
            saw_name = true;
        } else if (key == "kind") {
            std::uint64_t v = 0;
            if (wire::decode_u64(r, v) != GN_OK) { terminate(); return GN_ERR_OUT_OF_RANGE; }
            kind = static_cast<gn_plugin_kind_t>(v);
        } else if (key == "pid") {
            std::uint64_t v = 0;
            if (wire::decode_u64(r, v) != GN_OK) { terminate(); return GN_ERR_OUT_OF_RANGE; }
            (void)v;  // accepted, used in logs only
        } else {
            // Unknown key — skip its value by decoding into a
            // throwaway. We only know how to skip the shapes we
            // ourselves emit, so reject anything else conservatively.
            diagnostic = "HELLO carried unknown key: ";
            diagnostic += std::string(key);
            terminate();
            return GN_ERR_OUT_OF_RANGE;
        }
    }
    if (!saw_sdk || !saw_name) {
        diagnostic = "HELLO missing required keys (sdk/name)";
        terminate();
        return GN_ERR_OUT_OF_RANGE;
    }
    if (maj != static_cast<std::uint32_t>(GN_SDK_VERSION_MAJOR)) {
        diagnostic = "worker SDK major mismatch";
        terminate();
        return GN_ERR_VERSION_MISMATCH;
    }
    (void)mn; (void)pt;  // minor/patch accepted; additive evolution

    descriptor_name_storage_    = std::move(name);
    descriptor_version_storage_.assign("remote");
    descriptor_                 = gn_plugin_descriptor_t{};
    descriptor_.name            = descriptor_name_storage_.c_str();
    descriptor_.version         = descriptor_version_storage_.c_str();
    descriptor_.kind            = kind;
    worker_kind_                = kind;

    // Build HELLO_ACK: { "sdk": [maj, min, pat], "host_ctx_handle": <u64> }
    PayloadVec ack;
    wire::encode_map_header(ack, 2);
    wire::encode_text(ack, "sdk");
    wire::encode_array_header(ack, 3);
    wire::encode_u64(ack, GN_SDK_VERSION_MAJOR);
    wire::encode_u64(ack, GN_SDK_VERSION_MINOR);
    wire::encode_u64(ack, GN_SDK_VERSION_PATCH);
    wire::encode_text(ack, "host_ctx_handle");
    wire::encode_u64(ack, reinterpret_cast<std::uint64_t>(ctx_));

    if (auto rc = write_frame_(GN_WIRE_HELLO_ACK, 0, 0, ack);
        rc != GN_OK) {
        diagnostic = "failed to write HELLO_ACK";
        terminate();
        return rc;
    }
    return GN_OK;
}

void RemoteHost::terminate() noexcept {
    if (!spawned_.load(std::memory_order_acquire)) {
        return;
    }
    bool was_stopping = stopping_.exchange(true, std::memory_order_acq_rel);
    if (!was_stopping && fd_ >= 0) {
        // Try to send GOODBYE — best-effort.
        PayloadVec empty;
        (void)write_frame_(GN_WIRE_GOODBYE, 0, 0, empty);
        ::shutdown(fd_, SHUT_RDWR);
    }
    if (reader_.joinable()) {
        reader_.join();
    }
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
    if (pid_ > 0) {
        int status = 0;
        // Give the worker a moment; then SIGKILL if still alive.
        for (int i = 0; i < 50; ++i) {
            ::pid_t r = ::waitpid(pid_, &status, WNOHANG);
            if (r == pid_) { pid_ = -1; break; }
            if (r < 0)     { break; }
            ::usleep(10'000);  // 10ms
        }
        if (pid_ > 0) {
            ::kill(pid_, SIGKILL);
            ::waitpid(pid_, &status, 0);
            pid_ = -1;
        }
    }
    fail_pending_(GN_ERR_INVALID_STATE, "remote host terminated");
    spawned_.store(false, std::memory_order_release);
}

bool RemoteHost::read_exact_(std::uint8_t* out, std::size_t n) {
    std::size_t got = 0;
    while (got < n) {
        if (stopping_.load(std::memory_order_acquire)) return false;
        ssize_t r = ::read(fd_, out + got, n - got);
        if (r > 0) { got += static_cast<std::size_t>(r); continue; }
        if (r == 0) return false;  // EOF
        if (errno == EINTR) continue;
        return false;
    }
    return true;
}

void RemoteHost::reader_loop_() {
    std::uint8_t hdr_buf[16];
    while (!stopping_.load(std::memory_order_acquire)) {
        if (!read_exact_(hdr_buf, 16)) {
            break;
        }
        gn_wire_frame_t hdr{};
        parse_header(hdr_buf, hdr);
        if (hdr.payload_size > GN_WIRE_MAX_PAYLOAD) {
            // Protocol violation; bail.
            break;
        }
        std::vector<std::uint8_t> payload(hdr.payload_size);
        if (hdr.payload_size > 0 &&
            !read_exact_(payload.data(), hdr.payload_size)) {
            break;
        }

        switch (hdr.kind) {
            case GN_WIRE_HELLO:
                deliver_reply_(0, hdr.flags, payload);
                break;
            case GN_WIRE_PLUGIN_REPLY:
                deliver_reply_(hdr.request_id, hdr.flags, payload);
                break;
            case GN_WIRE_HOST_CALL:
                handle_host_call_(hdr.request_id, payload);
                break;
            case GN_WIRE_GOODBYE:
                stopping_.store(true, std::memory_order_release);
                break;
            default:
                // Unknown opcode — ignore but don't tear down. New
                // opcodes added in a future SDK minor must be benign.
                break;
        }
    }
    fail_pending_(GN_ERR_INVALID_STATE, "reader thread exited");
}

void RemoteHost::deliver_reply_(std::uint32_t request_id,
                                 std::uint32_t flags,
                                 std::span<const std::uint8_t> payload) {
    Pending taken;
    {
        std::lock_guard<std::mutex> lk(pending_mu_);
        auto it = pending_.find(request_id);
        if (it == pending_.end()) {
            return;  // unmatched reply — drop
        }
        taken = std::move(it->second);
        pending_.erase(it);
    }
    ReplyResult res;
    res.flags = flags;
    res.payload.assign(payload.begin(), payload.end());
    taken.result.set_value(std::move(res));
}

void RemoteHost::fail_pending_(gn_result_t code,
                                const char* message) noexcept {
    std::unordered_map<std::uint32_t, Pending> drained;
    {
        std::lock_guard<std::mutex> lk(pending_mu_);
        drained.swap(pending_);
    }
    for (auto& [rid, pending] : drained) {
        ReplyResult res;
        res.flags = GN_WIRE_FLAG_ERROR;
        encode_error_(res.payload, code, message);
        try {
            pending.result.set_value(std::move(res));
        } catch (const std::future_error& e) {
            // Promise already satisfied by a previous deliver_reply_
            // for this request_id — benign race during teardown.
            (void)e;
        }
    }
}

gn_result_t RemoteHost::write_frame_(std::uint32_t kind,
                                     std::uint32_t request_id,
                                     std::uint32_t flags,
                                     std::span<const std::uint8_t> payload) {
    if (payload.size() > GN_WIRE_MAX_PAYLOAD) {
        return GN_ERR_FRAME_TOO_LARGE;
    }
    if (fd_ < 0) {
        return GN_ERR_INVALID_STATE;
    }
    gn_wire_frame_t f{};
    f.kind         = kind;
    f.request_id   = request_id;
    f.payload_size = static_cast<std::uint32_t>(payload.size());
    f.flags        = flags;
    std::uint8_t hdr[16];
    serialise_header(f, hdr);

    iovec iov[2];
    iov[0].iov_base = hdr;
    iov[0].iov_len  = sizeof(hdr);
    iov[1].iov_base = const_cast<std::uint8_t*>(payload.data());
    iov[1].iov_len  = payload.size();
    const std::size_t total = sizeof(hdr) + payload.size();
    std::size_t written = 0;
    std::lock_guard<std::mutex> lk(write_mu_);
    while (written < total) {
        // Adjust iov for partial writes.
        iovec local[2];
        std::size_t skip = written;
        int n = 0;
        for (int i = 0; i < 2; ++i) {
            if (skip >= iov[i].iov_len) {
                skip -= iov[i].iov_len;
                continue;
            }
            local[n].iov_base =
                static_cast<std::uint8_t*>(iov[i].iov_base) + skip;
            local[n].iov_len = iov[i].iov_len - skip;
            ++n;
            for (int j = i + 1; j < 2; ++j) {
                local[n].iov_base = iov[j].iov_base;
                local[n].iov_len  = iov[j].iov_len;
                ++n;
            }
            break;
        }
        ssize_t w = ::writev(fd_, local, n);
        if (w > 0) { written += static_cast<std::size_t>(w); continue; }
        if (w < 0 && errno == EINTR) continue;
        return GN_ERR_INTERNAL;
    }
    return GN_OK;
}

gn_result_t RemoteHost::round_trip_(std::uint32_t slot_id,
                                    const PayloadVec& args,
                                    ReplyResult& out) {
    if (!spawned_.load(std::memory_order_acquire) ||
        stopping_.load(std::memory_order_acquire)) {
        return GN_ERR_INVALID_STATE;
    }
    const std::uint32_t rid =
        next_request_id_.fetch_add(1, std::memory_order_acq_rel);
    PayloadVec frame;
    wire::encode_array_header(frame, 1 + 1);   // [slot, args_array]
    wire::encode_u64(frame, slot_id);
    frame.insert(frame.end(), args.begin(), args.end());

    std::promise<ReplyResult> promise;
    auto fut = promise.get_future();
    {
        std::lock_guard<std::mutex> lk(pending_mu_);
        pending_.emplace(rid, Pending{std::move(promise)});
    }
    if (auto rc = write_frame_(GN_WIRE_PLUGIN_CALL, rid, 0, frame);
        rc != GN_OK) {
        std::lock_guard<std::mutex> lk(pending_mu_);
        pending_.erase(rid);
        return rc;
    }
    std::chrono::milliseconds wait_budget = reply_timeout_;
    {
        std::lock_guard<std::mutex> lk(timeout_overrides_mu_);
        if (auto it = timeout_overrides_.find(
                static_cast<std::uint16_t>(slot_id));
            it != timeout_overrides_.end()) {
            wait_budget = it->second;
        }
    }
    if (fut.wait_for(wait_budget) != std::future_status::ready) {
        std::lock_guard<std::mutex> lk(pending_mu_);
        pending_.erase(rid);
        return GN_ERR_INVALID_STATE;
    }
    out = fut.get();
    round_trips_.fetch_add(1, std::memory_order_relaxed);
    return GN_OK;
}

void RemoteHost::set_reply_timeout_for_slot(std::uint16_t slot_id,
                                            std::chrono::milliseconds t) {
    std::lock_guard<std::mutex> lk(timeout_overrides_mu_);
    timeout_overrides_[slot_id] = t;
}

void RemoteHost::clear_reply_timeout_overrides() {
    std::lock_guard<std::mutex> lk(timeout_overrides_mu_);
    timeout_overrides_.clear();
}

void RemoteHost::encode_error_(PayloadVec& out,
                                gn_result_t code,
                                std::string_view message) {
    wire::encode_map_header(out, 2);
    wire::encode_text(out, "code");
    wire::encode_i64(out, static_cast<std::int64_t>(code));
    wire::encode_text(out, "message");
    wire::encode_text(out, message);
}

// ── Entry-point round-trips ─────────────────────────────────────────

gn_result_t RemoteHost::call_init(void** out_self_handle) {
    PayloadVec args;  // empty — slot has no in-args
    ReplyResult reply;
    if (auto rc = round_trip_(GN_WIRE_SLOT_PLUGIN_INIT, args, reply);
        rc != GN_OK) {
        return rc;
    }
    if (reply.flags & GN_WIRE_FLAG_ERROR) {
        return GN_ERR_INTERNAL;
    }
    // Reply payload: code(i64), self_handle(u64) — inline.
    wire::Reader r{reply.payload, 0};
    std::int64_t code = 0;
    std::uint64_t self_handle = 0;
    if (wire::decode_i64(r, code) != GN_OK ||
        wire::decode_u64(r, self_handle) != GN_OK) {
        return GN_ERR_OUT_OF_RANGE;
    }
    if (code != GN_OK) {
        return static_cast<gn_result_t>(code);
    }
    worker_self_handle_ = self_handle;
    if (out_self_handle != nullptr) {
        // The handle is a worker-side opaque the kernel never
        // dereferences — PluginInstance::self stores it through
        // `void*` only because the dlopen path does. Cast through
        // uintptr_t so the value round-trips when uintptr_t and
        // u64 are the same width (every supported POSIX).
        const std::uintptr_t raw =
            static_cast<std::uintptr_t>(self_handle);
        *out_self_handle = reinterpret_cast<void*>(raw);  // NOLINT(performance-no-int-to-ptr)
    }
    return GN_OK;
}

gn_result_t RemoteHost::call_register(std::uint64_t self_handle) {
    PayloadVec args;
    wire::encode_u64(args, self_handle);
    ReplyResult reply;
    if (auto rc = round_trip_(GN_WIRE_SLOT_PLUGIN_REGISTER, args, reply);
        rc != GN_OK) {
        return rc;
    }
    if (reply.flags & GN_WIRE_FLAG_ERROR) {
        return GN_ERR_INTERNAL;
    }
    wire::Reader r{reply.payload, 0};
    std::int64_t code = 0;
    if (wire::decode_i64(r, code) != GN_OK) return GN_ERR_OUT_OF_RANGE;
    const auto worker_rc = static_cast<gn_result_t>(code);
    if (worker_rc != GN_OK) return worker_rc;

    /// Publish the synthesised link proxy in the kernel's link
    /// registry on behalf of the worker. The kernel sees a normal
    /// link plugin with the worker's plugin name as the scheme;
    /// scheme-based lookups (from `notify_connect`, `send`) hit
    /// `link_vtable_proxy()` and dispatch through the wire.
    if (worker_kind_ == GN_PLUGIN_KIND_LINK &&
        kernel_host_api_.register_vtable != nullptr &&
        registered_link_id_ == 0) {
        const gn_link_vtable_t* proxy = link_vtable_proxy();
        if (proxy != nullptr) {
            gn_register_meta_t meta{};
            meta.api_size    = sizeof(gn_register_meta_t);
            meta.name        = descriptor_name_storage_.c_str();
            meta.protocol_id = nullptr;
            (void)kernel_host_api_.register_vtable(
                kernel_host_api_.host_ctx,
                GN_REGISTER_LINK,
                &meta, proxy, this, &registered_link_id_);
        }
    }
    return GN_OK;
}

gn_result_t RemoteHost::call_unregister(std::uint64_t self_handle) {
    /// Pull the link proxy out of the kernel registry first so any
    /// in-flight `find_by_scheme` returns NOT_FOUND before the
    /// worker has a chance to start tearing down its own state.
    if (registered_link_id_ != 0 &&
        kernel_host_api_.unregister_vtable != nullptr) {
        (void)kernel_host_api_.unregister_vtable(
            kernel_host_api_.host_ctx, registered_link_id_);
        registered_link_id_ = 0;
    }

    PayloadVec args;
    wire::encode_u64(args, self_handle);
    ReplyResult reply;
    if (auto rc = round_trip_(GN_WIRE_SLOT_PLUGIN_UNREGISTER, args, reply);
        rc != GN_OK) {
        return rc;
    }
    if (reply.flags & GN_WIRE_FLAG_ERROR) {
        return GN_ERR_INTERNAL;
    }
    wire::Reader r{reply.payload, 0};
    std::int64_t code = 0;
    if (wire::decode_i64(r, code) != GN_OK) return GN_ERR_OUT_OF_RANGE;
    return static_cast<gn_result_t>(code);
}

void RemoteHost::call_shutdown(std::uint64_t self_handle) {
    PayloadVec args;
    wire::encode_u64(args, self_handle);
    ReplyResult reply;
    (void)round_trip_(GN_WIRE_SLOT_PLUGIN_SHUTDOWN, args, reply);
}

// ── HOST_CALL dispatcher ─────────────────────────────────────────────

void RemoteHost::handle_host_call_(std::uint32_t request_id,
                                    std::span<const std::uint8_t> payload) {
    PayloadVec reply_buf;
    std::uint32_t reply_flags = 0;

    wire::Reader r{payload, 0};
    std::size_t arr_n = 0;
    if (wire::decode_array_header(r, arr_n) != GN_OK || arr_n < 1) {
        reply_flags = GN_WIRE_FLAG_ERROR;
        encode_error_(reply_buf, GN_ERR_OUT_OF_RANGE, "bad HOST_CALL shape");
        (void)write_frame_(GN_WIRE_HOST_REPLY, request_id, reply_flags, reply_buf);
        return;
    }
    std::uint64_t slot_id = 0;
    if (wire::decode_u64(r, slot_id) != GN_OK) {
        reply_flags = GN_WIRE_FLAG_ERROR;
        encode_error_(reply_buf, GN_ERR_OUT_OF_RANGE, "bad slot id");
        (void)write_frame_(GN_WIRE_HOST_REPLY, request_id, reply_flags, reply_buf);
        return;
    }

    switch (static_cast<gn_wire_host_slot_t>(slot_id)) {
        case GN_WIRE_HOST_SLOT_LOG_EMIT: {
            // args: [level(u64), file(text), line(i64), message(text)]
            std::uint64_t level = 0;
            std::string_view file{}, msg{};
            std::int64_t line = 0;
            if (wire::decode_u64(r, level)    != GN_OK ||
                wire::decode_text(r, file)    != GN_OK ||
                wire::decode_i64(r, line)     != GN_OK ||
                wire::decode_text(r, msg)     != GN_OK) {
                reply_flags = GN_WIRE_FLAG_ERROR;
                encode_error_(reply_buf, GN_ERR_OUT_OF_RANGE, "bad log args");
                break;
            }
            if (kernel_host_api_.log.emit != nullptr) {
                std::string file_z(file);
                std::string msg_z(msg);
                kernel_host_api_.log.emit(
                    kernel_host_api_.host_ctx,
                    static_cast<gn_log_level_t>(level),
                    file_z.c_str(),
                    static_cast<int32_t>(line),
                    msg_z.c_str());
            }
            wire::encode_array_header(reply_buf, 1);
            wire::encode_i64(reply_buf, GN_OK);
            break;
        }
        case GN_WIRE_HOST_SLOT_IS_SHUTDOWN_REQUESTED: {
            int32_t v = 0;
            if (kernel_host_api_.is_shutdown_requested != nullptr) {
                v = kernel_host_api_.is_shutdown_requested(
                    kernel_host_api_.host_ctx);
            }
            wire::encode_array_header(reply_buf, 1);
            wire::encode_i64(reply_buf, v);
            break;
        }
        case GN_WIRE_HOST_SLOT_NOTIFY_INBOUND_BYTES: {
            // args: [conn(u64), bytes(bytestring)]
            std::uint64_t conn = 0;
            std::span<const std::uint8_t> bytes;
            if (wire::decode_u64(r, conn) != GN_OK ||
                wire::decode_bytes(r, bytes) != GN_OK) {
                reply_flags = GN_WIRE_FLAG_ERROR;
                encode_error_(reply_buf, GN_ERR_OUT_OF_RANGE,
                              "bad notify_inbound_bytes args");
                break;
            }
            gn_result_t rc = GN_ERR_NOT_IMPLEMENTED;
            if (kernel_host_api_.notify_inbound_bytes != nullptr) {
                rc = kernel_host_api_.notify_inbound_bytes(
                    kernel_host_api_.host_ctx,
                    static_cast<gn_conn_id_t>(conn),
                    bytes.data(),
                    bytes.size());
            }
            wire::encode_array_header(reply_buf, 1);
            wire::encode_i64(reply_buf, rc);
            break;
        }
        case GN_WIRE_HOST_SLOT_NOTIFY_CONNECT: {
            // args: [remote_pk(bytes), uri(text), trust(u64), role(u64)]
            // reply on success: [code(i64), conn(u64)]
            std::span<const std::uint8_t> pk_bytes;
            std::string_view uri{};
            std::uint64_t trust = 0;
            std::uint64_t role  = 0;
            if (wire::decode_bytes(r, pk_bytes) != GN_OK ||
                wire::decode_text(r, uri) != GN_OK ||
                wire::decode_u64(r, trust) != GN_OK ||
                wire::decode_u64(r, role) != GN_OK ||
                pk_bytes.size() != GN_PUBLIC_KEY_BYTES) {
                reply_flags = GN_WIRE_FLAG_ERROR;
                encode_error_(reply_buf, GN_ERR_OUT_OF_RANGE,
                              "bad notify_connect args");
                break;
            }
            gn_result_t rc = GN_ERR_NOT_IMPLEMENTED;
            gn_conn_id_t out_conn = 0;
            if (kernel_host_api_.notify_connect != nullptr) {
                std::string uri_z(uri);
                std::uint8_t pk_buf[GN_PUBLIC_KEY_BYTES];
                std::memcpy(pk_buf, pk_bytes.data(), GN_PUBLIC_KEY_BYTES);
                rc = kernel_host_api_.notify_connect(
                    kernel_host_api_.host_ctx,
                    pk_buf,
                    uri_z.c_str(),
                    static_cast<gn_trust_class_t>(trust),
                    static_cast<gn_handshake_role_t>(role),
                    &out_conn);
            }
            wire::encode_array_header(reply_buf, 2);
            wire::encode_i64(reply_buf, rc);
            wire::encode_u64(reply_buf, static_cast<std::uint64_t>(out_conn));
            break;
        }
        case GN_WIRE_HOST_SLOT_NOTIFY_DISCONNECT: {
            // args: [conn(u64), reason(i64)]
            std::uint64_t conn = 0;
            std::int64_t  reason = 0;
            if (wire::decode_u64(r, conn) != GN_OK ||
                wire::decode_i64(r, reason) != GN_OK) {
                reply_flags = GN_WIRE_FLAG_ERROR;
                encode_error_(reply_buf, GN_ERR_OUT_OF_RANGE,
                              "bad notify_disconnect args");
                break;
            }
            gn_result_t rc = GN_ERR_NOT_IMPLEMENTED;
            if (kernel_host_api_.notify_disconnect != nullptr) {
                rc = kernel_host_api_.notify_disconnect(
                    kernel_host_api_.host_ctx,
                    static_cast<gn_conn_id_t>(conn),
                    static_cast<gn_result_t>(reason));
            }
            wire::encode_array_header(reply_buf, 1);
            wire::encode_i64(reply_buf, rc);
            break;
        }
        case GN_WIRE_HOST_SLOT_REGISTER_VTABLE: {
            // args: [kind(u64), name(text), msg_id(u64), priority(u64),
            //        protocol_id(text), namespace_id(text)]
            // reply on success: [code(i64), id(u64)]
            //
            // The worker ships only the metadata — the vtable itself
            // is synthesised on the kernel side. LINK kind uses the
            // existing `link_vtable_proxy()`; HANDLER kind is deferred
            // until the handler proxy lands and returns
            // GN_ERR_NOT_IMPLEMENTED at this slot.
            std::uint64_t kind = 0;
            std::string_view name{}, proto{}, nsid{};
            std::uint64_t msg_id   = 0;
            std::uint64_t priority = 0;
            if (wire::decode_u64(r, kind) != GN_OK ||
                wire::decode_text(r, name) != GN_OK ||
                wire::decode_u64(r, msg_id) != GN_OK ||
                wire::decode_u64(r, priority) != GN_OK ||
                wire::decode_text(r, proto) != GN_OK ||
                wire::decode_text(r, nsid) != GN_OK) {
                reply_flags = GN_WIRE_FLAG_ERROR;
                encode_error_(reply_buf, GN_ERR_OUT_OF_RANGE,
                              "bad register_vtable args");
                break;
            }
            gn_result_t rc = GN_ERR_NOT_IMPLEMENTED;
            std::uint64_t out_id = 0;
            const auto reg_kind = static_cast<gn_register_kind_t>(kind);
            const void* vtable = nullptr;
            if (reg_kind == GN_REGISTER_LINK) {
                vtable = link_vtable_proxy();
            } else if (reg_kind == GN_REGISTER_HANDLER) {
                vtable = handler_vtable_proxy();
            }
            if (vtable != nullptr &&
                kernel_host_api_.register_vtable != nullptr) {
                std::string name_z(name);
                std::string proto_z(proto);
                std::string nsid_z(nsid);
                gn_register_meta_t meta{};
                meta.api_size     = sizeof(gn_register_meta_t);
                meta.name         = name_z.c_str();
                meta.msg_id       = static_cast<std::uint32_t>(msg_id);
                meta.priority     = static_cast<std::uint8_t>(priority);
                meta.protocol_id  = proto.empty() ? nullptr : proto_z.c_str();
                meta.namespace_id = nsid.empty()  ? nullptr : nsid_z.c_str();
                rc = kernel_host_api_.register_vtable(
                    kernel_host_api_.host_ctx,
                    reg_kind,
                    &meta, vtable, this, &out_id);
            }
            wire::encode_array_header(reply_buf, 2);
            wire::encode_i64(reply_buf, rc);
            wire::encode_u64(reply_buf, out_id);
            break;
        }
        case GN_WIRE_HOST_SLOT_UNREGISTER_VTABLE: {
            // args: [id(u64)]
            std::uint64_t id = 0;
            if (wire::decode_u64(r, id) != GN_OK) {
                reply_flags = GN_WIRE_FLAG_ERROR;
                encode_error_(reply_buf, GN_ERR_OUT_OF_RANGE,
                              "bad unregister_vtable args");
                break;
            }
            gn_result_t rc = GN_ERR_NOT_IMPLEMENTED;
            if (kernel_host_api_.unregister_vtable != nullptr) {
                rc = kernel_host_api_.unregister_vtable(
                    kernel_host_api_.host_ctx, id);
            }
            wire::encode_array_header(reply_buf, 1);
            wire::encode_i64(reply_buf, rc);
            break;
        }
        case GN_WIRE_HOST_SLOT_REGISTER_SECURITY: {
            // args: [provider_id(text)]
            // Security vtable is synthesised on the kernel side from
            // the worker's HELLO kind. The worker ships only the
            // provider id string; the kernel routes the synthesised
            // proxy through `host_api.register_security`.
            std::string_view provider_id{};
            if (wire::decode_text(r, provider_id) != GN_OK) {
                reply_flags = GN_WIRE_FLAG_ERROR;
                encode_error_(reply_buf, GN_ERR_OUT_OF_RANGE,
                              "bad register_security args");
                break;
            }
            gn_result_t rc = GN_ERR_NOT_IMPLEMENTED;
            const gn_security_provider_vtable_t* vtable = security_vtable_proxy();
            if (vtable != nullptr &&
                kernel_host_api_.register_security != nullptr) {
                std::string pid_z(provider_id);
                rc = kernel_host_api_.register_security(
                    kernel_host_api_.host_ctx,
                    pid_z.c_str(), vtable, this);
                if (rc == GN_OK) {
                    registered_security_id_ = std::move(pid_z);
                }
            }
            wire::encode_array_header(reply_buf, 1);
            wire::encode_i64(reply_buf, rc);
            break;
        }
        case GN_WIRE_HOST_SLOT_UNREGISTER_SECURITY: {
            // args: [provider_id(text)]
            std::string_view provider_id{};
            if (wire::decode_text(r, provider_id) != GN_OK) {
                reply_flags = GN_WIRE_FLAG_ERROR;
                encode_error_(reply_buf, GN_ERR_OUT_OF_RANGE,
                              "bad unregister_security args");
                break;
            }
            gn_result_t rc = GN_ERR_NOT_IMPLEMENTED;
            if (kernel_host_api_.unregister_security != nullptr) {
                std::string pid_z(provider_id);
                rc = kernel_host_api_.unregister_security(
                    kernel_host_api_.host_ctx, pid_z.c_str());
                if (rc == GN_OK && registered_security_id_ == provider_id) {
                    registered_security_id_.clear();
                }
            }
            wire::encode_array_header(reply_buf, 1);
            wire::encode_i64(reply_buf, rc);
            break;
        }
        default:
            reply_flags = GN_WIRE_FLAG_ERROR;
            encode_error_(reply_buf, GN_ERR_NOT_IMPLEMENTED,
                          "host slot not implemented");
            break;
    }
    (void)write_frame_(GN_WIRE_HOST_REPLY, request_id, reply_flags, reply_buf);
}

// ── Synthetic link vtable proxy ─────────────────────────────────────
//
// Every slot of the synthesised vtable carries the worker's
// `self_handle` through the wire — the worker dispatches the
// PLUGIN_CALL into its own real vtable using `cfg.link_self` as the
// in-process self. The kernel never deals with the worker's pointer
// directly; the synthesised vtable's `self` field is RemoteHost*, so
// the thunk can issue `round_trip_` against the wire.

namespace {

const char* link_scheme_thunk(void* self) noexcept {
    auto* host = static_cast<RemoteHost*>(self);
    return host->descriptor()->name;
}

// Decode `[code(i64)]` from a PLUGIN_REPLY payload into a
// gn_result_t. Used by every link-slot thunk that returns
// gn_result_t. Any decode error collapses to GN_ERR_INTERNAL — the
// wire is now in a state the kernel cannot reason about.
[[nodiscard]] gn_result_t decode_code_reply(
    const std::vector<std::uint8_t>& payload, std::uint32_t flags) noexcept {
    if (flags & GN_WIRE_FLAG_ERROR) {
        // Error map carries `code`/`message`; surface the code.
        wire::Reader r{payload, 0};
        std::size_t map_n = 0;
        if (wire::decode_map_header(r, map_n) != GN_OK) {
            return GN_ERR_INTERNAL;
        }
        gn_result_t observed = GN_ERR_INTERNAL;
        for (std::size_t i = 0; i < map_n; ++i) {
            std::string_view key;
            if (wire::decode_text(r, key) != GN_OK) return GN_ERR_INTERNAL;
            if (key == "code") {
                std::int64_t v = 0;
                if (wire::decode_i64(r, v) != GN_OK) return GN_ERR_INTERNAL;
                observed = static_cast<gn_result_t>(v);
            } else if (key == "message") {
                std::string_view m;
                if (wire::decode_text(r, m) != GN_OK) return GN_ERR_INTERNAL;
            } else {
                return GN_ERR_INTERNAL;
            }
        }
        return observed;
    }
    wire::Reader r{payload, 0};
    std::int64_t code = 0;
    if (wire::decode_i64(r, code) != GN_OK) return GN_ERR_INTERNAL;
    return static_cast<gn_result_t>(code);
}

gn_result_t link_listen_thunk(void* self, const char* uri) noexcept {
    auto* host = static_cast<RemoteHost*>(self);
    std::vector<std::uint8_t> args;
    wire::encode_u64(args, host->worker_self_handle_for_proxy());
    wire::encode_text(args, uri ? std::string_view(uri) : std::string_view());
    RemoteHost::ReplyResult reply;
    if (auto rc = host->round_trip_for_proxy(
            GN_WIRE_SLOT_LINK_LISTEN, args, reply);
        rc != GN_OK) return rc;
    return decode_code_reply(reply.payload, reply.flags);
}

gn_result_t link_connect_thunk(void* self, const char* uri) noexcept {
    auto* host = static_cast<RemoteHost*>(self);
    std::vector<std::uint8_t> args;
    wire::encode_u64(args, host->worker_self_handle_for_proxy());
    wire::encode_text(args, uri ? std::string_view(uri) : std::string_view());
    RemoteHost::ReplyResult reply;
    if (auto rc = host->round_trip_for_proxy(
            GN_WIRE_SLOT_LINK_CONNECT, args, reply);
        rc != GN_OK) return rc;
    return decode_code_reply(reply.payload, reply.flags);
}

gn_result_t link_send_thunk(void* self,
                             gn_conn_id_t conn,
                             const uint8_t* bytes,
                             size_t size) noexcept {
    auto* host = static_cast<RemoteHost*>(self);
    std::vector<std::uint8_t> args;
    wire::encode_u64(args, host->worker_self_handle_for_proxy());
    wire::encode_u64(args, conn);
    wire::encode_bytes(args, std::span<const std::uint8_t>(bytes, size));
    RemoteHost::ReplyResult reply;
    if (auto rc = host->round_trip_for_proxy(
            GN_WIRE_SLOT_LINK_SEND, args, reply);
        rc != GN_OK) return rc;
    return decode_code_reply(reply.payload, reply.flags);
}

// Scatter-gather batch send through the proxy. The remote LINK wire
// protocol carries one `send` slot per frame, so the proxy loops over
// the batch and issues a `send` PLUGIN_CALL for each entry. The
// in-process atomicity contract (`link.en.md` §4 — single-writer per
// connection) is preserved because the kernel write side serialises
// PLUGIN_CALL frames through `write_mu_`; nothing else interleaves on
// the same conn during the batch loop. The first failing send short-
// circuits the rest so the caller observes the first non-OK code.
gn_result_t link_send_batch_thunk(void* self,
                                   gn_conn_id_t conn,
                                   const gn_byte_span_t* batch,
                                   size_t count) noexcept {
    if (batch == nullptr && count != 0) return GN_ERR_NULL_ARG;
    for (size_t i = 0; i < count; ++i) {
        const auto rc = link_send_thunk(
            self, conn, batch[i].bytes, batch[i].size);
        if (rc != GN_OK) return rc;
    }
    return GN_OK;
}

gn_result_t link_disconnect_thunk(void* self,
                                   gn_conn_id_t conn) noexcept {
    auto* host = static_cast<RemoteHost*>(self);
    std::vector<std::uint8_t> args;
    wire::encode_u64(args, host->worker_self_handle_for_proxy());
    wire::encode_u64(args, conn);
    RemoteHost::ReplyResult reply;
    if (auto rc = host->round_trip_for_proxy(
            GN_WIRE_SLOT_LINK_DISCONNECT, args, reply);
        rc != GN_OK) return rc;
    return decode_code_reply(reply.payload, reply.flags);
}

void link_destroy_thunk(void* /*self*/) noexcept {
    // Lifetime is owned by the kernel-side RemoteHost; `destroy` is
    // a no-op on this side. The worker-side equivalent fires when
    // `call_shutdown` traverses the wire.
}

// ── Security vtable proxy thunks ────────────────────────────────────
//
// Each thunk echoes the worker's `self_handle` so the worker
// dispatcher can locate the right `gn_security_provider_vtable_t`
// without keeping a side-channel state map. `state` pointers from
// `handshake_open` are u64-sized handles that the worker owns and
// the kernel treats as opaque.

[[nodiscard]] const char* security_provider_id_thunk(void* self) noexcept {
    auto* host = static_cast<RemoteHost*>(self);
    return host->descriptor()->name;
}

gn_result_t security_handshake_open_thunk(
    void* self,
    gn_conn_id_t conn,
    gn_trust_class_t trust,
    gn_handshake_role_t role,
    const uint8_t local_static_sk[GN_PRIVATE_KEY_BYTES],
    const uint8_t local_static_pk[GN_PUBLIC_KEY_BYTES],
    const uint8_t* remote_static_pk,
    void** out_state) noexcept {
    if (out_state == nullptr ||
        local_static_sk == nullptr || local_static_pk == nullptr) {
        return GN_ERR_NULL_ARG;
    }
    auto* host = static_cast<RemoteHost*>(self);
    std::vector<std::uint8_t> args;
    wire::encode_u64(args, host->worker_self_handle_for_proxy());
    wire::encode_u64(args, conn);
    wire::encode_u64(args, static_cast<std::uint64_t>(trust));
    wire::encode_u64(args, static_cast<std::uint64_t>(role));
    wire::encode_bytes(args,
        std::span<const std::uint8_t>(local_static_sk, GN_PRIVATE_KEY_BYTES));
    wire::encode_bytes(args,
        std::span<const std::uint8_t>(local_static_pk, GN_PUBLIC_KEY_BYTES));
    if (remote_static_pk != nullptr) {
        wire::encode_bytes(args,
            std::span<const std::uint8_t>(remote_static_pk, GN_PUBLIC_KEY_BYTES));
    } else {
        wire::encode_bytes(args, std::span<const std::uint8_t>{});
    }
    RemoteHost::ReplyResult reply;
    if (auto rc = host->round_trip_for_proxy(
            GN_WIRE_SLOT_SECURITY_HANDSHAKE_OPEN, args, reply);
        rc != GN_OK) return rc;
    if (reply.flags & GN_WIRE_FLAG_ERROR) {
        return decode_code_reply(reply.payload, reply.flags);
    }
    wire::Reader r{reply.payload, 0};
    std::size_t n = 0;
    if (wire::decode_array_header(r, n) != GN_OK || n != 2) {
        return GN_ERR_OUT_OF_RANGE;
    }
    std::int64_t code = 0;
    std::uint64_t state_handle = 0;
    if (wire::decode_i64(r, code) != GN_OK ||
        wire::decode_u64(r, state_handle) != GN_OK) {
        return GN_ERR_OUT_OF_RANGE;
    }
    const std::uintptr_t raw = static_cast<std::uintptr_t>(state_handle);
    *out_state = reinterpret_cast<void*>(raw);  // NOLINT(performance-no-int-to-ptr)
    return static_cast<gn_result_t>(code);
}

gn_result_t security_handshake_step_thunk(
    void* self,
    void* state,
    const uint8_t* incoming, size_t incoming_size,
    gn_secure_buffer_t* out_message) noexcept {
    if (out_message == nullptr) return GN_ERR_NULL_ARG;
    auto* host = static_cast<RemoteHost*>(self);
    std::vector<std::uint8_t> args;
    wire::encode_u64(args, host->worker_self_handle_for_proxy());
    wire::encode_u64(args, reinterpret_cast<std::uintptr_t>(state));
    wire::encode_bytes(args,
        std::span<const std::uint8_t>(incoming, incoming_size));
    RemoteHost::ReplyResult reply;
    if (auto rc = host->round_trip_for_proxy(
            GN_WIRE_SLOT_SECURITY_HANDSHAKE_STEP, args, reply);
        rc != GN_OK) return rc;
    if (reply.flags & GN_WIRE_FLAG_ERROR) {
        return decode_code_reply(reply.payload, reply.flags);
    }
    wire::Reader r{reply.payload, 0};
    std::size_t n = 0;
    if (wire::decode_array_header(r, n) != GN_OK || n != 2) {
        return GN_ERR_OUT_OF_RANGE;
    }
    std::int64_t code = 0;
    std::span<const std::uint8_t> out_bytes;
    if (wire::decode_i64(r, code) != GN_OK ||
        wire::decode_bytes(r, out_bytes) != GN_OK) {
        return GN_ERR_OUT_OF_RANGE;
    }
    out_message->bytes = nullptr;
    out_message->size = 0;
    out_message->free_user_data = nullptr;
    out_message->free_fn = nullptr;
    if (!out_bytes.empty()) {
        auto* buf = static_cast<std::uint8_t*>(std::malloc(out_bytes.size()));
        if (buf == nullptr) return GN_ERR_OUT_OF_MEMORY;
        std::memcpy(buf, out_bytes.data(), out_bytes.size());
        out_message->bytes = buf;
        out_message->size = out_bytes.size();
        out_message->free_fn = [](void* /*ud*/, std::uint8_t* p) {
            std::free(p);
        };
    }
    return static_cast<gn_result_t>(code);
}

int security_handshake_complete_thunk(void* self, void* state) noexcept {
    auto* host = static_cast<RemoteHost*>(self);
    std::vector<std::uint8_t> args;
    wire::encode_u64(args, host->worker_self_handle_for_proxy());
    wire::encode_u64(args, reinterpret_cast<std::uintptr_t>(state));
    RemoteHost::ReplyResult reply;
    if (host->round_trip_for_proxy(
            GN_WIRE_SLOT_SECURITY_HANDSHAKE_COMPLETE, args, reply) != GN_OK) {
        return 0;
    }
    if (reply.flags & GN_WIRE_FLAG_ERROR) return 0;
    wire::Reader r{reply.payload, 0};
    std::size_t n = 0;
    if (wire::decode_array_header(r, n) != GN_OK || n != 1) return 0;
    std::int64_t v = 0;
    if (wire::decode_i64(r, v) != GN_OK) return 0;
    return static_cast<int>(v);
}

gn_result_t security_export_keys_thunk(
    void* self,
    void* state,
    gn_handshake_keys_t* out_keys) noexcept {
    if (out_keys == nullptr) return GN_ERR_NULL_ARG;
    auto* host = static_cast<RemoteHost*>(self);
    std::vector<std::uint8_t> args;
    wire::encode_u64(args, host->worker_self_handle_for_proxy());
    wire::encode_u64(args, reinterpret_cast<std::uintptr_t>(state));
    RemoteHost::ReplyResult reply;
    if (auto rc = host->round_trip_for_proxy(
            GN_WIRE_SLOT_SECURITY_EXPORT_KEYS, args, reply);
        rc != GN_OK) return rc;
    if (reply.flags & GN_WIRE_FLAG_ERROR) {
        return decode_code_reply(reply.payload, reply.flags);
    }
    // reply: [code(i64), send_key(bytes), recv_key(bytes),
    //         initial_send_nonce(u64), initial_recv_nonce(u64),
    //         handshake_hash(bytes), peer_static_pk(bytes)]
    wire::Reader r{reply.payload, 0};
    std::size_t n = 0;
    if (wire::decode_array_header(r, n) != GN_OK || n != 7) {
        return GN_ERR_OUT_OF_RANGE;
    }
    std::int64_t code = 0;
    std::span<const std::uint8_t> sk, rk, hh, pk;
    std::uint64_t sn = 0, rn = 0;
    if (wire::decode_i64(r, code) != GN_OK ||
        wire::decode_bytes(r, sk) != GN_OK ||
        wire::decode_bytes(r, rk) != GN_OK ||
        wire::decode_u64(r, sn) != GN_OK ||
        wire::decode_u64(r, rn) != GN_OK ||
        wire::decode_bytes(r, hh) != GN_OK ||
        wire::decode_bytes(r, pk) != GN_OK) {
        return GN_ERR_OUT_OF_RANGE;
    }
    if (code != GN_OK) return static_cast<gn_result_t>(code);
    if (sk.size() != GN_CIPHER_KEY_BYTES ||
        rk.size() != GN_CIPHER_KEY_BYTES ||
        hh.size() != GN_HASH_BYTES ||
        pk.size() != GN_PUBLIC_KEY_BYTES) {
        return GN_ERR_OUT_OF_RANGE;
    }
    out_keys->api_size = sizeof(gn_handshake_keys_t);
    std::memcpy(out_keys->send_cipher_key, sk.data(), GN_CIPHER_KEY_BYTES);
    std::memcpy(out_keys->recv_cipher_key, rk.data(), GN_CIPHER_KEY_BYTES);
    out_keys->initial_send_nonce = sn;
    out_keys->initial_recv_nonce = rn;
    std::memcpy(out_keys->handshake_hash, hh.data(), GN_HASH_BYTES);
    std::memcpy(out_keys->peer_static_pk, pk.data(), GN_PUBLIC_KEY_BYTES);
    return GN_OK;
}

[[nodiscard]] gn_result_t security_buffer_round_trip(
    RemoteHost* host,
    std::uint32_t slot_id,
    void* state,
    const uint8_t* in_bytes, size_t in_size,
    gn_secure_buffer_t* out) noexcept {
    if (out == nullptr) return GN_ERR_NULL_ARG;
    std::vector<std::uint8_t> args;
    wire::encode_u64(args, host->worker_self_handle_for_proxy());
    wire::encode_u64(args, reinterpret_cast<std::uintptr_t>(state));
    wire::encode_bytes(args,
        std::span<const std::uint8_t>(in_bytes, in_size));
    RemoteHost::ReplyResult reply;
    if (auto rc = host->round_trip_for_proxy(slot_id, args, reply);
        rc != GN_OK) return rc;
    if (reply.flags & GN_WIRE_FLAG_ERROR) {
        return decode_code_reply(reply.payload, reply.flags);
    }
    wire::Reader r{reply.payload, 0};
    std::size_t n = 0;
    if (wire::decode_array_header(r, n) != GN_OK || n != 2) {
        return GN_ERR_OUT_OF_RANGE;
    }
    std::int64_t code = 0;
    std::span<const std::uint8_t> out_bytes;
    if (wire::decode_i64(r, code) != GN_OK ||
        wire::decode_bytes(r, out_bytes) != GN_OK) {
        return GN_ERR_OUT_OF_RANGE;
    }
    out->bytes = nullptr;
    out->size = 0;
    out->free_user_data = nullptr;
    out->free_fn = nullptr;
    if (!out_bytes.empty()) {
        auto* buf = static_cast<std::uint8_t*>(std::malloc(out_bytes.size()));
        if (buf == nullptr) return GN_ERR_OUT_OF_MEMORY;
        std::memcpy(buf, out_bytes.data(), out_bytes.size());
        out->bytes = buf;
        out->size = out_bytes.size();
        out->free_fn = [](void* /*ud*/, std::uint8_t* p) { std::free(p); };
    }
    return static_cast<gn_result_t>(code);
}

gn_result_t security_encrypt_thunk(void* self, void* state,
                                    const uint8_t* plaintext, size_t plaintext_size,
                                    gn_secure_buffer_t* out) noexcept {
    auto* host = static_cast<RemoteHost*>(self);
    return security_buffer_round_trip(host,
        GN_WIRE_SLOT_SECURITY_ENCRYPT, state,
        plaintext, plaintext_size, out);
}

gn_result_t security_decrypt_thunk(void* self, void* state,
                                    const uint8_t* ciphertext, size_t ciphertext_size,
                                    gn_secure_buffer_t* out) noexcept {
    auto* host = static_cast<RemoteHost*>(self);
    return security_buffer_round_trip(host,
        GN_WIRE_SLOT_SECURITY_DECRYPT, state,
        ciphertext, ciphertext_size, out);
}

gn_result_t security_rekey_thunk(void* self, void* state) noexcept {
    auto* host = static_cast<RemoteHost*>(self);
    std::vector<std::uint8_t> args;
    wire::encode_u64(args, host->worker_self_handle_for_proxy());
    wire::encode_u64(args, reinterpret_cast<std::uintptr_t>(state));
    RemoteHost::ReplyResult reply;
    if (auto rc = host->round_trip_for_proxy(
            GN_WIRE_SLOT_SECURITY_REKEY, args, reply);
        rc != GN_OK) return rc;
    return decode_code_reply(reply.payload, reply.flags);
}

void security_handshake_close_thunk(void* self, void* state) noexcept {
    auto* host = static_cast<RemoteHost*>(self);
    std::vector<std::uint8_t> args;
    wire::encode_u64(args, host->worker_self_handle_for_proxy());
    wire::encode_u64(args, reinterpret_cast<std::uintptr_t>(state));
    RemoteHost::ReplyResult reply;
    (void)host->round_trip_for_proxy(
        GN_WIRE_SLOT_SECURITY_HANDSHAKE_CLOSE, args, reply);
}

void security_destroy_thunk(void* /*self*/) noexcept {
    // Lifetime is owned by the kernel-side RemoteHost; worker-side
    // teardown rides on `PLUGIN_SHUTDOWN`.
}

std::uint32_t security_allowed_trust_mask_thunk(void* self) noexcept {
    auto* host = static_cast<RemoteHost*>(self);
    std::vector<std::uint8_t> args;
    wire::encode_u64(args, host->worker_self_handle_for_proxy());
    RemoteHost::ReplyResult reply;
    if (host->round_trip_for_proxy(
            GN_WIRE_SLOT_SECURITY_PROVIDER_ID, args, reply) != GN_OK) {
        // PROVIDER_ID slot doubles as the trust-mask query — the
        // worker dispatcher returns [code, mask] for this slot.
        return 0u;
    }
    if (reply.flags & GN_WIRE_FLAG_ERROR) return 0u;
    wire::Reader r{reply.payload, 0};
    std::size_t n = 0;
    if (wire::decode_array_header(r, n) != GN_OK || n != 1) return 0u;
    std::uint64_t v = 0;
    if (wire::decode_u64(r, v) != GN_OK) return 0u;
    return static_cast<std::uint32_t>(v);
}

// ── Handler vtable proxy thunks ─────────────────────────────────────

[[nodiscard]] const char* handler_protocol_id_thunk(void* self) noexcept {
    auto* host = static_cast<RemoteHost*>(self);
    return host->descriptor()->name;
}

void handler_supported_msg_ids_thunk(void* self,
                                      const uint32_t** out_ids,
                                      size_t* out_count) noexcept {
    if (out_ids == nullptr || out_count == nullptr) {
        if (out_count != nullptr) *out_count = 0;
        return;
    }
    auto* host = static_cast<RemoteHost*>(self);
    std::vector<std::uint8_t> args;
    wire::encode_u64(args, host->worker_self_handle_for_proxy());
    RemoteHost::ReplyResult reply;
    if (host->round_trip_for_proxy(
            GN_WIRE_SLOT_HANDLER_SUPPORTED_MSG_IDS, args, reply) != GN_OK ||
        (reply.flags & GN_WIRE_FLAG_ERROR) != 0) {
        host->handler_msg_id_cache_for_proxy().clear();
        *out_ids = nullptr;
        *out_count = 0;
        return;
    }
    // reply: [code(i64), msg_ids_array]
    wire::Reader r{reply.payload, 0};
    std::size_t n = 0;
    if (wire::decode_array_header(r, n) != GN_OK || n != 2) {
        *out_ids = nullptr;
        *out_count = 0;
        return;
    }
    std::int64_t code = 0;
    std::size_t count = 0;
    if (wire::decode_i64(r, code) != GN_OK ||
        wire::decode_array_header(r, count) != GN_OK) {
        *out_ids = nullptr;
        *out_count = 0;
        return;
    }
    auto& cache = host->handler_msg_id_cache_for_proxy();
    cache.clear();
    cache.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
        std::uint64_t v = 0;
        if (wire::decode_u64(r, v) != GN_OK) {
            cache.clear();
            *out_ids = nullptr;
            *out_count = 0;
            return;
        }
        cache.push_back(static_cast<std::uint32_t>(v));
    }
    *out_ids = cache.empty() ? nullptr : cache.data();
    *out_count = cache.size();
}

gn_propagation_t handler_handle_message_thunk(
    void* self,
    const gn_message_t* envelope) noexcept {
    if (envelope == nullptr) return GN_PROPAGATION_CONTINUE;
    auto* host = static_cast<RemoteHost*>(self);
    std::vector<std::uint8_t> args;
    wire::encode_u64(args, host->worker_self_handle_for_proxy());
    wire::encode_bytes(args,
        std::span<const std::uint8_t>(envelope->sender_pk, GN_PUBLIC_KEY_BYTES));
    wire::encode_bytes(args,
        std::span<const std::uint8_t>(envelope->receiver_pk, GN_PUBLIC_KEY_BYTES));
    wire::encode_u64(args, envelope->msg_id);
    wire::encode_bytes(args,
        std::span<const std::uint8_t>(envelope->payload, envelope->payload_size));
    wire::encode_u64(args, static_cast<std::uint64_t>(envelope->conn_id));
    RemoteHost::ReplyResult reply;
    if (host->round_trip_for_proxy(
            GN_WIRE_SLOT_HANDLER_HANDLE_MESSAGE, args, reply) != GN_OK) {
        return GN_PROPAGATION_CONTINUE;
    }
    if (reply.flags & GN_WIRE_FLAG_ERROR) {
        return GN_PROPAGATION_CONTINUE;
    }
    wire::Reader r{reply.payload, 0};
    std::size_t n = 0;
    if (wire::decode_array_header(r, n) != GN_OK || n != 1) {
        return GN_PROPAGATION_CONTINUE;
    }
    std::uint64_t v = 0;
    if (wire::decode_u64(r, v) != GN_OK) return GN_PROPAGATION_CONTINUE;
    return static_cast<gn_propagation_t>(v);
}

void handler_on_result_thunk(void* self,
                              const gn_message_t* envelope,
                              gn_propagation_t result) noexcept {
    if (envelope == nullptr) return;
    auto* host = static_cast<RemoteHost*>(self);
    std::vector<std::uint8_t> args;
    wire::encode_u64(args, host->worker_self_handle_for_proxy());
    wire::encode_bytes(args,
        std::span<const std::uint8_t>(envelope->sender_pk, GN_PUBLIC_KEY_BYTES));
    wire::encode_u64(args, envelope->msg_id);
    wire::encode_u64(args, static_cast<std::uint64_t>(envelope->conn_id));
    wire::encode_u64(args, static_cast<std::uint64_t>(result));
    RemoteHost::ReplyResult reply;
    (void)host->round_trip_for_proxy(
        GN_WIRE_SLOT_HANDLER_ON_RESULT, args, reply);
}

void handler_on_init_thunk(void* self) noexcept {
    auto* host = static_cast<RemoteHost*>(self);
    std::vector<std::uint8_t> args;
    wire::encode_u64(args, host->worker_self_handle_for_proxy());
    RemoteHost::ReplyResult reply;
    (void)host->round_trip_for_proxy(
        GN_WIRE_SLOT_HANDLER_ON_INIT, args, reply);
}

void handler_on_shutdown_thunk(void* self) noexcept {
    auto* host = static_cast<RemoteHost*>(self);
    std::vector<std::uint8_t> args;
    wire::encode_u64(args, host->worker_self_handle_for_proxy());
    RemoteHost::ReplyResult reply;
    (void)host->round_trip_for_proxy(
        GN_WIRE_SLOT_HANDLER_ON_SHUTDOWN, args, reply);
}

}  // namespace

const gn_link_vtable_t* RemoteHost::link_vtable_proxy() noexcept {
    if (worker_kind_ != GN_PLUGIN_KIND_LINK) {
        return nullptr;
    }
    if (link_vtable_storage_) {
        return link_vtable_storage_.get();
    }
    link_vtable_storage_ = std::make_unique<gn_link_vtable_t>();
    auto& v = *link_vtable_storage_;
    v.api_size   = sizeof(gn_link_vtable_t);
    v.scheme     = &link_scheme_thunk;
    v.listen     = &link_listen_thunk;
    v.connect    = &link_connect_thunk;
    v.send       = &link_send_thunk;
    v.send_batch = &link_send_batch_thunk;
    v.disconnect = &link_disconnect_thunk;
    v.destroy    = &link_destroy_thunk;
    return link_vtable_storage_.get();
}

const gn_security_provider_vtable_t* RemoteHost::security_vtable_proxy() noexcept {
    if (worker_kind_ != GN_PLUGIN_KIND_SECURITY) {
        return nullptr;
    }
    if (security_vtable_storage_) {
        return security_vtable_storage_.get();
    }
    security_vtable_storage_ = std::make_unique<gn_security_provider_vtable_t>();
    auto& v = *security_vtable_storage_;
    v.api_size              = sizeof(gn_security_provider_vtable_t);
    v.provider_id           = &security_provider_id_thunk;
    v.handshake_open        = &security_handshake_open_thunk;
    v.handshake_step        = &security_handshake_step_thunk;
    v.handshake_complete    = &security_handshake_complete_thunk;
    v.export_transport_keys = &security_export_keys_thunk;
    v.encrypt               = &security_encrypt_thunk;
    v.decrypt               = &security_decrypt_thunk;
    v.rekey                 = &security_rekey_thunk;
    v.handshake_close       = &security_handshake_close_thunk;
    v.destroy               = &security_destroy_thunk;
    v.allowed_trust_mask    = &security_allowed_trust_mask_thunk;
    return security_vtable_storage_.get();
}

const gn_handler_vtable_t* RemoteHost::handler_vtable_proxy() noexcept {
    if (worker_kind_ != GN_PLUGIN_KIND_HANDLER) {
        return nullptr;
    }
    if (handler_vtable_storage_) {
        return handler_vtable_storage_.get();
    }
    handler_vtable_storage_ = std::make_unique<gn_handler_vtable_t>();
    auto& v = *handler_vtable_storage_;
    v.api_size          = sizeof(gn_handler_vtable_t);
    v.protocol_id       = &handler_protocol_id_thunk;
    v.supported_msg_ids = &handler_supported_msg_ids_thunk;
    v.handle_message    = &handler_handle_message_thunk;
    v.on_result         = &handler_on_result_thunk;
    v.on_init           = &handler_on_init_thunk;
    v.on_shutdown       = &handler_on_shutdown_thunk;
    return handler_vtable_storage_.get();
}

}  // namespace gn::core

#endif  // _WIN32 vs POSIX
