/// @file   core/plugin/remote_host.cpp
/// @brief  Implementation of `RemoteHost`. See `remote_host.hpp`
///         for the contract and `docs/contracts/remote-plugin.en.md`
///         for the wire protocol.

#include <core/plugin/remote_host.hpp>

#include <cerrno>
#include <chrono>
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
    if (fut.wait_for(reply_timeout_) != std::future_status::ready) {
        std::lock_guard<std::mutex> lk(pending_mu_);
        pending_.erase(rid);
        return GN_ERR_INVALID_STATE;
    }
    out = fut.get();
    round_trips_.fetch_add(1, std::memory_order_relaxed);
    return GN_OK;
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
    v.disconnect = &link_disconnect_thunk;
    v.destroy    = &link_destroy_thunk;
    return link_vtable_storage_.get();
}

}  // namespace gn::core

#endif  // _WIN32 vs POSIX
