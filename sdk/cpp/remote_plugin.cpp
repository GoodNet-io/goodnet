/// @file   sdk/cpp/remote_plugin.cpp
/// @brief  Worker-side reader loop + synthetic host_api. Mirror of
///         `core/plugin/remote_host.cpp` from the worker side.

#include <sdk/cpp/remote_plugin.hpp>

#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <span>
#include <string>
#include <string_view>
#include <unistd.h>
#include <unordered_map>
#include <vector>
#include <sys/uio.h>

#include <sdk/remote/slots.h>
#include <sdk/remote/wire.h>

#include <core/plugin/wire_codec.hpp>

namespace gn::sdk::remote {

namespace {

constexpr int kKernelFd = 3;

struct WorkerState {
    const WorkerConfig*       cfg            = nullptr;
    int                       fd             = kKernelFd;
    void*                     self           = nullptr;
    std::uint64_t             host_ctx_handle = 0;
    host_api_t                synth_api      = {};
    bool                      stopping       = false;

    /// Map from u64 state handle to the void* the worker's vtable
    /// returned from `handshake_open`. Kept inside the worker so the
    /// wire never sees a raw pointer.
    std::unordered_map<std::uint64_t, void*> security_states;
    std::uint64_t next_state_handle = 1;
};

WorkerState g_state{};

void serialise_header(const gn_wire_frame_t& f,
                      std::uint8_t out[16]) noexcept {
    std::memcpy(out + 0,  &f.kind,         4);
    std::memcpy(out + 4,  &f.request_id,   4);
    std::memcpy(out + 8,  &f.payload_size, 4);
    std::memcpy(out + 12, &f.flags,        4);
}

void parse_header(const std::uint8_t buf[16],
                  gn_wire_frame_t& out) noexcept {
    std::memcpy(&out.kind,         buf + 0,  4);
    std::memcpy(&out.request_id,   buf + 4,  4);
    std::memcpy(&out.payload_size, buf + 8,  4);
    std::memcpy(&out.flags,        buf + 12, 4);
}

[[nodiscard]] bool read_exact(int fd, std::uint8_t* out, std::size_t n) {
    std::size_t got = 0;
    while (got < n) {
        ssize_t r = ::read(fd, out + got, n - got);
        if (r > 0) { got += static_cast<std::size_t>(r); continue; }
        if (r == 0) return false;
        if (errno == EINTR) continue;
        return false;
    }
    return true;
}

[[nodiscard]] bool write_frame(int fd,
                               std::uint32_t kind,
                               std::uint32_t request_id,
                               std::uint32_t flags,
                               std::span<const std::uint8_t> payload) {
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
    while (written < total) {
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
        ssize_t w = ::writev(fd, local, n);
        if (w > 0) { written += static_cast<std::size_t>(w); continue; }
        if (w < 0 && errno == EINTR) continue;
        return false;
    }
    return true;
}

[[nodiscard]] gn_result_t do_host_call(std::uint32_t slot_id,
                                       const std::vector<std::uint8_t>& args,
                                       std::vector<std::uint8_t>& out_payload,
                                       std::uint32_t& out_flags) {
    static std::uint32_t s_next_request_id = 1;
    const std::uint32_t rid = s_next_request_id++;
    std::vector<std::uint8_t> frame;
    namespace wire = ::gn::core::wire;
    wire::encode_array_header(frame, 2);
    wire::encode_u64(frame, slot_id);
    frame.insert(frame.end(), args.begin(), args.end());
    if (!write_frame(g_state.fd, GN_WIRE_HOST_CALL, rid, 0, frame)) {
        return GN_ERR_INTERNAL;
    }
    // Read until we see HOST_REPLY for our rid. PLUGIN_CALL frames
    // received during the wait would deadlock — the single-threaded
    // worker contract forbids host_api calls during a PLUGIN_CALL
    // we are servicing, see remote_plugin.hpp.
    std::uint8_t hdr_buf[16];
    while (true) {
        if (!read_exact(g_state.fd, hdr_buf, 16)) return GN_ERR_INVALID_STATE;
        gn_wire_frame_t hdr{};
        parse_header(hdr_buf, hdr);
        std::vector<std::uint8_t> payload(hdr.payload_size);
        if (hdr.payload_size > 0 &&
            !read_exact(g_state.fd, payload.data(), hdr.payload_size)) {
            return GN_ERR_INVALID_STATE;
        }
        if (hdr.kind == GN_WIRE_HOST_REPLY && hdr.request_id == rid) {
            out_payload = std::move(payload);
            out_flags   = hdr.flags;
            return GN_OK;
        }
        if (hdr.kind == GN_WIRE_GOODBYE) {
            g_state.stopping = true;
            return GN_ERR_INVALID_STATE;
        }
        // Anything else (unexpected PLUGIN_CALL etc.) is a protocol
        // violation in single-threaded mode; bail.
        return GN_ERR_INVALID_STATE;
    }
}

// ── Synthetic host_api thunks ─────────────────────────────────────

void thunk_log_emit(void* /*host_ctx*/,
                    gn_log_level_t level,
                    const char* file,
                    int32_t line,
                    const char* msg) {
    namespace wire = ::gn::core::wire;
    std::vector<std::uint8_t> args;
    wire::encode_u64(args, static_cast<std::uint64_t>(level));
    wire::encode_text(args, file ? std::string_view(file) : std::string_view());
    wire::encode_i64(args, line);
    wire::encode_text(args, msg ? std::string_view(msg) : std::string_view());
    std::vector<std::uint8_t> reply;
    std::uint32_t flags = 0;
    (void)do_host_call(GN_WIRE_HOST_SLOT_LOG_EMIT, args, reply, flags);
}

int32_t thunk_is_shutdown_requested(void* /*host_ctx*/) {
    namespace wire = ::gn::core::wire;
    std::vector<std::uint8_t> args;
    std::vector<std::uint8_t> reply;
    std::uint32_t flags = 0;
    if (do_host_call(GN_WIRE_HOST_SLOT_IS_SHUTDOWN_REQUESTED, args, reply, flags)
        != GN_OK) {
        return 0;
    }
    wire::Reader r{reply, 0};
    std::size_t n = 0;
    if (wire::decode_array_header(r, n) != GN_OK || n != 1) return 0;
    std::int64_t v = 0;
    if (wire::decode_i64(r, v) != GN_OK) return 0;
    return static_cast<int32_t>(v);
}

gn_result_t thunk_notify_inbound_bytes(void* /*host_ctx*/,
                                       gn_conn_id_t conn,
                                       const uint8_t* bytes,
                                       size_t size) {
    namespace wire = ::gn::core::wire;
    std::vector<std::uint8_t> args;
    wire::encode_u64(args, conn);
    wire::encode_bytes(args,
        std::span<const std::uint8_t>(bytes, size));
    std::vector<std::uint8_t> reply;
    std::uint32_t flags = 0;
    if (auto rc = do_host_call(GN_WIRE_HOST_SLOT_NOTIFY_INBOUND_BYTES,
                                args, reply, flags);
        rc != GN_OK) return rc;
    if (flags & GN_WIRE_FLAG_ERROR) return GN_ERR_INTERNAL;
    wire::Reader r{reply, 0};
    std::size_t n = 0;
    if (wire::decode_array_header(r, n) != GN_OK || n != 1) {
        return GN_ERR_OUT_OF_RANGE;
    }
    std::int64_t code = 0;
    if (wire::decode_i64(r, code) != GN_OK) return GN_ERR_OUT_OF_RANGE;
    return static_cast<gn_result_t>(code);
}

gn_result_t thunk_notify_connect(void* /*host_ctx*/,
                                 const uint8_t remote_pk[GN_PUBLIC_KEY_BYTES],
                                 const char* uri,
                                 gn_trust_class_t trust,
                                 gn_handshake_role_t role,
                                 gn_conn_id_t* out_conn) {
    namespace wire = ::gn::core::wire;
    if (out_conn == nullptr || remote_pk == nullptr || uri == nullptr) {
        return GN_ERR_NULL_ARG;
    }
    std::vector<std::uint8_t> args;
    wire::encode_bytes(args,
        std::span<const std::uint8_t>(remote_pk, GN_PUBLIC_KEY_BYTES));
    wire::encode_text(args, std::string_view(uri));
    wire::encode_u64(args, static_cast<std::uint64_t>(trust));
    wire::encode_u64(args, static_cast<std::uint64_t>(role));
    std::vector<std::uint8_t> reply;
    std::uint32_t flags = 0;
    if (auto rc = do_host_call(GN_WIRE_HOST_SLOT_NOTIFY_CONNECT,
                                args, reply, flags);
        rc != GN_OK) return rc;
    if (flags & GN_WIRE_FLAG_ERROR) return GN_ERR_INTERNAL;
    wire::Reader r{reply, 0};
    std::size_t n = 0;
    if (wire::decode_array_header(r, n) != GN_OK || n != 2) {
        return GN_ERR_OUT_OF_RANGE;
    }
    std::int64_t code = 0;
    std::uint64_t conn = 0;
    if (wire::decode_i64(r, code) != GN_OK ||
        wire::decode_u64(r, conn) != GN_OK) {
        return GN_ERR_OUT_OF_RANGE;
    }
    *out_conn = static_cast<gn_conn_id_t>(conn);
    return static_cast<gn_result_t>(code);
}

gn_result_t thunk_notify_disconnect(void* /*host_ctx*/,
                                    gn_conn_id_t conn,
                                    gn_result_t reason) {
    namespace wire = ::gn::core::wire;
    std::vector<std::uint8_t> args;
    wire::encode_u64(args, conn);
    wire::encode_i64(args, static_cast<std::int64_t>(reason));
    std::vector<std::uint8_t> reply;
    std::uint32_t flags = 0;
    if (auto rc = do_host_call(GN_WIRE_HOST_SLOT_NOTIFY_DISCONNECT,
                                args, reply, flags);
        rc != GN_OK) return rc;
    if (flags & GN_WIRE_FLAG_ERROR) return GN_ERR_INTERNAL;
    wire::Reader r{reply, 0};
    std::size_t n = 0;
    if (wire::decode_array_header(r, n) != GN_OK || n != 1) {
        return GN_ERR_OUT_OF_RANGE;
    }
    std::int64_t code = 0;
    if (wire::decode_i64(r, code) != GN_OK) return GN_ERR_OUT_OF_RANGE;
    return static_cast<gn_result_t>(code);
}

gn_result_t thunk_register_vtable(void* /*host_ctx*/,
                                  gn_register_kind_t kind,
                                  const gn_register_meta_t* meta,
                                  const void* /*vtable*/,
                                  void* /*self*/,
                                  uint64_t* out_id) {
    namespace wire = ::gn::core::wire;
    if (meta == nullptr || meta->name == nullptr || out_id == nullptr) {
        return GN_ERR_NULL_ARG;
    }
    std::vector<std::uint8_t> args;
    wire::encode_u64(args, static_cast<std::uint64_t>(kind));
    wire::encode_text(args, std::string_view(meta->name));
    wire::encode_u64(args, static_cast<std::uint64_t>(meta->msg_id));
    wire::encode_u64(args, static_cast<std::uint64_t>(meta->priority));
    wire::encode_text(args, meta->protocol_id
                              ? std::string_view(meta->protocol_id)
                              : std::string_view());
    wire::encode_text(args, meta->namespace_id
                              ? std::string_view(meta->namespace_id)
                              : std::string_view());
    std::vector<std::uint8_t> reply;
    std::uint32_t flags = 0;
    if (auto rc = do_host_call(GN_WIRE_HOST_SLOT_REGISTER_VTABLE,
                                args, reply, flags);
        rc != GN_OK) return rc;
    if (flags & GN_WIRE_FLAG_ERROR) return GN_ERR_INTERNAL;
    wire::Reader r{reply, 0};
    std::size_t n = 0;
    if (wire::decode_array_header(r, n) != GN_OK || n != 2) {
        return GN_ERR_OUT_OF_RANGE;
    }
    std::int64_t code = 0;
    std::uint64_t id = 0;
    if (wire::decode_i64(r, code) != GN_OK ||
        wire::decode_u64(r, id) != GN_OK) {
        return GN_ERR_OUT_OF_RANGE;
    }
    *out_id = id;
    return static_cast<gn_result_t>(code);
}

gn_result_t thunk_register_security(void* /*host_ctx*/,
                                    const char* provider_id,
                                    const gn_security_provider_vtable_t* /*vtable*/,
                                    void* /*security_self*/) {
    namespace wire = ::gn::core::wire;
    if (provider_id == nullptr) return GN_ERR_NULL_ARG;
    std::vector<std::uint8_t> args;
    wire::encode_text(args, std::string_view(provider_id));
    std::vector<std::uint8_t> reply;
    std::uint32_t flags = 0;
    if (auto rc = do_host_call(GN_WIRE_HOST_SLOT_REGISTER_SECURITY,
                                args, reply, flags);
        rc != GN_OK) return rc;
    if (flags & GN_WIRE_FLAG_ERROR) return GN_ERR_INTERNAL;
    wire::Reader r{reply, 0};
    std::size_t n = 0;
    if (wire::decode_array_header(r, n) != GN_OK || n != 1) {
        return GN_ERR_OUT_OF_RANGE;
    }
    std::int64_t code = 0;
    if (wire::decode_i64(r, code) != GN_OK) return GN_ERR_OUT_OF_RANGE;
    return static_cast<gn_result_t>(code);
}

gn_result_t thunk_unregister_security(void* /*host_ctx*/,
                                      const char* provider_id) {
    namespace wire = ::gn::core::wire;
    if (provider_id == nullptr) return GN_ERR_NULL_ARG;
    std::vector<std::uint8_t> args;
    wire::encode_text(args, std::string_view(provider_id));
    std::vector<std::uint8_t> reply;
    std::uint32_t flags = 0;
    if (auto rc = do_host_call(GN_WIRE_HOST_SLOT_UNREGISTER_SECURITY,
                                args, reply, flags);
        rc != GN_OK) return rc;
    if (flags & GN_WIRE_FLAG_ERROR) return GN_ERR_INTERNAL;
    wire::Reader r{reply, 0};
    std::size_t n = 0;
    if (wire::decode_array_header(r, n) != GN_OK || n != 1) {
        return GN_ERR_OUT_OF_RANGE;
    }
    std::int64_t code = 0;
    if (wire::decode_i64(r, code) != GN_OK) return GN_ERR_OUT_OF_RANGE;
    return static_cast<gn_result_t>(code);
}

gn_result_t thunk_unregister_vtable(void* /*host_ctx*/, uint64_t id) {
    namespace wire = ::gn::core::wire;
    std::vector<std::uint8_t> args;
    wire::encode_u64(args, id);
    std::vector<std::uint8_t> reply;
    std::uint32_t flags = 0;
    if (auto rc = do_host_call(GN_WIRE_HOST_SLOT_UNREGISTER_VTABLE,
                                args, reply, flags);
        rc != GN_OK) return rc;
    if (flags & GN_WIRE_FLAG_ERROR) return GN_ERR_INTERNAL;
    wire::Reader r{reply, 0};
    std::size_t n = 0;
    if (wire::decode_array_header(r, n) != GN_OK || n != 1) {
        return GN_ERR_OUT_OF_RANGE;
    }
    std::int64_t code = 0;
    if (wire::decode_i64(r, code) != GN_OK) return GN_ERR_OUT_OF_RANGE;
    return static_cast<gn_result_t>(code);
}

// ── Lifecycle replies ─────────────────────────────────────────────

void encode_lifecycle_reply(std::vector<std::uint8_t>& out,
                            gn_result_t code,
                            std::uint64_t self_handle) {
    namespace wire = ::gn::core::wire;
    wire::encode_i64(out, code);
    wire::encode_u64(out, self_handle);
}

void encode_code_reply(std::vector<std::uint8_t>& out, gn_result_t code) {
    namespace wire = ::gn::core::wire;
    wire::encode_i64(out, code);
}

// Dispatch one PLUGIN_CALL frame and write its reply. Returns false
// if the wire is broken.
[[nodiscard]] bool dispatch_plugin_call(std::uint32_t request_id,
                                        std::span<const std::uint8_t> payload) {
    namespace wire = ::gn::core::wire;
    wire::Reader r{payload, 0};
    std::size_t arr_n = 0;
    if (wire::decode_array_header(r, arr_n) != GN_OK || arr_n < 1) {
        std::vector<std::uint8_t> err;
        wire::encode_i64(err, GN_ERR_OUT_OF_RANGE);
        return write_frame(g_state.fd, GN_WIRE_PLUGIN_REPLY, request_id, 0, err);
    }
    std::uint64_t slot_id = 0;
    if (wire::decode_u64(r, slot_id) != GN_OK) {
        std::vector<std::uint8_t> err;
        wire::encode_i64(err, GN_ERR_OUT_OF_RANGE);
        return write_frame(g_state.fd, GN_WIRE_PLUGIN_REPLY, request_id, 0, err);
    }
    std::vector<std::uint8_t> reply;
    switch (slot_id) {
        case GN_WIRE_SLOT_PLUGIN_INIT: {
            gn_result_t rc = GN_OK;
            if (g_state.cfg->on_init != nullptr) {
                rc = g_state.cfg->on_init(synthetic_host_api(),
                                          &g_state.self);
            } else if (g_state.cfg->link_self != nullptr) {
                g_state.self = g_state.cfg->link_self;
            }
            std::uint64_t handle = reinterpret_cast<std::uintptr_t>(g_state.self);
            encode_lifecycle_reply(reply, rc, handle);
            break;
        }
        case GN_WIRE_SLOT_PLUGIN_REGISTER: {
            gn_result_t rc = GN_OK;
            if (g_state.cfg->on_register != nullptr) {
                rc = g_state.cfg->on_register(g_state.self);
            }
            encode_code_reply(reply, rc);
            break;
        }
        case GN_WIRE_SLOT_PLUGIN_UNREGISTER: {
            gn_result_t rc = GN_OK;
            if (g_state.cfg->on_unregister != nullptr) {
                rc = g_state.cfg->on_unregister(g_state.self);
            }
            encode_code_reply(reply, rc);
            break;
        }
        case GN_WIRE_SLOT_PLUGIN_SHUTDOWN: {
            if (g_state.cfg->on_shutdown != nullptr) {
                g_state.cfg->on_shutdown(g_state.self);
            }
            encode_code_reply(reply, GN_OK);
            break;
        }
        case GN_WIRE_SLOT_LINK_LISTEN: {
            std::uint64_t worker_self = 0;
            std::string_view uri{};
            if (wire::decode_u64(r, worker_self) != GN_OK ||
                wire::decode_text(r, uri) != GN_OK) {
                encode_code_reply(reply, GN_ERR_OUT_OF_RANGE);
                break;
            }
            gn_result_t rc = GN_ERR_NOT_IMPLEMENTED;
            if (g_state.cfg->link_vtable && g_state.cfg->link_vtable->listen) {
                const std::string uri_z(uri);
                rc = g_state.cfg->link_vtable->listen(
                    g_state.cfg->link_self, uri_z.c_str());
            }
            encode_code_reply(reply, rc);
            (void)worker_self;
            break;
        }
        case GN_WIRE_SLOT_LINK_CONNECT: {
            std::uint64_t worker_self = 0;
            std::string_view uri{};
            if (wire::decode_u64(r, worker_self) != GN_OK ||
                wire::decode_text(r, uri) != GN_OK) {
                encode_code_reply(reply, GN_ERR_OUT_OF_RANGE);
                break;
            }
            gn_result_t rc = GN_ERR_NOT_IMPLEMENTED;
            if (g_state.cfg->link_vtable && g_state.cfg->link_vtable->connect) {
                const std::string uri_z(uri);
                rc = g_state.cfg->link_vtable->connect(
                    g_state.cfg->link_self, uri_z.c_str());
            }
            encode_code_reply(reply, rc);
            (void)worker_self;
            break;
        }
        case GN_WIRE_SLOT_LINK_SEND: {
            std::uint64_t worker_self = 0;
            std::uint64_t conn        = 0;
            std::span<const std::uint8_t> bytes;
            if (wire::decode_u64(r, worker_self) != GN_OK ||
                wire::decode_u64(r, conn) != GN_OK ||
                wire::decode_bytes(r, bytes) != GN_OK) {
                encode_code_reply(reply, GN_ERR_OUT_OF_RANGE);
                break;
            }
            gn_result_t rc = GN_ERR_NOT_IMPLEMENTED;
            if (g_state.cfg->link_vtable && g_state.cfg->link_vtable->send) {
                rc = g_state.cfg->link_vtable->send(
                    g_state.cfg->link_self,
                    static_cast<gn_conn_id_t>(conn),
                    bytes.data(), bytes.size());
            }
            encode_code_reply(reply, rc);
            (void)worker_self;
            break;
        }
        case GN_WIRE_SLOT_LINK_DISCONNECT: {
            std::uint64_t worker_self = 0;
            std::uint64_t conn        = 0;
            if (wire::decode_u64(r, worker_self) != GN_OK ||
                wire::decode_u64(r, conn) != GN_OK) {
                encode_code_reply(reply, GN_ERR_OUT_OF_RANGE);
                break;
            }
            gn_result_t rc = GN_ERR_NOT_IMPLEMENTED;
            if (g_state.cfg->link_vtable && g_state.cfg->link_vtable->disconnect) {
                rc = g_state.cfg->link_vtable->disconnect(
                    g_state.cfg->link_self,
                    static_cast<gn_conn_id_t>(conn));
            }
            encode_code_reply(reply, rc);
            (void)worker_self;
            break;
        }
        case GN_WIRE_SLOT_LINK_DESTROY: {
            // Lifetime is anchored on the kernel side; the worker's
            // destroy fires implicitly during PLUGIN_SHUTDOWN.
            encode_code_reply(reply, GN_OK);
            break;
        }
        case GN_WIRE_SLOT_SECURITY_PROVIDER_ID: {
            // Worker reply carries the trust mask; provider id text is
            // already in HELLO so the wire does not repeat it here.
            std::uint64_t worker_self = 0;
            (void)wire::decode_u64(r, worker_self);
            std::uint32_t mask = 0;
            if (g_state.cfg->security_vtable &&
                g_state.cfg->security_vtable->allowed_trust_mask) {
                mask = g_state.cfg->security_vtable->allowed_trust_mask(
                    g_state.cfg->security_self);
            }
            wire::encode_array_header(reply, 1);
            wire::encode_u64(reply, mask);
            break;
        }
        case GN_WIRE_SLOT_SECURITY_HANDSHAKE_OPEN: {
            std::uint64_t worker_self = 0;
            std::uint64_t conn = 0;
            std::uint64_t trust = 0;
            std::uint64_t role = 0;
            std::span<const std::uint8_t> sk, lpk, rpk;
            if (wire::decode_u64(r, worker_self) != GN_OK ||
                wire::decode_u64(r, conn) != GN_OK ||
                wire::decode_u64(r, trust) != GN_OK ||
                wire::decode_u64(r, role) != GN_OK ||
                wire::decode_bytes(r, sk) != GN_OK ||
                wire::decode_bytes(r, lpk) != GN_OK ||
                wire::decode_bytes(r, rpk) != GN_OK) {
                wire::encode_array_header(reply, 2);
                wire::encode_i64(reply, GN_ERR_OUT_OF_RANGE);
                wire::encode_u64(reply, 0);
                break;
            }
            if (sk.size() != GN_PRIVATE_KEY_BYTES ||
                lpk.size() != GN_PUBLIC_KEY_BYTES) {
                wire::encode_array_header(reply, 2);
                wire::encode_i64(reply, GN_ERR_OUT_OF_RANGE);
                wire::encode_u64(reply, 0);
                break;
            }
            void* state = nullptr;
            gn_result_t rc = GN_ERR_NOT_IMPLEMENTED;
            if (g_state.cfg->security_vtable &&
                g_state.cfg->security_vtable->handshake_open) {
                const std::uint8_t* rpk_ptr =
                    rpk.size() == GN_PUBLIC_KEY_BYTES ? rpk.data() : nullptr;
                rc = g_state.cfg->security_vtable->handshake_open(
                    g_state.cfg->security_self,
                    static_cast<gn_conn_id_t>(conn),
                    static_cast<gn_trust_class_t>(trust),
                    static_cast<gn_handshake_role_t>(role),
                    sk.data(), lpk.data(), rpk_ptr, &state);
            }
            std::uint64_t handle = 0;
            if (rc == GN_OK && state != nullptr) {
                handle = g_state.next_state_handle++;
                g_state.security_states[handle] = state;
            }
            wire::encode_array_header(reply, 2);
            wire::encode_i64(reply, rc);
            wire::encode_u64(reply, handle);
            break;
        }
        case GN_WIRE_SLOT_SECURITY_HANDSHAKE_STEP: {
            std::uint64_t worker_self = 0;
            std::uint64_t state_handle = 0;
            std::span<const std::uint8_t> incoming;
            if (wire::decode_u64(r, worker_self) != GN_OK ||
                wire::decode_u64(r, state_handle) != GN_OK ||
                wire::decode_bytes(r, incoming) != GN_OK) {
                wire::encode_array_header(reply, 2);
                wire::encode_i64(reply, GN_ERR_OUT_OF_RANGE);
                wire::encode_bytes(reply, std::span<const std::uint8_t>{});
                break;
            }
            auto it = g_state.security_states.find(state_handle);
            if (it == g_state.security_states.end()) {
                wire::encode_array_header(reply, 2);
                wire::encode_i64(reply, GN_ERR_NOT_FOUND);
                wire::encode_bytes(reply, std::span<const std::uint8_t>{});
                break;
            }
            gn_secure_buffer_t out{};
            gn_result_t rc = GN_ERR_NOT_IMPLEMENTED;
            if (g_state.cfg->security_vtable &&
                g_state.cfg->security_vtable->handshake_step) {
                rc = g_state.cfg->security_vtable->handshake_step(
                    g_state.cfg->security_self, it->second,
                    incoming.data(), incoming.size(), &out);
            }
            wire::encode_array_header(reply, 2);
            wire::encode_i64(reply, rc);
            wire::encode_bytes(reply,
                std::span<const std::uint8_t>(
                    out.bytes ? out.bytes : nullptr,
                    out.bytes ? out.size : 0));
            if (out.bytes && out.free_fn) {
                out.free_fn(out.free_user_data, out.bytes);
            }
            break;
        }
        case GN_WIRE_SLOT_SECURITY_HANDSHAKE_COMPLETE: {
            std::uint64_t worker_self = 0;
            std::uint64_t state_handle = 0;
            if (wire::decode_u64(r, worker_self) != GN_OK ||
                wire::decode_u64(r, state_handle) != GN_OK) {
                wire::encode_array_header(reply, 1);
                wire::encode_i64(reply, 0);
                break;
            }
            auto it = g_state.security_states.find(state_handle);
            int v = 0;
            if (it != g_state.security_states.end() &&
                g_state.cfg->security_vtable &&
                g_state.cfg->security_vtable->handshake_complete) {
                v = g_state.cfg->security_vtable->handshake_complete(
                    g_state.cfg->security_self, it->second);
            }
            wire::encode_array_header(reply, 1);
            wire::encode_i64(reply, v);
            break;
        }
        case GN_WIRE_SLOT_SECURITY_EXPORT_KEYS: {
            std::uint64_t worker_self = 0;
            std::uint64_t state_handle = 0;
            if (wire::decode_u64(r, worker_self) != GN_OK ||
                wire::decode_u64(r, state_handle) != GN_OK) {
                wire::encode_array_header(reply, 7);
                wire::encode_i64(reply, GN_ERR_OUT_OF_RANGE);
                wire::encode_bytes(reply, std::span<const std::uint8_t>{});
                wire::encode_bytes(reply, std::span<const std::uint8_t>{});
                wire::encode_u64(reply, 0);
                wire::encode_u64(reply, 0);
                wire::encode_bytes(reply, std::span<const std::uint8_t>{});
                wire::encode_bytes(reply, std::span<const std::uint8_t>{});
                break;
            }
            gn_handshake_keys_t keys{};
            keys.api_size = sizeof(gn_handshake_keys_t);
            gn_result_t rc = GN_ERR_NOT_IMPLEMENTED;
            auto it = g_state.security_states.find(state_handle);
            if (it != g_state.security_states.end() &&
                g_state.cfg->security_vtable &&
                g_state.cfg->security_vtable->export_transport_keys) {
                rc = g_state.cfg->security_vtable->export_transport_keys(
                    g_state.cfg->security_self, it->second, &keys);
            }
            wire::encode_array_header(reply, 7);
            wire::encode_i64(reply, rc);
            wire::encode_bytes(reply,
                std::span<const std::uint8_t>(keys.send_cipher_key, GN_CIPHER_KEY_BYTES));
            wire::encode_bytes(reply,
                std::span<const std::uint8_t>(keys.recv_cipher_key, GN_CIPHER_KEY_BYTES));
            wire::encode_u64(reply, keys.initial_send_nonce);
            wire::encode_u64(reply, keys.initial_recv_nonce);
            wire::encode_bytes(reply,
                std::span<const std::uint8_t>(keys.handshake_hash, GN_HASH_BYTES));
            wire::encode_bytes(reply,
                std::span<const std::uint8_t>(keys.peer_static_pk, GN_PUBLIC_KEY_BYTES));
            // Zeroise the local copy; the wire takes a snapshot above.
            std::memset(&keys, 0, sizeof(keys));
            break;
        }
        case GN_WIRE_SLOT_SECURITY_ENCRYPT:
        case GN_WIRE_SLOT_SECURITY_DECRYPT: {
            const bool is_encrypt =
                (slot_id == GN_WIRE_SLOT_SECURITY_ENCRYPT);
            std::uint64_t worker_self = 0;
            std::uint64_t state_handle = 0;
            std::span<const std::uint8_t> in_bytes;
            if (wire::decode_u64(r, worker_self) != GN_OK ||
                wire::decode_u64(r, state_handle) != GN_OK ||
                wire::decode_bytes(r, in_bytes) != GN_OK) {
                wire::encode_array_header(reply, 2);
                wire::encode_i64(reply, GN_ERR_OUT_OF_RANGE);
                wire::encode_bytes(reply, std::span<const std::uint8_t>{});
                break;
            }
            gn_secure_buffer_t out{};
            gn_result_t rc = GN_ERR_NOT_IMPLEMENTED;
            auto it = g_state.security_states.find(state_handle);
            if (it != g_state.security_states.end() && g_state.cfg->security_vtable) {
                auto fn = is_encrypt
                    ? g_state.cfg->security_vtable->encrypt
                    : g_state.cfg->security_vtable->decrypt;
                if (fn != nullptr) {
                    rc = fn(g_state.cfg->security_self, it->second,
                            in_bytes.data(), in_bytes.size(), &out);
                }
            }
            wire::encode_array_header(reply, 2);
            wire::encode_i64(reply, rc);
            wire::encode_bytes(reply,
                std::span<const std::uint8_t>(
                    out.bytes ? out.bytes : nullptr,
                    out.bytes ? out.size : 0));
            if (out.bytes && out.free_fn) {
                out.free_fn(out.free_user_data, out.bytes);
            }
            break;
        }
        case GN_WIRE_SLOT_SECURITY_REKEY: {
            std::uint64_t worker_self = 0;
            std::uint64_t state_handle = 0;
            if (wire::decode_u64(r, worker_self) != GN_OK ||
                wire::decode_u64(r, state_handle) != GN_OK) {
                encode_code_reply(reply, GN_ERR_OUT_OF_RANGE);
                break;
            }
            gn_result_t rc = GN_ERR_NOT_IMPLEMENTED;
            auto it = g_state.security_states.find(state_handle);
            if (it != g_state.security_states.end() &&
                g_state.cfg->security_vtable &&
                g_state.cfg->security_vtable->rekey) {
                rc = g_state.cfg->security_vtable->rekey(
                    g_state.cfg->security_self, it->second);
            }
            encode_code_reply(reply, rc);
            break;
        }
        case GN_WIRE_SLOT_SECURITY_HANDSHAKE_CLOSE: {
            std::uint64_t worker_self = 0;
            std::uint64_t state_handle = 0;
            if (wire::decode_u64(r, worker_self) != GN_OK ||
                wire::decode_u64(r, state_handle) != GN_OK) {
                encode_code_reply(reply, GN_ERR_OUT_OF_RANGE);
                break;
            }
            auto it = g_state.security_states.find(state_handle);
            if (it != g_state.security_states.end()) {
                if (g_state.cfg->security_vtable &&
                    g_state.cfg->security_vtable->handshake_close) {
                    g_state.cfg->security_vtable->handshake_close(
                        g_state.cfg->security_self, it->second);
                }
                g_state.security_states.erase(it);
            }
            encode_code_reply(reply, GN_OK);
            break;
        }
        case GN_WIRE_SLOT_HANDLER_PROTOCOL_ID: {
            // Worker-side handler ships protocol_id text inline. The
            // kernel proxy already serves descriptor->name without a
            // round-trip, so this slot is currently a no-op; reserved
            // for parity with the LINK pattern.
            wire::encode_array_header(reply, 1);
            wire::encode_i64(reply, GN_OK);
            break;
        }
        case GN_WIRE_SLOT_HANDLER_SUPPORTED_MSG_IDS: {
            std::uint64_t worker_self = 0;
            (void)wire::decode_u64(r, worker_self);
            const std::uint32_t* ids = nullptr;
            std::size_t count = 0;
            if (g_state.cfg->handler_vtable &&
                g_state.cfg->handler_vtable->supported_msg_ids) {
                g_state.cfg->handler_vtable->supported_msg_ids(
                    g_state.cfg->handler_self, &ids, &count);
            }
            wire::encode_array_header(reply, 2);
            wire::encode_i64(reply, GN_OK);
            wire::encode_array_header(reply, count);
            for (std::size_t i = 0; i < count; ++i) {
                wire::encode_u64(reply, ids != nullptr ? ids[i] : 0u);
            }
            break;
        }
        case GN_WIRE_SLOT_HANDLER_HANDLE_MESSAGE: {
            std::uint64_t worker_self = 0;
            std::span<const std::uint8_t> sender_pk, receiver_pk, body;
            std::uint64_t msg_id = 0;
            std::uint64_t conn_id = 0;
            if (wire::decode_u64(r, worker_self) != GN_OK ||
                wire::decode_bytes(r, sender_pk) != GN_OK ||
                wire::decode_bytes(r, receiver_pk) != GN_OK ||
                wire::decode_u64(r, msg_id) != GN_OK ||
                wire::decode_bytes(r, body) != GN_OK ||
                wire::decode_u64(r, conn_id) != GN_OK ||
                sender_pk.size() != GN_PUBLIC_KEY_BYTES ||
                receiver_pk.size() != GN_PUBLIC_KEY_BYTES) {
                wire::encode_array_header(reply, 1);
                wire::encode_u64(reply, GN_PROPAGATION_CONTINUE);
                break;
            }
            gn_message_t env{};
            env.api_size = sizeof(gn_message_t);
            std::memcpy(env.sender_pk, sender_pk.data(), GN_PUBLIC_KEY_BYTES);
            std::memcpy(env.receiver_pk, receiver_pk.data(), GN_PUBLIC_KEY_BYTES);
            env.msg_id = static_cast<std::uint32_t>(msg_id);
            env.payload = body.empty() ? nullptr : body.data();
            env.payload_size = body.size();
            env.conn_id = static_cast<gn_conn_id_t>(conn_id);
            gn_propagation_t rc = GN_PROPAGATION_CONTINUE;
            if (g_state.cfg->handler_vtable &&
                g_state.cfg->handler_vtable->handle_message) {
                rc = g_state.cfg->handler_vtable->handle_message(
                    g_state.cfg->handler_self, &env);
            }
            wire::encode_array_header(reply, 1);
            wire::encode_u64(reply, static_cast<std::uint64_t>(rc));
            break;
        }
        case GN_WIRE_SLOT_HANDLER_ON_RESULT: {
            std::uint64_t worker_self = 0;
            std::span<const std::uint8_t> sender_pk;
            std::uint64_t msg_id = 0;
            std::uint64_t conn_id = 0;
            std::uint64_t result = 0;
            if (wire::decode_u64(r, worker_self) != GN_OK ||
                wire::decode_bytes(r, sender_pk) != GN_OK ||
                wire::decode_u64(r, msg_id) != GN_OK ||
                wire::decode_u64(r, conn_id) != GN_OK ||
                wire::decode_u64(r, result) != GN_OK) {
                encode_code_reply(reply, GN_ERR_OUT_OF_RANGE);
                break;
            }
            if (g_state.cfg->handler_vtable &&
                g_state.cfg->handler_vtable->on_result) {
                gn_message_t env{};
                env.api_size = sizeof(gn_message_t);
                if (sender_pk.size() == GN_PUBLIC_KEY_BYTES) {
                    std::memcpy(env.sender_pk, sender_pk.data(), GN_PUBLIC_KEY_BYTES);
                }
                env.msg_id = static_cast<std::uint32_t>(msg_id);
                env.conn_id = static_cast<gn_conn_id_t>(conn_id);
                g_state.cfg->handler_vtable->on_result(
                    g_state.cfg->handler_self, &env,
                    static_cast<gn_propagation_t>(result));
            }
            encode_code_reply(reply, GN_OK);
            break;
        }
        case GN_WIRE_SLOT_HANDLER_ON_INIT: {
            std::uint64_t worker_self = 0;
            (void)wire::decode_u64(r, worker_self);
            if (g_state.cfg->handler_vtable &&
                g_state.cfg->handler_vtable->on_init) {
                g_state.cfg->handler_vtable->on_init(g_state.cfg->handler_self);
            }
            encode_code_reply(reply, GN_OK);
            break;
        }
        case GN_WIRE_SLOT_HANDLER_ON_SHUTDOWN: {
            std::uint64_t worker_self = 0;
            (void)wire::decode_u64(r, worker_self);
            if (g_state.cfg->handler_vtable &&
                g_state.cfg->handler_vtable->on_shutdown) {
                g_state.cfg->handler_vtable->on_shutdown(g_state.cfg->handler_self);
            }
            encode_code_reply(reply, GN_OK);
            break;
        }
        default:
            encode_code_reply(reply, GN_ERR_NOT_IMPLEMENTED);
            break;
    }
    return write_frame(g_state.fd, GN_WIRE_PLUGIN_REPLY, request_id, 0, reply);
}

}  // namespace

const host_api_t* synthetic_host_api() {
    return &g_state.synth_api;
}

int run_worker(const WorkerConfig& cfg) {
    namespace wire = ::gn::core::wire;
    g_state = WorkerState{};
    g_state.cfg = &cfg;
    g_state.synth_api.api_size = sizeof(host_api_t);
    g_state.synth_api.log.api_size = sizeof(gn_log_api_t);
    g_state.synth_api.log.emit = &thunk_log_emit;
    g_state.synth_api.is_shutdown_requested = &thunk_is_shutdown_requested;
    g_state.synth_api.notify_inbound_bytes  = &thunk_notify_inbound_bytes;
    g_state.synth_api.notify_connect        = &thunk_notify_connect;
    g_state.synth_api.notify_disconnect     = &thunk_notify_disconnect;
    g_state.synth_api.register_vtable       = &thunk_register_vtable;
    g_state.synth_api.unregister_vtable     = &thunk_unregister_vtable;
    g_state.synth_api.register_security     = &thunk_register_security;
    g_state.synth_api.unregister_security   = &thunk_unregister_security;

    // HELLO frame.
    std::vector<std::uint8_t> hello;
    wire::encode_map_header(hello, 4);
    wire::encode_text(hello, "sdk");
    wire::encode_array_header(hello, 3);
    wire::encode_u64(hello, GN_SDK_VERSION_MAJOR);
    wire::encode_u64(hello, GN_SDK_VERSION_MINOR);
    wire::encode_u64(hello, GN_SDK_VERSION_PATCH);
    wire::encode_text(hello, "name");
    wire::encode_text(hello, cfg.plugin_name ? cfg.plugin_name : "anonymous");
    wire::encode_text(hello, "kind");
    wire::encode_u64(hello, static_cast<std::uint64_t>(cfg.kind));
    wire::encode_text(hello, "pid");
    wire::encode_u64(hello, static_cast<std::uint64_t>(::getpid()));
    if (!write_frame(g_state.fd, GN_WIRE_HELLO, 0, 0, hello)) {
        return 1;
    }

    // HELLO_ACK.
    std::uint8_t hdr_buf[16];
    if (!read_exact(g_state.fd, hdr_buf, 16)) return 2;
    gn_wire_frame_t hdr{};
    parse_header(hdr_buf, hdr);
    if (hdr.kind != GN_WIRE_HELLO_ACK) return 3;
    std::vector<std::uint8_t> ack_payload(hdr.payload_size);
    if (hdr.payload_size > 0 &&
        !read_exact(g_state.fd, ack_payload.data(), hdr.payload_size)) {
        return 4;
    }
    wire::Reader r{ack_payload, 0};
    std::size_t map_n = 0;
    if (wire::decode_map_header(r, map_n) != GN_OK) return 5;
    for (std::size_t i = 0; i < map_n; ++i) {
        std::string_view key;
        if (wire::decode_text(r, key) != GN_OK) return 6;
        if (key == "sdk") {
            std::size_t arr_n = 0;
            if (wire::decode_array_header(r, arr_n) != GN_OK) return 7;
            std::uint64_t v = 0;
            for (std::size_t j = 0; j < arr_n; ++j) {
                if (wire::decode_u64(r, v) != GN_OK) return 8;
            }
        } else if (key == "host_ctx_handle") {
            if (wire::decode_u64(r, g_state.host_ctx_handle) != GN_OK) return 9;
        } else {
            return 10;
        }
    }
    {
        // The handle is opaque kernel-side state — we never deref
        // it; the wire ships the matching u64 back on every
        // HOST_CALL. Cast through uintptr_t so the value
        // round-trips when uintptr_t and u64 are the same width
        // (every supported POSIX).
        const std::uintptr_t raw =
            static_cast<std::uintptr_t>(g_state.host_ctx_handle);
        g_state.synth_api.host_ctx = reinterpret_cast<void*>(raw);  // NOLINT(performance-no-int-to-ptr)
    }

    // Reader loop.
    while (!g_state.stopping) {
        if (!read_exact(g_state.fd, hdr_buf, 16)) break;
        parse_header(hdr_buf, hdr);
        std::vector<std::uint8_t> payload(hdr.payload_size);
        if (hdr.payload_size > 0 &&
            !read_exact(g_state.fd, payload.data(), hdr.payload_size)) {
            break;
        }
        if (hdr.kind == GN_WIRE_PLUGIN_CALL) {
            if (!dispatch_plugin_call(hdr.request_id, payload)) break;
        } else if (hdr.kind == GN_WIRE_GOODBYE) {
            g_state.stopping = true;
        } else {
            // Unknown opcode — ignore.
        }
    }
    return 0;
}

}  // namespace gn::sdk::remote
