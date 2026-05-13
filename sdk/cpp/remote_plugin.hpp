/// @file   sdk/cpp/remote_plugin.hpp
/// @brief  Worker-side stub library for subprocess plugins.
///
/// A worker links against `goodnet_remote_plugin_stub`, fills in a
/// `WorkerConfig`, and hands control to `run_worker`. The stub
/// performs the HELLO/HELLO_ACK handshake on FD 3 (the socketpair
/// end the kernel sets up in `RemoteHost::spawn`), then drives a
/// blocking reader loop that dispatches `GN_WIRE_PLUGIN_CALL` frames
/// into the worker-supplied entry points. Worker code that needs to
/// reach back into the kernel uses the synthetic `host_api_t`
/// returned by `synthetic_host_api()`; each slot serialises a
/// `GN_WIRE_HOST_CALL` frame and blocks on the matching
/// `GN_WIRE_HOST_REPLY`.
///
/// Single-threaded by design: the reader loop and HOST_CALL writes
/// share one thread, so `host_api` slots may only be called from
/// inside an entry-point that the reader dispatched. Multi-threaded
/// workers need a response demultiplexer per request_id — pinned in
/// `docs/contracts/remote-plugin.en.md` §9 as a follow-up.

#pragma once

#include <cstdint>

#include <sdk/handler.h>
#include <sdk/host_api.h>
#include <sdk/link.h>
#include <sdk/plugin.h>
#include <sdk/security.h>

namespace gn::sdk::remote {

/// Worker-supplied configuration handed to `run_worker`.
struct WorkerConfig {
    /// Stable plugin name; carried in the HELLO frame so the kernel
    /// can identify the worker in logs and route the synthetic
    /// vtable. For link workers this doubles as the URI scheme.
    const char* plugin_name = nullptr;

    /// Plugin role; the kernel uses this to choose which vtable
    /// proxy to publish.
    gn_plugin_kind_t kind = GN_PLUGIN_KIND_UNKNOWN;

    /// For link workers: the real vtable the worker wants the
    /// kernel to invoke. The stub library dispatches incoming
    /// `GN_WIRE_PLUGIN_CALL` frames into this vtable on the
    /// worker side.
    const gn_link_vtable_t* link_vtable = nullptr;

    /// Per-instance opaque the worker hands back to itself
    /// through every vtable slot. Treated as a u64 handle on
    /// the wire — converted to/from `void*` exactly once at the
    /// worker boundary.
    void* link_self = nullptr;

    /// Entry-point lifecycle hooks. Optional: a worker that owns no
    /// per-instance state can leave them null and the stub treats
    /// each as a no-op returning `GN_OK`.
    gn_result_t (*on_init)(const host_api_t* api, void** out_self) = nullptr;
    gn_result_t (*on_register)(void* self)                         = nullptr;
    gn_result_t (*on_unregister)(void* self)                       = nullptr;
    void        (*on_shutdown)(void* self)                         = nullptr;
};

/// Run the worker's main loop. Blocks until the kernel sends
/// `GN_WIRE_GOODBYE` or the socket closes. Returns 0 on a clean
/// teardown, non-zero on a protocol violation or I/O failure;
/// the worker's `main()` should return the value verbatim.
[[nodiscard]] int run_worker(const WorkerConfig& cfg);

/// The synthetic `host_api_t` the stub publishes to the worker's
/// plugin code. Every slot serialises a `GN_WIRE_HOST_CALL`. Valid
/// for the lifetime of the current `run_worker` invocation.
[[nodiscard]] const host_api_t* synthetic_host_api();

}  // namespace gn::sdk::remote
