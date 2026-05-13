/**
 * @file   sdk/remote/slots.h
 * @brief  Slot identifiers for the subprocess-plugin wire protocol.
 *
 * Every `PLUGIN_CALL` and `HOST_CALL` frame starts with a CBOR array
 * `[slot_id, ...args]`. The slot id distinguishes which entry-point
 * or host_api slot the call addresses. The numeric values are pinned
 * — adding a new slot uses a fresh value and existing values never
 * shift. The two namespaces (plugin and host) are disjoint because
 * the frame opcode (`GN_WIRE_PLUGIN_CALL` vs `GN_WIRE_HOST_CALL`)
 * already disambiguates direction; keeping the values disjoint makes
 * a single `switch` on slot id cover both sides cleanly on either
 * peer.
 *
 * Held in the SDK so worker bindings (Python cbor2, Rust ciborium,
 * Go fxamacker/cbor, …) can mirror the constants from one source.
 *
 * See `docs/contracts/remote-plugin.en.md` §6.
 */
#ifndef GOODNET_SDK_REMOTE_SLOTS_H
#define GOODNET_SDK_REMOTE_SLOTS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Entry-point slots carried by `GN_WIRE_PLUGIN_CALL` frames. */
typedef enum gn_wire_plugin_slot_e {
    GN_WIRE_SLOT_PLUGIN_INIT          = 0x100,
    GN_WIRE_SLOT_PLUGIN_REGISTER      = 0x101,
    GN_WIRE_SLOT_PLUGIN_UNREGISTER    = 0x102,
    GN_WIRE_SLOT_PLUGIN_SHUTDOWN      = 0x103,

    /* Link vtable slots — invoked when the kernel drives a worker
     * link plugin. The worker's stub library dispatches into the
     * worker-provided `gn_link_vtable_t`. */
    GN_WIRE_SLOT_LINK_LISTEN          = 0x200,
    GN_WIRE_SLOT_LINK_CONNECT         = 0x201,
    GN_WIRE_SLOT_LINK_SEND            = 0x202,
    GN_WIRE_SLOT_LINK_DISCONNECT      = 0x203,
    GN_WIRE_SLOT_LINK_DESTROY         = 0x204
} gn_wire_plugin_slot_t;

/** `host_api_t` slots carried by `GN_WIRE_HOST_CALL` frames. The
 *  worker invokes them through the synthetic `host_api_t` its stub
 *  library publishes; the kernel-side `RemoteHost::handle_host_call_`
 *  routes them into the real `host_api_t`. */
typedef enum gn_wire_host_slot_e {
    GN_WIRE_HOST_SLOT_LOG_EMIT             = 0x10,
    GN_WIRE_HOST_SLOT_IS_SHUTDOWN_REQUESTED= 0x11,
    GN_WIRE_HOST_SLOT_NOTIFY_INBOUND_BYTES = 0x12,
    GN_WIRE_HOST_SLOT_NOTIFY_CONNECT       = 0x13,
    GN_WIRE_HOST_SLOT_NOTIFY_DISCONNECT    = 0x14,
    GN_WIRE_HOST_SLOT_REGISTER_VTABLE      = 0x15,
    GN_WIRE_HOST_SLOT_UNREGISTER_VTABLE    = 0x16
} gn_wire_host_slot_t;

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* GOODNET_SDK_REMOTE_SLOTS_H */
