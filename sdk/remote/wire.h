/**
 * @file   sdk/remote/wire.h
 * @brief  Wire protocol for out-of-process GoodNet plugins.
 *
 * The kernel spawns a plugin worker as a child process and talks
 * to it over a duplex IPC channel (AF_UNIX socketpair on POSIX,
 * named pipe pair on Windows once the named-pipe carrier lands).
 * Every C-ABI vtable invocation that would have been a direct
 * function call in the dlopen path becomes a wire frame in the
 * remote path. Two messages flow in each direction:
 *
 *   kernel → worker
 *     PLUGIN_CALL   — invoke a vtable slot (init, register,
 *                     link.listen, link.send, …)
 *     HOST_REPLY    — answer to a host_api request the worker
 *                     made earlier
 *
 *   worker → kernel
 *     HELLO         — first frame on the wire; carries SDK
 *                     version + descriptor name. Kernel rejects
 *                     mismatched major.
 *     HOST_CALL     — invoke a host_api slot (notify_connect,
 *                     emit_counter, register_vtable, …)
 *     PLUGIN_REPLY  — answer to a PLUGIN_CALL the kernel made
 *     GOODBYE       — last frame; worker exits 0 after sending
 *
 * Cross-language note: the protocol stays C-ABI clean — opcodes
 * are integers, the envelope is a packed struct, the payload is
 * CBOR-encoded scalars + bytestrings. Python (cbor2), Rust
 * (ciborium), Zig (std.cbor), Go (fxamacker/cbor) all decode the
 * subset documented in §5 of `docs/contracts/remote-plugin.en.md`.
 * No language affinity at the wire boundary; the binary
 * compatibility burden lives only in the wire codec, not in the
 * full host_api / vtable C ABI.
 *
 * Handle translation: every `void* host_ctx` and `void* self`
 * argument is serialised as a `uint64_t` opaque handle. The
 * kernel-side dispatcher maps incoming handles to its real
 * pointers; the worker's `host_ctx` is a synthetic value
 * allocated at HELLO_ACK time. Connection ids and message ids
 * pass through verbatim — they are already u64s with no
 * language-side state.
 */
#ifndef GOODNET_SDK_REMOTE_WIRE_H
#define GOODNET_SDK_REMOTE_WIRE_H

#include <stdint.h>

#include <sdk/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Wire-protocol frame opcode.
 *
 * The numeric values are pinned and must not change between SDK
 * versions; new frame kinds get fresh values. The 0xFF guard is
 * the GOODBYE sentinel — workers send it before `exit(0)` so the
 * kernel can tell a clean shutdown from a crash.
 */
typedef enum gn_wire_kind_e {
    GN_WIRE_HELLO          = 0x01, /**< worker → kernel, first frame */
    GN_WIRE_HELLO_ACK      = 0x02, /**< kernel → worker, version + host handles */
    GN_WIRE_HOST_CALL      = 0x10, /**< worker → kernel, invoke host_api slot */
    GN_WIRE_HOST_REPLY     = 0x11, /**< kernel → worker, host_api result */
    GN_WIRE_PLUGIN_CALL    = 0x20, /**< kernel → worker, invoke vtable slot */
    GN_WIRE_PLUGIN_REPLY   = 0x21, /**< worker → kernel, vtable result */
    GN_WIRE_NOTIFY         = 0x30, /**< kernel → worker, async notify_* */
    GN_WIRE_GOODBYE        = 0xFF  /**< either side, clean teardown */
} gn_wire_kind_t;

/**
 * @brief Fixed-size frame header. Little-endian on the wire.
 *
 * The header has no padding (16 bytes = 4 × uint32). Readers do
 * one `read(2)` for the header, validate `payload_size` against
 * `gn_wire_max_payload`, then a second `read(2)` for the payload.
 * No streaming codec needed; framing stays trivial across every
 * binding.
 */
typedef struct gn_wire_frame_s {
    uint32_t kind;          /**< gn_wire_kind_t value */
    uint32_t request_id;    /**< correlator; replies echo this */
    uint32_t payload_size;  /**< CBOR-encoded payload length */
    uint32_t flags;         /**< bit 0: error reply; bits 1-31 reserved */
} gn_wire_frame_t;

/**
 * @brief Cap on the CBOR payload length. Anything longer is a
 *        protocol error — the worker did not chunk a large frame
 *        per `docs/contracts/remote-plugin.en.md` §3.
 *
 * 1 MiB is large enough for any vtable invocation (the biggest
 * known argument shape is the `send_batch` frame list, capped by
 * `gn_limits_t::max_envelope`). Workers that need to ship larger
 * blobs use multiple HOST_CALL frames with a continuation flag.
 */
#define GN_WIRE_MAX_PAYLOAD ((uint32_t)1u << 20)

/**
 * @brief Frame flag — non-zero `flags` bit 0 marks an error
 *        reply. Payload then carries a CBOR-encoded
 *        `{ "code": <gn_result_t>, "message": "..." }` map
 *        instead of the success-path argument list.
 */
#define GN_WIRE_FLAG_ERROR 0x00000001u

/**
 * @brief Vtable-slot identifier carried as the first CBOR key of
 *        every PLUGIN_CALL / HOST_CALL frame.
 *
 * The slot id is the offset of the slot inside its vtable struct
 * (in bytes, divided by `sizeof(void*)`). That keeps the wire
 * stable across SDK versions: adding a new slot at the end
 * doesn't renumber existing ones. The dispatcher table on each
 * side maps the slot id back to its handler.
 */
typedef uint32_t gn_wire_slot_id_t;

/**
 * @brief SDK version triple carried in the HELLO frame's CBOR
 *        payload. The kernel rejects HELLO if `sdk_major !=
 *        kernel SDK major`, mirrors the dlopen path's
 *        `gn_plugin_sdk_version` check.
 */
typedef struct gn_wire_hello_s {
    uint32_t sdk_major;
    uint32_t sdk_minor;
    uint32_t sdk_patch;
    /** Worker process pid — best-effort, used for kernel logs only. */
    uint32_t worker_pid;
    /** Null-terminated plugin name; bounded by GN_WIRE_MAX_PAYLOAD. */
    const char* plugin_name;
} gn_wire_hello_t;

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* GOODNET_SDK_REMOTE_WIRE_H */
