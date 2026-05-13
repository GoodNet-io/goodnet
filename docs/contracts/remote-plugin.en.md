# Remote plugin wire protocol

Status: **active, single-threaded reference implementation landed on
dev**. The proof-of-concept binary is `plugins/workers/remote_echo`;
the kernel-side runtime lives in `core/plugin/remote_host.{hpp,cpp}`;
the worker stub library lives in `sdk/cpp/remote_plugin.{hpp,cpp}` +
`sdk/remote/{wire,slots}.h`. This document specifies the wire
contract every binding (C++, Python, Rust, Zig, Go, …) must respect.

## §1 — Overview

GoodNet plugins normally live inside the kernel address space — one
`.so` per plugin, loaded through `dlopen` (or compiled in
statically under `-DGOODNET_STATIC_PLUGINS=ON`). The **remote**
linkage mode is a third option: the kernel spawns the plugin as a
subprocess and talks to it over a duplex IPC channel. Every C-ABI
vtable invocation that would have been a direct function call in
the dlopen path becomes a wire frame in the remote path. The
binary-compatibility surface collapses from "the entire C ABI of
`sdk/host_api.h` plus every vtable" to "the wire codec plus a
handful of CBOR shapes". Languages with a CBOR library and a
socket — every reasonable language — can ship a plugin.

The wire protocol stays C-ABI clean. Opcodes are integers, the
envelope is a packed struct, the payload is CBOR. Python `cbor2`,
Rust `ciborium`, Zig `std.cbor`, Go `fxamacker/cbor` all decode the
subset documented in §5.

## §2 — Frame header

Every frame is a 16-byte header followed by a CBOR payload. The
header is the four-field struct `gn_wire_frame_t` from
`sdk/remote/wire.h` written little-endian:

| Offset | Field          | Size | Description                                          |
|-------:|----------------|-----:|------------------------------------------------------|
|      0 | `kind`         | 4    | opcode value from `gn_wire_kind_t`                   |
|      4 | `request_id`   | 4    | correlator; replies echo it                          |
|      8 | `payload_size` | 4    | CBOR-encoded payload length in bytes                 |
|     12 | `flags`        | 4    | bit 0 marks error; remaining bits reserved (must 0)  |

Readers do one `read(2)` for the header, validate `payload_size
<= GN_WIRE_MAX_PAYLOAD` (1 MiB), then a second `read(2)` for the
payload. No streaming codec.

## §3 — Fragmentation

Not supported in v1. A worker that needs to ship more than 1 MiB in
a single host_api call breaks the payload into multiple
`HOST_CALL`s with the application-level continuation flag carried
inside the CBOR. The wire codec stays trivial in every binding.

## §4 — Opcodes & state machine

The opcodes:

| Value | Name              | Direction        | Description                                  |
|------:|-------------------|------------------|----------------------------------------------|
|  0x01 | `HELLO`           | worker → kernel  | first frame; carries SDK version + name      |
|  0x02 | `HELLO_ACK`       | kernel → worker  | accepted; carries host_ctx handle            |
|  0x10 | `HOST_CALL`       | worker → kernel  | invoke a `host_api` slot                     |
|  0x11 | `HOST_REPLY`      | kernel → worker  | answer to a `HOST_CALL`                      |
|  0x20 | `PLUGIN_CALL`     | kernel → worker  | invoke a vtable / entry-point slot           |
|  0x21 | `PLUGIN_REPLY`    | worker → kernel  | answer to a `PLUGIN_CALL`                    |
|  0x30 | `NOTIFY`          | kernel → worker  | async one-way (`is_shutdown_requested`, …)   |
|  0xFF | `GOODBYE`         | either           | clean teardown signal                        |

Lifecycle:

1. Worker writes `HELLO` (request_id=0).
2. Kernel reads + validates; writes `HELLO_ACK` (request_id=0).
3. Kernel begins issuing `PLUGIN_CALL { slot = PLUGIN_INIT, … }`.
   Worker replies with `PLUGIN_REPLY` carrying `[code, self_handle]`.
4. During init/register/runtime the worker may issue zero or more
   `HOST_CALL` frames; each gets a matching `HOST_REPLY`.
5. Kernel issues `PLUGIN_CALL { slot = PLUGIN_REGISTER }`, then later
   `PLUGIN_UNREGISTER` and `PLUGIN_SHUTDOWN`.
6. Either side sends `GOODBYE`; worker exits 0 after sending or
   receiving one.

The reference `RemoteHost` (kernel side) and `remote_plugin_stub`
(worker side) implement this state machine in C++. Other languages
follow the same shape.

## §5 — CBOR subset

The codec under `core/plugin/wire_codec.{hpp,cpp}` is hand-rolled,
no third-party dependency. It supports:

- **Major 0** — unsigned integers (0 … 2⁶⁴-1). Width-adaptive encoding
  (1, 2, 3, 5, 9 bytes).
- **Major 1** — negative integers. Decoder maps to `int64_t`;
  magnitudes beyond `INT64_MAX+1` reject with `GN_ERR_OUT_OF_RANGE`.
- **Major 2** — byte strings. Length prefix per major 0 width rules.
  Decoder returns a `std::span<const std::uint8_t>` into the source
  buffer; zero allocation.
- **Major 3** — UTF-8 text strings, same length rules. Decoder
  returns `std::string_view`.
- **Major 4 / 5** — array / map headers. Element bodies follow
  inline; the codec does not validate header-claimed counts against
  trailing items.
- **Major 7** — simple values 20 (false), 21 (true), 22 (null).

Out of scope: floats, indefinite-length sequences, tags, simple
values other than the three above. Out-of-scope shapes return
`GN_ERR_OUT_OF_RANGE` on decode.

## §6 — Slot identifiers

Every `PLUGIN_CALL` and `HOST_CALL` frame starts with a CBOR array
`[slot_id, args_array]`. The slot id distinguishes which slot the
call addresses. Pinned values live in `sdk/remote/slots.h`. Plugin-
side and host-side slot ids share the same enum namespace but the
frame opcode disambiguates direction.

Plugin slots (carried by `PLUGIN_CALL`):

| Slot id | Name                       | Status        |
|--------:|----------------------------|---------------|
|   0x100 | `PLUGIN_INIT`              | implemented   |
|   0x101 | `PLUGIN_REGISTER`          | implemented   |
|   0x102 | `PLUGIN_UNREGISTER`        | implemented   |
|   0x103 | `PLUGIN_SHUTDOWN`          | implemented   |
|   0x200 | `LINK_LISTEN`              | implemented   |
|   0x201 | `LINK_CONNECT`             | implemented   |
|   0x202 | `LINK_SEND`                | implemented   |
|   0x203 | `LINK_DISCONNECT`          | implemented   |
|   0x204 | `LINK_DESTROY`             | implemented   |
|   0x300 | `SECURITY_PROVIDER_ID`     | contract only |
|   0x301 | `SECURITY_HANDSHAKE_OPEN`  | contract only |
|   0x302 | `SECURITY_HANDSHAKE_STEP`  | contract only |
|   0x303 | `SECURITY_HANDSHAKE_COMPLETE` | contract only |
|   0x304 | `SECURITY_EXPORT_KEYS`     | contract only |
|   0x305 | `SECURITY_ENCRYPT`         | contract only |
|   0x306 | `SECURITY_DECRYPT`         | contract only |
|   0x307 | `SECURITY_REKEY`           | contract only |
|   0x308 | `SECURITY_HANDSHAKE_CLOSE` | contract only |
|   0x400 | `HANDLER_PROTOCOL_ID`      | contract only |
|   0x401 | `HANDLER_SUPPORTED_MSG_IDS`| contract only |
|   0x402 | `HANDLER_HANDLE_MESSAGE`   | contract only |
|   0x403 | `HANDLER_ON_RESULT`        | contract only |
|   0x404 | `HANDLER_ON_INIT`          | contract only |
|   0x405 | `HANDLER_ON_SHUTDOWN`      | contract only |

"contract only" means the slot id is pinned in `sdk/remote/slots.h`
but neither `RemoteHost` (kernel) nor `goodnet_remote_plugin_stub`
(worker) currently dispatch it. A future commit can wire the proxy
on either side without renumbering; bindings in other languages
can lock against the IDs today.

Security-vtable wiring in particular needs careful `gn_secure_buffer_t`
zero-on-drop handling at every wire boundary — encode the bytes,
zeroise the source slice; decode the bytes, hand to the worker /
kernel, zeroise the receive buffer. The contract is stable; the
implementation lands when a real workload (Python Noise IK worker,
sandboxed identity-only provider) asks for it.

Host slots (carried by `HOST_CALL`) — kernel exposes the minimum
useful subset for the v1 proof:

| Slot id | Name                          |
|--------:|-------------------------------|
|    0x10 | `LOG_EMIT`                    |
|    0x11 | `IS_SHUTDOWN_REQUESTED`       |
|    0x12 | `NOTIFY_INBOUND_BYTES`        |
|    0x13 | `NOTIFY_CONNECT`              |
|    0x14 | `NOTIFY_DISCONNECT`           |
|    0x15 | `REGISTER_VTABLE`             |
|    0x16 | `UNREGISTER_VTABLE`           |

Adding a new slot uses a fresh integer; existing values never shift.

## §7 — Handle translation

The wire avoids exposing process-address-space pointers. Every
`void* host_ctx` and `void* self` argument crosses the boundary as
a `uint64_t` opaque handle. Each side maintains a translation
table:

- The worker's `host_ctx` is allocated by the kernel at HELLO_ACK
  time and returned to the worker as the `host_ctx_handle` field.
  Every `HOST_CALL` repeats it back so the kernel routes to the
  right plugin instance.
- The plugin's `self` is allocated by the worker during `PLUGIN_INIT`
  and returned in the reply. The kernel uses the value verbatim on
  every subsequent vtable call.

Connection ids (`gn_conn_id_t`), message ids, timer ids, key ids all
pass through verbatim — they are already u64s with no language-side
pointer state.

## §8 — Error encoding

A reply frame with `flags & GN_WIRE_FLAG_ERROR` set carries a CBOR
map `{ "code": <i64>, "message": <text> }` instead of the
success-path argument list. The integer code is a stable
`gn_result_t` value (`sdk/types.h`). Bindings should surface the
combination unchanged so logs and metrics aggregate cleanly across
linkage modes.

## §9 — Shutdown

Clean teardown:

1. Either side writes `GOODBYE` (request_id=0, payload empty).
2. The receiver flushes any in-flight reply, then exits its reader
   loop.
3. The worker exits 0 (the kernel reaps via `waitpid`).
4. The kernel closes the socket fd.

Worker crash, signal-kill, or `GOODBYE`-missing exit all surface to
the kernel as EOF on the socket. Pending replies on the kernel
side resolve with `GN_ERR_INVALID_STATE`. The synthesised vtable
becomes inert; any further dispatch returns the same code.

Workers must not call `host_api` slots after observing `GOODBYE`.
The reference stub library raises a single-threaded contract: a
worker may only call `host_api` while servicing a `PLUGIN_CALL`
the kernel sent (the reader loop is the only thread). Multi-
threaded workers add a response demultiplexer keyed by
`request_id`; deferred to a follow-up plan.

## §10 — Reference implementations

- **Kernel side**: `core/plugin/remote_host.{hpp,cpp}` — spawns the
  worker, drives the framing reader thread, exposes `call_init /
  call_register / call_unregister / call_shutdown` to the
  `PluginManager` (integration is a follow-up; the proof currently
  drives `RemoteHost` directly).
- **Worker stub (C++)**: `sdk/cpp/remote_plugin.{hpp,cpp}` plus
  `goodnet_remote_plugin_stub` static library. Workers fill in a
  `WorkerConfig` and hand control to `gn::sdk::remote::run_worker`.
- **Proof binary**: `plugins/workers/remote_echo/remote_echo.cpp` —
  ~80 LOC. Registers a `remote_echo://` link whose `send` slot
  copies bytes straight back through
  `host_api.notify_inbound_bytes`. Lives in-tree so the kernel
  ships a stable smoke against the wire.
- **Tests**: `tests/unit/plugin/test_wire_codec.cpp` (codec
  round-trip), `tests/unit/plugin/test_remote_host.cpp` (kernel
  side against the real `remote_echo` worker; 5 cases).
