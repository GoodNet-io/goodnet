/*
 * Single translation unit bindgen runs over to materialise the FFI
 * surface. Pulls only `sdk/core.h` — the host-side ABI a non-C++
 * application crosses to drive the kernel. `sdk/core.h` itself
 * transitively pulls `sdk/types.h`, `sdk/abi.h`, `sdk/limits.h`,
 * `sdk/host_api.h`, `sdk/link.h`, `sdk/protocol.h`, `sdk/security.h`,
 * `sdk/conn_events.h`, and `sdk/handler.h`, so the generated
 * `bindings.rs` carries the full kernel surface plus every typedef
 * those headers introduce.
 *
 * SDK C++ headers (`sdk/cpp/*.hpp`) are deliberately excluded — those
 * are C++-only convenience wrappers and bindgen would choke on the
 * `<atomic>` / `<asio>` reach-throughs.
 */
#include <sdk/core.h>
