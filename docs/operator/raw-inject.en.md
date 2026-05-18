# Raw inject bridge

`goodnet_link_raw_inject` exposes a goodnetd node to plain-TCP
clients that do not link the GoodNet SDK and do not speak GNET
framing. Bytes the client writes are piped through
`host_api->inject(GN_INJECT_LAYER_MESSAGE)` and become regular
mesh envelopes; bytes the handler answers with come back out the
client's TCP socket. The arrangement is SOCKS5-shape: the client
treats goodnetd like any other TCP echo / RPC service.

Audience: operators wiring legacy services into the mesh.

---

## When to use it

- Bridging a TCP-only service (legacy LSP, custom RPC, NRPE-style
  daemons) into goodnetd without writing a handler-side plugin.
- Smoke-testing the `host_api->inject` path during plugin
  development.
- Demos / examples / interview-style proofs that goodnetd can serve
  bytes to a client compiled against nothing but libc — see
  `tests/demo/c_raw_inject/`.

It is **not** a security boundary. The link declares
`GN_TRUST_LOOPBACK` so the `raw-v1` protocol layer admits the
connection; deployed on a non-loopback interface it widens the
attack surface to anyone who can reach the listener. Operators who
want public exposure should put the listener behind a real
authenticated terminator (TLS, WSS) and bridge from there.

## Configuration

```jsonc
{
  "raw_inject": {
    "listen":             "raw-inject://0.0.0.0:9999",
    "default_msg_id":     4351,
    "rate_limit_per_sec": 1000,
    "max_payload":        65536,
    "encode_msg_id":      "config"
  }
}
```

| Key                              | Type   | Default                       | Meaning                                              |
| -------------------------------- | ------ | ----------------------------- | ---------------------------------------------------- |
| `raw_inject.listen`              | string | `"raw-inject://0.0.0.0:9999"` | TCP `host:port` the bridge binds to.                 |
| `raw_inject.default_msg_id`      | int    | `4351` (`0x10FF`)             | msg_id stamped on every injected envelope (`config`).|
| `raw_inject.rate_limit_per_sec`  | int    | `1000`                        | Soft cap on inject calls per second per source.      |
| `raw_inject.max_payload`         | int    | `65536`                       | Hard cap on payload bytes per inject call.           |
| `raw_inject.encode_msg_id`       | string | `"config"`                    | `"config"` or `"stream"`; see below.                 |

### `encode_msg_id` modes

- `"config"` — every inbound chunk injects under `default_msg_id`.
  Choose this for transparent passthrough where the handler
  identity comes from configuration.
- `"stream"` — the first four bytes of every inbound chunk are
  read as a big-endian `uint32` and used as the envelope `msg_id`;
  the remaining bytes are the payload. Use this when one TCP
  connection multiplexes several routing keys (e.g. a binary RPC
  framing layer that already carries an opcode).

## Wiring a handler

The plugin only moves bytes. Something else has to answer. Register
a handler under the **same protocol id** (`raw-v1`) and the
configured `msg_id`:

```c
gn_register_meta_t meta = {
    .api_size = sizeof(meta),
    .name     = "raw-v1",        /* protocol the link declares */
    .msg_id   = 0x10FF,
    .priority = 128,
};
api->register_vtable(api->host_ctx, GN_REGISTER_HANDLER,
                     &meta, &handler_vtable, &state, &out_id);
```

The handler reply travels through `host_api->send(conn, msg_id,
payload, size)`. Because the link is bound to the `raw-v1` protocol
layer, the reply bytes are written to the TCP socket verbatim — no
GNET header on the wire.

## Demo client

`tests/demo/c_raw_inject/raw_client.c` is a plain POSIX echo client
the operator can build with stock `gcc`. It carries no GoodNet
headers; reading its source is the shortest possible answer to
"what does an external client have to do".

```sh
cd tests/demo/c_raw_inject
make
./raw_client          # connects 127.0.0.1:9999, prints the echo
```

## Limits and gotchas

- The kernel router rejects envelopes with an all-zero `sender_pk`,
  so the link mints a per-session synthetic public key with a
  recognisable prefix (`0xFA`). The pk is **not** an authenticated
  peer identity — it exists only to satisfy the router's
  zero-sender gate. Handlers that authenticate peers must use a
  proper security layer (Noise) instead.
- Outbound dial (`connect()`) returns `GN_ERR_NOT_IMPLEMENTED`. The
  bridge is one-way: foreign clients dial in.
- The trust class is `GN_TRUST_LOOPBACK`. Do not expose the listener
  outside the loopback interface without a fronting terminator.
