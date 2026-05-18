# goodnet-link-raw-inject

Transparent bridge that exposes goodnetd to plain TCP clients which
do not link the SDK or speak GNET framing. The plugin listens on a
TCP port, accepts foreign connections, and pipes every inbound byte
chunk through `host_api->inject(GN_INJECT_LAYER_MESSAGE)` as an
anonymous-source MESSAGE envelope. Handler replies flow back out the
same TCP socket verbatim — the link declares the `raw-v1` protocol
layer so the kernel does not add a header on the way back.

**Kind**: link · **Scheme**: `raw-inject` · **Protocol**: `raw-v1`
· **License**: Apache-2.0 (see `LICENSE`)

## Shape

```
plain-TCP client  ──▶  raw_inject link  ──▶  inject(MESSAGE, src=conn)
                          │
                          ◀──  handler reply via host_api->send
```

The client never learns the kernel exists. The handler dispatched
for the configured `msg_id` runs on the standard router chain and
can call `host_api->send(conn, msg_id, payload, size)` to answer; the
bytes land on the foreign TCP socket through the same conn.

## Config keys

| Key                              | Type   | Default                    |
| -------------------------------- | ------ | -------------------------- |
| `raw_inject.listen`              | string | `raw-inject://0.0.0.0:9999`|
| `raw_inject.default_msg_id`      | int64  | `4351` (`0x10FF`)          |
| `raw_inject.rate_limit_per_sec`  | int64  | `1000`                     |
| `raw_inject.max_payload`         | int64  | `65536`                    |
| `raw_inject.encode_msg_id`       | string | `config`                   |

### `encode_msg_id` modes

- `config` — every inbound chunk injects under `default_msg_id`.
- `stream` — first four bytes of every inbound chunk are read as a
  big-endian `uint32` and used as the envelope `msg_id`; the
  remaining bytes become the injected payload.

## When to use

- SOCKS5-style transparent proxy from legacy services into the mesh.
- Smoke harness for `host_api->inject` without writing custom
  goodnetd glue.
- Bridging foreign protocols (LSP, custom RPC) at the byte boundary
  while the mesh handles routing.
