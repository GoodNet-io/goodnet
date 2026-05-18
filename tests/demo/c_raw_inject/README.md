# C raw_inject demo client

Bare POSIX C client for the `goodnet_link_raw_inject` plugin. No
`#include <sdk/...>`. No link-time GoodNet dependency. The whole point
is that goodnetd can serve clients that know nothing about the mesh.

## Build

```sh
make
```

Or directly:

```sh
gcc -O2 -Wall -Wextra -Wpedantic -std=c11 raw_client.c -o raw_client
```

## Run

1. Start a `goodnetd` with `goodnet_link_raw_inject` loaded and a
   handler registered for the configured `msg_id` (default `0x10FF`).
   The handler is what answers — `raw_inject` only moves bytes.
2. Connect the client:

```sh
./raw_client                      # talks to 127.0.0.1:9999, sends "hello"
./raw_client 127.0.0.1 9999 ping  # custom message
./raw_client --help               # usage
```

## Pulse

```
raw_client (plain TCP)
     │ write("hello")
     ▼
goodnetd[raw_inject] ──▶ host_api->inject(MESSAGE, msg_id=0x10FF, payload="hello")
                            │
                            ▼
                       handler chain (echoes payload)
                            │
                            ▼
                       host_api->send(conn, msg_id, "hello")
                            │ frame() — raw-v1 is verbatim
                            ▼
goodnetd[raw_inject] ──▶ write("hello") on the same TCP socket
     │ read() == "hello"
     ▼
raw_client
```

The handler runs on whatever process loads `goodnetd`. The client
never sees that machinery.
