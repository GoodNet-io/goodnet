# Fuzzing — LibFuzzer harness for kernel-side parsers

GoodNet ships a small LibFuzzer harness under `tests/fuzz/` that
covers the parsers reachable from untrusted bytes:

| Target              | Parser                                          | Source                          |
|---------------------|-------------------------------------------------|---------------------------------|
| `fuzz_stun`         | STUN / TURN message + ChannelData               | `plugins/links/ice/stun.cpp`    |
| `fuzz_gnet_deframe` | GNET v1 fixed-header decoder                    | `plugins/protocols/gnet/wire.cpp` |
| `fuzz_ws_frame`     | RFC 6455 frame-header parser                    | `plugins/links/ws/wire.hpp`     |
| `fuzz_mdns_dns`     | mDNS / DNS message parser                       | `plugins/links/ice/mdns.cpp`    |

Each target is an independent `add_executable` linked against the
plugin's OBJECT lib (or, for header-only parsers, the headers directly)
so the fuzzer binary stays small and does not pull in the kernel
runtime, asio, or any plugin-side dlopen behaviour.

## Toolchain requirements

LibFuzzer is a clang-only runtime. The default GoodNet dev shell ships
gcc 15; clang is **not** on `PATH`. Configure with `clang` / `clang++`
explicitly:

```bash
nix develop --command bash -c '
    export CC=clang CXX=clang++
    cmake -B build-fuzz -G Ninja \
        -DGOODNET_BUILD_FUZZ=ON \
        -DCMAKE_BUILD_TYPE=RelWithDebInfo \
        .
    ninja -C build-fuzz fuzz_stun fuzz_gnet_deframe fuzz_ws_frame fuzz_mdns_dns
'
```

When clang is not available the configure prints

```
-- Fuzz harness      : skipped (clang required for libFuzzer)
```

and the fuzz subdirectory is not built — the rest of the tree still
configures and builds cleanly under gcc.

## Sanitiser stack

The fuzz binaries link `-fsanitize=fuzzer,address,undefined`. ASan
catches OOB / UAF; UBSan flags signed overflow, alignment, and
enum-range violations the parsers may surface under hostile input.
`-O1 -g -fno-omit-frame-pointer` keeps stack traces readable while
preserving inlining the fuzzer relies on for coverage signal.

## Running a target

```bash
# 60-second run against the STUN parser with the seed corpus
./build-fuzz/tests/fuzz/fuzz_stun \
    tests/fuzz/corpus/stun \
    -max_total_time=60
```

LibFuzzer flags worth knowing:

| Flag                       | Meaning                                  |
|----------------------------|------------------------------------------|
| `-max_total_time=SEC`      | Wall-clock budget                        |
| `-max_len=N`               | Cap input size                           |
| `-runs=N`                  | Exact iteration count                    |
| `-jobs=N -workers=N`       | Parallel fuzz workers                    |
| `-print_final_stats=1`     | Coverage / corpus statistics at exit     |

## Crash artefacts

On a finding, LibFuzzer writes the reproducer to the cwd as
`crash-<sha1>`, `oom-<sha1>`, `timeout-<sha1>`, or `leak-<sha1>`.
Reduce a crash to its minimum input:

```bash
./build-fuzz/tests/fuzz/fuzz_stun -minimize_crash=1 crash-<sha1>
# writes minimized-from-<sha1>-<n>
```

Replay a single input for debugging:

```bash
./build-fuzz/tests/fuzz/fuzz_stun crash-<sha1>
```

Open a found crash under gdb:

```bash
gdb --args ./build-fuzz/tests/fuzz/fuzz_stun crash-<sha1>
```

## Seed corpora

Minimal seeds live under `tests/fuzz/corpus/<target>/`:

* `corpus/stun/` — a STUN binding request, a binding response with
  `XOR-MAPPED-ADDRESS`, and a TURN ChannelData frame.
* `corpus/gnet/` — a header-only GNET v1 frame and a broadcast frame
  with `EXPLICIT_SENDER` set.
* `corpus/ws/` — an unmasked empty binary frame, a masked 5-byte
  frame, and a `len=126` (16-bit length) header.
* `corpus/mdns/` — a 1-question DNS query for `x.local`.

Pass the corpus directory as the first positional argument so
LibFuzzer reads seeds, mutates from them, and persists new coverage
inputs back into the same directory.

## When to run

The fuzz harness is **opt-in** — CI does not run it by default. Use
cases:

* Pre-release smoke before cutting an `-rcN`. 60 seconds per target
  is the floor; longer runs (hours / days) belong to a dedicated
  fuzz host or OSS-Fuzz integration.
* Reproducing a reported parser crash from the field — feed the
  captured bytes into the relevant target and minimise.
* Regression check after touching any of the parsers listed above.
  The matching target should reach a stable coverage plateau within
  a few minutes.
