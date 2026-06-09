# GoodNet — 5-minute quickstart

For contributors and operators who want a running node from scratch.
No system packages required beyond Nix and git.

---

## Prerequisites

- [Nix](https://nixos.org/download) with flakes enabled
- git

Enable flakes if not already set:
```sh
echo 'experimental-features = nix-command flakes' >> ~/.config/nix/nix.conf
```

---

## 1. Clone and bootstrap

```sh
git clone https://github.com/GoodNet-io/goodnet.git
cd goodnet
nix run .#setup
```

`nix run .#setup` does three things in sequence:
1. Mirrors every plugin repo locally (`~/.local/share/goodnet-mirrors/`)
2. Clones all loadable plugins into `plugins/<kind>/<name>/` slots
3. Wires `.githooks/` (pre-commit clang-tidy + pre-push CI subset)

Expected output: all plugin slots cloned, hooks installed.

---

## 2. Build

```sh
nix run .#build              # debug build → build/
nix run .#build -- release   # release build → build-release/
nix run .#build -- static    # static ELF (no dynamic deps) → build-static/
```

No `nix develop` required — Nix resolves the toolchain from the flake.

`goodnetd` and `gssh` are built as part of the monorepo (`apps/`).
The tarball layout and all three build paths are covered in
[`docs/operator/build.en.md`](build.en.md).

---

## 3. Run the demo

The kernel repo includes a two-node Noise-over-TCP smoke demo.
Requires step 1 (`nix run .#setup`) to have completed so that
`security-noise` and `link-tcp` are present in the build tree.

```sh
nix run .#run -- demo
```

This starts two in-process peers, exchanges one message over a local
TCP connection with Noise encryption, and exits 0.  If it exits 0
the kernel, security plugin, and TCP link are all wired correctly.

---

## 4. Run the test suite

```sh
nix run .#test               # 1510 tests, ~30 s
nix run .#test -- asan       # AddressSanitizer + UBSan
nix run .#test -- tsan       # ThreadSanitizer
```

---

## 5. Operator node

`goodnetd` is built from `apps/goodnetd/` in this repository and is
included in the debug/release builds above.

Key `goodnetd` commands:
```sh
goodnetd identity gen --out identity.bin   # generate node identity
goodnetd config validate node.json         # validate config file
goodnetd doctor                            # check runtime env
goodnetd run --config node.json \
             --manifest plugins.json \
             --identity identity.bin
```

Reference config and manifest: `dist/example/node.json`,
`dist/example/plugins.json`.

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `nix run .#run -- demo` fails with missing CMake target | Run `nix run .#setup` first — demo requires `security-noise` and `link-tcp` in the build tree |
| `ctest` fails outside `nix develop` with `GLIBCXX_3.4.35 not found` | Run `ctest` inside `nix develop` or set `LD_LIBRARY_PATH` to gcc 16 libs |
| `nix build` fails on aarch64-darwin | Darwin support is intentionally broken; see `--system x86_64-darwin` warning |

---

## Next steps

- [`docs/operator/build.en.md`](build.en.md) — three build paths, SDK layers, CMakePresets
- [`docs/operator/nix-build-system.en.md`](nix-build-system.en.md) — full Nix build map
- [`docs/operator/deployment.en.md`](deployment.en.md) — production systemd deployment
- [`docs/architecture/overview.ru.md`](../architecture/overview.ru.md) — kernel architecture
- [`CONTRIBUTING.md`](../../CONTRIBUTING.md) — contribution workflow
