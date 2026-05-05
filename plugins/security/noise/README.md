# goodnet-security-noise

Noise XX security provider for GoodNet. Pattern
`Noise_XX_25519_ChaChaPoly_BLAKE2b` on libsodium primitives, with
the prologue `"goodnet/v1/noise"` per Noise §6.5 and atomic rekey
on either cipher reaching `2^60`. The Ed25519 mesh-address keys
cross to X25519 inside this plugin via libsodium's birational map;
the kernel never sees the X25519 form.

**Kind**: security provider · **Artefact**: dynamic plugin (`.so` via
dlopen) · **License**: Apache-2.0 (see `LICENSE`)

## Build

In-tree, alongside the kernel:

```sh
nix build .#goodnet-security-noise
# result/lib/goodnet/plugins/libgoodnet_security_noise.so
```

Standalone, against an installed kernel SDK (libsodium on PATH):

```sh
cd plugins/security/noise
cmake -B build -DCMAKE_PREFIX_PATH=/usr/local -DBUILD_TESTING=OFF
cmake --build build
```

## Load

Manifest entry pins the SHA-256 digest; `gn_plugin_init` registers
the `noise` provider. See `docs/install.md` and
`docs/contracts/plugin-manifest.md` in the kernel tree.

## Contract

- Wire format + handshake spec: [`docs/handshake.md`](docs/handshake.md)
- Kernel-side trust-class policy: `docs/contracts/security-trust.md`
- Pattern: Noise XX (mutual auth, no preshared peer pk).
  IK as a v1.x sibling provider lands separately under
  `goodnet-security-noise-ik`.
