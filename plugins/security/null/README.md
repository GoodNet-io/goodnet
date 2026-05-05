# goodnet-security-null

Loopback / IntraNode pass-through security provider. Used on
trust-class connections where confidentiality and authenticity are
delegated to the underlying transport (AF_UNIX peer-cred check,
loopback IP). Refuses to upgrade Untrusted connections — production
deployments do not load this plugin on public-facing transports.

**Kind**: security provider · **Artefact**: dynamic plugin (`.so` via
dlopen) · **License**: Apache-2.0 (see `LICENSE`)

## Build

In-tree, alongside the kernel:

```sh
nix build .#goodnet-security-null
# result/lib/goodnet/plugins/libgoodnet_security_null.so
```

Standalone, against an installed kernel SDK:

```sh
cd plugins/security/null
cmake -B build -DCMAKE_PREFIX_PATH=/usr/local -DBUILD_TESTING=OFF
cmake --build build
```

## Load

Manifest entry pins the SHA-256 digest; `gn_plugin_init` registers
the `null` provider. See `docs/install.md` and
`docs/contracts/plugin-manifest.md` in the kernel tree.

## Contract

- Kernel-side trust-class policy: `docs/contracts/security-trust.md`
- `null_allowed_trust_mask = Loopback | IntraNode`; the protocol layer
  rejects any other trust class on connect.
