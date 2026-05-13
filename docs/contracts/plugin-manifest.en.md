# Contract: Plugin Manifest

**Status:** active · v1
**Owner:** `core/plugin/manager`, every operator
**Last verified:** 2026-04-29
**Stability:** v1.x; signed manifests land additively in v1.1

---

## 1. Purpose

Plugin loading is the single most-trust-sensitive operation the
kernel performs. A `.so` it accepts becomes part of the kernel's
own address space — once `dlopen` returns, every static
initialiser the binary contains has already run. The kernel's
existing checks before the manifest were:

- the path is reachable and openable through `dlopen`;
- the symbol set the path exposes matches `gn_plugin_*`;
- the symbol-reported SDK triple is compatible.

None of those distinguishes a plugin the operator approved from a
binary an attacker dropped into the plugins directory. The
manifest closes that gap: the operator pins each plugin path to a
SHA-256 of the bytes it approved, and the kernel refuses every
load whose on-disk hash does not match.

---

## 2. Manifest format

The manifest is a UTF-8 JSON document. The kernel rejects every
input that is not a valid object with a top-level `plugins` array.
A schema-compatible reading:

```json
{
  "plugins": [
    {
      "path":   "build/plugins/libgoodnet_security_null.so",
      "sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    },
    {
      "path":   "build/plugins/libgoodnet_link_tcp.so",
      "sha256": "<64-hex>"
    }
  ]
}
```

| Field | Type | Required | Notes |
|---|---|---|---|
| `plugins` | array of objects | yes | one entry per plugin path |
| `plugins[].path` | string | yes | absolute or relative to the kernel's working directory |
| `plugins[].sha256` | 64-character lowercase hex | yes | SHA-256 of the file at `path` at distribution time |

Parse rules:

- The document must be a JSON object. Anything else fails parse.
- `plugins` must be an array. Missing or wrongly typed fails parse.
- Every entry must be an object with `path` (non-empty string) and
  `sha256` (64 lowercase hex characters). Any deviation fails
  parse.
- Duplicate `path` entries fail parse — the manifest is the trust
  root, so an ambiguous binding is worse than no binding.
- Empty `plugins` array parses successfully and yields an empty
  manifest (developer-mode equivalent).

Parse failures return `GN_ERR_INTEGRITY_FAILED` with a diagnostic
that names the offending element.

---

## 3. Operating modes

Two modes, distinguished by whether the manifest contains entries:

### Developer mode (`PluginManifest::empty()` is `true`)

The kernel loads every plugin without integrity verification.
This is the default path when no manifest is installed and when an
operator parses an empty `plugins` array. In-tree fixtures, the
demo, and unit tests run in developer mode so they do not need to
fabricate hashes for ephemeral builds.

### Production mode (`PluginManifest::empty()` is `false`)

Every load consults the manifest before `dlopen`. The kernel
refuses every plugin whose path is not in the manifest, and every
plugin whose on-disk SHA-256 does not match the manifest's
expectation. Both failures emit `GN_ERR_INTEGRITY_FAILED` with a
diagnostic that distinguishes "no manifest entry" from "sha256
mismatch" from "could not read".

The kernel does not negotiate — there is no "warn and load
anyway" path in production mode. An operator who needs to
permit a new plugin extends the manifest before invoking
`PluginManager::load`.

---

## 4. Verification ordering

`PluginManager::open_one` runs the integrity check **before**
`dlopen`. The ordering matters: a tampered binary's static
initialisers are arbitrary code, so refusing the load before the
binary maps means even a hostile constructor never runs.

The full sequence per plugin:

1. **integrity check** — manifest's `verify(path)` returns
   true/false based on path presence + on-disk SHA-256;
2. **dlopen** — only reached when `verify` returned true;
3. symbol resolution, SDK-version check, descriptor read;
4. two-phase activation per `plugin-lifetime.md` §5.

Step 1 is short-circuited entirely in developer mode.

The kernel's hash function is libsodium's
`crypto_hash_sha256_*`; the file is streamed in 64 KiB chunks so
peak memory use stays bounded for plugins of any realistic size.

### 4.1 Hash and load through the same descriptor (Linux)

The integrity check and `dlopen` operate on the **same file
descriptor** so a symlink swap between hash and load — at any
component of the path — cannot route the loader to a different
inode than the one the kernel hashed. The Linux sequence:

1. `openat2(AT_FDCWD, path, {O_RDONLY | O_CLOEXEC,
   RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS})` — refuses
   every symlink along the path (leaf or any parent
   directory) and every magic-link such as `/proc/self/fd/N`.
   Linux 5.6+. Older kernels fall back to
   `open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)`, which
   covers only the leaf component;
2. `sha256_of_fd(fd)` — `pread`-based streaming; leaves the seek
   state at zero so the descriptor is reusable;
3. `verify_digest(path, observed)` — manifest lookup + compare;
4. `dlopen("/proc/self/fd/N")` — loader resolves the same inode
   the kernel just hashed, regardless of any concurrent path
   replacement.

`RESOLVE_NO_SYMLINKS` is the strongest portable defence
available against directory-level path-traversal swaps; the
older `O_NOFOLLOW` fallback narrows the threat to the leaf
component only.

Non-Linux builds fall back to the path-based `verify(path)` +
`dlopen(path)` sequence, which is race-prone. Production
deployments should stay on Linux until a `RESOLVE_BENEATH`-class
guard ships on the target platform.

---

## 5. Operator workflow

1. **Build distribution.** The operator (or CI pipeline) compiles
   each plugin to a `.so`. The output bytes are the trust anchor.
2. **Emit manifest.** Tooling computes
   SHA-256 of every shipped `.so` and writes the JSON document
   above. The tooling lives outside the kernel; the kernel only
   consumes the document.
3. **Distribute manifest with binaries.** Manifest and binaries
   travel together. An attacker who can replace a binary without
   replacing the manifest is detected at next load; an attacker
   who can replace both is the threat scope of v1.1's signed
   manifest (see §7).
4. **Install at runtime.** The operator parses the manifest into
   `PluginManifest::parse`, hands it to
   `PluginManager::set_manifest`, optionally calls
   `PluginManager::set_manifest_required(true)` to demand a
   non-empty manifest (see §7), and then calls
   `PluginManager::load`. The order matters: every setter runs on
   the bootstrap thread before `load`. `set_manifest_required(true)`
   without a paired `set_manifest` rejects every load.

---

## 6. Failure modes

| Condition | Result |
|---|---|
| Manifest empty, required flag clear (developer mode) | every plugin loads without integrity check |
| Manifest empty, required flag set | `GN_ERR_INTEGRITY_FAILED`, diagnostic "manifest required but empty: …" |
| Path not in manifest | `GN_ERR_INTEGRITY_FAILED`, diagnostic "no manifest entry for path: …" |
| Path in manifest, on-disk hash matches | proceed to `dlopen` |
| Path in manifest, on-disk hash differs | `GN_ERR_INTEGRITY_FAILED`, diagnostic "manifest sha256 mismatch on: …" |
| Path in manifest, file not readable | `GN_ERR_INTEGRITY_FAILED`, diagnostic "could not read plugin for hashing: …" |
| Manifest JSON malformed | parse stage returns `GN_ERR_INTEGRITY_FAILED`; nothing changes in the kernel state |
| Manifest contains duplicate paths | parse stage returns `GN_ERR_INTEGRITY_FAILED`; the manifest is rejected wholesale |

Every failure leaves the kernel state untouched — `PluginManager::
size()` stays zero, no `dlopen` ran, no rollback is needed.

---

## 7. Out of scope for v1

- **Signed manifests.** The v1 manifest is unsigned. An operator
  who wants tamper-evidence at rest signs the manifest file with
  Ed25519 outside the kernel and verifies the signature before
  calling `parse`. v1.1 will land an in-kernel verifier so the
  signed-manifest path is built in.
- **Live re-verification.** The manifest is consulted at load
  time; the kernel does not re-hash already-mapped plugins on a
  schedule. Tampering with a `.so` after `dlopen` does not change
  the running kernel — it changes what would happen at the next
  load.
- **Manifest reload.** v1 has no `update_manifest` API. An
  operator who needs to permit a new plugin restarts the kernel
  with the extended manifest. v1.1 may add hot manifest reload if
  a deployment needs it.
- **Capability manifest.** A separate manifest will pin per-plugin
  capabilities (filesystem, network, syscall) once the sandbox
  layer lands. v1 ships only the integrity manifest.
- **Empty-manifest dev-mode.** The default surface is permissive:
  in-tree fixtures and the demo run with an empty manifest and
  every `dlopen` succeeds. Production deployments install a
  non-empty manifest and pair it with the
  `set_manifest_required(true)` knob. With the flag set, an empty
  manifest refuses every load with `GN_ERR_INTEGRITY_FAILED` and
  the diag names "manifest required but empty" followed by the
  rejected path; the dev-mode flow keeps working only as long as
  the flag stays clear. The required-flag and the manifest itself
  are both bootstrap-only — the host calls
  `set_manifest_required` and `set_manifest` from the bootstrap
  thread before `load`. A config-key reader that wires the flag
  from a kernel-managed config sits outside the v1 surface; the
  embedding host maps the config to the setter call directly.

---

## 8. Per-package distribution manifest

The kernel-side manifest in §2 lists `(path, sha256)` pairs the
operator has approved. A separate, complementary artefact ships
with each plugin distribution: a JSON document next to the `.so`
that carries the build-time metadata about the plugin itself —
its name, kind, version, description, and integrity hash.

The build infrastructure emits `<libfile>.json` next to each
`<libfile>.so` it produces:

```json
{
  "meta": {
    "name":        "goodnet-plugin-noise",
    "type":        "security",
    "version":     "1.0.0-rc1",
    "description": "Noise XX security provider",
    "timestamp":   "2026-05-05T12:34:56Z"
  },
  "integrity": {
    "alg":  "sha256",
    "hash": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
  }
}
```

### 8.1 Field semantics

| Field | Type | Required | Notes |
|---|---|---|---|
| `meta.name` | string | yes | canonical plugin identifier, matches the binary's `gn_plugin_descriptor::name` |
| `meta.type` | string | yes | one of `security`, `link`, `handler`, `protocol` |
| `meta.version` | string | yes | semver triple (`MAJOR.MINOR.PATCH`) of the plugin distribution |
| `meta.description` | string | yes | short single-line plugin summary; may be empty |
| `meta.timestamp` | ISO-8601 UTC string | yes | when the manifest was generated |
| `integrity.alg` | string | yes | hash algorithm; v1 ships `sha256` only |
| `integrity.hash` | 64-character lowercase hex | yes | SHA-256 of the `<libfile>.so` bytes |

### 8.2 Relation to the operator manifest (§2)

The per-package JSON is **not** the trust root. The operator's §2
manifest is — the kernel reads the operator manifest at load and
ignores the per-package JSON entirely.

The per-package JSON is for downstream tooling:
- `goodnet manifest gen <so>...` reads each `<so>` and the
  adjacent `<so>.json` to assemble the operator manifest;
- distribution tarballs ship `<so>` + `<so>.json` paired so the
  receiver can rebuild the operator manifest without re-hashing
  every binary;
- `goodnet plugin hash <so>` corroborates the per-package
  integrity field independently of the operator manifest.

### 8.3 Failure modes

| Condition | Result |
|---|---|
| `<libfile>.so` exists, `<libfile>.json` missing | tooling falls back to fresh hash compute; plugin still loads (operator manifest is the trust root) |
| `<libfile>.json` exists, malformed JSON | tooling rejects the per-package file with a parse error citing line:column; does not fall back |
| `meta.type` not in {security, link, handler, protocol} | tooling rejects with «unknown plugin type» |
| `integrity.hash` does not match the actual `.so` bytes | tooling rejects with «per-package integrity mismatch» citing both observed and declared hashes |
| `meta.timestamp` not ISO-8601 | tooling rejects with «invalid timestamp format» |

Tooling MUST emit loud errors per the failure-mode table; silent
skips are forbidden — a manifest defect that the build glosses
over reaches operators as a runtime integrity-check failure with
no diagnostic trail.

### 8.4 Out of scope for v1

- **Capability declarations.** Per-plugin `ext_provides` /
  `ext_requires` / `capabilities` arrays land with the sandbox /
  manifest-v2 work in v1.x; the v1 per-package JSON carries only
  meta + integrity.
- **Signed per-package manifests.** The per-package JSON is
  unsigned at v1. Tampered per-package metadata is detected at
  the operator-manifest layer (§2) when the operator regenerates
  their manifest.

---

## 9. Cross-references

- Loader semantics: `plugin-lifetime.md` §5 (two-phase activation).
- Resource limits: `limits.md` §4a (`max_plugins`).
- Error codes: `sdk/types.h` `GN_ERR_INTEGRITY_FAILED`.
- Implementation: `core/plugin/plugin_manifest.{hpp,cpp}` and
  `core/plugin/plugin_manager.cpp::open_one`.
- Per-package emission: `nix/buildPlugin.nix` (build infrastructure).
- Aggregate manifest CLI: `apps/goodnet/subcommands/manifest_gen.cpp`.
