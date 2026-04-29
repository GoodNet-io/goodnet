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
      "path":   "build/plugins/libgoodnet_transport_tcp.so",
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
   `PluginManager::set_manifest`, and then calls
   `PluginManager::load`. The order matters: `set_manifest` must
   precede `load` for the integrity check to apply.

---

## 6. Failure modes

| Condition | Result |
|---|---|
| Manifest empty (developer mode) | every plugin loads without integrity check |
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
- **Verify-then-`dlopen` TOCTOU.** The integrity check opens the
  file once for hashing; `dlopen` opens it a second time to map
  the binary. An attacker with write access to the plugins
  directory between those two opens can swap the on-disk bytes —
  the kernel hashes one file and maps another. v1 explicitly
  assumes the plugins directory is operator-controlled and
  write-protected at OS level (filesystem permissions, immutable
  bind mount, or container-image read-only layer). v1.1 closes
  the window by hashing through the descriptor that backs
  `dlopen` (single open, `/proc/self/fd/N` re-resolution).
- **Symlink races.** `fopen` follows symlinks. An attacker who
  can replace a symlink target between manifest emission and
  load defeats the integrity check. The same operator-controls
  assumption applies; v1.1 will use `O_NOFOLLOW` on the hash
  open and refuse loads through symlinks unless the operator
  explicitly opts in.
- **Empty-manifest silent dev-mode.** A production deployment
  that ships an empty manifest by accident gets no warning. The
  v1 surface is permissive on purpose so in-tree fixtures and
  the demo do not have to fabricate hashes; production builds
  install a non-empty manifest, full stop. A future revision may
  add a `set_manifest_required(true)` knob that turns the empty
  case into a hard error.

---

## 8. Cross-references

- Loader semantics: `plugin-lifetime.md` §5 (two-phase activation).
- Resource limits: `limits.md` §4a (`max_plugins`).
- Error codes: `sdk/types.h` `GN_ERR_INTEGRITY_FAILED`.
- Implementation: `core/plugin/plugin_manifest.{hpp,cpp}` and
  `core/plugin/plugin_manager.cpp::open_one`.
