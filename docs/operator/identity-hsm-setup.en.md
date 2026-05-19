# Operator: HSM-backed identity setup (draft)

> **Status: forward-looking draft.** Gate this document until
> Phase 4 of the identity refactor lands (`goodnetd identity
> import-hsm`, `goodnetd doctor` HSM checks, `goodnetd
> quickstart` HSM option). Today's operator workflow is the
> file-backed identity described in `install.en.md` §3.4 and
> `downstream-app-setup.en.md`. This page documents the
> end-state so the design is reviewable before the code lands.
> See `contracts/identity.en.md` §12 for the 5-phase plan.

A node identity is two Ed25519 keypairs (user + device) plus a
signed attestation that binds them. The file-backed default
stores both seeds in a single `0600` file — a file copy is an
identity steal. An HSM-backed identity moves the **device-side
signing key** onto a hardware token (PKCS#11, TPM 2.0, macOS
Keychain, WebAuthn) so the secret half never materialises in
process memory.

The user-side keypair stays portable. A long-term user identity
that survives device replacement needs offline backup paths
(paper print of the seed, second HSM at a separate location);
hardware-only user keys are out of scope for v1.

---

## 1. What lands when

| Phase | Operator-visible artefact |
|---|---|
| 1 | none — internal `IdentitySigner` refactor, no UX change |
| 2 | `gn_core_install_identity_from_provider()` C ABI for embedding apps |
| 3 | PKCS#11 plugin exposes `gn.identity.pkcs11` extension id |
| 4 | `goodnetd identity import-hsm`, `goodnetd doctor` HSM checks, `goodnetd quickstart --hsm-module=...` |
| 5 | `gn::sdk::Core` ctor `Identity::from_hsm()` factory |

This page describes the **Phase 4** operator workflow. Phases 1-3
ship behind a flag that defaults to off; Phase 4 is the first
release where an operator types HSM into a command line.

---

## 2. Prerequisites

- A token that exposes Ed25519 through PKCS#11 v3.0 (`CKM_EDDSA`
  with `edwards25519` curve), with the vendor module .so on
  disk.
  - **YubiKey 5** with the PIV applet — `libykcs11.so`.
  - **SoftHSM2** (dev / CI) — `libsofthsm2.so`.
  - **AWS CloudHSM**, **Thales Luna**, **Entrust nShield** — same
    PKCS#11 contract; vendor-supplied module path.
- The vendor's CLI (or `pkcs11-tool`) provisioned an Ed25519 key
  on the token with a known `CKA_LABEL`.
- The user PIN is in a credential file `systemd-creds` /
  `LoadCredential=` can resolve at service start — **never** in
  a config file checked into git.

Native TPM 2.0 and macOS Keychain are sibling backends that arrive
post-Phase 5 under `plugins/identity/<backend>/`; the operator
surface mirrors PKCS#11 (a `--<backend>-...` flag set in place of
the `--pkcs11-...` set documented below). Until those land,
PKCS#11 is the recommended portable path.

---

## 3. Provisioning workflow

Three steps: provision the on-token key, import it into the
GoodNet identity, point the kernel at the HSM-backed identity.

### 3.1 Provision an Ed25519 key on the token

SoftHSM2 (development / CI):

```sh
softhsm2-util --init-token --slot 0 \
    --label goodnet-dev --pin 1234 --so-pin 1234
pkcs11-tool --module ${softhsm}/lib/softhsm/libsofthsm2.so \
    --login --pin 1234 \
    --keypairgen --key-type "EC:edwards25519" --label goodnet
```

YubiKey 5 with the PIV applet — substitute `libykcs11.so` for the
module path and use the YubiKey's configured PIN.

Verify the key is present:

```sh
pkcs11-tool --module $GOODNET_PKCS11_MODULE \
    --login --pin "$PIN" --list-objects
```

The output should include a private-key object with
`label: goodnet` and `EC: edwards25519`.

### 3.2 Import the HSM key into the GoodNet identity

```sh
goodnetd identity import-hsm \
    --backend pkcs11 \
    --pkcs11-module /usr/lib/x86_64-linux-gnu/libykcs11.so \
    --pkcs11-label goodnet \
    --pkcs11-pin-file /run/credentials/goodnet/pin \
    --out /etc/goodnet/identity.bin
```

What this does:

1. Connects to the token, reads the on-token Ed25519 public key
   for `CKA_LABEL=goodnet`.
2. Mints a fresh user keypair (kept in-file) and an attestation
   binding it to the HSM-derived device public key.
3. Writes a hybrid identity file at the named path — same `GNID`
   magic + version as the file-backed default, plus a new
   `backend = pkcs11` field referencing the module path / label.
   The device **secret seed slot is empty**; the kernel reads
   the backend descriptor on boot and routes `sign(AUTH)` /
   `sign(KEY_AGREEMENT)` through `C_Sign`.

The file at `--out` is **not** sensitive in the same way the
file-backed identity is — it carries the user secret (still
needs `0600`, still needs backup) but the device secret never
crosses the kernel boundary at all. A file copy gets the user
identity but not the device-side signing power.

### 3.3 Run goodnetd with the HSM-backed identity

```sh
goodnetd --identity /etc/goodnet/identity.bin --config /etc/goodnet/node.json
```

No new flag — the identity file's `backend` descriptor tells the
kernel to dlopen the PKCS#11 plugin and route signing calls
through it. The systemd unit picks up the PIN through
`LoadCredential=`:

```ini
[Service]
LoadCredential=pin:/etc/goodnet/pkcs11.pin
Environment=GOODNET_PKCS11_PIN_FILE=%d/pin
```

---

## 4. Operator checks (`goodnetd doctor`)

`goodnetd doctor` (Phase 4) gains HSM-aware checks:

| Check | What it verifies |
|---|---|
| `hsm.module-loaded` | the vendor module .so resolves and `C_Initialize` returns `CKR_OK` |
| `hsm.token-present` | a token is present in the configured slot |
| `hsm.key-found` | a private-key object exists with the configured `CKA_LABEL` |
| `hsm.sign-roundtrip` | a signature over a 32-byte test payload verifies under the public half (proves the PIN is correct, the key is usable, and the EDDSA mechanism is implemented) |

`doctor` exits non-zero on any check failure so a systemd
`ExecStartPre=` can gate the daemon's start on HSM readiness.
The check runs against the live token, not against a cached
descriptor — a token that was unplugged after boot fails the
check.

---

## 5. Quickstart (`goodnetd quickstart --hsm`)

The Phase 4 quickstart accepts an HSM option that runs the
import-hsm step inline:

```sh
goodnetd quickstart \
    --hsm-module /usr/lib/x86_64-linux-gnu/libykcs11.so \
    --hsm-label goodnet \
    --hsm-pin-file /run/credentials/goodnet/pin
```

The non-HSM path stays the default — `goodnetd quickstart` with
no flags mints a file-backed identity, the same as today.

---

## 6. Backup and rotation

The user-side keypair is the one that needs offline backup. It
survives device replacement; the device-side HSM key does not.
Two paths:

- **Paper / second-HSM print of the user seed.** The
  `goodnetd identity export-user-seed` subcommand (Phase 4)
  emits the 32-byte user seed as a BIP-39-style word list for
  paper backup, or as a PKCS#11-loadable blob for a second HSM.
  The subcommand requires a TTY and the operator's
  acknowledgement that the seed leaves the secure boundary.
- **Device-key rotation under unchanged user identity.** When
  the HSM is lost, a new HSM is provisioned and
  `goodnetd identity rotate-device --backend pkcs11 ...` mints a
  fresh attestation under the existing user keypair. Peers see
  this as a device replacement (per `identity.en.md` §3) — the
  mesh address moves, the user identity does not.

The wire-level rotation protocol (`announce_rotation`, msg_id
`0x12`, the 150-byte `RotationProof`) is unchanged from the
file-backed path; HSM-backed identity reuses the same signature
slot for `ROTATION_SIGN`.

---

## 7. Threat model deltas

The HSM-backed identity narrows the file-copy failure mode:

| Attack | File-backed | HSM-backed |
|---|---|---|
| File copy (laptop theft, backup leak) | identity stolen | user identity stolen; device-side signing power stays on the token |
| Process-memory dump (gdb against running daemon) | both seeds in memory while daemon runs | user seed in memory; device seed never enters process memory (`C_Sign` runs on the token) |
| Malicious dlopen plugin | both seeds reachable through host_api violations | device seed unreachable from process; user seed still reachable |
| Operator with disk read | full identity steal | user identity steal; device-side compromise needs token + PIN |

The HSM-backed path does **not** defend against an attacker who
holds the token **and** the PIN at the same time — that's the
standard PKCS#11 threat envelope. Operators rotate the device
key when a token leaves their physical custody.

The user-side keypair is the same trust root in both modes; the
backup discipline for the user seed is identical (`0600`,
encrypted-at-rest filesystem, off-host paper / second-HSM
copy).

---

## 8. Cross-references

- Canonical identity contract: `docs/contracts/identity.en.md`
  (storage, signing, the 5-phase roadmap in §12).
- PKCS#11 plugin scope: `plugins/security/pkcs11/README.md`.
  v0.1 exposes only `gn.security.pkcs11` (transport-side); the
  Phase 3 identity-side `gn.identity.pkcs11` is the real target.
- File-backed bootstrap (today's default):
  `docs/install.en.md` §3.4, `docs/operator/downstream-app-setup.en.md`.
- Attestation flow that consumes the device key:
  `docs/contracts/attestation.en.md`.
- Trust upgrade gate the attestation triggers:
  `docs/architecture/security-flow.ru.md`.
