# Security policy

## Reporting a vulnerability

Use GitHub's private vulnerability reporting:
**[open a security advisory](https://github.com/GoodNet-io/goodnet/security/advisories/new)**.
The form is encrypted in transit, scoped to project maintainers, and
keeps the report private until coordinated disclosure. Do **not** open
a public GitHub issue or pull request for an unpatched vulnerability.

The project is maintained by a small team and the security process
is best-effort. We aim to confirm receipt within seven calendar
days and post an initial severity assessment within fourteen, but
a single-maintainer escalation can push either window out — we say
so on the advisory thread when it happens. We coordinate disclosure
with the reporter; the default embargo is 90 days from the
assessment reply, shortened by mutual agreement when a fix is
staged sooner.

## Scope

In scope:

- The kernel (`core/`) and the SDK (`sdk/`).
- The bundled link plugins (`plugins/links/{tcp,udp,ipc,ws,tls}`).
- The bundled security plugins (`plugins/security/{noise,null}`).
- The mandatory protocol layer (`plugins/protocols/gnet`).

Out of scope:

- Third-party plugins outside this repository — report to their
  maintainers. The GoodNet kernel's plugin manifest (`plugin-manifest.en.md`)
  pins SHA-256 hashes of every loaded `.so`; an unverified plugin cannot
  reach the kernel address space, so a third-party plugin's
  vulnerability is bounded by the operator's manifest.
- Operator misconfiguration (e.g. running with an empty manifest in
  production, exposing IPC sockets without filesystem ACLs, weak
  passphrases on operator-owned key files).
- Side channels in plugin code that the kernel has no visibility into —
  TLS server cert handling beneath Noise (`security-trust.en.md` §3 covers
  the link-layer policy in `docs/contracts/security-trust.en.md`),
  application-level message contents.

## Threat model

[`docs/threat-model.en.md`](docs/threat-model.en.md) is authoritative. Summary:

- The kernel **enforces** envelope authentication (Noise XX / IK
  handshake binds peer pk to connection), replay window per session,
  TrustClass policy (loopback / IntraNode / Untrusted / Peer per
  `security-trust.en.md`), bridge identity binding (`attestation.en.md`).
- The kernel **does not enforce** denial-of-service resistance against
  a peer-privileged attacker (the attacker can flood the link layer;
  per-source rate limits live in `host_api->inject` and the link
  plugins' own backpressure paths, not at L1), traffic-pattern
  obscuring, anonymity at the link layer (a peer pk is the address
  by design), or guarantees about a plugin author's code.

## Disclosure timeline

| Time | Event |
|---|---|
| T+0 | Report received via GitHub Security Advisory. |
| T+7d | Confirmation reply, triage owner assigned. |
| T+14d | Initial severity assessment, embargo proposed. |
| T+90d | Public advisory + release note. |

Embargo can be shortened with reporter consent if a fix lands sooner;
extension only with reporter consent. The 7d / 14d shape is the
small-team best-effort envelope; the maintainer thread surfaces
slips on the advisory itself.

## Acknowledgements

We credit reporters in the GitHub Security Advisory and the
corresponding `CHANGELOG.md` entry unless the reporter requests
otherwise. We do not run a paid bounty programme; we cover
coordinated-disclosure cases responsibly and on the public record.

## Cryptographic primitives

The kernel and bundled security plugin use libsodium primitives
through Noise's IK / XX patterns:

- X25519 for the DH leg.
- ChaCha20-Poly1305 IETF for cipherstate.
- BLAKE2b-512 hash, BLAKE2b-MAC, Noise HKDF.
- Ed25519 for static identity keys (kernel-side `NodeIdentity`).

The TLS link plugin (`plugins/links/tls`) additionally uses the
OpenSSL-provided TLS 1.3 stack for the underlying transport
encryption when an operator runs over an untrusted network without
the application-layer Noise handshake. OpenSSL CVEs are in scope
for the TLS plugin; the rest of the kernel does not depend on
OpenSSL.

Cryptographic agility is intentionally limited: the wire protocol
ships one Noise pattern selection per connection (the operator's
config or `link.tls.verify_peer` flag does not affect the Noise
side). A vulnerability in any of the above means a kernel security
patch and a Noise-handshake version bump.

## Out-of-band channels

We never request credentials, key material, or remote execution
through any GoodNet channel; a request claiming to be from the
maintainers that asks for any of the above is adversarial — report
it through the same security advisory form.
