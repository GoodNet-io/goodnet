# Contract: DNS resolution

**Status:** active · v1
**Owner:** every transport plugin that accepts hostnames in its URI
**Last verified:** 2026-04-28
**Stability:** v1.x; the helper signature is locked, the resolver
backend may swap.

---

## 1. Purpose

`uri.md` §1 declares that the URI parser is pure string work — no
DNS lookup, no decoding. The connect path that turns a
`connect("tcp://example.com:443")` into a `notify_connect` needs
the hostname turned into an IP literal before it reaches the
registry, so:

1. The connection-registry URI index keys are stable across
   resolver changes (a host that resolves to two IPs over time
   produces a single registry entry per active connection, not
   one per A/AAAA record).
2. Cached `?peer=<hex>` keys keyed by `host:port` line up with
   the `ip:port` the transport reports back through
   `notify_connect`. Without resolution the connect path's stash
   misses on the on-connect callback, the cached peer pk is
   dropped, and Noise IK silently falls back to a fresh handshake
   or fails outright.

The resolver helper exists to make hostname → IP-literal
conversion uniform across transports without smuggling DNS into
either the URI parser (`uri.md`) or the kernel C ABI (`host-api.md`).

---

## 1a. Operator recommendation

Production deployments **should** pre-resolve hostnames to IP
literals before configuring the kernel. The helper documented
below exists for the call-site that still needs convenience
(short-lived initiator processes, dev / test harnesses), but
every blocking `getaddrinfo` lookup inherits the OS resolver's
adversarial-DNS surface — `EAI_AGAIN` retries, queue contention
under `/etc/resolv.conf` `timeout` / `attempts`, and the
fact that a local cached resolver (systemd-resolved, dnsmasq,
unbound) is the only sensible cache layer; the helper does not
cache because no in-process cache that is cheaper than asking
the local resolver gives a meaningful win on the connect-time
budget. An operator running an unattended daemon avoids the
exposure entirely by shipping IP literals through configuration
or letting a sidecar resolver write the configured URI.

A future cancellation-token rewrite of the resolve call only
buys the synchronous resolver a way out under load — not a
different exposure surface. Pre-resolution remains the
operator's lever.

---

## 2. Surface

```cpp
namespace gn::sdk {

/// Returns @p uri with the host segment replaced by an IPv4 / IPv6
/// literal. IP-literal hosts and path-style URIs (`ipc://...`) are
/// returned unchanged. Synchronous: a hostname triggers a blocking
/// `asio::ip::tcp::resolver` lookup on the calling thread. Hostname
/// resolves are init-time, not per-frame, so the blocking call is
/// the right shape — it bounds the cost to one event per `connect`.
[[nodiscard]] std::expected<std::string, ResolveError>
resolve_uri_host(asio::io_context& ioc, std::string_view uri);

}  // namespace gn::sdk
```

The helper lives at `sdk/cpp/dns.hpp` (header-only) so transport
plugins can include it without linking the kernel. The `asio`
dependency is shared by every transport already.

### Inputs

| Input | Behaviour |
|---|---|
| `tcp://1.2.3.4:443` | passes through unchanged — `asio::ip::make_address` succeeds |
| `tcp://[::1]:9000` | passes through unchanged — bracketed IPv6 literal |
| `tcp://example.com:443` | resolves the hostname; result `tcp://93.184.216.34:443` (v4) or `tcp://[2606:2800:220:1::1]:443` (v6) |
| `ipc:///run/goodnet.sock` | passes through unchanged — path-style URIs have no host |
| empty string / unparseable | returns `ResolveError::Kind::UnparseableUri` |

The query string (`?peer=<hex>` etc) is preserved verbatim
through the canonical-form rewrite — `uri.md` §6 carries the same
guarantee for the parser path.

### Address family preference

The helper takes the **first** result from
`asio::ip::tcp::resolver::resolve(host, "")`. Asio orders results
per the OS resolver's `getaddrinfo` policy (typically RFC 3484 /
RFC 6724 — IPv6 first when reachable, else IPv4). The helper does
not impose its own address-family preference; operators that need
IPv4-only or IPv6-only behaviour set the equivalent OS knob (e.g.
disable IPv6 in `/etc/gai.conf`) rather than carry a v1 SDK flag.

### Failure modes

| Condition | Returned `ResolveError::Kind` |
|---|---|
| `parse_uri` returns `nullopt` | `UnparseableUri` |
| `asio::ip::tcp::resolver::resolve` fails (`NXDOMAIN`, `EAI_AGAIN`, etc) | `ResolveFailed` (`message` carries the asio error string) |
| Resolved set is empty after a clean return | `ResolveFailed` (defensive — should not occur per the asio API) |

---

## 3. Caching is not the helper's concern

A naive `connect()` call resolves on every retry; that is fine
for v1 because hostname-bearing connects are sparse. A future
caching layer attaches in front of the helper through a transport
extension or a kernel service; the helper itself remains
stateless so the contract is observable as a pure function.

---

## 4. Cross-references

- URI parser this composes with: `uri.md`.
- Why hostnames cannot reach the registry literally: `uri.md` §4
  (canonical form) — `host` is normalised to a literal before the
  registry sees the URI.
- Transport ownership of DNS: `link.md` §2.
