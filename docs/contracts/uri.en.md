# Contract: Connection URI

**Status:** active · v1
**Owner:** `sdk/cpp/uri.hpp` (parser), `core/util/uri_query.hpp` (peer-pk decode)
**Last verified:** 2026-04-28
**Stability:** v1.x; new schemes append to the recognition table without changing the grammar.

---

## 1. Purpose

A connection URI identifies the wire-side counterpart of a kernel
`gn_conn_id_t` — where to listen, where to dial. One parser, one
canonical form, one set of invariants. Every transport plugin and
the kernel's connection-registry URI index share it; without that
shared parser, "tcp://1.2.3.4:80" can substring-match
"1.2.3.4:8080" and routing hits the wrong peer.

The parser is pure string operation — no DNS resolution, no URL
decoding. Transports own DNS and any auxiliary parameters (MQTT
topic, ICE candidate negotiation).

---

## 2. Recognised forms

| Form | Example | Notes |
|---|---|---|
| `scheme://host:port` | `tcp://127.0.0.1:9000` | host:port style; port mandatory, port 0 rejected |
| `scheme://host:port?query` | `mqtt://broker:1883?peer=abc&x=1` | `?` strips query before host:port parsing |
| `scheme://[v6-literal]:port` | `tcp://[2001:db8::1]:443` | RFC 3986 brackets disambiguate `::` from host:port `:` |
| `host:port` | `127.0.0.1:19800` | bare host:port — `scheme` field stays empty |
| `[v6-literal]:port` | `[::1]:9000` | bare bracketed v6 |
| `ipc://path` | `ipc:///run/goodnet.sock` | path-style — `port` stays 0, `path` carries the filesystem name |
| `ipc://path?query` | `ipc:///tmp/sock?peer=abc` | path-style with optional query |

A trailing query is permitted on every form. Anything after the first
unmatched `?` is the raw query string; the parser does not interpret
it.

---

## 3. Output structure

```
struct UriParts {
    string       scheme;   // "tcp", "udp", "ws", "ipc", … — empty when omitted
    string       host;     // IP literal / hostname for host:port; mirrors `path` for path-style
    uint16_t     port = 0; // 0 only when path-style
    string       path;     // empty for host:port; populated for `ipc://`
    string_view  query;    // raw "k=v&k=v" view, empty when no `?`
};
```

`is_path_style()` returns true iff `port == 0 && !path.empty()`. The
`host` field is mirrored from `path` on path-style URIs so call
sites that read `host` (registry URI-index stash key, transport
`listen` / `connect` arguments) keep working without scheme-specific
branches.

The `host` of a bracketed IPv6 URI is stored **without** brackets so
callers can hand it straight to the platform's address parser.

---

## 4. Canonical form

`UriParts::canonical()` returns the registry-key form:

| Input | Canonical |
|---|---|
| `tcp://1.2.3.4:80?peer=deadbeef` | `tcp://1.2.3.4:80` |
| `tcp://[::1]:9000?peer=abc` | `tcp://[::1]:9000` |
| `127.0.0.1:19800` | `127.0.0.1:19800` |
| `tcp://::1:9000` *(unbracketed v6)* | `tcp://[::1]:9000` |
| `ipc:///tmp/sock?peer=abc` | `ipc:///tmp/sock` |

The query is **always** stripped from the canonical key — registry
lookups must remain stable regardless of per-call metadata.

IPv6 hosts are re-bracketed on canonicalisation, including the
unbracketed-rfind-fallback case (§5.2). A second `parse_uri` of the
canonical string yields the same `UriParts`.

Two URIs are equivalent iff their canonical forms are byte-equal.
`tcp://1.2.3.4:80` and `tcp://1.2.3.4:8080` must produce different
canonical strings — substring matching is a forbidden lookup pattern.

---

## 5. Failure modes

The parser returns `nullopt` rather than partial data. The following
inputs **must** fail:

1. Empty input.
2. Scheme prefix without a body: `tcp://`.
3. Query-only input: `?peer=abc`.
4. Missing port on host:port form: `tcp://127.0.0.1`, `host:`,
   bare `host`.
5. Port zero is **accepted** by the parser. Port 0 has a real
   meaning on the listen side — the OS allocates an ephemeral port
   and the actual value is read back through the transport's
   bound-socket query. The connect side treats port 0 as an error
   per its own contract; the parser does not encode that policy
   because it is application-level.
6. Trailing garbage in the port segment: `tcp://h:9000x`,
   `tcp://h:xyz`. The query is split off first, so
   `tcp://h:9000?peer=...` is **valid** with port 9000.
7. Port overflow: `tcp://h:65536`, `tcp://h:99999`.
8. Unclosed bracket: `tcp://[::1:9000`.
9. Bracket without `:port` suffix: `tcp://[::1]`,
   `tcp://[::1]9000`.
10. Any byte ≤ `0x20` (any C0 control or space) or `0x7F` (DEL)
    anywhere in the input. RFC 3986 already forbids these without
    percent-encoding; the parser rejects up front so a URI carrying
    `\r\nEvil: 1\r\n` cannot be smuggled past transports that
    concatenate the URI into a wire frame.

    The `gn::uri_has_control_bytes` helper exposes the same gate to
    every kernel entry that accepts a raw URI without going through
    `parse_uri` — currently `notify_connect` writes URIs straight
    into the registry index. Bytes 0x21–0x7E pass; 0x80–0xFF pass
    too (the threat model is HTTP grammar, which is 7-bit ASCII).
    Callers MUST NOT percent-decode a URI before re-feeding it into
    these entries; the gate fires only on raw bytes, so a decoded
    `\r\n` would slip through.

Returning `nullopt` is the only failure protocol; the parser does not
throw or write through the optional argument.

### 5.1 Unbracketed IPv6 fallback

A literal `tcp://::1:9000` does not satisfy the strict bracket
requirement, but the rightmost-`:` split happens to produce a valid
parse (`host = "::1"`, `port = 9000`). The parser accepts this case
for legacy compatibility and **canonicalises to the bracketed form**:
`canonical() == "tcp://[::1]:9000"`. Future code paths reading the
canonical string only see the strict form.

---

## 6. Query string

Queries are key-value pairs separated by `&`, each `key=value`. The
parser stores them as a raw `string_view` slice — interpretation is the
caller's job.

`uri_query_value(query, key)` returns the first matching value or an
empty view when absent. No URL decoding, no allocation — the result is
a slice of the source URI.

Reserved query keys:

| Key | Meaning | Parsed by |
|---|---|---|
| `peer` | 64-hex X25519 public key for IK initiator preset | `core/util/uri_query.hpp::parse_peer_param` |

`parse_peer_param` lives in `core/util/uri_query.hpp` because hex
decoding via libsodium pulls a transitive dependency; transport plugins
that only need the raw query string include `sdk/cpp/uri.hpp` and
stay libsodium-free.

---

## 7. Cross-references

- Transport endpoints declared on `notify_connect`: `link.md` §3.
- Connection-record URI key as registry index: `registry.md` §6.
- Noise handshake's optional preset peer pk: `plugins/security/noise/docs/handshake.md` §1
  (IK pattern).
