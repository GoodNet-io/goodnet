# Attestation Payload — Wire Bytes

232-байтный payload, едущий по `msg_id == 0x11` после Noise handshake
complete. Описывает формат cert'а, channel binding и Ed25519 signature
по байтам, плюс шаги kernel-side dispatcher'а.

## Содержание

- [Цель](#цель)
- [Формат на проводе](#формат-на-проводе)
- [Cert structure (136 bytes)](#cert-structure-136-bytes)
- [Channel binding (32 bytes)](#channel-binding-32-bytes)
- [Signature](#signature)
- [Verification flow](#verification-flow)
- [Failure modes](#failure-modes)
- [Self-signed default](#self-signed-default)
- [Cross-refs](#cross-refs)

---

## Цель

Successful Noise handshake пруфит, что обе стороны владеют static
private key, который peer выучил в ходе handshake'а. Не пруфит, что
этот static — endorsed long-term user identity'ей: nodes мог cycle'нуть
device key без permission, или static мог принадлежать attacker'у,
терминировавшему Noise без user secret'а.

Attestation закрывает gap: после каждого Noise handshake'а, который
дотянулся до `Transport` фазы, обе стороны exchange'ят 232-байтный
signed payload, биндящий cert к текущей session'е через `handshake_hash`
channel-binding. Kernel gate'ит trust upgrade `Untrusted → Peer` на
успешный mutual exchange — peer, который не отправил валидную
attestation, остаётся `Untrusted` и handler'ы это видят через
`gn_endpoint_t::trust`.

---

## Формат на проводе

Total **232 байта** signed payload. Все multi-byte поля внутри cert'а —
big-endian per [identity.md](../contracts/identity.en.md) §4.

| Offset | Bytes | Field |
|---|---|---|
| 0 | 136 | attestation cert (peer-issued, см. ниже) |
| 136 | 32 | binding — `handshake_hash` текущей session'и |
| 168 | 64 | Ed25519 signature над `attestation \|\| binding`, signed `device_sk` |

Signature пинит cert к этой session'е: replay'нутый captured cert против
свежей session'и produces binding mismatch и consumer reject'ит.

Полная диаграмма:

```
0           136         168                        232
+-----------+-----------+-------------------------+
| cert      | binding   | Ed25519 sig             |
| 136 bytes | 32 bytes  | 64 bytes                |
+-----------+-----------+-------------------------+
       ^^^^^^^^^^^^^^^^^^^^^
       signed по этим 168 байтам
```

---

## Cert structure (136 bytes)

Самостоятельный sub-structure, минтится на `Attestation::create(user,
device_pk, expiry)` в kernel-internal `core/identity/`. Подписан
**user**'ским ключом (long-term portable identity), а не device'ным.

| Offset | Bytes | Field | Description |
|---|---|---|---|
| 0 | 32 | `user_pk` | Ed25519 public key user'а — issuer |
| 32 | 32 | `device_pk` | Ed25519 public key конкретного device'а — subject |
| 64 | 8 | `expiry_unix_ts` | int64 BE — Unix seconds, после которых cert невалиден |
| 72 | 64 | inner Ed25519 signature | подпись `user_sk` над первыми 72 байтами cert'а |

Total: 32 + 32 + 8 + 64 = **136 байт**.

`expiry_unix_ts` — signed int64 BE; signed чтобы negative время
обозначало «никогда» (применимо для тестовых fixture'ов, не для
production).

Inner sig валидируется как:

```
crypto_sign_verify_detached(
    sig         = cert[72..136],
    message     = cert[0..72],            // user_pk || device_pk || expiry
    public_key  = cert[0..32]             // user_pk
);
```

Self-verify: cert содержит user_pk, и тем же user_pk верифицируется
inner signature. Это работает потому что peer, до Noise handshake'а
закончившегося, **уже** знает peer's static (= peer's device_pk через
Noise XX). Cert говорит «вот user, который endorse'ит этот device»;
inner sig пруфит endorse'мент.

---

## Channel binding (32 bytes)

`gn_handshake_keys_t::handshake_hash` — 32 байта, экспортированных
provider'ом сразу после `Split` (первые 32 байта 64-байтного BLAKE2b
hash'а из symmetric state'а — см.
[noise-handshake](noise-handshake.ru.md) и
[handshake.md](../../plugins/security/noise/docs/handshake.md) §2).

Hash'и handshake'а у двух peer'ов идентичны после Split — обе стороны
сделали одинаковую последовательность `MixHash` over identical
transcript bytes. Использовать его как channel binding гарантирует:

1. Тот же cert не валиден на свежей session'е (binding не совпадёт).
2. Cert привязан конкретно к тому handshake transcript'у, из которого
   Noise учил peer's static.

Producer берёт hash из своего session'ного transport-keys block'а и
кладёт ровно как 32 байта BE.

---

## Signature

Ed25519 detached signature над `attestation || binding` (168 байт),
signed local **device** secret key.

```
sig = crypto_sign_detached(
    message     = payload[0..168],          // cert (136) || binding (32)
    private_key = device_sk
);
```

Total length signature'ы — 64 байта (Ed25519 signature size).

**Why device_sk, не user_sk:** user_sk — long-term backup identity, в
оптимальном deployment'е offline на отдельном устройстве. Подпись
свежей attestation'ы должна происходить на запущенной node'е каждую
сессию; device_sk там и сидит. Inner-cert sig (внутри 136-байтного
cert'а) подписан user_sk и подтверждает «device_sk endorsed user'ом»;
outer sig подтверждает «именно эта device-машина участвует в этой
session'е».

Двойная подпись закрывает scenarios:

| Scenario | Кто остановит |
|---|---|
| Attacker украл cert (общий, длинный) | outer sig fail'ит — не имеет device_sk |
| Attacker украл device_sk | inner sig fail'ит при cert verify (если cert не от него) — не имеет user_sk |
| Attacker украл оба | leaked-key attack, см. [attestation.md](../contracts/attestation.en.md) §10 |

---

## Verification flow

Kernel-internal `attestation_dispatcher` consume'ит inbound envelope с
`msg_id == 0x11` после `IProtocolLayer::deframe` шаге, до regular
handler chain'а. Шаги в order'е, dispatcher exit'ит на первом fail'е и
connection torn down:

1. **Size check.** `payload_size != 232` →
   `GN_DROP_ATTESTATION_BAD_SIZE`.
2. **Layout split.** Cert = `[0, 136)`, binding = `[136, 168)`,
   sig = `[168, 232)`.
3. **Binding match.** `binding != current session's handshake_hash`
   → `GN_DROP_ATTESTATION_REPLAY`.
4. **Cert parse.** 136-байт cert не парсится per
   [identity.md](../contracts/identity.en.md) §4 →
   `GN_DROP_ATTESTATION_PARSE_FAILED`.
5. **Outer signature verify.** Ed25519 detached verify
   `(sig, payload[0..168], cert.device_pk)` fail'ит →
   `GN_DROP_ATTESTATION_BAD_SIGNATURE`.
6. **Cert verify.** Inner sig self-check + не-expired (`now <
   expiry_unix_ts`) — fail →
   `GN_DROP_ATTESTATION_EXPIRED_OR_INVALID`.
7. **Cross-session identity stability.** `ConnectionRegistry::
   get_pinned_device_pk(peer_pk)` — если уже pinned и отличается от
   inbound `device_pk` → `GN_DROP_ATTESTATION_IDENTITY_CHANGE`. Если
   pin'а нет — write through `pin_device_pk(peer_pk, device_pk)`. Pin
   переживает `notify_disconnect` (см.
   [registry.md](../contracts/registry.en.md) §8a).
8. **Per-session identity stability.** Если на этой conn уже
   verified attestation, и new device_pk отличается → тот же
   `IDENTITY_CHANGE`. Same device_pk — duplicate, drop envelope без
   tear down (live re-attestation out-of-scope в v1).
9. Mark `their_received_valid = true`, cache `(user_pk, device_pk)`
   для handler observation.

При обоих flag'ах (`our_sent` и `their_received_valid`) dispatcher
promot'ит connection через
`connections.upgrade_trust(conn, GN_TRUST_PEER)` и fire'ит
`GN_CONN_EVENT_TRUST_UPGRADED`. Order irrelevant; upgrade fires exactly
once per connection (`upgrade_trust` policy gate — см.
[security-trust.md](../contracts/security-trust.en.md) §3).

---

## Failure modes

Каждое consumer-side rejection:

1. Envelope dropped — handler chain не видит.
2. `gn_drop_reason_t` counter инкрементируется ([types.h](../../sdk/types.h)).
3. Connection close через `notify_disconnect(conn, reason)`
   ([conn-events.md](../contracts/conn-events.en.md) §2a).

Producer-side fail (compose payload, frame через protocol layer,
encrypt через session, transport write) abort'ит §4 sequence без
set'а `our_sent`. Connection остаётся `Untrusted`, retry на свежей
session'е. Не emit'ит metric — operator видит warn line per session id.

| `gn_drop_reason_t` | Step |
|---|---|
| `GN_DROP_ATTESTATION_BAD_SIZE` | 1 — payload size != 232 |
| `GN_DROP_ATTESTATION_REPLAY` | 3 — binding mismatch |
| `GN_DROP_ATTESTATION_PARSE_FAILED` | 4 — cert parse |
| `GN_DROP_ATTESTATION_BAD_SIGNATURE` | 5 — outer sig verify |
| `GN_DROP_ATTESTATION_EXPIRED_OR_INVALID` | 6 — inner sig / expiry |
| `GN_DROP_ATTESTATION_IDENTITY_CHANGE` | 7, 8 — pin mismatch |

---

## Self-signed default

В default deployment'е node генерирует обе keypair'ы локально через
`NodeIdentity::generate(expiry)`:

- `user_kp` создаётся свежим — long-term portable identity, backup'ится
  user'ом.
- `device_kp` создаётся свежим — per-machine identity.
- Cert минтится с `cert.user_pk = user_kp.pk` и `cert.device_pk =
  device_kp.pk`, inner sig — `user_kp.sk` над первыми 72 байтами.

Это cryptographically self-signed: peer, который verify'ит cert,
пруфит, что owner of `user_pk` действительно endorse'ил `device_pk`,
но не пруфит что owner of `user_pk` — это та конкретная human entity,
которой user trust'ит в реальном мире.

В `compose(user, device, expiry)` варианте user_kp загружается из
backup'а на новой machine, а device_kp минтится свежим — так выглядит
device replacement scenario. Address (per [identity.md](../contracts/identity.en.md) §3) меняется,
но `user_pk` тот же, и peer'ы могут принять или отклонить новый
device per local policy.

Future: `cert.user_pk` ≠ `cert.issuer_pk` — external CA через
capability bitmap, multi-CA chains. v1 — single user-key signature
over device key; hierarchical делегирование post-v1.

---

## Cross-refs

- [attestation.md](../contracts/attestation.en.md) — kernel-side dispatcher
  spec, mutual-exchange flow, leaked-key model
- [identity.md](../contracts/identity.en.md) — `KeyPair`, `NodeIdentity`,
  cert layout source
- [security-trust.md](../contracts/security-trust.en.md) — TrustClass
  upgrade gate, gated на этом protocol'е
- [security-flow](../architecture/security-flow.ru.md) —
  attestation_dispatcher в kernel'ной FSM
- [noise-handshake](noise-handshake.ru.md) — где `handshake_hash`
  binding'а формируется
- [registry.md](../contracts/registry.en.md) §8a — cross-session pin
  semantics
