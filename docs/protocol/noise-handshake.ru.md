# Noise Handshake — Wire Bytes

Pattern Noise XX над X25519, ChaCha20-Poly1305 и BLAKE2b. Реализация —
`plugins/security/noise/`. Описывает три handshake-сообщения по байтам и
формат transport-фазных кадров после handshake complete.

## Содержание

- [Pattern](#pattern)
- [Prologue](#prologue)
- [msg 1 layout](#msg-1-layout)
- [msg 2 layout](#msg-2-layout)
- [msg 3 layout](#msg-3-layout)
- [Length prefix](#length-prefix)
- [Transport phase framing](#transport-phase-framing)
- [Nonce](#nonce)
- [Replay model](#replay-model)
- [Session keys](#session-keys)
- [Где это живёт](#где-это-живёт)
- [Cross-refs](#cross-refs)

---

## Pattern

```
Noise_XX_25519_ChaChaPoly_BLAKE2b
```

Имя протокола — **on-wire** идентификатор, mix'ится в symmetric state на
`InitializeSymmetric`. Каждый байт строки имеет значение: реализация,
которая использует BLAKE2s вместо BLAKE2b, должна декларировать
`...BLAKE2s` иначе peer'ы не interoperate.

XX — mutual-auth pattern, обе стороны учат public key друг друга в ходе
handshake'а. Три message'а:

| # | Direction | Tokens | Wire bytes |
|---|---|---|---|
| 1 | initiator → responder | `e` | 32 байта эфемерного pk инициатора |
| 2 | responder → initiator | `e, ee, s, es` | 32B эфемерный pk + 48B encrypted static |
| 3 | initiator → responder | `s, se` | 48B encrypted static |

После msg 3 обе стороны вызывают `Split` и получают пару cipher keys для
transport phase.

Hash function — BLAKE2b, `HASHLEN = 64`. Cipher — ChaCha20-Poly1305,
`KEYLEN = 32`, `NONCELEN = 12`, `TAGLEN = 16`. DH — X25519 (Ed25519
ключи конвертируются в X25519 при handshake_open через
`crypto_sign_ed25519_pk_to_curve25519` /
`crypto_sign_ed25519_sk_to_curve25519`).

`gn_handshake_keys_t::handshake_hash` экспортируется как 32 байта (первые
32 байта 64-байтного `h`); этого достаточно для channel binding'а на
collision-resistance уровне 256 бит.

---

## Prologue

Сразу после `InitializeSymmetric` обе стороны mix'ат литеральные байты
строки `"goodnet/v1/noise"` (16 байт ASCII) в symmetric handshake hash
через `MixHash` per Noise §6.5.

Пролог биндит транскрипт к домену GoodNet: внешний Ed25519-message,
делящий префикс с XX-run, не replay'ится как начало hostile handshake'а
— prefix байты не совпадают с прологом, MAC падает на первом же
encrypted token'е.

При смене wire format'а пролог сдвигается (`"goodnet/v1.x/noise"` и
далее) — два транскрипта под разными прологами никогда не collide'ят.

---

## msg 1 layout

Initiator → responder. Pattern token `e`.

| Offset | Bytes | Field |
|---|---|---|
| 0 | 32 | initiator ephemeral X25519 public key |

Total: **32 байта**. Шифрования нет — symmetric state ещё без cipher key.
Inicialator перед записью генерирует свежую X25519 keypair (`e_init`),
сериализует `e_init.public` в первые 32 байта msg, mix'ит в `h` через
`MixHash`.

Responder на receive'е читает 32 байта, mix'ит их в свой `h`, помечает
peer's ephemeral. На этом этапе `ck` ещё не initialised — DH не делался.

---

## msg 2 layout

Responder → initiator. Pattern tokens `e, ee, s, es`.

| Offset | Bytes | Field |
|---|---|---|
| 0 | 32 | responder ephemeral X25519 public key |
| 32 | 32 | responder static X25519 public key (encrypted) |
| 64 | 16 | Poly1305 tag над зашифрованным static |

Total: **80 байт**.

Что происходит между токенами:

1. `e` — responder генерирует `e_resp`, пишет `e_resp.public`,
   `MixHash(e_resp.public)`.
2. `ee` — `MixKey(DH(e_resp.private, e_init.public))`. С этого момента
   `ck` initialised, derived `k` готов к AEAD.
3. `s` — responder шифрует `s_resp.public` под текущим `(k, n)` с AAD =
   `h`, инкрементирует nonce, mix'ит ciphertext в `h`. Пишет 32 байта
   ciphertext'а + 16 байт Poly1305 tag.
4. `es` — `MixKey(DH(s_resp.private, e_init.public))`. Rotates `k`.

Initiator на receive'е воспроизводит шаги симметрично, decrypt'ит
responder static (это и есть, как initiator его учит), валидирует tag.
Ошибка decrypt'а → handshake abort, connection torn down с
`GN_ERR_INVALID_ENVELOPE`.

---

## msg 3 layout

Initiator → responder. Pattern tokens `s, se`.

| Offset | Bytes | Field |
|---|---|---|
| 0 | 32 | initiator static X25519 public key (encrypted) |
| 32 | 16 | Poly1305 tag |

Total: **48 байт**.

Шаги:

1. `s` — initiator шифрует `s_init.public` под текущим `(k, n)`, AAD
   = `h`, mix'ит ciphertext в `h`. Пишет 32 + 16 байт.
2. `se` — `MixKey(DH(s_init.private, e_resp.public))`. Rotates `k`.

После `se` оба пира делают `Split` и получают `(k_send, k_recv)` пару.
Symmetric state'а после Split не существует — все его секрет-буферы
zero'ятся eagerly per [handshake.md](../../plugins/security/noise/docs/handshake.md) §5.

Responder на receive'е decrypt'ит initiator static — это и есть, как
responder его учит. Mutual auth complete: обе стороны убедились, что
peer владеет соответствующим static private key через успешные DH-mix'ы.

---

## Length prefix

Каждое handshake-сообщение приходит на провод с 2-байтным big-endian
префиксом длины:

```
+------+--------------+
| u16  | Noise bytes  |
+------+--------------+
```

| msg | u16 length value |
|---|---|
| 1 | `0x0020` (32) |
| 2 | `0x0050` (80) |
| 3 | `0x0030` (48) |

Префикс emit'ит и consume'ит kernel-side `SecuritySession`, не плагин.
Provider vtable работает на bare bytes через
`handshake_step(state, incoming, incoming_size, out_message)` — incoming
уже sliced по длине, out_message — без префикса.

Это разделение даёт kernel-side framer'у работать одинаково для всех
провайдеров (noise, null, future post-quantum) — каждый плагин знает
только свой AEAD primitive.

---

## Transport phase framing

После handshake complete и `Split` каждый transport-message ходит в том
же 2-байтном префиксе:

| Offset | Bytes | Field |
|---|---|---|
| 0 | 2 | u16 BE — `length - 2` (bytes of ciphertext + tag) |
| 2 | N | ChaCha20-Poly1305 ciphertext |
| 2+N | 16 | Poly1305 authentication tag |

Где `N + 16 = length`. Associated data — empty (v1 не использует
AAD; framing layer уже несёт MAC implicitly через ciphertext).

Plaintext под ciphertext'ом — целая GNET frame (см.
[gnet-frames](gnet-frames.ru.md)). Pre-fragmentation на kernel уровне
гарантирует, что plaintext ≤ `kMaxFrameBytes` = 65536, что вмещается в
u16 длину минус `TAGLEN`.

### Inline-crypto fast path

После `export_transport_keys` kernel-side `SecuritySession` инициализирует
inline-crypto state с экспортированными ключами и обходит
provider vtable. ChaCha20-Poly1305 запускается напрямую на keys — без
лишнего FFI hop'а на каждое сообщение.

Provider'ские `encrypt`/`decrypt` slot'ы остаются populated — fallback
для провайдеров, которые отказываются экспортировать ключи (возвращают
`GN_ERR_NOT_IMPLEMENTED`). На noise hot path они не вызываются.

---

## Nonce

64-битный AEAD nonce, per-direction independent counter, инкрементируется
на каждый AEAD call.

`gn_handshake_keys_t` экспортирует initial-значения:

```c
typedef struct gn_handshake_keys_s {
    uint32_t api_size;
    uint8_t  send_cipher_key[32];
    uint8_t  recv_cipher_key[32];
    uint64_t initial_send_nonce;
    uint64_t initial_recv_nonce;
    uint8_t  handshake_hash[32];   /* channel binding */
    uint8_t  peer_static_pk[32];
    void*    _reserved[4];
} gn_handshake_keys_t;
```

Inline-crypto state стартует с этих значений; hard-code'ить ноль
запрещено, так как vtable-encrypt path и inline path расходились бы по
nonce на rekey transition'е.

ChaCha20 ожидает 96-битный nonce; формирование — `0x00000000` (4 байта)
+ 64-битный counter big-endian (8 байт). Counter увеличивается до
порога rekey'а.

---

## Replay model

Sliding-window replay protection — **отсутствует**. v1 noise provider
полагается на свой transport satisfy'ить три инварианта:

| Invariant | Кем требуется |
|---|---|
| Reliable delivery | rekey schedule — silently dropped frame оставляет стороны на расходящихся counter'ах |
| In-order delivery | recv nonce implicit — re-ordered frame fails AEAD |
| No link-layer replay | nonce check отвергает второй copy, но metric attribution даёт спурный fail |

TCP, TLS-over-TCP, IPC и WS satisfy'ют все три; UDP-class транспорты —
нет, и v1 noise на UDP не работает. Future provider variant для
UDP-class транспортов добавит explicit replay window per session.

Cross-link: [security-trust.md](../contracts/security-trust.en.md) §6
описывает cross-cutting trust-class policy.

---

## Session keys

`Split` в конце handshake'а produces две независимые `CipherState`:

- `cs1` — initiator-to-responder key
- `cs2` — responder-to-initiator key

Для initiator'а: `send = cs1`, `recv = cs2`.
Для responder'а: `send = cs2`, `recv = cs1`.

Это обеспечивает asymmetric setup: каждая сторона encrypt'ит своими
ключами и decrypt'ит peer'ский — и обе стороны пара видят свои keypairs
через один `gn_handshake_keys_t` view.

### Rekey

Threshold:

```
REKEY_INTERVAL = 2^60
```

Match WireGuard. Lower would force rekey на каждый bulk transfer и
amplify nonce-handling bug.

Auto-trigger живёт внутри `encrypt`/`decrypt`: после advance'а nonce
provider проверяет threshold, и при пересечении atomic rekey'ит обе
cipher state одной операцией:

```
rekey():
    derive_next_keys(send_cipher, recv_cipher)
    send_cipher.nonce = 0
    recv_cipher.nonce = 0
```

Atomic — оба cipher rekey'ятся вместе и оба nonce ресетятся вместе.
Иначе peer'ы дивергируются: send на key `k+1`, recv ещё на `k`, и
decrypt silently fail'ит до следующего explicit handshake'а.

### Zeroisation

`export_transport_keys` zeroises все cipher keys, nonces и hash buffer'ы
в source session после копирования. Subsequent encrypt/decrypt на
exported state'е возвращают `GN_ERR_INVALID_STATE`.

Inline-crypto state zeroises свои ключи в destructor'е.

---

## Где это живёт

Pattern реализован в `plugins/security/noise/`:

| File | Owner |
|---|---|
| `noise.cpp` | provider vtable instance, registration |
| `handshake.hpp` / `.cpp` | XX state machine, Split |
| `symmetric.hpp` / `.cpp` | InitializeSymmetric, MixKey, MixHash, Encrypt/Decrypt with cipher state |
| `cipher.hpp` / `.cpp` | ChaCha20-Poly1305 wrapper |
| `hash.hpp` / `.cpp` | BLAKE2b wrapper |
| `hkdf.hpp` / `.cpp` | HKDF-BLAKE2b for key derivation |
| `transport.hpp` / `.cpp` | post-handshake CipherState pair |

Plugin separation: noise — собственный git, GPL-2 license, standalone
flake. Kernel side `SecuritySession` invoke'ит provider vtable; plugin
никогда не видит `gn_message_t` envelope'а — только bare bytes.

`gn_security_provider_vtable_t` декларирован в
[security.h](../../sdk/security.h); все 13 slot'ов (api_size,
provider_id, handshake_open, handshake_step, handshake_complete,
export_transport_keys, encrypt, decrypt, rekey, handshake_close,
destroy, allowed_trust_mask, _reserved[4]).

---

## Cross-refs

- [attestation-bytes](attestation-bytes.ru.md) — payload, обменивающийся
  поверх transport phase после handshake complete
- [security-trust.md](../contracts/security-trust.en.md) — TrustClass
  policy, attestation gate
- [security-flow](../architecture/security-flow.ru.md) — где SecuritySession
  живёт в kernel'е, как chain'ятся events
- [handshake.md](../../plugins/security/noise/docs/handshake.md) —
  plugin-side контракт (rekey threshold, zeroisation, transport
  invariants)
- [gnet-frames](gnet-frames.ru.md) — plaintext-layer, сидящий внутри
  ciphertext'а
