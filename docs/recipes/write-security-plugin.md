# Recipe: написать security-плагин

**Status:** active · v1
**Owner:** plugin authors
**Last verified:** 2026-05-06

---

## Содержание

1. Цель
2. Что нужно
3. Шаг 1. Scaffold
4. Шаг 2. `allowed_trust_mask` и регистрация
5. Шаг 3. `handshake_open`
6. Шаг 4. `handshake_step` и `handshake_complete`
7. Шаг 5. `export_transport_keys`
8. Шаг 6. `encrypt` / `decrypt`
9. Шаг 7. Replay protection и rekey
10. Шаг 8. Attestation hook
11. Шаг 9. `handshake_close` и `destroy`
12. Шаг 10. Что плагин НЕ делает
13. Проверка
14. Cross-refs

---

## 1. Цель

Security provider — это плагин, который терминирует handshake,
выводит транспортные ключи и шифрует/расшифровывает каждое
сообщение. Канон — Noise-XX поверх Curve25519 + ChaCha20-Poly1305;
эта последовательность шагов одинаково применима к любому AEAD-
паттерну с двусторонним handshake.

В этом рецепте мы пишем provider под произвольный trust class,
обычно `GN_TRUST_PEER`. Provider регистрируется один на ядро (v1
ограничение, см. §6 security-trust): второй `register_security`
получает `GN_ERR_LIMIT_REACHED`.

---

## 2. Что нужно

`gn_security_provider_vtable_t` из `sdk/security.h` — 11 слотов
плюс `allowed_trust_mask`:

| Слот | Роль |
|---|---|
| `provider_id` | стабильный идентификатор: `"noise-xx"`, `"null"`, `…` |
| `handshake_open` | создать per-conn handshake state |
| `handshake_step` | один шаг handshake: in-bytes → out-bytes |
| `handshake_complete` | булева проверка готовности transport-фазы |
| `export_transport_keys` | вынуть AEAD-ключи + handshake_hash |
| `encrypt` | зашифровать transport-payload |
| `decrypt` | расшифровать transport-payload |
| `rekey` | сбросить nonce-стейт обоих cipher'ов атомарно |
| `handshake_close` | освободить state, обнулить ключи |
| `destroy` | освободить provider'а целиком |
| `allowed_trust_mask` | bitmask trust-классов, которые provider обслуживает |

Поверх — `gn_handshake_keys_t` (export_transport_keys) и
`gn_secure_buffer_t` (`{bytes, size, free_user_data, free_fn}`) для
переноса ownership.

---

## 3. Шаг 1. Scaffold

```sh
nix run .#new-plugin -- security myprov
```

Скелет — `plugins/security/myprov/` с тем же набором
(`CMakeLists.txt`, `default.nix`, `flake.nix`, `myprov.cpp`,
`tests/`). Дальнейшее наполнение идёт в `myprov.cpp` против SDK-
headers.

Plugin-роль `GN_PLUGIN_KIND_SECURITY` отличает security-плагины от
links/handlers; loader-side host_api gate'ит `notify_connect`-
семейство только для link'ов, поэтому security-плагины их не
трогают (правильное поведение).

---

## 4. Шаг 2. `allowed_trust_mask` и регистрация

Provider регистрируется через выделенный slot
`host_api->register_security(provider_id, vtable, security_self)`.
До регистрации plugin обязан определить, какие классы trust он
готов обслуживать:

```c
static uint32_t myprov_allowed_trust_mask(void* self) {
    (void)self;
    /* Стандарт canonical Noise: разрешены все четыре. */
    return (1u << GN_TRUST_UNTRUSTED) |
           (1u << GN_TRUST_PEER)      |
           (1u << GN_TRUST_LOOPBACK)  |
           (1u << GN_TRUST_INTRA_NODE);
}
```

Ядро читает маску один раз при `register_security` и проверяет на
каждом `SessionRegistry::create` (`security-trust.md` §4): trust class
соединения, отсутствующий в маске, ⇒ `GN_ERR_INVALID_ENVELOPE` ещё до
первого handshake-байта + bump `metrics.drop.trust_class_mismatch`.

Single-active per-provider invariant: повторный `register_security`
вернёт `GN_ERR_LIMIT_REACHED`. v1.x StackRegistry разрешит multi-
provider per trust class.

```c
GN_PLUGIN_EXPORT gn_result_t gn_plugin_register(void* self_v) {
    myprov_self_t* self = self_v;

    self->vt.api_size              = sizeof(self->vt);
    self->vt.provider_id           = myprov_provider_id;
    self->vt.handshake_open        = myprov_handshake_open;
    self->vt.handshake_step        = myprov_handshake_step;
    self->vt.handshake_complete    = myprov_handshake_complete;
    self->vt.export_transport_keys = myprov_export_keys;
    self->vt.encrypt               = myprov_encrypt;
    self->vt.decrypt               = myprov_decrypt;
    self->vt.rekey                 = myprov_rekey;
    self->vt.handshake_close       = myprov_handshake_close;
    self->vt.destroy               = myprov_destroy;
    self->vt.allowed_trust_mask    = myprov_allowed_trust_mask;

    return self->api->register_security(self->api->host_ctx,
                                        "myprov",
                                        &self->vt, self);
}
```

---

## 5. Шаг 3. `handshake_open`

Ядро вызывает `handshake_open` сразу после `notify_connect`, передавая
identity-ключи местной стороны и (опционально) static pk peer'а:

```c
static gn_result_t myprov_handshake_open(
    void* self_v,
    gn_conn_id_t conn,
    gn_trust_class_t trust,
    gn_handshake_role_t role,
    const uint8_t local_static_sk[GN_PRIVATE_KEY_BYTES],
    const uint8_t local_static_pk[GN_PUBLIC_KEY_BYTES],
    const uint8_t* remote_static_pk,
    void** out_state)
{
    myprov_self_t* self = self_v;
    if (!out_state) return GN_ERR_NULL_ARG;

    handshake_state_t* hs = calloc(1, sizeof(*hs));
    if (!hs) return GN_ERR_OUT_OF_MEMORY;

    hs->conn  = conn;
    hs->trust = trust;
    hs->role  = role;
    /* Derive X25519 / sign material из local_static_sk. */
    /* remote_static_pk: NULL для XX/NK, non-NULL для IK initiator. */

    *out_state = hs;
    return GN_OK;
}
```

`local_static_sk` borrowed на время вызова — из 64-байтного libsodium-
layout'а plugin сам считает X25519, signing material и затем
обнуляет копии.

`role`:
- `GN_ROLE_INITIATOR` — local-сторона дёргает первый wire-message при
  ближайшем `handshake_step` с `incoming_size = 0`;
- `GN_ROLE_RESPONDER` — local-сторона ждёт первое incoming-сообщение
  и отвечает.

`out_state` остаётся `@owned` plugin'ом до парного
`handshake_close(state)`.

---

## 6. Шаг 4. `handshake_step` и `handshake_complete`

Драйвит ядро на каждом inbound-сообщении handshake-фазы. Возвращает
исходящие байты через `gn_secure_buffer_t` — plugin аллоцирует, плагин
же освобождает по `out_message->free_fn`.

```c
static gn_result_t myprov_handshake_step(
    void* self_v, void* state_v,
    const uint8_t* incoming, size_t incoming_size,
    gn_secure_buffer_t* out_message)
{
    handshake_state_t* hs = state_v;

    /* 1. Если incoming_size > 0 — потребить байты, продвинуть state-machine. */
    /* 2. Если local-сторона должна ответить — собрать out-bytes. */

    out_message->api_size = sizeof(*out_message);
    out_message->bytes    = NULL;
    out_message->size     = 0;
    out_message->free_user_data = NULL;
    out_message->free_fn  = NULL;

    if (/* hs готов отправить сообщение */ 0) {
        size_t   sz   = /* … */ 64;
        uint8_t* buf  = malloc(sz);
        if (!buf) return GN_ERR_OUT_OF_MEMORY;
        /* … заполнить buf … */
        out_message->bytes          = buf;
        out_message->size           = sz;
        out_message->free_user_data = NULL;
        out_message->free_fn        = myprov_free_buffer;
    }

    return GN_OK;
}

static int myprov_handshake_complete(void* self_v, void* state_v) {
    handshake_state_t* hs = state_v;
    return hs->phase == PHASE_TRANSPORT ? 1 : 0;
}
```

`free_fn` имеет shape `void (*)(void* user_data, uint8_t* bytes)` —
первый аргумент — opaque destruction state, который binding
(Rust/Python) может использовать для recovery handle'а; чистый C
обычно передаёт `free_user_data = NULL` и в `free_fn` зовёт
`free(bytes)`.

Промежуточные шаги возвращают `GN_OK` без выходного буфера, если
local-сторона ничего не отправляет (responder, ждущий следующее
сообщение).

---

## 7. Шаг 5. `export_transport_keys`

После `handshake_complete()` возвращает 1, ядро вызывает
`export_transport_keys` — provider один раз отдаёт send/recv ключи
+ initial nonces + handshake hash + peer static pk:

```c
static gn_result_t myprov_export_keys(void* self_v, void* state_v,
                                      gn_handshake_keys_t* out) {
    handshake_state_t* hs = state_v;
    if (!out) return GN_ERR_NULL_ARG;
    if (hs->phase != PHASE_TRANSPORT) return GN_ERR_INVALID_STATE;

    out->api_size = sizeof(*out);
    memcpy(out->send_cipher_key, hs->send_key, GN_CIPHER_KEY_BYTES);
    memcpy(out->recv_cipher_key, hs->recv_key, GN_CIPHER_KEY_BYTES);
    out->initial_send_nonce = hs->send_nonce;
    out->initial_recv_nonce = hs->recv_nonce;
    memcpy(out->handshake_hash, hs->h, GN_HASH_BYTES);
    memcpy(out->peer_static_pk, hs->peer_pk, GN_PUBLIC_KEY_BYTES);

    /* Plugin обнуляет собственные копии — последующие encrypt/decrypt
       на этом state вернут GN_ERR_INVALID_STATE. */
    sodium_memzero(hs->send_key, sizeof(hs->send_key));
    sodium_memzero(hs->recv_key, sizeof(hs->recv_key));
    hs->phase = PHASE_EXPORTED;

    return GN_OK;
}
```

`handshake_hash` — channel-binding 32-байт для attestation
(`attestation.md`); peer'ы подписывают его при формировании 232-
байтного аттестационного payload'а.

---

## 8. Шаг 6. `encrypt` / `decrypt`

В transport-фазе ядро вызывает `encrypt` на каждый исходящий
payload и `decrypt` на каждый входящий. Оба используют
`gn_secure_buffer_t` для transferring ownership.

```c
static gn_result_t myprov_encrypt(void* self_v, void* state_v,
                                  const uint8_t* plaintext,
                                  size_t plaintext_size,
                                  gn_secure_buffer_t* out)
{
    transport_state_t* ts = state_v;
    if (!out) return GN_ERR_NULL_ARG;
    if (ts->phase != PHASE_EXPORTED) return GN_ERR_INVALID_STATE;

    size_t   ct_size = plaintext_size + GN_AEAD_TAG_BYTES;
    uint8_t* ct      = malloc(ct_size);
    if (!ct) return GN_ERR_OUT_OF_MEMORY;

    /* AEAD encrypt с nonce = ts->send_nonce++, AAD = ts->h (или фрейм-
       контекст по контракту protocol layer'а). */

    out->api_size       = sizeof(*out);
    out->bytes          = ct;
    out->size           = ct_size;
    out->free_user_data = NULL;
    out->free_fn        = myprov_free_buffer;
    return GN_OK;
}

static gn_result_t myprov_decrypt(void* self_v, void* state_v,
                                  const uint8_t* ciphertext,
                                  size_t ct_size,
                                  gn_secure_buffer_t* out) {
    /* Симметрично: AEAD decrypt + verify tag. На provider'е:
       обновить replay-window, проверить что nonce в окне. */
    (void)self_v; (void)state_v; (void)ciphertext; (void)ct_size;
    (void)out;
    return GN_OK;
}
```

Wire-framing — kernel-side: kernel оборачивает provider'ский
ciphertext в 2-байт BE length prefix per Noise §7. Plugin не возится с
обрамлением chunk'а — он шифрует логический payload.

---

## 9. Шаг 7. Replay protection и rekey

Provider реализует sliding nonce-window per
[security-trust.md](../contracts/security-trust.md) §6 (cross-refs ниже
указывают на noise/docs/handshake.md как канонический wire-spec):

- send-side: монотонный счётчик nonce, инкремент per encrypt;
- recv-side: окно фиксированной ширины (обычно 64 / 128); сообщения
  с nonce ниже минимума окна — drop, повторы внутри окна — drop.

```c
static gn_result_t myprov_rekey(void* self_v, void* state_v) {
    transport_state_t* ts = state_v;
    /* Атомарный сброс nonce обоих cipher'ов; новые ключи деривятся
       из текущих per Noise rekey rules. */
    ts->send_nonce = 0;
    ts->recv_nonce = 0;
    /* update keys via HKDF / Noise's REKEY function */
    return GN_OK;
}
```

`rekey` инициируется ядром по политике (счётчик байт, время),
никогда — peer-сообщением. Симметрия гарантирует, что обе стороны
сделают rekey на одном и том же noise-event'е.

---

## 10. Шаг 8. Attestation hook

Promotion `Untrusted → Peer` гейтится attestation'ом
([attestation.md](../contracts/attestation.md)), а не успехом Noise.
После того как handshake достиг Transport, ядро публикует
ATTESTATION-события через kernel-internal dispatcher:

- сторона A отправляет 232-байтный payload (cert + binding + signature)
  на reserved msg_id `0x11`;
- сторона B принимает, проверяет, что binding == `handshake_hash`
  свой сессии, парсит cert (136 байт), проверяет Ed25519 подпись над
  `cert || binding`;
- при успехе ядро upgrade'ит trust класс соединения на `Peer`.

Provider в этом не участвует. Его обязанность — только корректный
`handshake_hash` в `gn_handshake_keys_t`. Все остальные шаги — ядро +
identity-сервис.

`Loopback` / `IntraNode` — final at notify_connect, attestation для
них пропускается; gate `can_upgrade(from, to)` отвергает любые
переходы кроме `Untrusted → Peer`.

---

## 11. Шаг 9. `handshake_close` и `destroy`

`handshake_close(state)` — per-conn teardown. Plugin зануляет
оставшийся keying material и освобождает state-block; subsequent
`encrypt`/`decrypt`/`handshake_step` на closed state ⇒
`GN_ERR_INVALID_STATE`.

```c
static void myprov_handshake_close(void* self_v, void* state_v) {
    handshake_state_t* hs = state_v;
    if (!hs) return;
    sodium_memzero(hs, sizeof(*hs));
    free(hs);
}

static void myprov_destroy(void* self_v) {
    myprov_self_t* self = self_v;
    /* Освободить provider'ские глобалы; per-conn state'ы уже
       зачищены через handshake_close. */
    free(self);
}
```

`free_fn` для `gn_secure_buffer_t`:

```c
static void myprov_free_buffer(void* user_data, uint8_t* bytes) {
    (void)user_data;
    free(bytes);
}
```

`gn_plugin_unregister` снимает provider'а:

```c
GN_PLUGIN_EXPORT gn_result_t gn_plugin_unregister(void* self_v) {
    myprov_self_t* self = self_v;
    return self->api->unregister_security(self->api->host_ctx, "myprov");
}

GN_PLUGIN_EXPORT void gn_plugin_shutdown(void* self_v) {
    myprov_self_t* self = self_v;
    free(self);
}
```

Quiescence-wait (`plugin-lifetime.md` §4) обеспечивает, что после
`unregister_security` ни одна in-flight encrypt/decrypt-операция уже
не входит в plugin'у `.text`.

---

## 12. Шаг 10. Что плагин НЕ делает

- **Не инициирует trust transitions.** Класс на соединении ставит link
  в `notify_connect`; upgrade `Untrusted → Peer` делает ядро после
  attestation. Никаких вызовов upgrade-API из provider'а нет — их в
  ABI нет.
- **Не управляет timing'ом handshake.** Ретраи, таймеры,
  reconnect — поверх; provider — pure state machine на input/output.
- **Не владеет соединениями.** `gn_conn_id_t` приходит как аргумент;
  link их создаёт, ядро их закрывает.
- **Не парсит wire-framing.** 2-byte BE length prefix per Noise §7
  обрабатывает kernel-side `SecuritySession` (см.
  `feedback_kernel_only_subflake_pivot` контекст про bench defect
  fix); provider шифрует логический payload.
- **Не делает attestation сам.** Attestation flow — kernel-internal
  dispatcher на reserved msg_id `0x11` (см. handler-registration.md
  §2a). Provider только экспортирует `handshake_hash`.
- **Не вызывает `notify_connect` / `notify_inbound_bytes` /
  `notify_disconnect` / `kick_handshake`.** Это loader-side host_api,
  гейтнутый для kind=`LINK`. Security-плагин получит
  `GN_ERR_NOT_IMPLEMENTED`.

---

## 13. Проверка

1. Поднять две ноды, у каждой загружен myprov + один из baseline-
   link'ов (например `tcp` или `ipc`).
2. Одна нода `connect`, другая `listen` — оба зарегистрированы как
   handshake-роли (initiator / responder).
3. Проверить, что после initial round'ов `handshake_step` обе
   стороны вернули `handshake_complete() == 1`.
4. После `export_transport_keys` пара отправляет несколько
   transport-сообщений; receiver успешно `decrypt`.
5. Subscriber на conn-state канал получает
   `GN_CONN_EVENT_TRUST_UPGRADED` (Untrusted → Peer) после
   успешного attestation round'а.
6. Replay-test: переслать тот же ciphertext повторно — receiver
   возвращает ошибку (`GN_ERR_INVALID_ENVELOPE` или ad-hoc reject)
   и метрика `drop.attestation_replay` / эквивалент инкрементируется.
7. Hash-check: убедиться, что `handshake_hash` у обеих сторон совпал —
   именно он используется в attestation как binding.

---

## 14. Cross-refs

- [security-trust.md](../contracts/security-trust.md) — TrustClass,
  per-component admission gates §4, single-active provider §6,
  conn-id ownership gate §6a, replay protection §6.
- [attestation.md](../contracts/attestation.md) — 232-байтный
  payload, kernel-internal dispatcher, gating `Untrusted → Peer`.
- [plugin-lifetime.md](../contracts/plugin-lifetime.md) — фазы,
  registration window, quiescence wait, shutdown sequence.
- [host-api.md](../contracts/host-api.md) — `register_security`,
  `unregister_security`.
- [security-flow](../architecture/security-flow.md) — общая
  диаграмма handshake → attestation → transport phase.
- [plugin-model](../architecture/plugin-model.md) — где security
  стоит относительно link'а и handler'а в plugin-граф.
