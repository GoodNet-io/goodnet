# Архитектура: топология, capability exchange и inject

Этот документ описывает три взаимосвязанных механизма: как ядро строит и
обновляет снапшот структурного состояния (топологию), как узлы обмениваются
capability-блобами для обнаружения несовместимости, и как bridge-плагины
вводят внешние байты в mesh через inject.

---

## 1. Топология

### 1.1 Что это

`gn_topology_t` (`sdk/topology.h:79-111`) — read-only снапшот всего,
что зарегистрировано в ядре: линки, security-провайдеры, протокольные слои,
handler-цепочки. Структура является **data struct** без поля `api_size`.
ABI-рост через `_reserved[4]` per `abi-evolution.en.md §4`.

```
fingerprint[32]           SHA-256 по четырём отсортированным секциям
link_count                кол-во зарегистрированных линков
security_count            кол-во security-провайдеров
protocol_count            кол-во протокольных слоёв
handler_count             кол-во (protocol_id, msg_id) пар
links / security / protocols / handlers   @borrowed указатели в kernel storage
contour_gaps              bitmask: бит N = 1 → GN_TRUST_N без E2E-шифрования
_reserved[4]              MUST be zero; новые поля потребляют эти слоты
```

Все pointer-поля `@borrowed` из kernel-owned storage. Действительны до
`gn_core_destroy()` или следующего `gn_core_reload_topology()`.

### 1.2 Fingerprint

SHA-256 по четырём секциям в строго фиксированном порядке
(`core/topology/topology_builder.cpp:52-92`):

| Тег  | Секция    | Ключ сортировки          | Поля на запись                             |
|------|-----------|--------------------------|---------------------------------------------|
| 0x01 | links     | scheme ascending         | scheme (NUL) + le32 caps_flags + le32 max_payload |
| 0x02 | security  | provider_id ascending    | provider_id (NUL) + le32 trust_mask + le32 provides_flags |
| 0x03 | protocols | protocol_id ascending    | protocol_id (NUL)                           |
| 0x04 | handlers  | (protocol_id, msg_id)    | protocol_id (NUL) + le32 msg_id + le32 chain_length |

Сортировка — по идентификатору, не по порядку регистрации. Два узла с
одинаковым набором плагинов дают одинаковый fingerprint независимо от
последовательности загрузки.

### 1.3 contour_gaps

Bitmask (`topology_builder.cpp:211-248`). Бит N установлен, когда ни один
зарегистрированный security-провайдер не покрывает `GN_TRUST_N` флагом
`GN_SEC_PROVIDES_E2E_ENCRYPTION`. Специальный случай для
`GN_TRUST_LINK_ENCRYPTED`: покрыт когда link имеет `GN_LINK_CAP_ENCRYPTED_PATH`
и провайдер пропускает этот trust-класс.

Корректный production-стек: `contour_gaps == 0b11100 == 28`
(биты 2, 3, 4 — loopback, intra-node, anon-loopback не требуют E2E).
`contour_gaps & 0x3 != 0` — внешний trust-класс без E2E, контур открыт.

Подробно: `docs/contracts/layer-capability.en.md §5`.

### 1.4 Security-провайдеры: два класса

Оба класса влияют на fingerprint при регистрации/выгрузке.
Разница — в severity и в `contour_gaps`:

**E2E encryption провайдеры** (напр. Noise XX):
- `provides_flags & GN_SEC_PROVIDES_E2E_ENCRYPTION` = true
- Выгрузка → `contour_gaps` меняется → critical: внешние trust-классы без шифрования
- fingerprint меняется по секции 0x02

**Attestation / key verification провайдеры** (PKCS11, HSM, кастомные):
- `provides_flags = 0` — только аутентификация, не шифрование
- Выгрузка → fingerprint меняется, но `contour_gaps` может не измениться
  если E2E остаётся через другого провайдера
- Severity: recoverable

---

## 2. Жизненный цикл топологии

### 2.1 Cold-start

```
gn_core_start()  (core/kernel/core_c.cpp:358-366)
  └─ build_topology(kernel)
       ├─ snapshot всех registry под shared_lock
       ├─ сортировка по стабильному ключу
       ├─ query link caps: extension_vtable → gn_link_api_t → get_capabilities
       ├─ read security provides_flags + allowed_trust_mask
       ├─ SHA-256 fingerprint (topology_builder.cpp:52-92)
       ├─ contour_gaps (topology_builder.cpp:211-248)
       └─ on_topology_sealed(self, &topo) на каждый link plugin (253-260)
  └─ encode_topology_wire_blob(topo)  → TLV 0x0004 blob
  └─ kernel.set_topology_wire_blob(blob)
  └─ capability_blob_bus.subscribe(topology_caps_cb)
```

`on_topology_sealed` — синхронный вызов, до начала приёма соединений.
Слот опциональный, защищён `GN_API_HAS(gn_link_vtable_t, vtable, on_topology_sealed)`.
Подробно: `docs/contracts/layer-capability.en.md §4`.

### 2.2 Reload

```
gn_core_reload_topology(core)  (core/kernel/core_c.cpp:1303-1313)
  ├─ prev = &core->topology_->topo  (или nullptr если не было)
  ├─ new_snap = build_topology(kernel)
  ├─ encode_topology_wire_blob(*next) → новый blob
  ├─ kernel.set_topology_wire_blob(blob)
  ├─ kernel.on_topology_reload().fire({prev, next})   ← F1.1 subscriber notification
  └─ core->topology_ = move(new_snap)
```

**Подтверждённый gap:** после reload `topology_wire_blob_` обновляется в ядре,
но существующие соединения в фазе Transport **не получают** новый blob автоматически.
`send_topology_caps_blob` вызывается только при достижении Transport phase
(`notifications.cpp:433`) — то есть только для новых handshake.

Следствие: peer с active Transport-phase соединением продолжает работать со
старым fingerprint до следующего переподключения. Для немедленной синхронизации
нужна итерация `connections().for_each()` + вызов send-пути для каждого
Transport-phase соединения. Это ещё не реализовано.

---

## 3. Capability exchange (TLV wire blob)

### 3.1 Wire format

Blob, отправляемый как msg_id=0x13 (`kCapabilityBlobMsgId`):

```
[8 bytes]   expiry_unix_ts: int64 big-endian
[N bytes]   TLV sequence: [type:u16 BE][length:u16 BE][value:length bytes]*
```

`encode_topology_wire_blob` (`topology_builder.cpp:265-283`) кодирует:
- expiry = INT64_MAX (действителен всё время жизни ядра)
- TLV 0x0004, len=32, value=fingerprint[32]

TLV-кодек: `sdk/cpp/capability_tlv.hpp`. Unknown type → skip, продолжать.
Усечённый header или value → `TlvError::Truncated`.

### 3.2 Все известные TLV-типы

| Тип   | Имя                   | Value                                | Источник   |
|-------|-----------------------|--------------------------------------|------------|
| 0x0000 | transport-set        | 4+ bytes bitmap (GN_LINK_CAP_*)      | плагины    |
| 0x0001 | protocol-set         | 4+ bytes bitmap (индексы в 0x0002)   | плагины    |
| 0x0002 | protocol-list        | UTF-8 имена через `\n`               | плагины    |
| 0x0003 | compression-set      | 1 byte: бит 0 = ZSTD                 | плагины    |
| 0x0004 | topology-fingerprint | 32 bytes SHA-256                     | **ядро**   |
| 0x0200 | heartbeat-interval-ms | 4 bytes BE u32                      | плагины    |

Тип 0x0004 — **единственный TLV, отправляемый ядром автоматически**.
Все остальные — через `host_api->present_capability_blob`.

Полная спецификация wire format: `docs/contracts/capability-tlv.en.md`.

### 3.3 Отправка и приём

**Отправка нового соединению** (`notifications.cpp:333-367`, вызов на строке 433):
- Ядро вызывает `send_topology_caps_blob` сразу после достижения `SecurityPhase::Transport`
- Direct path: frame → encrypt → link.send (не через очередь, не через rate-limit)
- Использует pre-computed `kernel->topology_wire_blob()`

**Отправка плагином** через `host_api->present_capability_blob`:
- Стандартный path: queue → drain → AEAD encryption → link send
- Ограничение размера: `limits.max_capability_blob_bytes` (default 16 KiB)
- expiry timestamp задаёт вызывающий

**Приём** (`topology_caps_cb`, `core_c.cpp:321-355`):
- Подписан на `capability_blob_bus` при старте ядра
- Вызывается для каждого входящего msg_id=0x13
- Ищет только TLV 0x0004, игнорирует остальные типы
- Сравнивает с `core->topology_->topo.fingerprint` через `memcmp`
- Вызывает `connections().set_peer_caps_verified(conn, match)`
- При mismatch: логирует warning, НЕ закрывает соединение

`peer_caps_verified` флаг доступен через `get_endpoint` для оператора/плагинов.

---

## 4. Subscribe to topology reload

`host_api->subscribe_topology_reload` (`sdk/host_api.h`, слот перед `_reserved[8]`).
Channel: `GN_SUBSCRIBE_TOPOLOGY_RELOAD = 3` (`sdk/conn_events.h`).
Callback: `gn_topology_reload_cb_t(void* user_data, const gn_topology_s* prev, const gn_topology_s* next)`.

Любой тип плагина подписывается в `gn_plugin_register` — это не vtable линка,
а kernel pub/sub. Prev == nullptr на первом reload.
Оба указателя действительны только в течение callback.

Проверка наличия слота: `GN_API_HAS(host_api_t, api, subscribe_topology_reload)`.

C++ удобство: `gn::sdk::Subscription::on_topology_reload(api, fn)` (`sdk/cpp/subscription.hpp`).

В callback плагин сравнивает `prev` и `next`:
- `handler_entries[i].chain_length` — выпала ли handler-цепочка для msg_id
- `security_count` — изменился ли состав security-провайдеров
- `contour_gaps` — изменилось ли покрытие E2E
- fingerprint — изменился ли structural fingerprint

Ядро не предписывает recovery policy — только доставляет событие.

---

## 5. Inject

`host_api->inject` (`sdk/host_api.h:387-393`). Позволяет bridge-плагинам вводить
внешние байты в mesh под идентификатором source-соединения.

### 5.1 Два режима

```c
typedef enum { GN_INJECT_LAYER_MESSAGE = 0, GN_INJECT_LAYER_FRAME = 1 } gn_inject_layer_t;
```
(`sdk/types.h:141-144`)

| Аспект | MESSAGE | FRAME |
|--------|---------|-------|
| Входные данные | payload bytes | полностью сформированный wire frame |
| Конверт | ядро строит: sender=source.remote_pk, receiver=local_identity | ядро deframes, извлекает конверты |
| msg_id | обязателен, ненулевой, вне identity-range | игнорируется |
| Размер | `limits.max_payload_bytes` | `limits.max_frame_bytes` |
| Применение | bridge re-publishes foreign client payload | relay tunnel с opaque inner frames |

### 5.2 Ограничения (верифицированы по коду)

**Identity-range** (`system_handler_ids.hpp:30-72`, `notifications.cpp:596-604`):
- `0x11` (attestation) — hard-reserved, заблокирован
- `0x10–0x1F` — identity-range: MESSAGE-inject заблокирован, FRAME проходит через deframer
- Причина: плагин не должен синтезировать identity-события на чужих соединениях

**Rate limiting** (`notifications.cpp:637-649`):
- Token bucket на source-pk (первые 8 байт)
- Default: 100 msg/s, burst 50 (конфигурируется через `limits`)
- Применяется после всех остальных проверок — bad inputs не сжигают бюджет

**Depth limiting** (`notifications.cpp`):
- Цепочки синхронных inject ограничены `max_inject_depth` (default 32) на поток
- Защита от stack exhaustion при рекурсивных inject

**Ownership check**:
- source-соединение должно существовать и принадлежать вызывающему плагину
- `target_ns` — обязательный, ненулевой string

**Role check** (`notifications.cpp:571`):
- inject доступен link-role плагинам

### 5.3 Связь с топологией

Если link-плагин, через который шёл inject, выгружается:
- topology reload происходит (link_count меняется)
- следующий inject через этот link → `links().find_by_scheme()` → nullptr → `GN_ERR_NOT_FOUND`
- caller получает ошибку, больше ничего не происходит

Если handler для целевого msg_id выгружается:
- topology reload (handler_count или chain_length меняется)
- inject доставляет payload в ядро, `dispatch_chain` → `DroppedNoHandler` → молчаливый дроп
- peer не получает уведомления до следующего capability exchange с новым fingerprint

Подробно о inject-паттернах: `docs/contracts/host-api.en.md §8`.

---

## 6. Известные gaps

| Gap | Место | Статус |
|-----|-------|--------|
| На reload не пушится blob на existing Transport-phase connections | `core_c.cpp:gn_core_reload_topology` | не реализовано |
| DroppedNoHandler — нет backpressure к peer | `router.cpp:dispatch_chain` | по дизайну; recovery через capability exchange |
| Нет standalone контракта для inject | — | `host-api.en.md §8` как временное место |
| Нет named contours (F1.2) | `sdk/topology.h` | в плане (#33) |
| Нет contour state BROKEN/PARTIAL (F1.4) | `sdk/topology.h` | в плане (#34) |
| TLV 0x0005 (contour fingerprint) не существует | `topology_builder.cpp` | в плане (#34) |

---

## 7. Ссылки

**SDK:**
- `sdk/topology.h` — `gn_topology_t`, `gn_topo_*_entry_t`, `contour_gaps`
- `sdk/host_api.h` — `inject`, `subscribe_topology_reload`, `present_capability_blob`, `for_each_connection`
- `sdk/conn_events.h` — `GN_SUBSCRIBE_TOPOLOGY_RELOAD`, `gn_topology_reload_cb_t`
- `sdk/types.h:141-144` — `gn_inject_layer_t`
- `sdk/cpp/capability_tlv.hpp` — TLV encode/parse
- `sdk/cpp/subscription.hpp` — `Subscription::on_topology_reload()`

**Core:**
- `core/topology/topology_builder.cpp` — `build_topology`, fingerprint, contour_gaps, `encode_topology_wire_blob`
- `core/kernel/core_c.cpp:321-366` — `topology_caps_cb`, blob setup on start
- `core/kernel/core_c.cpp:1303-1313` — `gn_core_reload_topology`
- `core/kernel/host_api/notifications.cpp:333-367` — `send_topology_caps_blob`
- `core/kernel/host_api/notifications.cpp:556-691` — `inject` implementation
- `core/kernel/router.cpp:94-107` — `dispatch_chain`, `DroppedNoHandler`
- `core/kernel/system_handler_ids.hpp` — identity-range definitions

**Contracts:**
- `docs/contracts/layer-capability.en.md` — topology lifecycle, fingerprint, contour_gaps, vtable slots
- `docs/contracts/capability-tlv.en.md` — wire format, TLV type allocations
- `docs/contracts/host-api.en.md §8` — inject semantics, patterns, failure modes
- `docs/contracts/identity.en.md` — identity-range msg_id reservations (0x10–0x1F)
- `docs/contracts/security-trust.en.md` — trust classes, allowed_trust_mask
- `docs/contracts/abi-evolution.en.md` — data struct growth rules, _reserved promotion
