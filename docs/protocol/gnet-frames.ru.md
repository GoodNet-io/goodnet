# GNET Frame Format

Канонический mesh-framing GoodNet v1.x. Реализация —
`plugins/protocols/gnet/` (статически слинкованный плагин-слот).
Описывает байт-в-байт, что попадает на провод после AEAD-encrypt'а
security-сессии и до link plugin'а.

## Содержание

- [Формат рамки](#формат-рамки)
- [Семантика длины](#семантика-длины)
- [Sender pk](#sender-pk)
- [Receiver pk](#receiver-pk)
- [msg_id](#msg_id)
- [Payload](#payload)
- [Coalescing](#coalescing)
- [Backpressure](#backpressure)
- [Контраст с raw protocol](#контраст-с-raw-protocol)
- [Cross-refs](#cross-refs)

---

## Формат рамки

Все многобайтные поля — big-endian.

### Fixed header (14 байт, всегда)

| Offset | Bytes | Field | Description |
|---|---|---|---|
| 0 | 4 | `magic` | `0x47 0x4E 0x45 0x54` (ASCII «GNET»); mismatch → `GN_ERR_DEFRAME_CORRUPT` |
| 4 | 1 | `ver` | `0x01` для v1; иной версии → `GN_ERR_DEFRAME_CORRUPT` |
| 5 | 1 | `flags` | bitfield, см. ниже |
| 6 | 4 | `msg_id` | uint32 BE — routing target внутри receiver |
| 10 | 4 | `length` | uint32 BE — total frame size, fixed header inclusive |

### Conditional PK поля

Опциональные 32-байтные блоки сразу после fixed header'а; присутствие
управляется флагами:

| Offset | Bytes | Field | Present when |
|---|---|---|---|
| 14 | 32 | `sender_pk` | `(flags & 0x01) != 0` — `EXPLICIT_SENDER` |
| 14 \| 46 | 32 | `receiver_pk` | `(flags & 0x02) != 0` — `EXPLICIT_RECEIVER` |

Порядок фиксирован: `sender_pk` идёт перед `receiver_pk`, когда
оба присутствуют.

### Flags байт (offset 5)

```
bit  mask   name                  meaning
---  ----   --------------------  --------------------------------
 0   0x01   EXPLICIT_SENDER       sender_pk на проводе
 1   0x02   EXPLICIT_RECEIVER     receiver_pk на проводе
 2   0x04   BROADCAST             receiver — implicit ZERO; SENDER MUST = 1
 3   0x08   reserved              MUST be 0 в v1
 4   0x10   reserved              MUST be 0 в v1
 5   0x20   reserved              MUST be 0 в v1
 6   0x40   reserved              MUST be 0 в v1
 7   0x80   reserved              MUST be 0 в v1
```

Reserved биты на inbound — frame проходит парсер (биты маскируются), но
deframer записывает counter `gnet.dropped.reserved_bit` для observability.
Forward-compatibility: v1.1 расширения садятся в reserved биты без bump
версии.

### Три encoding-режима

GNET оптимизирует overhead под общий случай direct-mesh, но поддерживает
relay и broadcast как первоклассные режимы:

| Mode | Flags | Header overhead | Use case |
|---|---|---|---|
| Direct | `0x00` | **14 B** | прямой Noise-туннель; sender/receiver приходят из `ConnectionContext` |
| Broadcast | `0x05` (`SENDER \| BROADCAST`) | **46 B** | gossip, heartbeat, neighbour-discovery; receiver implicit ZERO |
| Relay-transit | `0x03` (`SENDER \| RECEIVER`) | **78 B** | relay-extension forwarding; identity preserved end-to-end |

Прямой режим — преобладающий: после Noise handshake обе стороны знают PK
друг друга, на проводе они избыточны. Кодировщик flags=0x00 экономит 64
байта на frame.

---

## Семантика длины

`length` (uint32 BE на offset 10) — total frame size **включая** fixed
header и любые conditional PK поля. Payload byte count вычисляется как:

```
header_size  = 14 + 32 * popcount(flags & 0x03)
payload_size = length - header_size
```

Корректность:

- `length < header_size` → `GN_ERR_DEFRAME_CORRUPT`
- `length > kMaxFrameBytes` (default 65536) → `GN_ERR_FRAME_TOO_LARGE`
  и counter `drop.frame_too_large` ([metrics.md](../contracts/metrics.en.md)
  §3)

Mismatch первой категории — потенциально hostile peer (overflow probe);
второй — заведомо враждебный или мисконфигурированный peer. Operator
различает их по counter'у без strace.

---

## Sender pk

32 байта Ed25519 raw public key. **Конечный** identifier originator'а:
relay-узлы не переписывают `sender_pk` при transit'е — это и есть
end-to-end identity guarantee mesh-framing'а
([protocol-layer.md](../contracts/protocol-layer.en.md) §5).

Источник на inbound зависит от encoding-режима:

| Mode | Источник |
|---|---|
| Direct | `gn_ctx_remote_pk(ctx)` — из Noise handshake |
| Broadcast | wire (`EXPLICIT_SENDER` обязателен) |
| Relay-transit | wire — preserved сквозь hops |

Spoofing предотвращён двумя гейтами:
1. Direct-mode envelope не несёт `sender_pk` на проводе вообще; deframer
   выставляет его из session-bound `ctx.remote_pk`.
2. `EXPLICIT_SENDER` без `gn_ctx_allows_relay(ctx) == true` отклоняется
   с `GN_ERR_INTEGRITY_FAILED` — peer без relay-capability не может
   подделать произвольный `sender_pk`.

`sender_pk == ZERO` — невалидное значение; kernel отклоняет на ingress
с counter `metrics.dropped.zero_sender`.

---

## Receiver pk

32 байта Ed25519 raw. **Прямая адресация** на mesh-уровне.

Все нули (`ZERO`) — broadcast marker. Kernel при дисклавиатуре smотрит
`gn_pk_is_zero(envelope.receiver_pk)`; на true разворачивает envelope в
fan-out по всем зарегистрированным handler'ам с матчинговым `msg_id`,
независимо от `local_identities` множества. Broadcast scope (gossip TTL,
neighbour-only, flood) — per-protocol policy внутри плагина, kernel её
не определяет.

Source на inbound:

| Mode | Источник |
|---|---|
| Direct | `gn_ctx_local_pk(ctx)` — local node identity |
| Broadcast | implicit ZERO (`EXPLICIT_RECEIVER` запрещён) |
| Relay-transit | wire — final destination после forwarding hop'ов |

`EXPLICIT_RECEIVER` без relay-capability отклоняется по тому же flag —
peer не должен иметь возможность редиректить dispatch на identity, которой
он не владеет.

---

## msg_id

uint32 BE — per-protocol routing key. Handler регистрируется на пару
`(protocol_id, msg_id)`; одинаковый `msg_id` под разными протоколами —
независимые namespace'ы.

### Reserved msg_id ranges

| Range | Назначение |
|---|---|
| `0x00000000` | invalid sentinel; envelope с `msg_id == 0` отклоняется как `GN_ERR_INVALID_ENVELOPE` |
| `0x00000001 – 0x000000FF` | kernel-canon msg_id (см. ниже) |
| `0x00000100 – 0x0000FFFF` | core-плагины (heartbeat, discovery) |
| `0x00010000 – 0x7FFFFFFF` | application-defined |
| `0x80000000 – 0xFFFFFFFF` | experimental, **не** к release-stability |

### Kernel-canon allocation

| msg_id | Owner | Payload |
|---|---|---|
| `0x10` | heartbeat (pre-attestation) | `HeartbeatSchema` per `protocol-layer.md` §3.2 |
| `0x11` | attestation dispatcher | 232 байта signed payload, см. [attestation-bytes](attestation-bytes.ru.md) |
| `0x12` | capability TLV blob | TLV records, см. [capability-tlv.md](../contracts/capability-tlv.en.md) |

Регистрация handler'а на любой kernel-canon `msg_id` (через
`register_vtable(GN_REGISTER_HANDLER)`) отклоняется с
`GN_ERR_INVALID_ENVELOPE`
([handler-registration.md](../contracts/handler-registration.en.md) §2a).

---

## Payload

Opaque application bytes. Граница:

```
payload_max = max_payload_bytes - 14 - 64
            = max_payload_bytes - 78          # worst case: relay-transit mode
```

Default `max_payload_bytes = 65458` ⇒ ~64 KiB payload.

`payload` указатель внутри `gn_message_t` — **borrowed** на время
синхронного `handle_message` вызова; handler, которому байты нужны после
return, обязан скопировать их в свой буфер до yield
([protocol-layer.md](../contracts/protocol-layer.en.md) §2.2).

Plugin handler dispatch — по `msg_id`. Payload format — вотчина handler'а,
GNET его не парсит.

---

## Coalescing

TCP delivers stream — несколько GNET-кадров могут прийти в одном
`recv()`. SecuritySession внутри kernel slice'ит inbound bytes по
2-байтному Noise длине-префиксу до того, как plaintext попадает в
deframe; но и после расшифровки один plaintext-чанк может содержать
несколько GNET-кадров (rare, но допустимо).

`gn_protocol_layer_vtable_t::deframe` обрабатывает это через
`gn_deframe_result_t`:

```c
typedef struct gn_deframe_result_s {
    uint32_t            api_size;
    const gn_message_t* messages;        /* zero or more envelopes */
    size_t              count;
    size_t              bytes_consumed;  /* wire bytes the kernel discards */
    void*               _reserved[4];
} gn_deframe_result_t;
```

Plugin deframe'ит сколько может за один call, возвращает массив envelope'ов
с разделёнными payload-указателями (borrow'ит из inbound buffer'а), и
говорит kernel'у через `bytes_consumed`, сколько байт можно сбросить.
Partial frame в хвосте → `bytes_consumed < bytes_size`, kernel буферит
остаток до следующего chunk'а.

Partial header (< 14 байт) → `GN_ERR_DEFRAME_INCOMPLETE`, kernel ждёт.
Это не ошибка — это нормальный flow streaming-парсера.

---

## Backpressure

`host_api->send` возвращает `gn_backpressure_t`:

| Value | Meaning | Recommended response |
|---|---|---|
| `GN_BP_OK` | принято, queue ниже soft watermark | продолжать |
| `GN_BP_SOFT_LIMIT` | queue ≥ `pending_queue_bytes_soft` | sender замедляется |
| `GN_BP_HARD_LIMIT` | dropped, queue ≥ `pending_queue_bytes_hard` | back off, **не** retry tight |
| `GN_BP_DISCONNECT` | connection ушла | прекратить отправку |

Tight-loop на `HARD_LIMIT` — contract violation
([types.h](../../sdk/types.h) — `gn_backpressure_e` Doxygen).

Cross-link: [backpressure.md](../contracts/backpressure.en.md) формализует
queue thresholds и SecuritySession partial-frame буферный бюджет.

---

## Контраст с raw protocol

`plugins/protocols/raw/` (статический build-time выбор) — alternative
protocol layer для bridges/debugging. Wire format raw'а — голые
plaintext-байты, без magic, без header'а, без identity полей. Mapping
`gn_message_t` ↔ wire-байты:

| Поле envelope'а | Откуда у raw |
|---|---|
| `sender_pk` | `gn_ctx_remote_pk(ctx)` |
| `receiver_pk` | `gn_ctx_local_pk(ctx)` |
| `msg_id` | фиксированный синтетический id (зависит от deployment) |
| `payload` | **все** байты, что приехали в `bytes` |

raw `allowed_trust_mask` = `Loopback | IntraNode`; kernel отказывает
конструкцию стека на любом другом trust class'е до первого байта.

raw применим строго где mesh-framing избыточен: in-process pipe между
kernel'ом и bridge-плагином, simulator harness который инжектирует
известный wire поток, PCAP replay в тесте. На production публичном
listener'е raw не работает — kernel не админит транспорт без identity.

---

## Cross-refs

- [protocol-layer.md](../contracts/protocol-layer.en.md) — kernel-side
  envelope semantics (`gn_message_t` lifetime, identity sourcing)
- [routing](../architecture/routing.ru.md) — что kernel делает между
  `deframe` и handler dispatch
- [wire-protocol](../architecture/wire-protocol.ru.md) — почему
  mesh-framing мандаторен
- [limits.md](../contracts/limits.en.md) §2 — `max_frame_bytes`,
  `max_payload_bytes`
- [handler-registration.md](../contracts/handler-registration.en.md) §2a —
  reserved msg_id ranges, kernel-canon allocation
- [capability-tlv.md](../contracts/capability-tlv.en.md) — TLV-blob,
  едущий по `msg_id == 0x12`
- [noise-handshake](noise-handshake.ru.md) — security-слой, который
  обнимает GNET frame с обеих сторон
- [attestation-bytes](attestation-bytes.ru.md) — payload `msg_id == 0x11`
