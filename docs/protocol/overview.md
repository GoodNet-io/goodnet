# Wire Layer Overview

Слой байтов между транспортной парой сокетов и kernel-side диспетчером. Что
GoodNet кладёт на провод, в какой последовательности слоёв, и где границы
ответственности между transport, security session, и mesh-framing плагином.

## Содержание

- [Один обязательный слой](#один-обязательный-слой)
- [Один опциональный режим](#один-опциональный-режим)
- [Слойный байтовый стек](#слойный-байтовый-стек)
- [Endianness](#endianness)
- [Размеры](#размеры)
- [Что читать дальше](#что-читать-дальше)

---

## Один обязательный слой

Mesh-framing — единственный обязательный плагин-слот. Kernel binary
статически линкует ровно одну реализацию `IProtocolLayer` через
`target_link_libraries(kernel PUBLIC <impl>)`; `plugins/protocols/gnet/` —
канонический выбор для v1.x.

Без mesh-framing kernel не умеет маршрутизировать по 32-байтному mesh
адресу: deframe возвращает `gn_message_t` с парой `(receiver_pk, msg_id)`,
по которой работает дисклавиатура handler'ов. Рантайм-выбор второй
реализации не поддерживается — одна нода = один формат рамки на проводе.

Cross-link: [protocol-layer.md](../contracts/protocol-layer.md) §4
формализует правило mandatory single-implementation;
[wire-protocol](../architecture/wire-protocol.md) описывает архитектурные
последствия.

---

## Один опциональный режим

`plugins/protocols/raw/` — альтернативный статический плагин, собирается
вместо gnet через `-DGOODNET_MESH_LAYER=raw-v1`. raw deframer'ит только
на `GN_TRUST_LOOPBACK` / `GN_TRUST_INTRA_NODE` через
`allowed_trust_mask`; на публичных линках kernel отклоняет конструкцию
стека до того, как первый байт приедет.

Применение raw — симуляторные harness'ы, PCAP-replay, foreign-protocol
passthrough на in-process IPC. На production-листенере raw непригоден:
он не несёт sender/receiver на проводе, и kernel не сможет запруфить
identity inbound envelope'а.

Cross-link: [protocol-layer.md](../contracts/protocol-layer.md) §4
описывает trust-class маски обоих плагинов.

---

## Слойный байтовый стек

Снизу вверх, как байт идёт от сокета до handler'а:

```
+------------------------------------------------+
| application payload (handler-defined bytes)    |  ← gn_message_t.payload
+------------------------------------------------+
| GNET frame (14B header + opt 32B + opt 32B)    |  ← protocol layer
+------------------------------------------------+
| Noise transport frame (2B BE len + AEAD blob)  |  ← security session
+------------------------------------------------+
| link bytes (TCP / WS / IPC / TLS stream)       |  ← link plugin
+------------------------------------------------+
```

Граница ответственности на каждом стыке:

| Стык | Кто пишет | Кто читает |
|---|---|---|
| link → security | link plugin вызывает `notify_inbound_bytes` | kernel-side `SecuritySession::on_inbound_bytes` |
| security → protocol | session слайсит по 2-байтному префиксу, AEAD-decrypt'ит, отдаёт plaintext | `IProtocolLayer::deframe` |
| protocol → handler | deframe возвращает `gn_deframe_result_t` | dispatcher по `(receiver_pk, msg_id)` |

Транспорт никогда не парсит security-префикс; security-сессия никогда не
парсит GNET-magic; handler никогда не видит wire-байты mesh-framing'а
([protocol-layer.md](../contracts/protocol-layer.md) §6).

---

## Endianness

Все многобайтные поля — network big-endian. Касается:

- 4-байтного `length` поля в GNET fixed header
- 4-байтного `msg_id` поля в GNET fixed header
- 2-байтного префикса длины Noise transport frame
- 2-байтных `type` / `length` полей TLV-записи capability-blob
- 8-байтных `valid_from` / `valid_until` полей в attestation cert

Раскодирование — через `gn::util::read_be<T>` в kernel; кодирование —
через `gn::util::write_be<T>`. SDK не экспортирует эти helper'ы для
плагинов: каждый плагин пишет свой byte-IO, чтобы зависимость на kernel
internals не утекала через ABI.

---

## Размеры

`gn_limits_t::max_frame_bytes` — потолок на одну wire frame после AEAD
расшифровки. Default 65536; конфигурируется через kernel JSON-config до
старта.

`gn_limits_t::max_payload_bytes` — потолок на envelope payload, который
deframe возвращает handler'у. По умолчанию `max_frame_bytes - 14 - 64`
(вычитая GNET header + relay-mode оба PK), что даёт ~64 KiB полезной
нагрузки в самом тяжёлом режиме encoding'а.

Cross-link: [limits.md](../contracts/limits.md) §2 формализует таблицу
лимитов; [backpressure.md](../contracts/backpressure.md) §9 — буферный
бюджет partial-frame аккумуляции внутри SecuritySession.

Attestation payload фиксированный — 232 байта; не масштабируется с
лимитами.

---

## Что читать дальше

Каждый из трёх соседних документов раскрывает один слой стека
по-байтно:

- [gnet-frames](./gnet-frames.md) — 14-байтный fixed header GNET, три
  encoding-режима, conditional PK поля, парсер state machine.
- [noise-handshake](./noise-handshake.md) — 3-message XX exchange,
  layout каждого сообщения, transport-phase framing, rekey threshold.
- [attestation-bytes](./attestation-bytes.md) — 232-байтный signed
  payload по `msg_id == 0x11`, поля cert, binding, signature.

Контракты на C ABI:

- [protocol-layer.md](../contracts/protocol-layer.md) — kernel↔plugin
  envelope shape, vtable для `IProtocolLayer`.
- [security-trust.md](../contracts/security-trust.md) — TrustClass
  policy, mask gate, attestation upgrade.
- [attestation.md](../contracts/attestation.md) — dispatcher на стороне
  kernel, mutual-exchange flow.

Архитектурные обоснования:

- [wire-protocol](../architecture/wire-protocol.md) — почему
  mesh-framing мандаторен, почему `inject_external_message` —
  единственный путь для bridge-плагинов.
- [security-flow](../architecture/security-flow.md) — где живут
  handshake state, transport keys, attestation dispatcher.
