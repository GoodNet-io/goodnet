# Диагностика

Документ описывает runtime-проблемы, с которыми сталкивается operator
запущенного узла GoodNet, и алгоритм их разбора. Все сообщения об
ошибках в журнале и любые коды возврата C ABI ссылаются на
`gn_result_t` из `sdk/types.h` — таблица §1 переводит каждое
значение в operator-понятный смысл.

## Содержание

- [Error codes — общая таблица](#error-codes--общая-таблица)
- [Plugin loading проблемы](#plugin-loading-проблемы)
- [Connection issues](#connection-issues)
- [Identity / config issues](#identity--config-issues)
- [Performance regression](#performance-regression)
- [Где смотреть](#где-смотреть)
- [Common scenarios](#common-scenarios)
- [Cross-references](#cross-references)

---

## Error codes — общая таблица

Каждый запрос к ядру через `host_api_t` или к CLI возвращает
`gn_result_t`. Ноль — успех; отрицательные значения — отказ. Operator
видит код в журнале и в счётчиках `metrics.host_api.<entry>.errors`
по [host-api](../contracts/host-api.en.md) §5.

| Код | Значение | Что делать |
|---|---|---|
| `GN_OK` (0) | success | действий не требуется |
| `GN_ERR_NULL_ARG` (-1) | передан NULL там, где обязателен указатель, либо unbound slot host_api | проверить совместимость SDK плагина и ядра |
| `GN_ERR_OUT_OF_MEMORY` (-2) | allocation fail | проверить RSS процесса, лимиты cgroup |
| `GN_ERR_INVALID_ENVELOPE` (-3) | wire-format violation: zero `sender_pk`, `msg_id == 0`, или ненулевой `_reserved`; также type-mismatch в `config_get` | подозрение на повреждённый плагин или drift конфигурации |
| `GN_ERR_UNKNOWN_RECEIVER` (-4) | роутер не нашёл локальную identity для `receiver_pk`, relay не загружен | route-only код; внешний caller видит `GN_ERR_NOT_FOUND` |
| `GN_ERR_PAYLOAD_TOO_LARGE` (-5) | payload превышает `gn_limits_t::max_payload_bytes` | поднять лимит или починить отправителя |
| `GN_ERR_DEFRAME_INCOMPLETE` (-6) | partial frame — буфер хранится, ядро ждёт остатка | штатно при медленной сети; alarm только при росте `pending_handshake_bytes` |
| `GN_ERR_DEFRAME_CORRUPT` (-7) | magic mismatch / bad version / overflow | hostile peer или несовместимый протокол; проверить версию плагина протокола |
| `GN_ERR_NOT_IMPLEMENTED` (-8) | slot зарезервирован, расширение не подняло L2 composer | загрузить нужный плагин или обновить ядро |
| `GN_ERR_VERSION_MISMATCH` (-9) | major plugin SDK не совпадает с ядром, либо identity-file unsupported version | пересобрать плагин против актуального SDK |
| `GN_ERR_LIMIT_REACHED` (-10) | cap из `gn_limits_t` исчерпан | поднять лимит в `node.json` или разгрузить узел |
| `GN_ERR_INVALID_STATE` (-11) | вызов в неподходящей фазе FSM (handshake-only op в transport-сессии, `set_timer` после shutdown) | bug плагина; собрать journal-выписку и завести issue |
| `GN_ERR_INTEGRITY_FAILED` (-12) | manifest hash mismatch, tampered binary, manifest absent в strict mode, испорченный identity-file | re-run `goodnet manifest gen` или `goodnet identity gen`; рассмотреть compromise host'а |
| `GN_ERR_INTERNAL` (-13) | ядро поймало exception на C ABI границе | bug плагина; перезагрузить плагин, собрать backtrace |
| `GN_ERR_NOT_FOUND` (-14) | lookup miss: config key, handler-id, link session, inject-target conn | typo в конфиге или несовпадение состояний; см. §3 |
| `GN_ERR_OUT_OF_RANGE` (-15) | значение вне допустимого диапазона: array index, config integer выше cap'а из `limits.md` | поправить конфиг |
| `GN_ERR_FRAME_TOO_LARGE` (-16) | wire-frame превышает `kMaxFrameBytes`; счётчик `drop.frame_too_large` | hostile peer signal |

`gn_strerror(rc)` в `sdk/types.h` отдаёт стабильную строку для
каждого кода — оператор видит её в каждой строке журнала ядра.

---

## Plugin loading проблемы

PluginManager делает четыре прохода: discover → dlopen → init →
register. Любая ошибка приводит к полному rollback'у — узел не
стартует с частично загруженным набором.

### `GN_ERR_INTEGRITY_FAILED` при load

Журнал содержит одну из подстрок:

- `plugin integrity check failed: no manifest entry for path: <path>` —
  путь не перечислен в `/etc/goodnet/plugins.json`. Re-run
  `goodnet manifest gen /usr/lib/goodnet/lib*.so > /tmp/plugins.json`
  после установки нового `.so` и переустановить файл, см.
  [install.en.md](../install.en.md) §3.3.
- `plugin integrity check failed: <path>: digest mismatch` — SHA-256
  на диске не совпадает с записью манифеста. Версия `.so` обновилась
  без regen'а манифеста, либо бинарник подменили. Сначала regen,
  потом — если совпадения нет — расследовать как possible compromise.
- `plugin integrity check failed: manifest required but empty` —
  ядро запущено в strict-mode (`set_manifest_required(true)`) с пустым
  манифестом. Либо положить манифест, либо выключить strict-mode
  для dev-build.

Счётчик `plugin.leak.dlclose_skipped` инкрементится, когда rollback
не дождался quiescence — async callbacks плагина не вернулись в
отведённый таймаут. Это не fatal, но диагностический сигнал: либо
плагин игнорирует `is_shutdown_requested`, либо у него «зависшие»
рабочие потоки.

### `dlopen failed: cannot open shared object`

Возвращается код `GN_ERR_NOT_FOUND`. Журнал содержит вывод
`dlerror()`. Типичные причины:

- путь в манифесте неверный — переустановить плагин;
- runtime dependency отсутствует — `ldd /usr/lib/goodnet/<plugin>.so`
  покажет недостающую `lib*.so`;
- плагин собран против другой `glibc` / `libsodium` ABI — пересобрать
  через `nix run .#build`.

### SDK version mismatch

Журнал: `sdk-version mismatch in <path>`. Код возврата
`GN_ERR_VERSION_MISMATCH`. Плагин экспортирует `gn_plugin_sdk_version`,
несовместимое с `GN_SDK_VERSION_MAJOR` ядра. Major bump = ABI break:
плагин надо пересобрать против актуального SDK перед deploy.

Если плагин не экспортирует один из обязательных символов
(`gn_plugin_init`, `gn_plugin_register`, `gn_plugin_unregister`,
`gn_plugin_shutdown`, `gn_plugin_sdk_version`) — журнал содержит
`missing required gn_plugin_* entry symbol` и тот же код. Это
чаще всего сборка против обрезанного SDK или поломанный заголовок;
полная пересборка решает.

### `gn_plugin_init` returned `GN_OK` но self == NULL

Журнал: `plugin '<name>' returned GN_OK from gn_plugin_init but did
not set *self_out`. Soft warning — для stateless плагинов (`raw`
протокол, `null` security) это валидно; для stateful плагина это
bug автора, проявится падением на первом vtable-вызове. Поднимать
issue в репозитории плагина.

---

## Connection issues

### Connection refused

Клиент-сторона видит TCP RST или EOF на `connect`. Серверная
сторона: проверить, что нужный link-плагин загружен. Без
`libgoodnet_link_tcp.so` (или `link_ws`, `link_ipc`, `link_tls`)
ядро не открывает listening socket. Команда:

```
sudo systemctl status goodnet
journalctl -u goodnet --since=boot | grep "register_vtable.*kind=LINK"
```

Отсутствие записи означает, что плагин не зарегистрирован — см. §2.

Если плагин загружен, но connection всё равно refused: проверить,
что URI в `peers.json` совпадает по схеме (TCP-URI к UDP-listener'у
не подключится), и что firewall пропускает порт.

### Trust upgrade timed out

`gssh bridge: trust upgrade timed out (15s)` (apps/gssh, см.
[gssh](./gssh.ru.md)) — peer не доступен или identity не известна
обеим сторонам. Алгоритм:

- проверить, что security-плагин загружен на обоих узлах
  (`libgoodnet_security_noise.so`); без него класс `Trusted` не
  достижим;
- сверить identity peer'а: `goodnet identity show /etc/goodnet/identity.bin`
  на обеих сторонах — `address` должен совпадать с записью в
  `peers.json`;
- наличие listening socket на удалённой стороне — см. предыдущий
  пункт.

### Backpressure

`notify_backpressure` событие с kind=`BACKPRESSURE_SOFT` означает,
что send-queue connection'а перешла high-watermark. Плагин-отправитель
должен снизить темп; наличие события в журнале — не error, а ожидаемый
сигнал. Если события идут потоком и не сменяются `BACKPRESSURE_CLEAR`:

- увеличить `gn_limits_t::pending_queue_bytes_high` /
  `pending_queue_bytes_hard` в `node.json`, см.
  [limits](../contracts/limits.en.md) §2;
- проверить throughput канала на удалённой стороне (drain rate);
- счётчик `drop.queue_hard_cap` растёт когда per-conn queue
  достигает hard-cap'а — далее connection отключается.

---

## Identity / config issues

### `load_from_file: signature mismatch`

Код возврата `GN_ERR_INTEGRITY_FAILED`. Identity-file повреждён
либо несоответствует своему magic-prefix. Журнал содержит одну из:

- `file size != 77 bytes` — обрезанный файл; восстановить из
  бэкапа или regen через `goodnet identity gen --out
  /etc/goodnet/identity.bin`;
- `magic prefix mismatch` — файл не GoodNet-identity (v1 layout);
- `unsupported identity-file version` — формат от другой major
  версии ядра; пересобрать identity актуальным CLI;
- `attestation signature mismatch` — seed-байты не reconstruct'ят
  валидную подпись; файл повреждён, regen.

Regen меняет адрес узла на mesh; обновить `peers.json` у каждого
peer'а (см. [identity](../contracts/identity.en.md) §3).

### `expiry=0` в identity

Sentinel «без срока истечения» — verify-путь пропускает проверку
дедлайна для `expiry == 0` (per [identity](../contracts/identity.en.md)
§4). `goodnet identity gen` без явного `--expiry` создаёт файл с
`expiry=0` и его нормально загружают и старая, и новая версия
ядра. Если на `expiry=0`-файле всё равно появляется
`signature mismatch` — значит повреждены seed-байты, а не sentinel:
лечится `goodnet identity gen --out /etc/goodnet/identity.bin`.

### Config reload не отрабатывает

Hot-reload `node.json` v1.x. Если редактирование файла + `systemctl
reload goodnet` не подхватилось:

- счётчик `config_reload.fail` растёт после неудачного парса;
- проверить JSON-синтаксис: `goodnet config validate
  /etc/goodnet/node.json` — отдаёт `GN_ERR_INVALID_CONFIG` с
  именем поля при cross-field validation failure (limits.md §3);
- большинство `limits.*` менять hot нельзя — они определяют
  at-startup allocations; нужен `systemctl restart goodnet`.

---

## Performance regression

### `route.outcome.no_handler` rising

Счётчик `route.outcome.dropped_no_handler` растёт, если handler был
unregister'ен раньше, чем ожидаемо. Plugin lifecycle issue:

- проверить, что плагин-handler не выгрузился через rollback —
  одновременно вырастает `plugin.leak.dlclose_skipped`;
- проверить, что приоритет регистрации не перебит вторым плагином
  (см. [handler-registration](../contracts/handler-registration.en.md)).

### `metrics.cardinality_rejected` growing

Счётчик растёт, когда `emit_counter` пытается создать новое имя
поверх `gn_limits_t::max_counter_names` (default 8192). Один из
плагинов кодирует динамические данные (peer-id, msg-id) в имя
счётчика. Решение: либо плагин-fix (пакетировать имена через
плоский префикс), либо поднять `max_counter_names` в `node.json`,
если total не угрожает потреблению памяти.

### Connection throughput drop

Падение пропускной способности обычно — backpressure. Цепочка проверки:

- counter `notify_backpressure` events на per-conn level — рост
  свидетельствует о медленной drain rate;
- compare `bytes_buffered` на per-conn metrics surface (см.
  [registry](../contracts/registry.en.md) §8) против
  `pending_queue_bytes_high` из загруженных limits;
- если `bytes_buffered` колеблется вокруг high-watermark и не уходит
  ниже — bottleneck на удалённой стороне или в локальном link-плагине.

CryptoPath не имеет своих counter'ов в v1 — кернел-side
encrypt/decrypt latency наблюдается через `perf record` /
дашборд-side. Per-conn счётчиков bytes-encrypted / bytes-
decrypted v1 не выставляет.

---

## Где смотреть

| Инструмент | Команда | Что показывает |
|---|---|---|
| systemd | `systemctl status goodnet` | состояние юнита, последние строки журнала |
| journal | `journalctl -u goodnet -f` | live-tail логов ядра и всех плагинов |
| journal | `journalctl -u goodnet --since="1 hour ago"` | recent records |
| journal | `journalctl -u goodnet --since=boot \| grep ERROR` | error-level записи с момента старта |
| metrics | exporter scrape (см. exporter-плагин) | snapshot всех counter'ов через `iterate_counters` |
| CLI | `goodnet config validate /etc/goodnet/node.json` | offline-валидация конфигурации |
| CLI | `goodnet identity show /etc/goodnet/identity.bin` | address, user_pk, device_pk, expiry — без секретов |
| CLI | `goodnet manifest gen /usr/lib/goodnet/lib*.so` | regen plugin manifest |
| CLI | `ldd /usr/lib/goodnet/<plugin>.so` | проверить runtime deps |

Каждый плагин эмитит логи под собственным namespace prefix через
`gn_log_api_t::emit`. Имя плагина прибавляется ядром, поэтому
journal-grep на `<plugin-name>` отфильтровывает строки нужного
плагина без правки кода.

---

## Common scenarios

**После upgrade плагина kernel не стартует.** Журнал содержит
`integrity check failed: <path>: digest mismatch`. Решение:
re-run `sudo goodnet manifest gen /usr/lib/goodnet/lib*.so >
/tmp/plugins.json` и переустановить файл, см.
[install.en.md](../install.en.md) §3.3.

**SSH через gssh теряет connection после нескольких минут.**
Heartbeat extension (`gn.heartbeat`) должен быть зарегистрирован
на обоих узлах. Команда:
`journalctl -u goodnet --since=boot | grep heartbeat` на обеих
сторонах. Если плагин загружен только на одной стороне, RTT-зонды
не доходят и одна из сторон закрывает conn по своему inactivity-таймеру.

**Memory growth.** Проверить три cap'а:

- `gn_limits_t::max_handlers_per_msg_id` — слишком длинная chain
  держит много per-handler state;
- `gn_limits_t::max_counter_names` — рост уникальных counter
  имён без cap'а; см. предыдущую секцию;
- `gn_limits_t::max_connections` и per-conn `pending_queue_bytes_*` —
  суммарно ограничивают объём буферов на лету.

Если RSS растёт без correlation с этими cap'ами — leak в плагине
или ядре, прицепить ASan-build (`nix run .#test -- asan`) и
завести issue с reproducer'ом.

---

## Cross-references

- [host-api](../contracts/host-api.en.md) — § «Error semantics», `gn_result_t` propagation
- [limits](../contracts/limits.en.md) — `gn_limits_t` и cross-field validation
- [identity](../contracts/identity.en.md) — формат identity-file, derive адреса
- [metrics](../contracts/metrics.en.md) — naming conventions, cardinality cap
- [plugin-manifest](../contracts/plugin-manifest.en.md) — SHA-256 верификация
- [plugin-lifetime](../contracts/plugin-lifetime.en.md) — quiescence, leaked handles
- [backpressure](../contracts/backpressure.en.md) — watermark policy
- [config](../contracts/config.en.md) — `node.json` schema
- [deployment](./deployment.en.md) — install / systemd hardening
- [gssh](./gssh.ru.md) — SSH bridge runtime
- [install.en.md](../install.en.md) — manifest gen, identity gen, daemon операции
