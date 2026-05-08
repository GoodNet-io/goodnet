---
Stability: v1.x
---

# Транспорты — как работать с link plugin'ом

Транспорт в GoodNet — это плагин с одной обязанностью: переносить
байты между двумя `gn_conn_id_t`, которые ядро ему выделило, через
конкретный URI scheme (`tcp://`, `udp://`, `ws://`, `ipc://`,
`tls://`, потом ICE / QUIC / BLE / что добавится). Всё что не
байты — handshake, framing, encryption, routing, dispatch — делает
не транспорт. Эта глава фиксирует, почему граница нарисована
именно так и какие повторяющиеся ошибки она ловит.

Контракт от ядра: [`link.md`](../../contracts/link.en.md). Этот
документ — сопровождающий гид: что транспорт обязан выдать на
своей стороне границы, как threading-модель ядра пересекает
плагиновую, и какие паттерны спасают от типичных race'ов и
silent-fail'ов.

## Содержание

- [Что такое link plugin](#что-такое-link-plugin)
- [Threading model](#threading-model)
- [Send path](#send-path)
- [Receive path](#receive-path)
- [Listen и connect](#listen-и-connect)
- [Teardown protocol](#teardown-protocol)
- [Conn-id ownership gate](#conn-id-ownership-gate)
- [Тестирование](#тестирование)
- [Регулярные грабли](#регулярные-грабли)
- [Cross-references](#cross-references)

## Что такое link plugin

Каждый транспорт регистрирует ровно одну запись в `LinkRegistry`
ядра через `host_api->register_vtable(GN_REGISTER_LINK, …)`, передав
четыре вещи:

| Поле | Что в нём |
|---|---|
| `meta->name` | scheme — `"tcp"`, `"udp"`, `"ws"`, `"ipc"`, `"tls"`. Один scheme = один plugin. |
| `vtable` | `gn_link_vtable_t*` — primary surface (см. [`sdk/link.h`](../../../sdk/link.h)). |
| `self` | per-plugin state (типично `*Link` C++ объект). |
| `lifetime_anchor` | `shared_ptr<void>` для quiescence wait per [`plugin-lifetime.md` §4](../../contracts/plugin-lifetime.en.md). |

Vtable несёт `listen`, `connect`, `send`, `send_batch`, `disconnect`,
`extension_name`, `extension_vtable`, `destroy`. Дополнительно
плагин может выставить через `extension_vtable` объект типа
[`gn_link_extension_t`](../../../sdk/extensions/link.h) — это L2-композиция,
пользовательский surface для статистик / настройки / композиции
секций (TLS over TCP, WSS over TLS, etc).

Идентичность peer'а — `remote_pk` (Ed25519 32 байта). URI и
`gn_conn_id_t` эфемерны: транспорт может закрыть `tcp://` и
плагин маршрутизации откроет `tls://` к тому же `peer_pk` —
ядро увидит это как два разных connection'а, identity-плагин
сошьёт их через свою таблицу `peer_pk → conn_id`. Транспорт не
участвует в этом процессе.

## Threading model

Каждый link plugin держит **собственный** `asio::io_context` и
worker pool под него. Ядро не предоставляет общий executor —
плагин владеет своими потоками. Канонический pattern (см.
[`plugins/links/tcp/tcp.cpp`](../../../plugins/links/tcp/tcp.cpp)):

```cpp
TcpLink::TcpLink()
    : ioc_(),
      work_(asio::make_work_guard(ioc_)) {
    const unsigned hc = std::thread::hardware_concurrency();
    const unsigned n  = std::max(1u, hc / 2);
    workers_.reserve(n);
    for (unsigned i = 0; i < n; ++i) {
        workers_.emplace_back([this] { ioc_.run(); });
    }
}
```

`hardware_concurrency()/2` — половина ядер на link's I/O. Вторая
половина остаётся для kernel-side frame/encrypt работы что бежит
на caller thread'е (см. [Send path](#send-path)) и для service
executor'а (`set_timer`). Это разделение пинит ROI на конкретных
рабочих нагрузках; operator может перевзвесить через `TasksMax=` /
config-knob под свой профиль.

Worker'ы все вызывают `ioc_.run()` на одном `io_context`. Asio
допускает это: io_context потокобезопасен на dispatch уровне.
Сериализация per-conn держится через **strand**:

| Plugin | Стрэнд | Почему |
|---|---|---|
| TCP / WS / IPC / TLS | `asio::strand` per-Session | Каждое соединение — отдельный socket, два worker'а могут параллельно гнать разные сессии. |
| UDP | один общий strand на сокет | Только один FD; recvfrom/sendto на нём не interleave'ятся. |

**Single-writer invariant** на сокете
([`link.md §4`](../../contracts/link.en.md)) держится strand'ом:
любой `async_write_some` всегда post'ится на strand сессии,
поэтому два worker'а никогда не пересекаются на одном FD.

### Что **safe**, что **не safe**

- `host_api->send` от любого app thread'а — kernel-side
  `SendQueueManager` сериализует push на per-conn ring, и драйнер
  выходит ровно одним worker'ом per CAS. Безопасно.
- `notify_inbound_bytes` — link plugin зовёт это синхронно из
  своего worker'а, ядро дальше уже обрабатывает сам.
- Внутри visitor'а `for_each_connection` вызывать другие методы
  ядра, которые re-acquire'ят shard mutex — **UB**. `std::shared_mutex`
  не рекурсивен, ядро структурно полагается на это (counters
  передаются вместе с записью; читай только то, что приходит в
  visitor'е).
- На worker thread'е делать blocking I/O / `sleep` / mutex с
  contention — останавливает drain для всех сессий sharing'их
  worker'а. Идиоматично — скопировать payload и сигнализировать
  app thread'у.

## Send path

```
host_api->send(conn, msg_id, payload, size)
  ↓
[kernel] frame envelope through protocol_layer
  ↓
[kernel] encrypt through SecuritySession (InlineCrypto fast path)
  ↓
[kernel] PerConnQueue::try_push(wire_bytes, priority = Low)
  │       ── if pending_bytes > pending_queue_bytes_hard ──▶ GN_ERR_LIMIT_REACHED
  ↓
[kernel] CAS-claim drain_scheduled
  ↓
[kernel] drain_send_queue(): batch up to drain_batch_size frames
  ↓
[link] vtable->send_batch(self, conn, batch[], count)
  │     ── if NOT_IMPLEMENTED ──▶ kernel falls back to send() per frame
  ↓
[link] writev / async_write on session strand
```

Контракт между ядром и плагином в этой цепочке:

1. **Hard-cap detect — на kernel'е, не на link'е.** Когда
   `pending_bytes` пересекает `gn_limits_t::pending_queue_bytes_hard`,
   `host_api->send` возвращает `GN_ERR_LIMIT_REACHED` ещё до
   того, как link что-либо увидит. Link's `send`/`send_batch`
   возвращают `GN_OK` всегда, когда байты приняты в свой
   socket-buffer.

2. **`send_batch` опционален.** Plugin может вернуть
   `GN_ERR_NOT_IMPLEMENTED` — ядро прозрачно fallback'нёт на
   loop через `send`. Это закрывает sending'у на тестовых
   loopback-stub'ах (см. `tests/unit/integration/test_send_loopback.cpp`)
   без обязательной writev-реализации.

3. **Soft watermark — link's сигнал, не kernel's.** Если link
   видит свою write-queue над `pending_queue_bytes_high`, он
   обязан позвать `host_api->notify_backpressure(SOFT)` (rising
   edge). Когда drain опускает её ниже `_low` — `CLEAR`
   (falling edge). Гистерезис между low/high удерживает
   осцилляции. См. [`backpressure.md §3`](../../contracts/backpressure.en.md).

4. **Control-flood — disconnect, не LIMIT_REACHED.** Peer
   inundated сторону с ping'ами, локальный сокет не успевает
   pong'нуть — link's reply path тоже считает себе
   `bytes_buffered`, и когда он переходит hard-cap, link
   обязан **разорвать соединение**, не пытаться вернуть
   `LIMIT_REACHED` peer'у через wire. Это структурное abuse
   detection per [`backpressure.md §3.1`](../../contracts/backpressure.en.md).

5. **Borrowed bytes.** `bytes` в `send(self, conn, bytes, size)`
   валидны только до возврата из этой функции. Link обязан
   скопировать (memcpy в свой write buffer) если хочет
   удержать после.

## Receive path

```
[link] async_read_some on session strand
  ↓
[link] api->notify_inbound_bytes(host_ctx, conn_id, bytes, size)
  ↓
[kernel] SecuritySession::feed_transport(): partial-frame buffer
  │       ── если кадр неполный, kernel хранит остаток до следующего notify_inbound_bytes
  ↓
[kernel] SecuritySession::decrypt_transport(ciphertext, plaintext)
  ↓
[kernel] protocol_layer->deframe(plaintext) → gn_message_t
  ↓
[kernel] router.dispatch(envelope) → handler chain
```

Что link'у важно знать:

1. **`notify_inbound_bytes` — синхронный.** Ядро на этом же
   worker thread'е выполнит decrypt + deframe + dispatch и
   вернёт. Link не получает back-pressure от ядра в этой
   точке — handler chain'у запрещено блокировать. Если
   handler нужно отложенное outbound, он делает
   `host_api->set_timer(0, …)` на service executor.

2. **Partial frames — забота `SecuritySession`, не link'а.**
   TCP/WS/IPC/TLS прокидывают любые осколки сколько socket
   readiness отдаёт. `SecuritySession` буферит до полного
   кадра по 2-байтному length-prefix per
   [`security-noise/handshake.md §7`](../../../plugins/security/noise/docs/handshake.md).
   Cap буфера — `2 * gn_limits_t::max_frame_bytes +
   kFramePrefixBytes`. Превышение — `GN_ERR_LIMIT_REACHED`,
   ядро публикует disconnect.

3. **Failure threshold.** Если `notify_inbound_bytes` возвращает
   non-OK (`GN_ERR_INVALID_ENVELOPE` от deframe / decrypt failure),
   link обязан считать failures per-conn и при threshold
   (рекомендация: 16) разорвать соединение через
   `host_api->notify_disconnect`. Иначе peer'у даётся бесконечно
   много попыток подобрать AEAD nonce.

4. **`return GN_OK` от link'а** означает «байты переданы ядру»,
   не «handler отработал». Application-уровень получает
   результат через handler chain'a, не через return code link's
   `notify_inbound_bytes`.

## Listen и connect

Один scheme — два surface'а на link'е, и они **разные**:

### Primary vtable

`vtable->listen(self, uri)` и `vtable->connect(self, uri)` — это
**актуальный** path, который kernel'side composer'ы и applications
используют. Доступен через:

```cpp
auto link = kernel.links().find_by_scheme(scheme);
if (!link || !link->vtable->listen) return GN_ERR_NOT_IMPLEMENTED;
return link->vtable->listen(link->self, uri);
```

### Link extension API (`gn.link.<scheme>`)

Если link выставляет extension через
`vtable->extension_vtable()`, его можно достать через
`host_api->query_extension_checked("gn.link.tcp", ABI_VER, &api)`.
Extension API имеет **те же** поля `listen` / `connect` / `send`
по дизайну ([`sdk/extensions/link.h`](../../../sdk/extensions/link.h)),
но они **возвращают `GN_ERR_NOT_IMPLEMENTED`** — extension
существует только для **L2-композиторов** (типа TLS-over-TCP,
WSS-over-TLS), где композитор сам реализует listen/connect, а
link primary vtable играет вспомогательную роль.

**Регулярный bug:** application или binding достаёт extension
API и зовёт его `listen` — silently получает NOT_IMPLEMENTED, и
никакого binding'а к порту не происходит. Лекарство — звать
`kernel.links().find_by_scheme(scheme)->vtable->listen()`, не
extension's listen. См. реальный fix в `apps/gssh/mode_listen.cpp`.

## Teardown protocol

Подробности — в [`concurrency.ru.md`](./concurrency.ru.md). Краткий
повтор:

- `shutdown_` — atomic bool, ставится **под `sessions_mu_`**
  через `exchange(true)`.
- `published_ids_` — append-only список id'ов прошедших через
  `notify_connect`. Только `shutdown()` его очищает.
- `claim_disconnect(id)` — runtime helper для worker callback'ов:
  под `sessions_mu_` проверяет `shutdown_`, удаляет id из
  `sessions_` и возвращает true только если caller получил
  ownership emit'а.
- `shutdown()` берёт `sessions_mu_`, ставит флаг, забирает
  `published_ids_`, выходит из mutex'а, эмитит
  `notify_disconnect` для каждого id на caller thread'е.

UDP — исключение: нет per-session strand'а, нет per-session
объекта; teardown эмитит `notify_disconnect` для каждого peer'а
из in-memory peer-map'а в `shutdown()`. Паттерн `claim_disconnect`
не применим.

## Conn-id ownership gate

`gn_conn_id_t` — kernel-issued, monotonic, никогда не reused.
Plugin `A` зарегистрировал scheme `tcp` и получил для одного
peer'а `conn_id = 42`. Если plugin `B` попытается позвать
`host_api->notify_inbound_bytes(host_ctx, 42, …)`, ядро
возвращает `GN_ERR_NOT_FOUND` per
[`security-trust.md §6a`](../../contracts/security-trust.en.md) — не
`GN_ERR_PERMISSION_DENIED`, потому что error code равен тому, что
получил бы plugin `B` для несуществующего id. Сам факт
существования чужого conn id не leak'ится через error code.

Тот же gate применяется к `notify_disconnect`,
`notify_link_event`, `notify_backpressure`, `kick_handshake`.
Плагин уважает собственный scheme — кусок
`pc->kernel->links().find_by_scheme(rec->scheme)->lifetime_anchor`
сравнивается с `pc->plugin_anchor` через `weak_ptr` ownership
chain.

## Тестирование

Плагин живёт в собственном git'е c flake'ом. Полный test cycle:

```sh
nix run .#test            # vanilla — 7-13 unit тестов
nix run .#test -- asan    # AddressSanitizer
nix run .#test -- tsan    # ThreadSanitizer
nix run .#test -- all     # все три варианта по очереди
```

### Conformance suite

SDK выставляет typed-test template
[`sdk/test/conformance/link_teardown.hpp`](../../../sdk/test/conformance/link_teardown.hpp).
Каждый link plugin INSTANTIATE'ит его под свой type:

```cpp
INSTANTIATE_TYPED_TEST_SUITE_P(
    TcpLink, LinkTeardownConformance,
    ::testing::Types<gn::link::tcp::TcpLink>);
```

Результат: `LinkTeardownConformance.ShutdownReleasesEverySession`
гонит teardown под TSan'ом, проверяя единственность emit'а на
caller thread (см. [`concurrency.ru.md`](./concurrency.ru.md)).
Если этот тест падает в plugin's own gate, никакая другая
проверка не имеет значения — link нарушает базовый contract
[`link.md §9`](../../contracts/link.en.md).

### Kernel-level integration

Kernel git'а под `tests/integration/` держит cross-plugin тесты —
NoiseTcpE2E (handshake + transport phase + frame coalescing),
PluginTeardown (multiplugin shutdown ordering). Эти тесты гонятся
вместе с kernel'a unit suite и ловят интеграционные регрессии,
которые plugin standalone tests увидеть не могут.

## Регулярные грабли

Список того, что чаще всего ломалось при имплементации
плагинов и в integration'ах с приложениями:

1. **`send_batch` returns NOT_IMPLEMENTED.** Loopback test stub'ы
   так делают, kernel должен fallback'нуть на scalar `send`.
   Проверяется в `SendLoopback.RoundTripThroughHostApi`. Если
   fallback не работает — bytes silently дропаются.

2. **Listen через extension API, не primary vtable.** Симптом —
   `listen` возвращает `GN_OK` (или silent NOT_IMPLEMENTED), но
   сокет не bind'ится. Лекарство — kernel-side
   `find_by_scheme(scheme)->vtable->listen()`, не
   `query_extension_checked("gn.link.<scheme>")->listen()`.

3. **TRUST_UPGRADED не fires на loopback.** Это event между
   `Untrusted → Peer` через attestation; loopback заходит c
   `trust = LOOPBACK` сразу на CONNECTED, attestation не идёт,
   `TRUST_UPGRADED` никогда. Bridge'ы / прокси, ждавшие именно
   этот event, висят. Лекарство — unblock на CONNECTED если
   `trust != UNTRUSTED`.

4. **expiry=0 sentinel в attestation cert.** `goodnet identity gen`
   без `--expiry` ставит 0 = «no expiry». Naive verify path
   проверяет `expiry_unix_ts <= now_unix_ts` — true когда оба
   ноль — fail'ит как «attestation signature mismatch» (хотя
   это actually time check). Лекарство — `if (expiry_unix_ts !=
   0 && expiry_unix_ts <= now) return false;` per
   `core/identity/attestation.cpp`.

5. **`shared_mutex` recursion в `for_each` visitor.** Visitor
   получает `const ConnectionRecord&`; если он зовёт
   `find_by_id` или `read_counters`, тот пытается re-acquire
   shard mutex как shared_lock — std::shared_mutex не
   рекурсивен, UB. Counter snapshot передаётся вместе с
   record'ом в visitor'а; читай его, не зови back.

6. **WS `worker_.detach()` на dtor — diagnostic, не bug.**
   Если dtor дошёл с still-joinable worker'ом — у caller'а
   ownership cycle (async session handler держит последний
   `shared_ptr<WsLink>`). Detach + warning в host log; кaller
   обязан развязать цикл.

7. **`gn_backpressure_t` НЕ возврат `host_api->send`.** Send
   возвращает `gn_result_t` (`GN_OK` / `GN_ERR_LIMIT_REACHED` /
   `GN_ERR_NOT_FOUND`). `gn_backpressure_t` — wire shape
   зарезервированный под per-conn pressure канал; FFI binding
   что switch'ит по `GN_BP_*` после `send` не получит ни один
   из них.

## Cross-references

- [`contracts/link.md`](../../contracts/link.en.md) — формальный contract
  vtable + API
- [`contracts/host-api.md`](../../contracts/host-api.en.md) — все ABI
  slot'ы, которые link использует
- [`contracts/backpressure.md`](../../contracts/backpressure.en.md) — send
  queue, watermark events, control-reply path
- [`contracts/security-trust.md`](../../contracts/security-trust.en.md) — conn-id
  ownership gate, trust class transitions
- [`impl/cpp/concurrency.ru.md`](./concurrency.ru.md) — teardown
  invariants, claim_disconnect pattern, single-emit гарантия
- [`recipes/write-link-plugin.ru.md`](../../recipes/write-link-plugin.ru.md) —
  cookbook для авторов нового транспорта
- [`architecture/multi-path.ru.md`](../../architecture/multi-path.ru.md) —
  как несколько link plugin'ов координируются на один peer
- [`sdk/link.h`](../../../sdk/link.h),
  [`sdk/extensions/link.h`](../../../sdk/extensions/link.h) — ABI
  заголовки
