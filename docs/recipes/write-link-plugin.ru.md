# Recipe: написать link-плагин

**Status:** active · v1
**Owner:** plugin authors
**Last verified:** 2026-05-06

---

## Содержание

1. Цель
2. Что нужно
3. Шаг 1. Scaffold
4. Шаг 2. URI и `scheme`
5. Шаг 3. `connect` и `notify_connect`
6. Шаг 4. `notify_inbound_bytes` — hot path
7. Шаг 5. `send` и backpressure
8. Шаг 6. `listen` и accept
9. Шаг 7. `disconnect` и shutdown
10. Шаг 8. Объявление trust class и handshake-роли
11. Шаг 9. Per-link extension surface
12. Шаг 10. Регистрация в `gn_plugin_register`
13. Проверка
14. Cross-refs

---

## 1. Цель

Link перемещает байты. Он не интерпретирует payload, не аутентифицирует
peer'ов, не маршрутизирует сообщения. Его задача — взять URI с
поддерживаемым scheme, открыть соответствующее транспортное соединение,
отдавать прибывающие байты ядру и принимать исходящие байты от ядра.

В этом рецепте мы напишем `tcp+x://` link: вариант поверх POSIX-сокетов
со scheme, отличающимся от каноничного `tcp://`, чтобы пройти весь путь
от пустой папки до зарегистрированного transport'а.

---

## 2. Что нужно

Один vtable из `sdk/link.h` — `gn_link_vtable_t`:

| Слот | Кто вызывает | Контракт |
|---|---|---|
| `scheme` | plugin → kernel | стабильный lowercase scheme |
| `listen(uri)` | kernel → plugin | bind + accept loop |
| `connect(uri)` | kernel → plugin | outbound dial; завершается через `notify_connect` |
| `send(conn, bytes, size)` | kernel → plugin | bytes borrowed на вызов |
| `send_batch(conn, batch, count)` | kernel → plugin | scatter-gather single-write |
| `disconnect(conn)` | kernel → plugin | идемпотентный teardown |
| `extension_name` / `extension_vtable` | plugin → kernel | per-link surface `gn.link.<scheme>` |
| `destroy(self)` | kernel → plugin | финальное освобождение `self` |

Плюс host_api-обратные вызовы из `sdk/host_api.h`:

| Slot | Когда вызывать |
|---|---|
| `notify_connect(remote_pk, uri, trust, role, &out_conn)` | как только handshake (sock-level) завершился |
| `notify_inbound_bytes(conn, bytes, size)` | каждый chunk прочитанных байт |
| `notify_disconnect(conn, reason)` | при закрытии — clean (`GN_OK`) или ошибочном |
| `notify_backpressure(conn, kind, pending_bytes)` | при пересечении high/low watermark |
| `kick_handshake(conn)` | один раз после `notify_connect`, когда socket уже зарегистрирован |

---

## 3. Шаг 1. Scaffold

```sh
nix run .#new-plugin -- links tcpx
```

Скелет создаётся в `plugins/links/tcpx/` с тем же набором
(CMakeLists / default.nix / flake.nix / `tcpx.cpp` / tests / README /
LICENSE). Дальше — наполняем `tcpx.cpp` C-кодом против SDK-headers.

Plugin-роль `GN_PLUGIN_KIND_LINK` гейтит loader-side host_api: только
link-плагины могут вызывать `notify_connect` /
`notify_inbound_bytes` / `notify_disconnect` / `kick_handshake`. Не
указав `kind` в descriptor'е, плагин получит permissive treatment под
`UNKNOWN`, но это compatibility-shim для legacy и его лучше не
использовать.

---

## 4. Шаг 2. URI и `scheme`

Слот `scheme` отдаёт стабильный lowercase идентификатор. Ядро держит
карту `scheme → link_id`, поэтому `scheme` уникален среди загруженных
links — duplicate scheme отвергается с `GN_ERR_LIMIT_REACHED`.

```c
static const char* tcpx_scheme(void* self) {
    (void)self;
    return "tcp+x";
}
```

Парсинг URI делает ядро через [uri.md](../contracts/uri.en.md). Authority-
часть link разбирает сам: `tcp+x://[::1]:9000`, `tcp+x://192.0.2.5:443`.
Если link принимает hostname-формы — резолвинг идёт через
`resolve_uri_host` (`hostname-resolver.md` §2); operator'ам рекомендуется
pre-resolve'ить hostnames до конфига и передавать IP литералы.

---

## 5. Шаг 3. `connect` и `notify_connect`

Outbound dial асинхронный: `connect(uri)` возвращает `GN_OK` сразу,
сам сокет открывается в worker-loop. Когда ОС отчиталась об успешном
SYN/ACK, link вызывает `notify_connect` — ядро аллоцирует
`gn_conn_id_t`, который хранится в плагине и используется на каждом
последующем send/disconnect.

```c
typedef struct tcpx_self_s {
    const host_api_t*       api;
    gn_link_vtable_t        vt;
    uint64_t                link_id;
    /* runtime: io_context, accept-loop, conn-table conn_id ↔ socket */
} tcpx_self_t;

static gn_result_t tcpx_connect(void* self_v, const char* uri) {
    tcpx_self_t* self = self_v;

    /* 1. Распарсить authority, открыть socket(), connect() async. */
    /* 2. По завершении (worker-thread): */

    uint8_t          remote_pk[GN_PUBLIC_KEY_BYTES] = {0}; /* learned in handshake */
    gn_conn_id_t     conn = GN_INVALID_ID;
    gn_trust_class_t trust = GN_TRUST_UNTRUSTED;       /* public TCP — §3 link.md */

    gn_result_t r = self->api->notify_connect(
        self->api->host_ctx,
        remote_pk, uri, trust,
        GN_ROLE_INITIATOR, &conn);
    if (r != GN_OK) return r;

    /* 3. Зарегистрировать (conn ↔ socket) в собственной таблице
          ДО первого notify_inbound_bytes. */
    /* 4. Дёрнуть kick_handshake — пусть security-сторона начинает
          гнать первое handshake-сообщение (для responder'а это no-op). */
    return self->api->kick_handshake(self->api->host_ctx, conn);
}
```

Порядок «register socket → kick_handshake» обязателен: ядро при
`notify_connect` создаёт security-сессию в фазе Handshake, но не
генерирует первое wire-сообщение (иначе оно гналось бы быстрее, чем
link успевает связать `conn` с сокетом). См. host_api.h docstring у
`kick_handshake`.

---

## 6. Шаг 4. `notify_inbound_bytes` — hot path

Это центральный inbound-callback. Каждый прочитанный из сокета chunk
сразу же передаётся ядру; ядро прогонит байты через security
decrypt → protocol deframe → router dispatch.

```c
/* Внутри read-completion handler'а worker-loop'а. */
static void tcpx_on_read(tcpx_self_t* self,
                         gn_conn_id_t conn,
                         const uint8_t* bytes, size_t size) {
    if (size == 0) return;
    (void)self->api->notify_inbound_bytes(self->api->host_ctx,
                                          conn, bytes, size);
}
```

Hot-path требования (sdk/host_api.h §`notify_inbound_bytes`):

- байты `@borrowed` на время вызова — ядро копирует, если нужно
  удержать;
- запрещено блокирующее ожидание внутри callback'а (никаких
  `pthread_join`, `cv.wait`);
- malloc'ов на горячем пути избегаем — ядро спроектировано так, что
  передача chunk'а в `notify_inbound_bytes` не аллоцирует на стороне
  link'а;
- single-writer-инвариант (`link.md` §4) распространяется только на
  send-сторону; reader — естественно один.

§6a `security-trust.md` (conn-id ownership gate): попытка одного link
сделать `notify_inbound_bytes` на чужой `gn_conn_id_t` вернёт
`GN_ERR_NOT_FOUND` — anchor'ы сравниваются.

---

## 7. Шаг 5. `send` и backpressure

`send(self, conn, bytes, size)` — outbound на конкретное соединение.
Bytes borrowed на время вызова; link копирует в свой socket-side
write buffer (asio strand или эквивалент). App-level pending bytes
account и hard-cap reject — на стороне kernel'я через
`SendQueueManager`, не на link'е: к моменту вызова link'a `send` /
`send_batch` `host_api->send` уже прошёл queue check, kernel-side
drainer выкладывает batch на link's writev. Link обязан:

- Уважать single-writer per-conn: kernel CAS-сериализует drain'еры,
  но link MUST сам serialise control-replies (ping/pong, close echo)
  с teми же socket-FD per [`link.md` §4](../contracts/link.en.md).
- Отдавать `GN_OK` если bytes accepted в socket buffer; на свой
  internal hard cap (peer flood control replies past
  `pending_queue_bytes_hard`) — disconnect, не возвращать
  `LIMIT_REACHED` (это код для kernel-side queue, не link's
  internal).
- Эмитить `notify_backpressure(SOFT/CLEAR)` если link имеет
  собственное окно зрения на write-buffer drain rate —
  rising/falling edge per [`backpressure.md` §3](../contracts/backpressure.en.md).

`gn_result_t` возвраты: `GN_OK` принят в socket-buffer;
`GN_ERR_NOT_FOUND` нет такого conn'а; `GN_ERR_INVALID_STATE`
disconnect в полёте.

```c
static gn_result_t tcpx_send(void* self_v, gn_conn_id_t conn,
                             const uint8_t* bytes, size_t size) {
    tcpx_self_t* self = self_v;

    const gn_limits_t* lim = gn_limits(self->api);
    if (size > lim->max_payload_bytes) return GN_ERR_PAYLOAD_TOO_LARGE;

    /* per-conn queue.push(bytes, size) — single-writer strand */
    /* if queue.bytes >= pending_queue_bytes_high && !was_high: */
    (void)self->api->notify_backpressure(self->api->host_ctx, conn,
                                         GN_CONN_EVENT_BACKPRESSURE_SOFT,
                                         /*pending=*/0);
    /* if queue.bytes drops below pending_queue_bytes_low && was_high: */
    (void)self->api->notify_backpressure(self->api->host_ctx, conn,
                                         GN_CONN_EVENT_BACKPRESSURE_CLEAR,
                                         /*pending=*/0);
    return GN_OK;
}

static gn_result_t tcpx_send_batch(void* self_v, gn_conn_id_t conn,
                                   const gn_byte_span_t* batch, size_t count) {
    /* writev-style: батч идёт одним логическим write. Single-writer
       инвариант покрывает весь батч — никто не может вставить send
       посередине. */
    (void)self_v; (void)conn; (void)batch; (void)count;
    return GN_OK;
}
```

Soft-edge → operator замедляется; hard-edge → ядро отбрасывает frame
и эмить `drop.queue_hard_cap` ещё до вызова link'a. Tight-loop retry
на `GN_ERR_LIMIT_REACHED` от `host_api->send` — контрактное нарушение:
hard-cap дроп означает «sender обогнал kernel drain rate», retry до
drain'а ring'а получит тот же отказ.

---

## 8. Шаг 6. `listen` и accept

```c
static gn_result_t tcpx_listen(void* self_v, const char* uri) {
    tcpx_self_t* self = self_v;

    /* 1. Парс authority, bind socket(), listen(). */
    /* 2. Запустить accept-loop на dedicated strand. */
    /* На каждом accept'е — асинхронно: */

    gn_conn_id_t      conn = GN_INVALID_ID;
    uint8_t           remote_pk[GN_PUBLIC_KEY_BYTES] = {0};
    gn_trust_class_t  trust = GN_TRUST_UNTRUSTED;   /* публичный bind */

    gn_result_t r = self->api->notify_connect(
        self->api->host_ctx,
        remote_pk, uri, trust,
        GN_ROLE_RESPONDER, &conn);
    if (r != GN_OK) return r;

    return self->api->kick_handshake(self->api->host_ctx, conn);
}
```

Inbound от loopback (`127.0.0.1` / `::1`) — `GN_TRUST_LOOPBACK` (см.
[security-trust.md](../contracts/security-trust.en.md) §3). AF_UNIX —
тоже Loopback. `IntraNode` — для intra-process pipe (bridge-плагины).

---

## 9. Шаг 7. `disconnect` и shutdown

`disconnect(conn)` — идемпотентен, второй вызов возвращает `GN_OK`
no-op. После завершения teardown link обязан позвать
`notify_disconnect(conn, reason)`, иначе ядро будет держать
`ConnectionRegistry`-запись и блокировать quiescence-wait (`link.md`
§9).

`reason = GN_OK` — clean close; иное — код, спровоцировавший teardown.

Shutdown целого link'а (link.md §9 канонический порядок):

1. Закрыть acceptor.
2. Снять snapshot живых `gn_conn_id_t` под session-lock;
   закрыть каждый сокет (синхронно или через strand-posted task).
3. Прямо в shutdown-thread'е вызвать `notify_disconnect(host_ctx, id,
   GN_OK)` для каждого id из snapshot'а.
4. Остановить executor, join worker thread'у.

Без шага 3 ядро посчитает соединения живыми и зависнет на
quiescence-wait.

```c
static gn_result_t tcpx_disconnect(void* self_v, gn_conn_id_t conn) {
    tcpx_self_t* self = self_v;
    /* close socket, flush queue, fire notify_disconnect synchronously. */
    return self->api->notify_disconnect(self->api->host_ctx, conn, GN_OK);
}

static void tcpx_destroy(void* self_v) {
    tcpx_self_t* self = self_v;
    /* shutdown executor, join, free per-conn state */
    free(self);
}
```

---

## 10. Шаг 8. Объявление trust class и handshake-роли

`gn_trust_class_t` — позиционный аргумент `notify_connect`. Не
выводится из defaults: `link.md` §3 + `security-trust.md` §3
требуют, чтобы транспорт сам объявил класс по наблюдаемым свойствам:

| Свойство | Class |
|---|---|
| AF_UNIX | `Loopback` |
| `127.0.0.1` / `::1` | `Loopback` |
| публичный TCP/UDP | `Untrusted` |
| intra-process pipe | `IntraNode` |

После Noise handshake + успешной attestation ядро может upgrade'нуть
`Untrusted → Peer` — ни в коем случае не link.

`gn_handshake_role_t`:

| Origin | Role |
|---|---|
| outbound (наш `connect` вернул success) | `GN_ROLE_INITIATOR` |
| inbound (accept'нули на listen-сокете) | `GN_ROLE_RESPONDER` |

Ошибиться нельзя: Noise XX initiator, ошибочно объявивший себя
responder'ом, провалит handshake без какой-либо актуальной
диагностики.

---

## 11. Шаг 9. Per-link extension surface

`gn.link.<scheme>` — extension с типизированным vtable
`gn_link_api_t` (см. `sdk/extensions/link.h`). Каждый link публикует
один и тот же набор слотов:

- **Steady** (`get_stats`, `get_capabilities`, `send`, `send_batch`,
  `close`) — реализуется во всех baseline-links;
- **Composer** (`listen`, `connect`, `subscribe_data`,
  `unsubscribe_data`) — для L2-композиции (TLS-over-TCP,
  ICE-over-UDP); baseline-links возвращают `GN_ERR_NOT_IMPLEMENTED`.

Capability flags: `STREAM`, `DATAGRAM`, `RELIABLE`, `ORDERED`,
`ENCRYPTED_PATH`, `LOCAL_ONLY`. TCP / IPC публикуют `Stream | Reliable
| Ordered`; UDP — `Datagram` + ненулевой `max_payload`.

```c
static const char* tcpx_extension_name(void* self) {
    (void)self;
    return "gn.link.tcp+x";
}

static const void* tcpx_extension_vtable(void* self_v) {
    tcpx_self_t* self = self_v;
    /* возвращаем &gn_link_api_t self'а; ядро публикует через
       register_extension. */
    return /* &self->ext */ NULL;
}
```

---

## 12. Шаг 10. Регистрация в `gn_plugin_register`

```c
GN_PLUGIN_EXPORT gn_result_t gn_plugin_init(const host_api_t* api,
                                            void** out_self) {
    if (!api || !out_self) return GN_ERR_NULL_ARG;

    tcpx_self_t* self = calloc(1, sizeof(*self));
    if (!self) return GN_ERR_OUT_OF_MEMORY;

    self->api                  = api;
    self->vt.api_size          = sizeof(self->vt);
    self->vt.scheme            = tcpx_scheme;
    self->vt.listen            = tcpx_listen;
    self->vt.connect           = tcpx_connect;
    self->vt.send              = tcpx_send;
    self->vt.send_batch        = tcpx_send_batch;
    self->vt.disconnect        = tcpx_disconnect;
    self->vt.extension_name    = tcpx_extension_name;
    self->vt.extension_vtable  = tcpx_extension_vtable;
    self->vt.destroy           = tcpx_destroy;

    *out_self = self;
    return GN_OK;
}

GN_PLUGIN_EXPORT gn_result_t gn_plugin_register(void* self_v) {
    tcpx_self_t* self = self_v;
    return gn_register_link(self->api, "tcp+x",
                            &self->vt, self, &self->link_id);
}

GN_PLUGIN_EXPORT gn_result_t gn_plugin_unregister(void* self_v) {
    tcpx_self_t* self = self_v;
    return gn_unregister_link(self->api, self->link_id);
}

GN_PLUGIN_EXPORT void gn_plugin_shutdown(void* self_v) {
    tcpx_self_t* self = self_v;
    /* destroy() уже отработал из ядра, но shutdown — последний шанс
       забрать всё, что ещё держит self. */
    if (self) free(self);
}
```

Convenience-обёртка `gn_register_link` берёт scheme и упаковывает
`gn_register_meta_t{name=scheme, msg_id=0, priority=0}` —
`msg_id`/`priority` для links игнорируются.

---

## 13. Проверка

1. Собрать link через `nix run .#test`. Подключить к ноде через
   operator-manifest.
2. Поднять две ноды: одна делает `listen tcp+x://[::1]:9000`, другая
   — `connect tcp+x://[::1]:9000`.
3. Убедиться, что после `notify_connect` оба узла прошли Noise
   handshake (Untrusted → Peer после attestation), а транспортные
   envelope (например ping/pong через handler-heartbeat extension)
   ходят туда-обратно.
4. Послать payload, превышающий `pending_queue_bytes_high`, проверить
   `GN_CONN_EVENT_BACKPRESSURE_SOFT`-event на subscriber'ах
   conn-state канала.
5. Закрыть слушающую сторону; убедиться, что `notify_disconnect`
   стрельнул синхронно ДО stop'а executor'а.

---

## 14. Cross-refs

- [link.md](../contracts/link.en.md) — каноничный link-контракт: ABI,
  TrustClass declaration, single-writer invariant, shutdown release.
- [uri.md](../contracts/uri.en.md) — формат URI, kernel-side парсер,
  hostname resolution rules.
- [host-api.md](../contracts/host-api.en.md) — `notify_connect`,
  `notify_inbound_bytes`, `notify_disconnect`,
  `notify_backpressure`, `kick_handshake`.
- [security-trust.md](../contracts/security-trust.en.md) — TrustClass
  values §2, link-объявляемые классы §3, conn-id ownership gate §6a.
- [backpressure.md](../contracts/backpressure.en.md) — soft/hard
  watermark, edge-triggered события.
- [plugin-lifetime.md](../contracts/plugin-lifetime.en.md) — фазы,
  weak-observer pattern для async callback'ов.
- [routing](../architecture/routing.ru.md) — куда ядро отправляет байты
  после `notify_inbound_bytes`.
- [plugin-model](../architecture/plugin-model.ru.md) — общая
  плагин-картина: где link стоит относительно security/handler.
- [transports](../impl/cpp/transports.ru.md) — реализационный гид
  поверх этого рецепта: threading, send/recv, listen vs extension
  API, регулярные грабли при integration'е.
