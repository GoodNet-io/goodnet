# Handler patterns

Handler — это application-protocol единица. Link плагин двигает
байты, security plugin их шифрует, protocol-layer их деframe'ит в
сообщения, **handler решает что с этими сообщениями делать**.
Каждое осмысленное взаимодействие в GoodNet — heartbeat, discovery,
keepalive, peer-info exchange, store-and-forward, RPC, gossip — это
handler.

[`plugin-model`](plugin-model.ru.md) описывает 4 vtable kind'а на
уровне «handler — один из них». [`routing`](routing.ru.md) показывает
дorgan dispatcher chain. [`handler-registration.md`](../contracts/handler-registration.en.md) —
формальный contract. Эта глава — про **повседневные паттерны**: как
typical handler выглядит, как handlers композятся между собой,
куда не надо лезть.

## Содержание

- [Что такое handler](#что-такое-handler)
- [Жизнь одного сообщения](#жизнь-одного-сообщения)
- [Шесть паттернов](#шесть-паттернов)
  - [Pure handler — heartbeat](#pure-handler--heartbeat)
  - [Handler + extension — peer-info](#handler--extension--peer-info)
  - [Handler chain — middleware](#handler-chain--middleware)
  - [Request-reply — RPC](#request-reply--rpc)
  - [Broadcast subscribe — gossip](#broadcast-subscribe--gossip)
  - [Кernel-canon msg ids — heartbeat & capability TLV](#kernel-canon-msg-ids--heartbeat--capability-tlv)
- [Anti-patterns](#anti-patterns)
- [App-registered handler vs plugin handler](#app-registered-handler-vs-plugin-handler)
- [Тестирование handler'а](#тестирование-handlerа)
- [Cross-references](#cross-references)

## Что такое handler

Handler — структура с пятью обязательными ABI-точками:

```c
typedef struct gn_handler_vtable_t {
    uint32_t            api_size;
    const char*       (*protocol_id)(void* self);
    void              (*supported_msg_ids)(void* self,
                                            const uint32_t** out_ids,
                                            size_t* out_count);
    gn_propagation_t  (*handle_message)(void* self,
                                          const gn_message_t* env);
    void              (*on_result)(void* self,
                                    const gn_message_t* env,
                                    gn_propagation_t result);
} gn_handler_vtable_t;
```

Регистрация: `host_api->register_vtable(host_ctx, GN_REGISTER_HANDLER,
&meta, &vtable, self, &out_id)` — где `meta.protocol_id` и
`meta.priority` cyfra'ят handler в `(protocol_id × msg_id) →
priority-ordered list` карту.

`protocol_id` — например `"gnet-v1"` для приложений на mesh-framing
протоколе, либо custom строка для своего wire-протокола поверх
`raw://`. `supported_msg_ids` — массив msg_id'шек на которые handler
хочет получать. `handle_message` — основной callback. `on_result` —
optional post-dispatch hook (для logging, metrics, etc).

`gn_propagation_t` — три значения:

- `GN_PROPAGATION_CONTINUE` — handler не возражает; диспетчер
  продолжает идти по списку handler'ов с тем же `(protocol_id,
  msg_id)` priority-desc
- `GN_PROPAGATION_CONSUMED` — handler обработал, остальным не
  показываем
- `GN_PROPAGATION_REJECT` — невалидное сообщение, kernel disconnect'ит
  conn (suspicious peer)

## Жизнь одного сообщения

Каждый inbound байт идёт по одной и той же цепочке:

1. Peer'ский TCP write → link plugin вызывает
   `host_api->notify_inbound_bytes(conn, bytes, size)`.
2. Security plugin расшифровывает: `decrypt_transport(bytes) →
   plaintext`.
3. Protocol layer деframe'ит: `deframe(bytes) →
   vector<gn_message_t>`.
4. Kernel router на каждое сообщение делает
   `lookup_handlers(msg.protocol_id, msg.msg_id)`, получает
   priority-desc snapshot of handlers, и проходит по нему:
   - `handler[0].handle_message(msg)` возвращает `CONTINUE` /
     `CONSUMED` / `REJECT`
   - `handler[0].on_result(msg, result)` (если зарегистрирован)
   - `handler[1].handle_message(msg)` (только если предыдущий
     вернул `CONTINUE`)
   - и так далее до `CONSUMED`, `REJECT` или конца snapshot'а

![Dispatch chain](../img/dispatch_chain.svg)

Существенные точки:

1. **`gn_message_t` envelope** — `conn_id`, `msg_id`,
   `sender_pk[32]`, `recipient_pk[32]`, `payload` + `payload_size`,
   `_reserved[4]`. Все поля `@borrowed` — handler не должен хранить
   pointer'ы за пределы своего `handle_message` invocation. Если
   нужно сохранить bytes — copy.
2. **Snapshot dispatch** — kernel снимает priority-desc snapshot
   handler'ов раз в начале walk'а; если handler unregister'ится
   mid-walk, snapshot его всё равно содержит. Per
   [`handler-registration.md §3`](../contracts/handler-registration.en.md).
3. **Synchronous dispatch** — `handle_message` бегает на kernel
   dispatch thread. Не блокировать. Не вызывать back в host_api
   методы что могут recurse'нуть в dispatch.

## Шесть паттернов

### Pure handler — heartbeat

Простейший случай: один handler регистрируется на ровно один msg_id,
respond'ит на каждое сообщение, возвращает `CONSUMED`.

Пример: heartbeat plugin отвечает на ping → pong.

```cpp
struct HeartbeatHandler {
    const host_api_t* api = nullptr;
    static constexpr uint32_t kPingMsgId = 0x10;
    static constexpr uint32_t kPongMsgId = 0x11;
};

const char* hb_protocol_id(void*) { return "gnet-v1"; }

void hb_supported_msg_ids(void*, const uint32_t** out_ids, size_t* out_count) {
    static const uint32_t ids[] = {HeartbeatHandler::kPingMsgId};
    *out_ids   = ids;
    *out_count = 1;
}

gn_propagation_t hb_handle_message(void* self, const gn_message_t* env) {
    auto* h = static_cast<HeartbeatHandler*>(self);
    /// Echo the ping payload back as pong on the same conn.
    (void)h->api->send(h->api->host_ctx, env->conn_id,
                       HeartbeatHandler::kPongMsgId,
                       env->payload, env->payload_size);
    return GN_PROPAGATION_CONSUMED;
}
```

Plugin's `gn_plugin_register` вызывает `register_vtable(GN_REGISTER_HANDLER,
{.protocol_id="gnet-v1", .priority=128, .msg_id=kPingMsgId},
&vtable, self, &out_id)`.

Trade-off: priority 128 (mid-range) означает что более приоритетные
handler'ы (например logging) увидят msg раньше. Если heartbeat
должен быть «catch-all final responder» — priority=0 (последний).

### Handler + extension — peer-info

Handler принимает messages, **maintain'ит состояние**, **expose'ит
state другим плагинам через extension**. Это «publisher» pattern.

Пример: peer-info plugin слушает announce-сообщения от peer'ов,
накапливает map `peer_pk → known_uris`, expose'ит lookup через
`gn.peer-info` extension.

```cpp
struct PeerInfoPlugin {
    std::mutex mu_;
    std::unordered_map<PeerPk, std::vector<std::string>> peers_;
    
    /// Handler vtable callback
    gn_propagation_t handle_message(const gn_message_t* env) {
        auto announce = parse_announce(env->payload, env->payload_size);
        if (!announce) return GN_PROPAGATION_REJECT;  // malformed
        std::lock_guard lk(mu_);
        peers_[env->sender_pk] = announce->uris;
        return GN_PROPAGATION_CONSUMED;
    }
    
    /// Extension vtable: callable by other plugins
    gn_result_t get_uris(const uint8_t pk[32], char* out_buf, size_t* out_size) {
        std::lock_guard lk(mu_);
        auto it = peers_.find(PeerPk{pk});
        if (it == peers_.end()) return GN_ERR_NOT_FOUND;
        // serialize uris into out_buf
        return GN_OK;
    }
};
```

Регистрация — две register'а в `gn_plugin_register`:

```cpp
host_api->register_vtable(host_ctx, GN_REGISTER_HANDLER,
                          &handler_meta, &handler_vtable, self, &h_id);
host_api->register_extension(host_ctx, "gn.peer-info", 0x10000,
                             &extension_vtable, self, &e_id);
```

Other plugins — например relay-direct-upgrade handler — вызывают
`query_extension_checked("gn.peer-info", 1, &vt, &vt_self)` чтобы
получить `vt->get_uris(...)`. Per
[`extension-model`](extension-model.ru.md), kernel agnostic — только
registry.

### Handler chain — middleware

Несколько handler'ов на тот же `(protocol_id, msg_id)` с разной
priority. Высокий-приоритетный transform'ирует / валидирует /
loggers сообщение, возвращает `CONTINUE`. Низкий-приоритетный
делает финальную обработку, возвращает `CONSUMED`.

Пример: rate-limit handler (priority=200) → audit-log handler
(priority=150) → business-logic handler (priority=100, returns
CONSUMED).

```cpp
gn_propagation_t rate_limit_handle(void* self, const gn_message_t* env) {
    auto* h = static_cast<RateLimit*>(self);
    if (!h->bucket(env->sender_pk).consume()) {
        return GN_PROPAGATION_REJECT;  // disconnects peer
    }
    return GN_PROPAGATION_CONTINUE;  // pass to next handler
}

gn_propagation_t audit_log_handle(void* self, const gn_message_t* env) {
    log_inbound(env->sender_pk, env->msg_id, env->payload_size);
    return GN_PROPAGATION_CONTINUE;  // pass to business handler
}

gn_propagation_t business_handle(void* self, const gn_message_t* env) {
    process_request(env);
    return GN_PROPAGATION_CONSUMED;  // final
}
```

Все три регистрируются под одинаковым `(protocol_id="myproto",
msg_id=0x100)` с разной `priority`. Kernel сам выстраивает их в
цепочку.

`limit.md::max_handlers_per_msg_id` ограничивает длину цепочки
(default 16).

### Request-reply — RPC

Handler принимает request с `request_id` в payload, обрабатывает,
sends response back с тем же `request_id`. Sender держит map
`request_id → callback` чтобы matched response найти.

Stylistic — request_id живёт в первых 4 байтах payload (или в
`_reserved[0]` envelope). Application defines wire format поверх.

```cpp
// Request handler on responder side
gn_propagation_t rpc_handle_request(void* self, const gn_message_t* env) {
    auto* h = static_cast<RpcServer*>(self);
    if (env->payload_size < 4) return GN_PROPAGATION_REJECT;
    
    uint32_t request_id = read_be32(env->payload);
    std::span<const uint8_t> args(env->payload + 4, env->payload_size - 4);
    
    // Compute response
    std::vector<uint8_t> response_bytes;
    write_be32(response_bytes, request_id);
    h->dispatcher(args, response_bytes);
    
    // Send back on same conn with reply msg_id
    h->api->send(h->api->host_ctx, env->conn_id,
                 kRpcReplyMsgId,
                 response_bytes.data(), response_bytes.size());
    return GN_PROPAGATION_CONSUMED;
}

// Reply handler on initiator side
gn_propagation_t rpc_handle_reply(void* self, const gn_message_t* env) {
    auto* h = static_cast<RpcClient*>(self);
    if (env->payload_size < 4) return GN_PROPAGATION_REJECT;
    
    uint32_t request_id = read_be32(env->payload);
    auto callback = h->pending_requests().take(request_id);
    if (callback) {
        callback(env->payload + 4, env->payload_size - 4);
    }
    return GN_PROPAGATION_CONSUMED;
}
```

Handler'ы на initiator и responder обычно живут в одном плагине
(симметричный RPC) или в двух плагинах одного приложения. Один и
тот же handler может exposed'ить extension `gn.<myproto>.rpc` для
других плагинов чтобы делать RPC через него.

### Broadcast subscribe — gossip

Handler принимает broadcast (recipient_pk = 0x00..00 за исключением
sender_pk filter), хранит state, fan-out'ит интересную часть в
extension'е. Применяется для discovery, NAT-state, status gossip.

```cpp
gn_propagation_t gossip_handle(void* self, const gn_message_t* env) {
    /// Broadcast — recipient_pk all-zeros. Plugin's send() ставит
    /// этот marker, kernel routes к всем connections that match
    /// msg_id range.
    if (!is_all_zero(env->recipient_pk)) {
        // Direct addressed — not gossip
        return GN_PROPAGATION_CONTINUE;
    }
    
    auto news = parse_news(env->payload, env->payload_size);
    auto* h = static_cast<GossipPlugin*>(self);
    if (h->is_known(news.id)) {
        // Already saw this news — don't re-broadcast
        return GN_PROPAGATION_CONSUMED;
    }
    h->store(news);
    
    /// Fan-out to other peers (except the sender). for_each_connection
    /// iterates connections; send to each conn except env->sender_pk.
    h->api->for_each_connection(h->api->host_ctx, &fan_out_visitor, &news);
    
    return GN_PROPAGATION_CONSUMED;
}
```

Anti-pattern: hot-loop `for_each_connection + send` на каждом
inbound — может перегрузить kernel. Используй set_timer + batch'и
gossip-out, чтобы не fan-out'ить чаще раза в секунду.

### Кernel-canon msg ids — heartbeat & capability TLV

Несколько msg_id зарезервированы под kernel-internal протокол:

- `0x10` — heartbeat (per heartbeat plugin convention)
- `0x12` — capability TLV (per [`capability-tlv.md`](../contracts/capability-tlv.en.md))
- `0x11` — attestation dispatch (kernel-managed,
  [`attestation.md`](../contracts/attestation.en.md))

Plugin может зарегистрировать handler на эти msg_id, но обычно не
надо — kernel сам processes их через специальные dispatcher'ы. Если
plugin регистрируется на reserved id с priority выше kernel canon —
ломает framework.

Application msg ids — `0x100+`. Plugin author выбирает range для
своего протокола.

## Anti-patterns

### Не держать конкретные conn'ы в handler state

Если handler хранит `unordered_map<gn_conn_id_t, my_state>` —
обязательно subscribe к conn-events чтобы reagировать на
DISCONNECTED и убрать запись. Иначе утечка памяти на каждом dropped
peer'е.

Лучше: state по `peer_pk` — он стабильнее (conn_id переиспользуются
после disconnect; peer_pk — это identity peer'а, переживающая
переустановки connection'а).

```cpp
// плохо
std::unordered_map<gn_conn_id_t, ConnState> conn_state_;

// хорошо
std::unordered_map<PeerPk, PeerState> peer_state_;
```

### Не блокировать в `handle_message`

Dispatch thread обрабатывает все handler'ы для всех conn'ов
sequentially. Заблокированный handler stall'ит весь kernel.

Если работа долгая — `host_api->set_timer(0, work_fn, ud, anchor,
&id)` чтобы schedule на executor'е, return `CONSUMED` immediately.
Если работа требует I/O — она должна жить в transport plugin или
external thread, handler только записывает intent.

```cpp
// плохо — блокирует dispatch на secюнду
gn_propagation_t handle(void* self, const gn_message_t* env) {
    auto result = sync_database_query(env->payload);  // 1s
    send_response(env->conn_id, result);
    return GN_PROPAGATION_CONSUMED;
}

// хорошо — schedule на executor, dispatch не stall'ится
gn_propagation_t handle(void* self, const gn_message_t* env) {
    auto* h = static_cast<MyHandler*>(self);
    auto* work = new WorkItem{*env, h};
    gn_timer_id_t id;
    h->api->set_timer(h->api->host_ctx, /*delay_ms=*/0,
                       &async_work_fn, work, h->plugin_anchor, &id);
    return GN_PROPAGATION_CONSUMED;
}
```

### Не recurse в host_api callbacks из handler

Если handler call'ит `host_api->send` который trigger'ит обратную
inbound bytes path → notify_inbound → deframe → dispatch → handler →
send → ... — потенциальный stack overflow или deadlock на mutex'ах.

Async send: handler возвращает CONSUMED; otherwise schedule send
через timer (timer.delay_ms=0 равно post-to-executor).

`send` сам по себе обычно безопасен — он ставит bytes в queue, не
recurse'ит. Но если plugin использует `inject` (test-only API) —
recursion реальна.

### Не игнорировать propagation enum

Некоторые plugin author'ы возвращают `CONSUMED` для всего «на
всякий случай». Это ломает chain: следующий handler никогда не
увидит сообщение.

Правило: возвращай `CONSUMED` только если **ответственно** обработал
или это финальный handler. Возвращай `CONTINUE` если ты middleware.
Возвращай `REJECT` только если payload явно невалидный (peer
malicious / broken).

### Не смешивать protocol_id'ы

Handler регистрируется под одним `protocol_id`. Сообщения с другим
protocol_id просто не доходят. Если хочешь handler'ить несколько
протоколов — register несколько handler'ов с разными `meta.protocol_id`.

## App-registered handler vs plugin handler

App может зарегистрировать свой handler через capi:

```cpp
// app-side, через bridges/cpp
auto handle = gn::cpp::register_handler(
    core,
    std::span<const uint32_t>{my_msg_ids},
    [&](gn_conn_id_t conn, uint32_t msg_id,
        std::span<const uint8_t> payload) {
        process(conn, msg_id, payload);
    });
```

Это создаёт handler instance в kernel'е с lifetime равным
`HandlerHandle`. Когда handle уничтожается — handler unregister'ится.

App-side handler ничем не отличается от plugin-side — тот же
vtable shape, тот же chain dispatch. Разница только в lifecycle:
plugin handler живёт пока plugin loaded; app handler живёт пока
app's handle alive.

Use case'ы:
- gssh listen регистрирует handler на `kSshAppMsgId` для
  forward'инга байтов в local sshd
- goodnet-store зарегистрировал бы handler на kv-protocol msg ids
- monitoring panel подключается к узлу как peer, регистрирует
  handler на metrics-stream msg id

Plugin handler vs app handler — выбор по lifetime / packaging:
- если handler — часть permanent infrastructure node'а (heartbeat,
  discovery) — plugin
- если handler — часть конкретного operator-side workflow
  (tunnel, monitoring tool) — app

## Тестирование handler'а

`sdk/test/conformance/` пока не содержит typed-test для handler'ов
(только `link_teardown.hpp`). Plugin-author пишет свои unit tests:

```cpp
TEST(MyHandler, EchoesPing) {
    HostStub host;
    auto api = host.make_api();
    
    MyHandler h{&api};
    gn_handler_vtable_t vt = make_my_vtable();
    
    /// Synthesize a gn_message_t directly without kernel routing
    gn_message_t env{};
    env.conn_id = 42;
    env.msg_id = MyHandler::kPingMsgId;
    env.payload = "test"; env.payload_size = 4;
    
    auto result = vt.handle_message(&h, &env);
    EXPECT_EQ(result, GN_PROPAGATION_CONSUMED);
    EXPECT_EQ(host.last_send.conn_id, 42);
    EXPECT_EQ(host.last_send.msg_id, MyHandler::kPongMsgId);
}
```

`HostStub` — минимальный mock с counter'ами для send / register /
subscribe — каждый plugin делает свой; общий conformance helper в
SDK ещё не shipped.

Integration tests с реальным kernel'ом — через
`tests/integration/` overlay. Например `test_noise_tcp_e2e.cpp`
демонстрирует full pipe (link → security → protocol → handler).

## Cross-references

- [`handler-registration.md`](../contracts/handler-registration.en.md) —
  формальный contract: vtable shape, propagation rules, snapshot
  dispatch invariants
- [`recipes/write-handler-plugin.md`](../recipes/write-handler-plugin.ru.md) —
  пошаговое создание handler plugin'а от scaffold до commit
- [`recipes/subscribe-conn-events.md`](../recipes/subscribe-conn-events.ru.md) —
  cleanup handler-side state on DISCONNECTED
- [`recipes/register-extension.md`](../recipes/register-extension.ru.md) —
  handler-as-publisher pattern (handler + extension surface)
- [`recipes/instrument-with-metrics.md`](../recipes/instrument-with-metrics.ru.md) —
  emit_counter через api в handler'е
- [`routing`](routing.ru.md) — kernel router внутрь handler chain
- [`extension-model`](extension-model.ru.md) — как handler-as-publisher
  resolved'ится через `query_extension_checked`
- [`overview`](overview.ru.md) §«Что знает ядро» — kernel agnostic
  про handlers, registry-only
- [`capability-tlv.md`](../contracts/capability-tlv.en.md) — wire
  format для capability negotiation msg ids
- [`limits.md`](../contracts/limits.en.md) — `max_handlers_per_msg_id`
  и другие quota
