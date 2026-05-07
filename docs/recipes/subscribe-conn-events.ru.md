# Recipe: subscribe to connection events

## Содержание

- [Цель](#цель)
- [Шаг 1. Event kinds](#шаг-1-event-kinds)
- [Шаг 2. subscribe_conn_state](#шаг-2-subscribe_conn_state)
- [Шаг 3. Callback signature и thread model](#шаг-3-callback-signature-и-thread-model)
- [Шаг 4. Filtering на стороне плагина](#шаг-4-filtering-на-стороне-плагина)
- [Шаг 5. ud_destroy для teardown](#шаг-5-ud_destroy-для-teardown)
- [Шаг 6. Lifecycle и manual unsubscribe](#шаг-6-lifecycle-и-manual-unsubscribe)
- [Пример: relay-direct upgrade](#пример-relay-direct-upgrade)
- [Cross-refs](#cross-refs)

---

## Цель

Плагин реагирует на изменения lifecycle'а connection'ов — установление, разрыв, trust-upgrade, backpressure soft/clear watermarks. Вместо polling'а connection registry плагин подписывается на channel и получает event-payload'ы синхронно от publishing thread'а ядра.

Этот рецепт показывает, как корректно подписаться, как обработать callback не блокируя publisher'а, как корректно высвободить subscription при shutdown.

---

## Шаг 1. Event kinds

Channel `GN_SUBSCRIBE_CONN_STATE` фанит структурой `gn_conn_event_t`:

```c
typedef struct gn_conn_event_s {
    uint32_t              api_size;
    gn_conn_event_kind_t  kind;
    gn_conn_id_t          conn;
    gn_trust_class_t      trust;
    uint8_t               remote_pk[GN_PUBLIC_KEY_BYTES];
    uint64_t              pending_bytes;  /* BACKPRESSURE_* only */
    void*                 _reserved[4];
} gn_conn_event_t;
```

Семантика по kind'у:

| Kind | Когда |
|---|---|
| `GN_CONN_EVENT_CONNECTED` | `notify_connect` зарегистрировал conn в registry |
| `GN_CONN_EVENT_DISCONNECTED` | `notify_disconnect` снял запись (см. `conn-events.md` §2a) |
| `GN_CONN_EVENT_TRUST_UPGRADED` | one-way `Untrusted` → `Peer` upgrade после security handshake |
| `GN_CONN_EVENT_BACKPRESSURE_SOFT` | per-conn pending queue превысил `pending_queue_bytes_high` |
| `GN_CONN_EVENT_BACKPRESSURE_CLEAR` | pending queue упал ниже `pending_queue_bytes_low` |

`remote_pk` на CONNECTED-side для responder может быть all-zero до завершения handshake'а; на TRUST_UPGRADED уже всегда осмысленный. `pending_bytes` ненулевой только для BACKPRESSURE_*.

---

## Шаг 2. subscribe_conn_state

Подписка живёт всё время between `gn_plugin_register` и `gn_plugin_unregister`; типовой случай — одна subscription на плагин.

```c
#include <sdk/conn_events.h>
#include <sdk/host_api.h>

typedef struct plugin_state_s {
    const host_api_t*    api;
    gn_subscription_id_t conn_sub;
} plugin_state_t;

static void on_conn_event(void* user_data, const gn_conn_event_t* ev);

gn_result_t gn_plugin_register(void* self) {
    plugin_state_t* st = (plugin_state_t*)self;
    return st->api->subscribe_conn_state(st->api->host_ctx,
                                         &on_conn_event,
                                         /* user_data  */ st,
                                         /* ud_destroy */ NULL,
                                         &st->conn_sub);
}
```

Возможные failure modes:

| Условие | Result |
|---|---|
| `host_ctx == NULL` или `cb == NULL` или `out_id == NULL` | `GN_ERR_NULL_ARG` |
| Subscription cap exceeded (default 256) | `GN_ERR_LIMIT_REACHED` |
| Иначе | `GN_OK`, `*out_id` ненулевой |

После успешного вызова плагин не получает «replay» уже-произошедших событий. Если плагину нужна полная картина текущего состояния, нужно сначала `subscribe_conn_state`, потом `for_each_connection` для bootstrap'а — не наоборот.

---

## Шаг 3. Callback signature и thread model

```c
static void on_conn_event(void* user_data, const gn_conn_event_t* ev) {
    plugin_state_t* st = (plugin_state_t*)user_data;

    switch (ev->kind) {
        case GN_CONN_EVENT_CONNECTED:
            st->api->emit_counter(st->api->host_ctx, "myplugin.connected");
            break;
        case GN_CONN_EVENT_DISCONNECTED:
            st->api->emit_counter(st->api->host_ctx, "myplugin.disconnected");
            break;
        case GN_CONN_EVENT_TRUST_UPGRADED:
            handle_trust_upgrade(st, ev);
            break;
        case GN_CONN_EVENT_BACKPRESSURE_SOFT:
            on_pressure_rising(st, ev->conn, ev->pending_bytes);
            break;
        case GN_CONN_EVENT_BACKPRESSURE_CLEAR:
            on_pressure_clear(st, ev->conn);
            break;
        default:
            /* unknown event kind — additive evolution, default-handle */
            break;
    }
}
```

Callback запускается на **publishing thread'е** ядра — это transport's strand для CONNECTED / DISCONNECTED / TRUST_UPGRADED / BACKPRESSURE_*. Один thread для всех событий не гарантируется — ядро не синтезирует unified order across публикующих thread'ов.

Контракт callback'а:

- **Возвращайся быстро.** Долгая работа держит publisher'а; следующие subscriber'ы в snapshot'е стоят.
- **Не блокируйся**, не ходи в I/O.
- **Не бросай C++ exceptions** через C ABI boundary. SignalChannel ловит exception как kernel-side defence, но это не контрактное право плагина (`signal-channel.md` §6.2).
- **State, разделяемый между event kind'ами, защищай локом** — разные kinds могут прилететь с разных thread'ов.
- **Долгую работу постируй** через `host_api->set_timer(0, fn, ud, &id)` — service executor сериализует работу.
- **Не вызывай `for_each_connection` изнутри callback'а connection-registry-mutating slot'а**: visitor держит per-shard read lock и self-deadlock'ится на любом мутирующем вызове registry.

`payload` (структура `gn_conn_event_t`) borrowed для duration of the call. Плагин не должен ретейнить указатель после возврата — байты могут быть stack-resident на publisher'е.

---

## Шаг 4. Filtering на стороне плагина

Ядро постит **все** conn-event'ы каждому subscriber'у; плагин фильтрует сам. Типовой filter — по kind:

```c
if (ev->kind != GN_CONN_EVENT_TRUST_UPGRADED) return;
```

Filter по trust class:

```c
if (ev->trust != GN_TRUST_PEER) return;
```

Filter по conn_id requires per-plugin tracking, какой `gn_conn_id_t` относится к плагину — для этого ведётся local set, обновляемый из CONNECTED / DISCONNECTED.

---

## Шаг 5. ud_destroy для teardown

Четвёртый параметр `subscribe_conn_state` — `ud_destroy`, опциональный деструктор для `user_data`. Ядро вызывает его ровно один раз: либо при `unsubscribe(id)`, либо когда lifetime-anchor плагина закрывается на shutdown.

```c
static void ud_destroy_state(void* ud) {
    plugin_state_t* st = (plugin_state_t*)ud;
    /* free heap-owned поля; static state — оставить ud_destroy = NULL */
    free(st);
}
```

Если `user_data` живёт на статическом storage (как в примере выше — `st` — это `out_self` плагина), `ud_destroy` оставляют `NULL`: ядро ничего не освобождает, плагин освобождает в `gn_plugin_shutdown`.

`ud_destroy` нужен тогда, когда subscription is the sole owner данных, на которые она указывает (например, замыкание из FFI binding'а, allocated на subscribe'е).

---

## Шаг 6. Lifecycle и manual unsubscribe

Subscription лежит между `gn_plugin_register` и `gn_plugin_unregister`. Если плагин хочет снять её раньше:

```c
static void cleanup_conn_sub(plugin_state_t* st) {
    if (st->conn_sub != GN_INVALID_SUBSCRIPTION_ID) {
        st->api->unsubscribe(st->api->host_ctx, st->conn_sub);
        st->conn_sub = GN_INVALID_SUBSCRIPTION_ID;
    }
}
```

`unsubscribe` идемпотентен — снятие отсутствующего id возвращает `GN_OK`.

Если плагин не вызывает `unsubscribe`, ядро через lifetime-anchor (`plugin-lifetime.md` §4) auto-снимает все subscription'ы плагина при `gn_plugin_unregister`. Manual call — для случая re-subscribe'а с другими параметрами без полной выгрузки плагина.

Внутри callback'а `subscribe`/`unsubscribe` — допустимы (`signal-channel.md` §4): вновь-добавленные subscriber'ы не получат in-flight event, вновь-удалённые — получат (snapshot уже снят).

---

## Пример: relay-direct upgrade

Гипотетический relay-upgrade плагин: на TRUST_UPGRADED для conn'и, поднявшейся через relay, достаёт у `gn.peer-info` альтернативные direct-URI и пробует прямой dial. Если прямой dial успешен, исходящий relay-conn закрывается через `disconnect`.

```c
static void on_conn_event(void* user_data, const gn_conn_event_t* ev) {
    relay_upgrade_state_t* st = (relay_upgrade_state_t*)user_data;
    if (ev->kind != GN_CONN_EVENT_TRUST_UPGRADED) return;
    if (ev->trust != GN_TRUST_PEER) return;

    /* пост долгой работы на service executor — handler returns fast */
    pending_upgrade_t* p = malloc(sizeof(*p));
    if (!p) return;
    p->st   = st;
    p->conn = ev->conn;
    memcpy(p->pk, ev->remote_pk, GN_PUBLIC_KEY_BYTES);

    gn_timer_id_t id = GN_INVALID_TIMER_ID;
    st->api->set_timer(st->api->host_ctx, /* delay_ms */ 0,
                       &try_upgrade_to_direct, p, &id);
    /* посланная задача владеет `p`; freed внутри try_upgrade_to_direct */
}
```

Обработка ушла на service executor; callback вернулся за микросекунду — publisher не задержан.

---

## Cross-refs

- [conn-events.md](../contracts/conn-events.en.md) — event kinds, DISCONNECTED spec, ordering, dropped events.
- [signal-channel.md](../contracts/signal-channel.en.md) — pub/sub primitive под капотом, snapshot rule, exception-catch contract.
- [host-api.md §2](../contracts/host-api.en.md) — `subscribe_conn_state` / `unsubscribe` / `for_each_connection` slot signatures.
- [relay-direct](../architecture/relay-direct.ru.md) — пример consumer'а для TRUST_UPGRADED.
- [timer.md §2-3](../contracts/timer.en.md) — куда постить долгую работу из callback'а.
- [plugin-lifetime.md §4](../contracts/plugin-lifetime.en.md) — auto-reap subscriptions через lifetime anchor.
