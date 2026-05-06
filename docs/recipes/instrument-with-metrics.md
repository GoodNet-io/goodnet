# Recipe: instrument with metrics

## Содержание

- [Цель](#цель)
- [Шаг 1. Naming convention](#шаг-1-naming-convention)
- [Шаг 2. emit_counter](#шаг-2-emit_counter)
- [Шаг 3. Cardinality cap](#шаг-3-cardinality-cap)
- [Шаг 4. Iteration со стороны exporter'а](#шаг-4-iteration-со-стороны-exporterа)
- [Шаг 5. No labels — encode в имя](#шаг-5-no-labels--encode-в-имя)
- [Cross-refs](#cross-refs)

---

## Цель

Плагин публикует кросс-cutting telemetry — relay forwards, cache hits, retries, dial failures — через kernel-side counter store. Operator получает один observable surface, поверх которого out-of-tree exporter рендерит свой wire format. Ядро не несёт ни HTTP-сервера, ни Prometheus-renderer'а; плагин-author тоже их не пишет — только `emit_counter("<plugin>.<event>")`.

Этот рецепт показывает, как корректно назвать счётчик, как избежать cardinality blow-up'а и как exporter подхватывает счётчик без согласований с провайдером.

---

## Шаг 1. Naming convention

Имена — flat UTF-8 strings, dot-separated, lowercase. Конвенция: `<plugin>.<event>` для базовых счётчиков и `<plugin>.<event>.<reason>` для разбивки по причине.

| Хорошо | Почему |
|---|---|
| `heartbeat.miss` | плагин-prefix + событие |
| `link_tcp.dial_fail` | подсистема-prefix без двусмысленности |
| `security_noise.handshake_complete` | event-name без global namespace |
| `relay.forward.timeout` | три уровня — subsystem.event.reason |

| Плохо | Почему |
|---|---|
| `heartbeat_miss` | underscore вместо dot — exporter'у труднее парсить |
| `drop.queue_hard_cap` | `drop.*` зарезервирован за ядром (`metrics.md` §3) |
| `route.outcome.relay` | `route.outcome.*` тоже kernel-only |
| `MyPluginMissCount` | CamelCase ломает скрипты scrape'а |

Конкретно `drop.*` и `route.outcome.*` — kernel-internal namespace для router и deframe-pipeline drops. Плагин, которому нужен собственный drop-counter, использует `<plugin>.drop.<reason>` (e.g. `gnet.drop.reserved_bit`).

---

## Шаг 2. emit_counter

Один вызов — один инкремент. Slot не возвращает ошибки; пустое или NULL имя ядро дропнет молча.

```c
#include <sdk/host_api.h>

static void on_heartbeat_pong(plugin_state_t* st) {
    st->api->emit_counter(st->api->host_ctx, "heartbeat.pong");
}

static void on_heartbeat_miss(plugin_state_t* st) {
    st->api->emit_counter(st->api->host_ctx, "heartbeat.miss");
}
```

Имя — borrowed для duration of the call: ядро либо находит существующий slot и инкрементит атомарно, либо лениво создаёт новый под exclusive-locked путь. Hot path (existing counter) не блокирует readers — `iterate_counters` идёт под shared lock.

Convenience-обёртка для condition'нальных bump'ов:

```c
static inline void bump_if(const host_api_t* api,
                           int condition,
                           const char* name) {
    if (condition) api->emit_counter(api->host_ctx, name);
}
```

---

## Шаг 3. Cardinality cap

Ядро держит cap по числу уникальных имён через `gn_limits_t::max_counter_names` (default `8192`). Когда cap достигнут, `emit_counter` на **новое** имя дропается и инкрементит сентинель `metrics.cardinality_rejected`. Существующие счётчики продолжают расти across cap.

Плагин-author следит за двумя вещами:

1. **Не генерируй имена per-conn / per-peer / per-message-id**. `link_tcp.dial_fail.<peer_pk>` обронит cap за минуты под нагрузкой — pk имеет 2^256 значений.
2. **Используй закрытое множество reason'ов**. `<plugin>.dial_fail.timeout`, `<plugin>.dial_fail.refused`, `<plugin>.dial_fail.unreachable` — это конечный список, который operator покажет на dashboard'е.

Для high-cardinality диагностики правильный канал — log entries (`host-api.md` §11), не counter'ы. Один log-line на dial-fail с peer_pk внутри сообщения наблюдаем через grep, и не давит на counter store.

```c
/* Right: closed set of reasons */
static void on_dial_failure(plugin_state_t* st, dial_error_t e) {
    switch (e) {
        case DIAL_TIMEOUT:    st->api->emit_counter(st->api->host_ctx,
                                                    "link_tcp.dial_fail.timeout");
                              break;
        case DIAL_REFUSED:    st->api->emit_counter(st->api->host_ctx,
                                                    "link_tcp.dial_fail.refused");
                              break;
        case DIAL_UNREACHABLE:st->api->emit_counter(st->api->host_ctx,
                                                    "link_tcp.dial_fail.unreachable");
                              break;
    }
}
```

---

## Шаг 4. Iteration со стороны exporter'а

Counter'ы видны всем плагинам через `iterate_counters`. Out-of-tree exporter (Prometheus / OpenMetrics / statsd) проходит по slots, рендерит и отдаёт по своему wire-протоколу.

```c
typedef struct exporter_state_s {
    /* ... */
} exporter_state_t;

static int32_t accumulate(void* ud, const char* name, uint64_t value) {
    exporter_state_t* ex = (exporter_state_t*)ud;
    /* render `name = value` в собственный buffer, потом отдать клиенту scrape'а */
    (void)ex; (void)name; (void)value;
    return 0;  /* 0 продолжить, non-zero остановиться */
}

static void exporter_scrape(const host_api_t* api, exporter_state_t* ex) {
    api->iterate_counters(api->host_ctx, &accumulate, ex);
}
```

`name` — borrowed на время одного callback'а; exporter, который буферизирует имена для async-write на HTTP-сокет, копирует их в собственный storage.

Кадrence scrape'а — задача exporter'а, ядро не имеет встроенного интервала.

---

## Шаг 5. No labels — encode в имя

v1 counter'ы — flat name + uint64. Никаких label'ов, никаких histogram-buckets, никаких gauge'ей. Если exporter хочет Prometheus-style labels, он парсит их обратно из dotted-name'а:

```text
link_tcp.dial_fail.timeout  ->  link_tcp_dial_fail{reason="timeout"}
link_tcp.dial_fail.refused  ->  link_tcp_dial_fail{reason="refused"}
```

Это решение exporter'а, не провайдера. Провайдер просто эмитит structured names.

Для значений, которые могут уменьшаться (active conn count, queue depth), counter не подходит — они монотонные. Future minor releases добавят отдельный `gauge` slot; v1 это закрывает периодическим `set_timer(N_ms, …)` callback'ом, который снимает snapshot и пишет его в собственный (плагин-private) gauge через extension API.

---

## Cross-refs

- [metrics.md](../contracts/metrics.md) — kernel-side counter store, cardinality cap, drop counter discipline.
- [host-api.md §2 + §11](../contracts/host-api.md) — `emit_counter` / `iterate_counters` slot signatures + log surface.
- [limits.md](../contracts/limits.md) — `max_counter_names` and other caps плагин consume'ит.
