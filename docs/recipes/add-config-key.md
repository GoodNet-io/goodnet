# Recipe: add a config key

## Содержание

- [Цель](#цель)
- [Шаг 1. Schema convention](#шаг-1-schema-convention)
- [Шаг 2. Read через config_get](#шаг-2-read-через-config_get)
- [Шаг 3. Default fallback](#шаг-3-default-fallback)
- [Шаг 4. Reload subscription](#шаг-4-reload-subscription)
- [Шаг 5. ud_destroy для teardown](#шаг-5-ud_destroy-для-teardown)
- [Пример: heartbeat.interval_ms](#пример-heartbeatinterval_ms)
- [Cross-refs](#cross-refs)

---

## Цель

Плагину нужно собственное operator-controlled значение — interval таймера, путь к сертификату, capacity dedup-таблицы. Этот рецепт показывает, как читать config через типизированный slot, как реагировать на reload без рестарта плагина и как корректно владеть памятью string-значений.

Конфигурация ядра — один JSON-документ; плагины читают листья по dotted-path ключу через `host_api->config_get`. Своего JSON-парсера у плагина нет.

---

## Шаг 1. Schema convention

Плагин владеет namespace'ом `<plugin-name>.<key>` под top-level. Базовые ключи `limits.*` и `log.*` парсит ядро; всё остальное — opaque JSON, который ядро отдаёт через `config_get` без интерпретации. Ключи переданные в `config_get` — dotted-path; ядро резолвит их под shared lock.

Heartbeat кладёт под `heartbeat.*`, TLS link — под `links.tls.*`, гипотетический relay — под `relay.*`. Конфликтов между плагинами ядро не разруливает; namespace выбирает плагин-author и публикует его в собственном README.

Embedding application свободно сидит свой namespace до загрузки плагина — ядро игнорирует unknown top-level ключи на load. Это позволяет один JSON-документ держать config для всех плагинов одного развёртывания.

---

## Шаг 2. Read через config_get

Slot `config_get` типизированный: плагин на каждом чтении заявляет, какой тип ожидает (`INT64` / `BOOL` / `DOUBLE` / `STRING` / `ARRAY_SIZE`). Если live-значение в дереве не того типа — ядро возвращает `GN_ERR_INVALID_ENVELOPE`, а не молча zero-fill'ит результат.

```c
#include <sdk/host_api.h>

static int64_t read_interval_ms(const host_api_t* api, int64_t fallback) {
    int64_t out_value = 0;
    gn_result_t r = api->config_get(api->host_ctx,
                                    "heartbeat.interval_ms",
                                    GN_CONFIG_VALUE_INT64,
                                    GN_CONFIG_NO_INDEX,
                                    &out_value,
                                    /* out_user_data */ NULL,
                                    /* out_free      */ NULL);
    if (r == GN_OK) return out_value;
    return fallback;
}
```

Для `STRING`-чтения out-of-the-box передаётся пара `out_user_data` + `out_free`: ядро аллоцирует buffer (NUL-terminated), плагин освобождает его через `(*out_free)(out_user_data, out_value)`. Разделение деструкционного state'а от function pointer'а позволяет binding'ам non-C языков (Rust `Box`, Python object) cleanly hand back capture'нутый handle.

```c
char* path = NULL;
void* ud = NULL;
void (*free_fn)(void*, void*) = NULL;

gn_result_t r = api->config_get(api->host_ctx,
                                "links.tls.cert_path",
                                GN_CONFIG_VALUE_STRING,
                                GN_CONFIG_NO_INDEX,
                                &path,
                                &ud,
                                &free_fn);
if (r == GN_OK) {
    /* use `path` */
    free_fn(ud, path);   /* mandatory release */
}
```

`out_free` обязателен для `STRING`-чтений и запрещён для остальных типов: передача `NULL` для STRING вернёт `GN_ERR_NULL_ARG`, передача non-NULL для INT64/BOOL/DOUBLE/ARRAY_SIZE — тоже `GN_ERR_NULL_ARG`. Асимметрия специально: tooling видит, что слот не предполагает деструктор там, где его не нужно.

---

## Шаг 3. Default fallback

`config_get` отсутствующего ключа возвращает `GN_ERR_NOT_FOUND`. Это normal case: плагин-default значение остаётся в коде, операторская конфигурация только переопределяет. Никакого warning'а ядро при этом не пишет — schema discovery ляжет в v1.1 (`config.md` §7).

```c
#define MY_PLUGIN_DEFAULT_INTERVAL_MS  30000

static int64_t resolve_interval(const host_api_t* api) {
    int64_t v = read_interval_ms(api, MY_PLUGIN_DEFAULT_INTERVAL_MS);

    /* clamp against limits — operator может выставить безумно высокое значение */
    const gn_limits_t* lim = api->limits(api->host_ctx);
    if (lim && lim->max_timers > 0 && v < 100) {
        v = 100;  /* плагин-side floor */
    }
    return v;
}
```

Если у плагина есть hard-bound по каким-то limit'ам (max payload, max storage value), сверка с `host_api->limits` идёт сразу после чтения. Сами cross-field инварианты ядро уже проверило при `load_json` (`config.md` §3): на момент `config_get` `gn_limits_t` уже консистентен.

---

## Шаг 4. Reload subscription

Operator может вызвать `Kernel::reload_config` или `reload_config_merge` без рестарта kernel'а. Плагины узнают про это через `subscribe_config_reload`:

```c
static void on_config_reload(void* user_data) {
    plugin_state_t* st = (plugin_state_t*)user_data;
    int64_t new_interval = resolve_interval(st->api);

    if (new_interval != st->interval_ms) {
        /* пересоздать timer / переподнять connection / etc. */
        st->interval_ms = new_interval;
        rearm_heartbeat_timer(st);
    }
}

static gn_subscription_id_t g_reload_sub = GN_INVALID_SUBSCRIPTION_ID;

gn_result_t gn_plugin_register(void* self) {
    plugin_state_t* st = (plugin_state_t*)self;
    return st->api->subscribe_config_reload(st->api->host_ctx,
                                            &on_config_reload,
                                            /* user_data    */ st,
                                            /* ud_destroy   */ NULL,
                                            &g_reload_sub);
}
```

Callback запускается на kernel-side reload thread'е *синхронно* перед возвратом из `Kernel::reload_config` — payload отсутствует. Плагин внутри callback'а ре-читает свои ключи через `config_get` и обновляет local state.

Subscriber должен быть дешёвым; долгая работа постится через `host_api->set_timer(0, …)` на service executor (`timer.md`).

---

## Шаг 5. ud_destroy для teardown

`subscribe_config_reload` принимает четвёртый параметр — `ud_destroy`, опциональный деструктор для `user_data`. Ядро вызовет его ровно один раз: когда subscription снимается через `unsubscribe(out_id)` или когда lifetime-anchor плагина закрывается на shutdown.

```c
static void plugin_state_destroy(void* ud) {
    plugin_state_t* st = (plugin_state_t*)ud;
    /* free здесь, если state был heap-allocated и shared между subscription'ами */
    free(st);
}
```

Если `user_data` владеется самим плагином через статический storage или per-plugin handle, `ud_destroy` оставляют `NULL`. Передача non-NULL обязательна только когда subscription is the sole owner данных, на которые она указывает (например, замыкание из FFI binding'а).

---

## Пример: heartbeat.interval_ms

Плагин heartbeat читает интервал PING на инициализации, держит default `30000`, переподнимает таймер на reload:

```c
typedef struct heartbeat_state_s {
    const host_api_t*    api;
    gn_timer_id_t        timer;
    int64_t              interval_ms;
    gn_subscription_id_t reload_sub;
} heartbeat_state_t;

static int64_t heartbeat_read_interval(const host_api_t* api) {
    int64_t v = 0;
    gn_result_t r = api->config_get(api->host_ctx,
                                    "heartbeat.interval_ms",
                                    GN_CONFIG_VALUE_INT64,
                                    GN_CONFIG_NO_INDEX,
                                    &v, NULL, NULL);
    return (r == GN_OK && v > 0) ? v : 30000;
}

static void on_heartbeat_reload(void* ud) {
    heartbeat_state_t* st = (heartbeat_state_t*)ud;
    int64_t v = heartbeat_read_interval(st->api);
    if (v != st->interval_ms) {
        st->api->cancel_timer(st->api->host_ctx, st->timer);
        st->interval_ms = v;
        /* rearm — shown in instrument-with-metrics recipe */
    }
}

gn_result_t gn_plugin_init(const host_api_t* api, void** out_self) {
    heartbeat_state_t* st = calloc(1, sizeof(*st));
    if (!st) return GN_ERR_OUT_OF_MEMORY;
    st->api         = api;
    st->interval_ms = heartbeat_read_interval(api);
    *out_self       = st;
    return GN_OK;
}

gn_result_t gn_plugin_register(void* self) {
    heartbeat_state_t* st = (heartbeat_state_t*)self;
    return st->api->subscribe_config_reload(st->api->host_ctx,
                                            &on_heartbeat_reload,
                                            st, NULL,
                                            &st->reload_sub);
}
```

Operator кладёт в JSON:

```jsonc
{
    "heartbeat": { "interval_ms": 5000 }
}
```

После `Kernel::reload_config` плагин видит новое значение и перерегистрирует таймер.

---

## Cross-refs

- [config.md](../contracts/config.md) — schema, validation, reload semantics.
- [host-api.md §2.1](../contracts/host-api.md) — `config_get` typed read, out_free contract.
- [limits.md](../contracts/limits.md) — kernel-side `gn_limits_t` поля, cross-field инварианты.
- [conn-events.md §3](../contracts/conn-events.md) — semantics для `subscribe_config_reload` (та же subscription model).
- [timer.md §3](../contracts/timer.md) — куда постить долгую reload-side работу.
