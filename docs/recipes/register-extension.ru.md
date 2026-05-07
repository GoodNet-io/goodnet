# Recipe: register an extension

## Содержание

- [Цель](#цель)
- [Шаг 1. SDK header для vtable](#шаг-1-sdk-header-для-vtable)
- [Шаг 2. Versioning](#шаг-2-versioning)
- [Шаг 3. Регистрация на стороне provider'а](#шаг-3-регистрация-на-стороне-providerа)
- [Шаг 4. Запрос со стороны consumer'а](#шаг-4-запрос-со-стороны-consumerа)
- [Шаг 5. Lifetime](#шаг-5-lifetime)
- [Пример: gn.peer-info](#пример-gnpeer-info)
- [Cross-refs](#cross-refs)

---

## Цель

Плагин выставляет собственный API другим плагинам через extension registry. Ядро не знает заранее, какие custom-контракты плагины захотят шарить — DHT lookup, peer-info с альтернативными URI, RTT-статистика, forwarding table relay'ы. Все они живут между плагинами; ядро их видит как именованный `const void*` и сверяет только major-версию при выдаче.

Этот рецепт показывает, как опубликовать новый vtable под именем `gn.<area>` и как другой плагин его достаёт.

---

## Шаг 1. SDK header для vtable

Плагин-author объявляет structure в собственном public include — либо в дереве `sdk/extensions/<area>.h` (когда контракт ожидается стабильным и шарится несколькими плагинами), либо внутри своего `include/<plugin>/api.h`. Layout стабилизируется при первой публикации и подчиняется правилам `abi-evolution.md`: первое поле — `uint32_t api_size`, новые поля добавляются перед `_reserved[N]`, ничего не переезжает.

```c
/* include/peer_info/api.h */
#ifndef MY_PEER_INFO_API_H
#define MY_PEER_INFO_API_H

#include <stddef.h>
#include <stdint.h>

#include <sdk/abi.h>
#include <sdk/types.h>

#define GN_EXT_PEER_INFO          "gn.peer-info"
#define GN_EXT_PEER_INFO_VERSION  0x00010000u  /* v1.0 */

typedef struct gn_peer_info_api_s {
    uint32_t api_size;

    /** @return 0 on success, -1 if peer is unknown. */
    int (*lookup_uri)(void* ctx,
                      const uint8_t pk[GN_PUBLIC_KEY_BYTES],
                      char* out_buf, size_t buf_size);

    void* ctx;
    void* _reserved[4];
} gn_peer_info_api_t;

GN_VTABLE_API_SIZE_FIRST(gn_peer_info_api_t);

#endif
```

`ctx` — это provider-side `self` указатель. Каждый entry-point получает его первым аргументом; consumer не разворачивает структуру, а вызывает методы через vtable.

---

## Шаг 2. Versioning

Версия — `uint32_t`, старшие 16 бит — major, младшие — minor. Patch не передаётся через extension API; для документационных правок вообще не двигаем число.

| Изменение в vtable | Что увеличиваем |
|---|---|
| Новое поле перед `_reserved[N]`, остальные signature не тронуты | minor |
| Изменилась signature существующего метода / поле переехало / удалили метод | major |
| Изменились семантика без shape break (e.g. tighter return contract) | minor + log change |

Major bump = новое имя в `name` тоже допустимо (`gn.peer-info` → `gn.peer-info.v2`), если provider хочет одновременно держать обе версии параллельно.

`query_extension_checked` использует `gn_version_compatible` (`sdk/abi.h`): consumer видит провайдера, если major совпадает и provider's minor >= consumer's minor. Старый consumer всегда читает новый provider; новый consumer не читает старый provider.

---

## Шаг 3. Регистрация на стороне provider'а

Provider регистрирует vtable из `gn_plugin_register` (фаза 5 жизненного цикла). До `gn_plugin_init` host_api ещё не передан, после `gn_plugin_unregister` слот закроют.

```c
typedef struct peer_info_state_s {
    /* плагин-private state */
} peer_info_state_t;

static int peer_info_lookup_uri(void* ctx,
                                const uint8_t pk[GN_PUBLIC_KEY_BYTES],
                                char* out_buf, size_t buf_size) {
    peer_info_state_t* st = (peer_info_state_t*)ctx;
    /* ... */
    return 0;
}

static gn_peer_info_api_t g_vtable;
static peer_info_state_t  g_state;
static const host_api_t*  g_api;

gn_result_t gn_plugin_register(void* self) {
    g_vtable.api_size   = sizeof(g_vtable);
    g_vtable.lookup_uri = &peer_info_lookup_uri;
    g_vtable.ctx        = &g_state;

    return g_api->register_extension(g_api->host_ctx,
                                     GN_EXT_PEER_INFO,
                                     GN_EXT_PEER_INFO_VERSION,
                                     &g_vtable);
}
```

Возможные failure modes:

| Условие | Result |
|---|---|
| `name == NULL` или `vtable == NULL` | `GN_ERR_NULL_ARG` |
| Под этим `name` уже зарегистрирован другой vtable | `GN_ERR_LIMIT_REACHED` |
| Иначе | `GN_OK` |

Имя — стабильный C-string, живущий всю lifetime'у плагина-провайдера. Ядро не копирует строку и держит указатель, поэтому литерал в read-only сегменте подходит, динамическая строка — только если plugin её не освободит до `unregister_extension`.

---

## Шаг 4. Запрос со стороны consumer'а

Consumer достаёт vtable в любой момент после своего `gn_plugin_init`. Provider может ещё не существовать в момент запроса — это normal case при partial load order.

```c
static const gn_peer_info_api_t* g_peer_info;

static void resolve_peer_info(const host_api_t* api) {
    const void* vt = NULL;
    gn_result_t r = api->query_extension_checked(api->host_ctx,
                                                 GN_EXT_PEER_INFO,
                                                 GN_EXT_PEER_INFO_VERSION,
                                                 &vt);
    switch (r) {
        case GN_OK:
            g_peer_info = (const gn_peer_info_api_t*)vt;
            break;
        case GN_ERR_NOT_FOUND:
            /* provider not loaded — fall back to direct dial */
            g_peer_info = NULL;
            break;
        case GN_ERR_VERSION_MISMATCH:
            /* provider too old / too new — operator config drift */
            g_peer_info = NULL;
            break;
        default:
            g_peer_info = NULL;
            break;
    }
}
```

Различение `NOT_FOUND` и `VERSION_MISMATCH` — намеренное. Первое значит «provider не загружен в этой сборке», второе — «provider есть, но major не подходит». Реакция consumer'а на эти два случая обычно разная: на `NOT_FOUND` — graceful degradation, на `VERSION_MISMATCH` — operator alert.

Возвращённый указатель `@borrowed`: его lifetime привязан к provider'у. Consumer не должен ретейнить копию через перезагрузку provider'а (см. ниже).

---

## Шаг 5. Lifetime

Provider снимает регистрацию двумя путями:

1. Явно через `host_api->unregister_extension(host_ctx, "gn.peer-info")` — например, когда плагин хочет перезарегистрироваться под другой версией, не выгружаясь сам.
2. Автоматически — при `gn_plugin_unregister` ядро через lifetime-anchor (`plugin-lifetime.md` §4) проходит по плагин-owned subscriptions / extensions / handlers / links и снимает их.

Consumer, держащий cached vtable pointer, должен либо подписаться на FSM-события `plugin-lifetime.md` для invalidation, либо ре-резолвить через `query_extension_checked` перед каждым critical use, либо принять, что provider стабилен на всё время сборки (типичный случай для in-tree плагинов).

`unregister_extension` идемпотентен — снятие отсутствующего имени возвращает `GN_ERR_NOT_FOUND`, без побочных эффектов.

---

## Пример: gn.peer-info

Provider — гипотетический peer-info плагин — публикует таблицу известных peer'ов с альтернативными URI:

```c
/* In peer-info plugin: */
gn_result_t gn_plugin_register(void* self) {
    peer_info_state_t* st = (peer_info_state_t*)self;
    st->vtable.api_size   = sizeof(st->vtable);
    st->vtable.lookup_uri = &peer_info_lookup_uri;
    st->vtable.ctx        = st;
    return st->api->register_extension(st->api->host_ctx,
                                       GN_EXT_PEER_INFO,
                                       GN_EXT_PEER_INFO_VERSION,
                                       &st->vtable);
}
```

Consumer — relay-direct upgrade (`relay-direct`) — на `TRUST_UPGRADED` для relay'ной conn'и достаёт альтернативные URI и пытается прямой dial:

```c
/* In relay-upgrade plugin's TRUST_UPGRADED handler: */
char uri[256];
if (g_peer_info && g_peer_info->lookup_uri(g_peer_info->ctx,
                                           ev->remote_pk,
                                           uri, sizeof(uri)) == 0) {
    /* dial uri through link API */
}
```

Никакого глобального registry с типизированной семантикой ядро не держит — оно видит лишь `("gn.peer-info", 0x00010000) -> const void*`. Layout vtable'а — приватный контракт между provider'ом и consumer'ом.

---

## Cross-refs

- [host-api.md §2 (Extension API)](../contracts/host-api.en.md) — slot definitions для `register_extension` / `query_extension_checked` / `unregister_extension`.
- [extension-model](../architecture/extension-model.ru.md) — почему extensions, namespace conventions, anti-patterns.
- [relay-direct](../architecture/relay-direct.ru.md) — пример consumer-side use case.
- [plugin-lifetime.md §4](../contracts/plugin-lifetime.en.md) — auto-reap registrations через lifetime-anchor.
- [abi-evolution.md §3](../contracts/abi-evolution.en.md) — size-prefix evolution для vtable shape.
