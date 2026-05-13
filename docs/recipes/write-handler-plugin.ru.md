# Recipe: написать handler-плагин

**Status:** active · v1
**Owner:** plugin authors
**Last verified:** 2026-05-06

---

## Содержание

1. Цель
2. Что нужно
3. Шаг 1. Scaffold
4. Шаг 2. Манифест распространения
5. Шаг 3. `gn_plugin_init` и удержание `host_api`
6. Шаг 4. `handle_message` и propagation
7. Шаг 5. `supported_msg_ids`
8. Шаг 6. Регистрация в `gn_plugin_register`
9. Шаг 7. Снятие регистрации и `gn_plugin_shutdown`
10. Шаг 8. Сборка и установка
11. Проверка
12. Cross-refs

---

## 1. Цель

Handler — это плагин, который реагирует на envelope с конкретным
`(protocol_id, msg_id)`. GoodNet выстраивает таких плагинов в
priority-цепочку и пропускает по ней входящее сообщение, пока кто-то
не вернёт `GN_PROPAGATION_CONSUMED`.

В этом рецепте мы напишем echo-handler: на сообщение `msg_id = 0x100`
по протоколу `gnet-v1` он отправит обратно тот же payload и завершит
дальнейший разбор цепочкой.

---

## 2. Что нужно

Минимальная поверхность handler-плагина состоит из пяти C-символов
(`sdk/plugin.h`):

| Символ | Фаза | Роль |
|---|---|---|
| `gn_plugin_sdk_version` | 3 | сообщить SDK-триплет |
| `gn_plugin_init` | 4 | сохранить `host_api*`, разместить `self` |
| `gn_plugin_register` | 5 | вызвать `register_vtable(GN_REGISTER_HANDLER, …)` |
| `gn_plugin_unregister` | 8 | снять регистрацию |
| `gn_plugin_shutdown` | 9 | освободить ресурсы `self` |

Плюс одна структура: `gn_handler_vtable_t` из `sdk/handler.h` с тремя
обязательными слотами (`protocol_id`, `supported_msg_ids`,
`handle_message`) и тремя опциональными (`on_result`, `on_init`,
`on_shutdown`).

---

## 3. Шаг 1. Scaffold

GoodNet поставляет генератор скелета — он раскладывает каталог,
прописывает CMake-таргет `add_plugin`, standalone `flake.nix`,
`default.nix`, плейсхолдер-тест и stub'ы README/LICENSE:

```sh
nix run .#new-plugin -- handlers echo
```

После запуска появляется `plugins/handlers/echo/` со следующим
составом:

```
plugins/handlers/echo/
├── CMakeLists.txt        # add_plugin(goodnet_handler_echo …)
├── default.nix           # derivation, потребляющая goodnet-core
├── flake.nix             # standalone dev / build / test apps
├── echo.cpp              # entry-точки + descriptor
├── tests/
│   ├── CMakeLists.txt
│   └── test_echo.cpp
├── README.md
└── LICENSE               # placeholder; заменить до merge
```

Скелет запускается под собственным `git init`; remote'ом служит локальный
mirror в `~/.local/share/goodnet-mirrors/handler-echo.git` до тех пор,
пока плагин не уезжает в свой репозиторий организации.

---

## 4. Шаг 2. Манифест распространения

Каждый собранный `.so` сопровождается per-package JSON-манифестом
`<libfile>.json` (см. [plugin-manifest.md](../contracts/plugin-manifest.en.md) §8).
Для echo он выглядит так:

```json
{
  "meta": {
    "name":        "goodnet-handler-echo",
    "type":        "handler",
    "version":     "1.0.0-rc1",
    "description": "Echo handler for msg_id 0x100",
    "timestamp":   "2026-05-06T10:00:00Z"
  },
  "integrity": {
    "alg":  "sha256",
    "hash": "<64-hex SHA-256 of the .so>"
  }
}
```

Per-package JSON собирается из `<so>` инструментом `goodnet plugin hash`
автоматически. Trust root — operator-manifest со списком
`(path, sha256)` пар (§2 plugin-manifest). Подпись Ed25519 поверх
operator-manifest — отдельный шаг, выполняется снаружи ядра до v1.1
(§7).

---

## 5. Шаг 3. `gn_plugin_init` и удержание `host_api`

`gn_plugin_init` получает `host_api*`, у которого уже выставлен
`api->host_ctx`. Плагин сохраняет указатель в свою `self` и больше
ничего не регистрирует — registration живёт в фазе 5
(`plugin-lifetime.md` §5).

```c
#include <stdlib.h>
#include <string.h>
#include <sdk/plugin.h>
#include <sdk/host_api.h>
#include <sdk/handler.h>
#include <sdk/convenience.h>

typedef struct echo_self_s {
    const host_api_t*       api;
    gn_handler_vtable_t     vt;
    uint64_t                handler_id;
    uint32_t                msg_ids[1];
} echo_self_t;

static const char* echo_protocol_id(void* self) {
    (void)self;
    return "gnet-v1";
}

GN_PLUGIN_EXPORT void gn_plugin_sdk_version(uint32_t* major,
                                            uint32_t* minor,
                                            uint32_t* patch) {
    *major = GN_SDK_VERSION_MAJOR;
    *minor = GN_SDK_VERSION_MINOR;
    *patch = GN_SDK_VERSION_PATCH;
}

GN_PLUGIN_EXPORT gn_result_t gn_plugin_init(const host_api_t* api,
                                            void** out_self) {
    if (!api || !out_self) return GN_ERR_NULL_ARG;

    echo_self_t* self = calloc(1, sizeof(*self));
    if (!self) return GN_ERR_OUT_OF_MEMORY;

    self->api        = api;
    self->msg_ids[0] = 0x100u;

    self->vt.api_size          = sizeof(self->vt);
    self->vt.protocol_id       = echo_protocol_id;
    self->vt.supported_msg_ids = NULL;   /* выставим ниже */
    self->vt.handle_message    = NULL;   /* выставим ниже */

    *out_self = self;
    return GN_OK;
}
```

`api` валиден до возврата из `gn_plugin_shutdown` — захватывать его в
process-global запрещено (`plugin-lifetime.md` §9): плагин может быть
hot-reload'нут.

---

## 6. Шаг 4. `handle_message` и propagation

`handle_message` вызывается синхронно. `envelope->payload` borrowed на
время вызова — копировать только если нужно удержать байты дольше.
Возврат — `gn_propagation_t`:

| Значение | Семантика |
|---|---|
| `GN_PROPAGATION_CONTINUE` | передать envelope следующему handler в цепочке |
| `GN_PROPAGATION_CONSUMED` | остановить цепочку — обработано |
| `GN_PROPAGATION_REJECT` | отбросить envelope и закрыть connection |

```c
static gn_propagation_t echo_handle_message(void* self_v,
                                            const gn_message_t* env) {
    echo_self_t* self = self_v;

    /* §3a: handler, читающий env->conn_id, обязан толерировать
       GN_INVALID_ID как CONTINUE — никогда REJECT. */
    if (env->conn_id == GN_INVALID_ID) {
        return GN_PROPAGATION_CONTINUE;
    }

    gn_result_t r = gn_send(self->api, env->conn_id,
                            env->msg_id,
                            env->payload, env->payload_size);
    if (r != GN_OK) {
        gn_log_warn(self->api, "echo: send failed: %s", gn_strerror(r));
    }
    return GN_PROPAGATION_CONSUMED;
}
```

Контракт: `handle_message` не имеет права бросать исключения сквозь
C-границу. Ошибки `host_api->send` обрабатывает сам плагин — как
правило, лог + метрика; closing connection здесь делает ядро.

---

## 7. Шаг 5. `supported_msg_ids`

Ядро запрашивает массив один раз при регистрации. Указатель должен
жить столько же, сколько сам handler — обычно держим внутри `self`:

```c
static void echo_supported_msg_ids(void* self_v,
                                   const uint32_t** out_ids,
                                   size_t* out_count) {
    echo_self_t* self = self_v;
    *out_ids   = self->msg_ids;
    *out_count = sizeof(self->msg_ids) / sizeof(self->msg_ids[0]);
}
```

`msg_id == 0` зарезервирован под unset sentinel; `0x11` — под
attestation dispatcher. Регистрация против них вернёт
`GN_ERR_INVALID_ENVELOPE`. Полная таблица —
[handler-registration.md](../contracts/handler-registration.en.md) §2a.

---

## 8. Шаг 6. Регистрация в `gn_plugin_register`

Регистрация — единственная фаза, где можно дёргать
`register_vtable`. Используем удобную обёртку `gn_register_handler` из
`sdk/convenience.h`, которая упаковывает `gn_register_meta_t` за нас:

```c
GN_PLUGIN_EXPORT gn_result_t gn_plugin_register(void* self_v) {
    echo_self_t* self = self_v;

    self->vt.supported_msg_ids = echo_supported_msg_ids;
    self->vt.handle_message    = echo_handle_message;
    /* on_result / on_init / on_shutdown оставляем NULL: цепочка
       вызовет их транзитно, пустая реализация не нужна. */

    const uint8_t priority = 128;   /* application default */
    return gn_register_handler(self->api,
                               "gnet-v1", 0x100u, priority,
                               &self->vt, self,
                               &self->handler_id);
}
```

`priority` — целое в диапазоне 0..255, дефолт приложения 128, fallback
0, observability 64, pin-eligible 255. Хвостовой `priority`-битик
определяет порядок на одном `(protocol_id, msg_id)`; равные приоритеты
получают envelope в порядке регистрации.

`*out_id` несёт kind-tag в верхних 4 битах — `unregister_vtable(id)`
сам найдёт правильный registry.

---

## 9. Шаг 7. Снятие регистрации и `gn_plugin_shutdown`

Симметрия фаз 8 → 9. `unregister` снимает handler из цепочки для
будущих диспетчей; in-flight цепочки доходят до конца на снимке
старого вектора (`plugin-lifetime.md` §6). После завершения
quiescence-wait ядро вызывает `gn_plugin_shutdown` — теперь можно
освобождать память, в которую могли смотреть посекундные продолжения.

```c
GN_PLUGIN_EXPORT gn_result_t gn_plugin_unregister(void* self_v) {
    echo_self_t* self = self_v;
    return gn_unregister_handler(self->api, self->handler_id);
}

GN_PLUGIN_EXPORT void gn_plugin_shutdown(void* self_v) {
    echo_self_t* self = self_v;
    free(self);
    /* host_api после возврата трогать нельзя. */
}
```

Никаких worker-тредов, переживающих `gn_plugin_shutdown`: ядро
выгрузит `.so` сразу же, и любая запоздавшая callback-функция
сослалась бы на размапленный код.

---

## 10. Шаг 8. Сборка и установка

```sh
cd plugins/handlers/echo
nix develop                # вход в plugin shell
nix run .#test             # Release-сборка + ctest (плейсхолдер тест)
nix run .#test-asan        # ASan/UBSan
nix run .#test-tsan        # TSan
nix run .#build            # просто сборка, артефакты в ./build/
```

Установка в композит-ноду — через основной flake ядра или через
оператор-манифест: путь до `.so` + SHA-256 заносится в JSON-документ,
который ядро читает перед `dlopen`. Empty manifest — developer-mode,
все плагины грузятся без проверки. Production:
`set_manifest_required(true)` + non-empty manifest, mismatch ⇒
`GN_ERR_INTEGRITY_FAILED`.

---

## 11. Проверка

1. Поднять пару нод (`nix run .#run -- node`) с загруженным
   echo-плагином.
2. Послать с одной ноды envelope `(protocol_id="gnet-v1",
   msg_id=0x100, payload="ping")` в адрес второй.
3. Убедиться, что вторая нода отправила обратно
   envelope с тем же payload и тем же `msg_id`.
4. На приёмнике handler вернул `CONSUMED`; цепочка lower-priority
   handler'ов traffic не увидела (можно проверить регистрацией
   `priority=64` метрик-watcher'а).

---

## 12. Cross-refs

- [handler-registration.md](../contracts/handler-registration.en.md) —
  семантика регистрации, priority, цепочка диспетчеризации,
  reserved msg_id'ы, `conn_id` контракт §3a.
- [plugin-lifetime.md](../contracts/plugin-lifetime.en.md) — фазы 3..10,
  два-фазная активация, weak-observer pattern.
- [plugin-manifest.md](../contracts/plugin-manifest.en.md) — operator
  manifest, per-package JSON, integrity-check ordering.
- [host-api.md](../contracts/host-api.en.md) — `register_vtable`,
  `send`, `is_shutdown_requested`.
- [plugin-model](../architecture/plugin-model.ru.md) — общая
  архитектурная картина: где живут handler/link/security в граф-схеме
  ядра.
