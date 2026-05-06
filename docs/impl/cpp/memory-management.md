# C++ implementation guide — управление памятью

C ABI граница не разделяет аллокатор. Каждая сторона освобождает то,
что выделила сама. Этот документ описывает соглашения SDK — borrowed
vs owned, паттерн `out_user_data + out_free`, время жизни vtable'ов
и подписок, типичные баги и как их избежать.

## Содержание

- [Две стороны](#две-стороны)
- [`host_api` соглашение: `out_value + out_user_data + out_free`](#host_api-соглашение-out_value--out_user_data--out_free)
- [Паттерн `ud_destroy`](#паттерн-ud_destroy)
- [Время жизни подписки: RAII-обёртка](#время-жизни-подписки-raii-обёртка)
- [Время жизни vtable'а](#время-жизни-vtableа)
- [Контейнеры с allocator-awareness](#контейнеры-с-allocator-awareness)
- [Borrowed-указатели (`@borrowed`)](#borrowed-указатели-borrowed)
- [Owned-указатели (`@owned`)](#owned-указатели-owned)
- [In-out параметры (`@in-out`)](#in-out-параметры-in-out)
- [Типичные баги](#типичные-баги)
- [Перекрёстные ссылки](#перекрёстные-ссылки)

## Две стороны

Аллокаторы ядра и плагина — разные. На macOS / Linux они даже могут
быть из разных libc-реализаций (например, плагин слинкован с
mimalloc, ядро — с системной glibc). Прохождение указателя через ABI
не даёт права противоположной стороне его освободить.

Правило: **свободит тот, кто аллоцировал**.

Из этого вытекают все остальные паттерны.

## `host_api` соглашение: `out_value + out_user_data + out_free`

Когда ядру нужно вернуть плагину кусок памяти, который оно выделило
само (например, строковое значение из конфига), сигнатура entry-функции
содержит три out-параметра:

```c
gn_result_t (*config_get)(void* host_ctx,
                          const char* key,
                          gn_config_value_type_t type,
                          size_t index,
                          void* out_value,            /* куда писать саму строку */
                          void** out_user_data,       /* opaque destruction state */
                          void (**out_free)(void* user_data, void* bytes));
```

Плагин-сторона:

```cpp
char*  str_value     = nullptr;
void*  free_ud       = nullptr;
void (*free_fn)(void*, void*) = nullptr;

auto rc = api->config_get(api->host_ctx,
                          "tcp.bind_uri",
                          GN_CONFIG_VALUE_STRING,
                          GN_CONFIG_NO_INDEX,
                          &str_value,
                          &free_ud,
                          &free_fn);
if (rc == GN_OK) {
    std::string copy{str_value};   // плагин копирует в свой аллокатор
    if (free_fn) free_fn(free_ud, str_value);
}
```

`out_user_data` нужен, чтобы non-C языковая привязка могла протащить
своё destruction-state (Rust `Box`, Python-объект, arena-id) через
`void*`-форму, не теряя его. Для C-аллокаций ядро обычно ставит
`free_ud == nullptr` и в `free_fn` кладёт обёртку над `std::free`.

RAII-обёртка для шаблонного использования:

```cpp
class ConfigString {
public:
    ConfigString() = default;

    ~ConfigString() { reset(); }

    ConfigString(ConfigString&& o) noexcept
        : value_{std::exchange(o.value_, nullptr)},
          ud_{std::exchange(o.ud_, nullptr)},
          free_{std::exchange(o.free_, nullptr)} {}

    [[nodiscard]] std::string_view view() const noexcept {
        return value_ ? std::string_view{value_} : std::string_view{};
    }

    /// Доступ к адресам для передачи в `config_get`.
    char**  out_value()     noexcept { return &value_; }
    void**  out_user_data() noexcept { return &ud_; }
    void  (**out_free())(void*, void*) noexcept { return &free_; }

private:
    void reset() noexcept {
        if (free_ && value_) free_(ud_, value_);
        value_ = nullptr; ud_ = nullptr; free_ = nullptr;
    }

    char*  value_{nullptr};
    void*  ud_{nullptr};
    void  (*free_{nullptr})(void*, void*);
};
```

## Паттерн `ud_destroy`

Подписочные entry-функции (`subscribe_conn_state`, `subscribe_config_reload`)
принимают пару `(user_data, ud_destroy)`:

```c
gn_result_t (*subscribe_conn_state)(void* host_ctx,
                                    gn_conn_state_cb_t cb,
                                    void* user_data,
                                    void (*ud_destroy)(void*),
                                    gn_subscription_id_t* out_id);
```

`ud_destroy(user_data)` вызывается ядром **ровно один раз** —
когда подписка снимается через `unsubscribe(id)` или когда ядро
наблюдает истечение plugin-lifetime-якоря (см.
[plugin-lifetime](../../contracts/plugin-lifetime.md) §weak-anchor).

Это инвертирует обычный C++ подход: плагин не пишет destructor для
своей `MyState*`, передаваемой в callback — он передаёт деструктор
как функцию-указатель и уступает ownership ядру:

```cpp
auto* state = new MyState{...};
gn_subscription_id_t id = GN_INVALID_ID;
auto rc = api->subscribe_conn_state(
    api->host_ctx,
    &MyState::trampoline,
    state,
    /*ud_destroy=*/+[](void* ud) { delete static_cast<MyState*>(ud); },
    &id);
if (rc != GN_OK) {
    delete state;        // подписка не создана — обязательно вернуть память
    return rc;
}
// state теперь принадлежит ядру; будет удалён при unsubscribe или teardown.
```

Если `user_data` — статическая структура, можно передать `nullptr` в
`ud_destroy`. Это допустимо, но сужает рефакторинг: позже потребуется
динамический owner — придётся менять signature вызывающего кода.

## Время жизни подписки: RAII-обёртка

Подписка — это `gn_subscription_id_t`. Снять её можно вызовом
`api->unsubscribe(host_ctx, id)`. Класс-обёртка:

```cpp
class Subscription {
public:
    Subscription() = default;

    Subscription(const host_api_t* api, gn_subscription_id_t id) noexcept
        : api_{api}, id_{id} {}

    ~Subscription() { reset(); }

    Subscription(Subscription&&) noexcept;
    Subscription& operator=(Subscription&&) noexcept;
    Subscription(const Subscription&) = delete;
    Subscription& operator=(const Subscription&) = delete;

    void reset() noexcept {
        if (api_ && id_ != GN_INVALID_ID) {
            (void)api_->unsubscribe(api_->host_ctx, id_);
            id_ = GN_INVALID_ID;
        }
    }

    [[nodiscard]] bool active() const noexcept { return id_ != GN_INVALID_ID; }

private:
    const host_api_t*    api_{nullptr};
    gn_subscription_id_t id_{GN_INVALID_ID};
};
```

Аналогичный шаблон применим к `gn_handler_id_t` (отвязывается через
`unregister_vtable`), `gn_link_id_t` (то же), `gn_timer_id_t`
(`cancel_timer`, идемпотентен).

## Время жизни vtable'а

`register_vtable` принимает указатель на `gn_*_vtable_t`. Ядро **не
копирует структуру** — оно держит указатель. Это значит:

- vtable должен жить, пока активен `gn_link_id_t` / `gn_handler_id_t`,
  возвращённый из регистрации.
- безопасно ставить vtable как `static const` или как поле в
  plugin-instance-структуре.
- небезопасно конструировать vtable на стеке функции, которая
  возвращает после регистрации — UAF на следующем kernel-вызове.

`GN_LINK_PLUGIN` решает это автоматически: vtable инстанцируется как
`const` глобал в анонимном namespace плагина:

```cpp
const gn_link_vtable_t _gn_link_kVtable = _gn_link_make_vtable();
```

Время жизни — весь plugin-runtime, что строго больше времени жизни
любого `link_id` под ним.

## Контейнеры с allocator-awareness

`std::vector<uint8_t>`, `std::string`, `std::unique_ptr<T>` —
полностью plugin-side, никогда не передаются ядру по адресу `data()` с
ожиданием освобождения с другой стороны. Когда плагин копирует
inbound-payload в свой буфер, он использует свой обычный аллокатор; на
выход (`send`, `notify_inbound_bytes`) — передаёт `payload` как
borrowed `const uint8_t*`, ядро копирует.

В hot-path можно избежать аллокации совсем:

```cpp
gn_result_t handle_message(const gn_message_t& env) override {
    auto view = std::span{env.payload, env.payload_size};
    process_inplace(view);   // без копирования
    return GN_PROPAGATION_CONTINUE;
}
```

Но handler не может **запомнить** этот указатель: payload borrowed на
время dispatch'а. Нужно сохранить — копируй в `std::vector<uint8_t>`.

## Borrowed-указатели (`@borrowed`)

В SDK заголовках встречается аннотация `@borrowed`. Это значит:
указатель валиден только на время вызова (или на время, явно
указанное в комментарии). После return'а плагин не должен использовать
адрес.

Примеры в `host_api.h`:

- `send(host_ctx, conn, msg_id, payload, payload_size)` — `payload` borrowed; ядро копирует до return'а.
- `query_extension_checked(..., out_vtable)` — вернувшийся
  `*out_vtable` borrowed на время жизни extension provider'а
  (обычно — весь runtime).
- `register_vtable(..., vtable, ...)` — `vtable` borrowed до
  `unregister(id)` returns.

## Owned-указатели (`@owned`)

`@owned` обозначает «callee получает ownership; обязан освободить
парным free-fn». Примеры:

- `gn_secure_buffer_t::bytes` (см. [`sdk/security.h`](../../../sdk/security.h)) — плагин аллоцирует, ядро освобождает через `free_fn(user_data, bytes)`.
- `handshake_open(... out_state)` — handle, который ядро потом
  освобождает через `handshake_close(state)`.

## In-out параметры (`@in-out`)

`@in-out` — caller аллоцирует, callee заполняет:

- `get_endpoint(host_ctx, conn, gn_endpoint_t* out)` — caller выделяет
  на стеке, ядро записывает поля.
- `export_transport_keys(self, state, gn_handshake_keys_t* out_keys)` — caller
  передаёт zero-init'нутый `gn_handshake_keys_t{}` (нужно
  инициализировать `api_size` через паттерн `GN_VTABLE_API_SIZE_FIRST`).

Заполнить `api_size` обязательно перед передачей — это `size-prefix
evolution`, см. [abi-evolution](../../contracts/abi-evolution.md).

## Типичные баги

**Утечка `out_free` (config string).** Плагин читает `STRING`, забывает
вызвать `*out_free(*out_ud, *out_value)`. Симптом — линейный рост RSS
при `subscribe_config_reload` + повторных чтениях. Ловится через
RAII-обёртку (см. выше).

**UAF на vtable-указателе.** Плагин строит `gn_link_vtable_t v{};`
на стеке `register_link()`-функции, регистрирует, возвращает.
Следующий вызов от ядра попадает на освобождённый стек. Симптом — SIGSEGV
с указателем, лежащим в стеке функции, которая давно вышла. Решение —
`static const` или поле в plugin-instance.

**Неотписанный subscriber после unload.** Плагин держит подписку до
момента `gn_plugin_shutdown`, но `ud_destroy` пишет в `MyState`,
который уже delete'нут. Ядро гарантирует weak-anchor (см.
[plugin-lifetime](../../contracts/plugin-lifetime.md) §8): после
shutdown callback'и не диспатчатся, `ud_destroy` гарантированно
вызывается до полного `dlclose`. Но плагин-автору проще RAII'нуть
подписку в `Subscription`-обёртку и не зависеть от kernel-стороны.

**Двойное освобождение `gn_secure_buffer_t::bytes`.** Плагин
заполнил структуру, вернул её ядру через `encrypt(... out)`, и затем
сам же вызвал `free_fn`. Ядро освободит через свой проход — UAF.
Правило: после успешного `return GN_OK` ownership ушёл, плагин на
него больше не смотрит.

**Передача plugin-side `std::vector<uint8_t>` ядру с ожиданием
освобождения.** `data()` через ABI без `free_fn` — это borrowed
view, не транзит ownership. Если ядро должно держать буфер дольше
вызова — нужен паттерн `gn_secure_buffer_t` с `free_fn`.

## Перекрёстные ссылки

- [host-api contract](../../contracts/host-api.md) — каждое entry с
  borrowed/owned аннотацией.
- [plugin-lifetime contract](../../contracts/plugin-lifetime.md) —
  weak-anchor, drain, shutdown ordering.
- [overview](./overview.md) — общая структура C++ обёрток.
- [error-handling](./error-handling.md) — `GN_ERR_OUT_OF_MEMORY`,
  cleanup-guards.
