# C++ implementation guide — обработка ошибок

C ABI граница оперирует одним типом возврата — `gn_result_t`. Этот
документ описывает, как C++ плагин-код использует `gn_result_t` на
границе и `std::expected<T, Error>` внутри, как ловить исключения в
trampoline'ах, и какие коды для каких симптомов.

## Содержание

- [`gn_result_t`](#gn_result_t)
- [Список кодов](#список-кодов)
- [C++ обёртки: `Error`, `Result<T>`](#c-обёртки-error-resultt)
- [Исключения не пересекают C ABI](#исключения-не-пересекают-c-abi)
- [`std::expected<T, gn_result_t>` для plugin-internal flow](#stdexpectedt-gn_result_t-для-plugin-internal-flow)
- [Логирование](#логирование)
- [Типичные паттерны](#типичные-паттерны)
- [Перекрёстные ссылки](#перекрёстные-ссылки)

## `gn_result_t`

Единственный тип, которым ядро и плагин обмениваются на C ABI границе.
Полное определение — [`sdk/types.h`](../../../sdk/types.h):

```c
typedef enum gn_result_e {
    GN_OK                     =  0,   /* успех */
    GN_ERR_NULL_ARG           = -1,
    GN_ERR_OUT_OF_MEMORY      = -2,
    GN_ERR_INVALID_ENVELOPE   = -3,
    GN_ERR_NOT_FOUND          = -14,
    GN_ERR_OUT_OF_RANGE       = -15,
    GN_ERR_FRAME_TOO_LARGE    = -16,
    /* ... полный список ниже */
} gn_result_t;
```

Ноль — успех; отрицательные значения — категории неудач. Новые коды
добавляются только в minor-релизах; consumer'ы default-handle'ят
неизвестные значения вместо явного перечисления.

`gn_strerror(rc)` — статическая inline-функция в `sdk/types.h`
возвращает стабильный человекочитаемый литерал для каждого кода. NULL
не возвращает; для неизвестных значений отдаёт
`"unknown gn_result_t"`.

## Список кодов

| Код | Категория | Когда |
|---|---|---|
| `GN_ERR_NULL_ARG` | Контракт | NULL там, где требовался указатель |
| `GN_ERR_OUT_OF_MEMORY` | Ресурс | `malloc` / `new (std::nothrow)` вернул NULL |
| `GN_ERR_INVALID_ENVELOPE` | Контракт | sender_pk == 0, msg_id == 0, `_reserved` ненулевой |
| `GN_ERR_PAYLOAD_TOO_LARGE` | Лимит | payload > `limits.max_payload_bytes` |
| `GN_ERR_FRAME_TOO_LARGE` | Лимит | wire-frame > `kMaxFrameBytes` |
| `GN_ERR_DEFRAME_INCOMPLETE` | Поток | частичный frame, ядро буферизирует |
| `GN_ERR_DEFRAME_CORRUPT` | Поток | magic-mismatch, плохая версия, overflow |
| `GN_ERR_NOT_IMPLEMENTED` | Контракт | вызвана необязательная entry (composer slot) |
| `GN_ERR_VERSION_MISMATCH` | ABI | плагин-major ≠ ядро-major (или extension minor mismatch) |
| `GN_ERR_LIMIT_REACHED` | Лимит | `max_timers` / `max_subscribers` exhausted, дубликат имени |
| `GN_ERR_INVALID_STATE` | Контракт | wrong phase (handshake op после transport, set_timer после shutdown) |
| `GN_ERR_INTEGRITY_FAILED` | Безопасность | manifest mismatch, tampered binary |
| `GN_ERR_INTERNAL` | Внутренняя | исключение пересекло C ABI границу — операция отменена |
| `GN_ERR_NOT_FOUND` | Lookup | config-key absent, registry-id miss, link session miss |
| `GN_ERR_OUT_OF_RANGE` | Контракт | значение вне допустимого диапазона |

`GN_ERR_UNKNOWN_RECEIVER` зарезервирован для router'а и не возвращается из C ABI thunk'ов; см. [host-api](../../contracts/host-api.en.md) §returns.

## C++ обёртки: `Error`, `Result<T>`

`sdk/cpp/types.hpp` определяет два типа для plugin-internal кода:

```cpp
namespace gn {

struct Error {
    gn_result_t code{GN_ERR_NOT_IMPLEMENTED};
    std::string what;
};

template<class T>
using Result = std::expected<T, Error>;

} // namespace gn
```

`Result<T>` — стандартный C++23 `std::expected`, обёрнутый под наш
`Error`. Это plugin-internal API; через C ABI границу проходит только
`gn_result_t` код (без сообщения).

Плагин-уровневая исключение-style ошибка:

```cpp
class GoodNetError : public std::runtime_error {
public:
    GoodNetError(gn_result_t code, std::string ctx)
        : std::runtime_error(std::move(ctx)), code_{code} {}

    [[nodiscard]] gn_result_t code() const noexcept { return code_; }

private:
    gn_result_t code_;
};

inline void expect_ok(gn_result_t rc, std::string ctx = "") {
    if (rc != GN_OK) {
        throw GoodNetError(rc, std::move(ctx));
    }
}
```

`expect_ok` бросает только **внутри** plugin-кода. Trampoline'ы ловят
её и конвертируют обратно в `gn_result_t`.

## Исключения не пересекают C ABI

Каждый callback, фигурирующий в vtable, объявлен `noexcept` и оборачивает тело в
`try/catch(...)`. Любое исключение, которое выскочило бы наружу, превращается
в `gn_result_t` код:

```cpp
gn_result_t _gn_link_send(void* self, gn_conn_id_t conn,
                          const std::uint8_t* bytes, size_t size) noexcept {
    if (!self) return GN_ERR_NULL_ARG;
    if (!bytes && size > 0) return GN_ERR_NULL_ARG;
    try {
        return _gn_link_of(self).send(
            conn, std::span<const std::uint8_t>(bytes, size));
    } catch (const gn::GoodNetError& e) {
        return e.code();
    } catch (const std::bad_alloc&) {
        return GN_ERR_OUT_OF_MEMORY;
    } catch (...) {
        return GN_ERR_INTERNAL;
    }
}
```

`GN_ERR_INTERNAL` — это ядро-видимый сигнал «плагин нарушил
контракт `extern "C"`». Если он возник, операция была отменена до
любых side-effect'ов на стороне ядра. Плагин-автор должен исследовать
причину и не оставлять её в release.

`GN_LINK_PLUGIN` macro делает упрощённую версию: ловит любое
исключение и возвращает `GN_ERR_NULL_ARG`. Для production-плагина с
доменными ошибками рекомендуется не использовать макрос «как есть», а
расширять trampoline'ы своими catch-ветками.

## `std::expected<T, gn_result_t>` для plugin-internal flow

Внутри плагина монадическая форма читается лучше exception-style:

```cpp
gn::Result<MyConfig> load_config(const host_api_t* api) {
    int64_t port = 0;
    auto rc = api->config_get(api->host_ctx, "tcp.port",
                              GN_CONFIG_VALUE_INT64, GN_CONFIG_NO_INDEX,
                              &port, nullptr, nullptr);
    if (rc != GN_OK) return std::unexpected(gn::Error{rc, "tcp.port"});

    if (port <= 0 || port > 65535)
        return std::unexpected(gn::Error{GN_ERR_OUT_OF_RANGE, "tcp.port range"});

    return MyConfig{.port = static_cast<uint16_t>(port)};
}
```

Caller использует C++23 monadic chaining:

```cpp
auto cfg = load_config(api)
    .and_then([&](auto c) { return open_listener(c.port); })
    .or_else([&](gn::Error e) -> gn::Result<int> {
        GN_LOGF_ERROR(api, "init failed: {} ({})",
                      e.what, gn_strerror(e.code));
        return std::unexpected(e);
    });
```

## Логирование

Плагин **никогда** не пишет в `stderr` или `std::clog` напрямую.
Ядро централизует логирование через `host_api->log` — структурный
формат, отгрузка в spdlog, фильтрация по уровню. См.
[`sdk/cpp/log.hpp`](../../../sdk/cpp/log.hpp):

```cpp
GN_LOGF_INFO (api, "session {} accepted from {}", id, peer);
GN_LOGF_WARN (api, "rate-limited: {} drops in 5s", drop_count);
GN_LOGF_ERROR(api, "send failed: {}", gn_strerror(rc));
```

`should_log` короткозамкнут до форматирования: `GN_LOGF_DEBUG` на
INFO-уровне ядра не платит за `std::format_to_n`.

## Типичные паттерны

**Early return на ошибку:**

```cpp
auto rc = api->register_vtable(...);
if (rc != GN_OK) {
    GN_LOGF_ERROR(api, "register failed: {}", gn_strerror(rc));
    return rc;
}
```

**RAII-guard для cleanup при ошибке:**

```cpp
auto* p = new (std::nothrow) MyState{};
if (!p) return GN_ERR_OUT_OF_MEMORY;
auto guard = std::unique_ptr<MyState>{p};   // освобождается на любом return

if (auto rc = init_state(*p); rc != GN_OK) return rc;
if (auto rc = register_state(*p); rc != GN_OK) return rc;

(void)guard.release();   // переход к ownership ядра
return GN_OK;
```

**Идемпотентный unregister.** Контракт ядра: повторный unregister
уже-удалённого id возвращает `GN_OK`. Плагин-destruktor может вызвать
unregister без NULL-чекинга — повтор безопасен.

## Перекрёстные ссылки

- [host-api contract](../../contracts/host-api.en.md) — все коды,
  возвращаемые каждым vtable-entry.
- [plugin-lifetime contract](../../contracts/plugin-lifetime.en.md) —
  что считать ошибкой инициализации.
- [overview](overview.ru.md) — общее место в SDK.
- [memory-management](memory-management.ru.md) — какие коды для
  ошибок выделения / освобождения.
