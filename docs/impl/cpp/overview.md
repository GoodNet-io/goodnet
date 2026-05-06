# C++ implementation guide — обзор

Plugin author пишет плагин на C++ против header-only обёрток в
`sdk/cpp/`. Эти обёртки превращают C ABI границу с ядром в идиоматичный
C++23: `std::span`, `std::expected`, RAII-handles, концепты для
плагин-классов. Документ описывает SDK boundaries, доступные обёртки,
паттерны жизненного цикла и ограничения, которые накладывает
прохождение через `extern "C"`.

## Содержание

- [Цель](#цель)
- [SDK boundaries](#sdk-boundaries)
- [Заголовки `sdk/cpp/`](#заголовки-sdkcpp)
- [RAII-паттерны](#raii-паттерны)
- [Trampoline-паттерн](#trampoline-паттерн)
- [Компилятор и стандарт](#компилятор-и-стандарт)
- [Перекрёстные ссылки](#перекрёстные-ссылки)

## Цель

C++ автор плагина:

1. Определяет один класс с известной формой методов (см. концепт ниже
   и `link_plugin.hpp` файл-заголовок).
2. Один раз инстанцирует макрос `GN_LINK_PLUGIN(MyLink, "tcp")` или
   аналог для своего kind.
3. Получает на выходе готовый `lib<name>.so` с пятью обязательными
   `extern "C"` точками входа, vtable-thunk'ами для kernel-facing C
   ABI и зарегистрированным extension'ом `gn.link.<scheme>` /
   `gn.handler.<protocol>`.

Плагин не пишет boilerplate и не объявляет `extern "C"` руками. Все
скучные части — диспетчинг через `void* self`, `try/catch`-щиты на
границе ABI, генерация дескриптора плагина — спрятаны в обёртке.

## SDK boundaries

Граница с ядром — C ABI. Только C-типы пересекают её: `gn_message_t`,
`gn_result_t`, `host_api_t`, `gn_*_vtable_t`. Это позволяет одному
ядру загружать плагины, написанные на разных языках (C, C++, Rust,
Zig), без runtime-рантайма.

Обёртки `sdk/cpp/*.hpp` живут на стороне плагина. Это header-only
inline-шаблоны — плагин компилирует их в свою TU, ядро ничего о них
не знает. После `make install` обёртки попадают в
`include/sdk/cpp/`.

Лицензионная граница: ядро поставляется под GPL-2 с linking-exception,
SDK заголовки (включая `sdk/cpp/`) — под MIT. Это значит, что плагин,
который линкует только `GoodNet::sdk`, не наследует GPL.

## Заголовки `sdk/cpp/`

| Заголовок | Назначение |
|---|---|
| `types.hpp` | `MessageView`, `PublicKey`, `Result<T>`, `Error` |
| `handler.hpp` | абстрактный класс `IHandler` для message-обработчиков |
| `link_plugin.hpp` | макрос `GN_LINK_PLUGIN(Class, scheme)` — собирает link-плагин |
| `link.hpp` | абстрактный интерфейс `ILink` |
| `protocol_layer.hpp` | shape для protocol-layer плагинов (frame/deframe) |
| `log.hpp` | `GN_LOGF_*` макросы поверх `std::format` |
| `convenience.hpp` | C++-обёртки над host_api операциями |
| `wire.hpp`, `uri.hpp`, `dns.hpp` | утилитарные парсеры, общие на стороне плагина |
| `capability_tlv.hpp` | TLV-кодек для capability-объявлений |

## RAII-паттерны

Обёртки управляют идентификаторами регистраций и подписок через RAII.
В destructor'е плагин-класса автоматически отпускается всё, что было
взято — даже если producer забыл вызвать `unregister`.

Базовый паттерн:

```cpp
class Subscription {
public:
    Subscription() = default;

    Subscription(const host_api_t* api, gn_subscription_id_t id) noexcept
        : api_{api}, id_{id} {}

    Subscription(Subscription&& other) noexcept
        : api_{other.api_}, id_{std::exchange(other.id_, GN_INVALID_ID)} {}

    Subscription& operator=(Subscription&& other) noexcept {
        if (this != &other) { reset(); api_ = other.api_;
            id_ = std::exchange(other.id_, GN_INVALID_ID); }
        return *this;
    }

    ~Subscription() { reset(); }

private:
    void reset() noexcept {
        if (api_ && id_ != GN_INVALID_ID) {
            (void)api_->unsubscribe(api_->host_ctx, id_);
        }
        id_ = GN_INVALID_ID;
    }

    const host_api_t*    api_{nullptr};
    gn_subscription_id_t id_{GN_INVALID_ID};
};
```

Тот же узор применим к `gn_handler_id_t`, `gn_link_id_t`,
`gn_timer_id_t`. См. [memory-management](./memory-management.md) §subscription-lifetime.

## Trampoline-паттерн

C ABI vtable принимает указатели на свободные функции. C++ методы
имеют скрытый `this`, который через `extern "C"` не пройдёт. Решение —
trampoline: статическая C-функция, диспатчит на C++ метод через
`void* self`, который ядро передаёт первым аргументом.

`GN_LINK_PLUGIN` делает это автоматически:

```cpp
gn_result_t _gn_link_send(void* self, gn_conn_id_t conn,
                          const std::uint8_t* bytes, size_t size) noexcept {
    if (!self) return GN_ERR_NULL_ARG;
    if (!bytes && size > 0) return GN_ERR_NULL_ARG;
    try {
        return _gn_link_of(self).send(
            conn, std::span<const std::uint8_t>(bytes, size));
    } catch (...) {
        return GN_ERR_NULL_ARG;
    }
}
```

Три инварианта trampoline'а:

1. **`noexcept` + `try/catch` всегда.** Исключение не должно
   пересечь C ABI границу. Если поймали — возвращается `gn_result_t`
   код. См. [error-handling](./error-handling.md) §no-exceptions.
2. **NULL-checks перед dereference.** `self`, payload-указатели,
   out-параметры проверяются до диспатча.
3. **Аргументы оборачиваются в C++-типы.** `const uint8_t* + size_t`
   становится `std::span<const std::uint8_t>` до того, как plugin-код
   их видит.

Если автор пишет свой kind-плагин (не link/handler), он повторяет ту
же форму руками. Ориентир — `link_plugin.hpp`.

## Компилятор и стандарт

- **C++23**, gcc 15+ (для `std::format`, `std::expected`,
  `std::span` с deduction guides). Clang 18+ работает на чтение, но
  кодовая база ядра собирается gcc15.
- **`-fno-exceptions` не нужен**, но за пределы плагина исключения не
  выходят.
- **PIC обязательна** — все плагины компилируются в `.so`. Этот
  флаг ставит `add_plugin()` автоматически.
- **Скрытая видимость по-умолчанию.** Только пять `gn_plugin_*`
  символов экспортируются (атрибут `GN_PLUGIN_EXPORT`). Это уменьшает
  размер `.so` и устраняет конфликты имён между плагинами.

## Перекрёстные ссылки

- [error-handling](./error-handling.md) — gn_result_t,
  std::expected, перенос ошибок через C ABI.
- [memory-management](./memory-management.md) — owned/borrowed,
  out_user_data + out_free, vtable lifetime.
- [clock](./clock.md) — инъекция времени для тестируемости.
- [cmake-integration](./cmake-integration.md) —
  `find_package(GoodNet)`, `add_plugin()`.
- [plugin-model](../../architecture/plugin-model.md) — какие kind'ы
  плагинов существуют, как ядро их грузит.
- [write-handler-plugin](../../recipes/write-handler-plugin.md) —
  пошаговый рецепт первого handler-плагина.
- [host-api](../../contracts/host-api.md) — полная спецификация
  vtable, которую обёртки скрывают.
