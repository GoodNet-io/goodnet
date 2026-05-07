# C++ implementation guide — clock injection

Контракт [clock.md](../../contracts/clock.en.md) требует, чтобы каждый
компонент, который наблюдает время, принимал источник времени как
явный вход. Этот документ объясняет, как удовлетворить инвариант на
C++ — без виртуальных вызовов в hot-path и без зависимости от
`std::chrono::system_clock` в продакшене.

## Содержание

- [Зачем инъекция времени](#зачем-инъекция-времени)
- [Часы ядра](#часы-ядра)
- [Plugin pattern: концепт `Clock`](#plugin-pattern-концепт-clock)
- [`FakeClock` для тестов](#fakeclock-для-тестов)
- [Планирование таймеров](#планирование-таймеров)
- [Wall-clock — отдельный вход](#wall-clock--отдельный-вход)
- [Перекрёстные ссылки](#перекрёстные-ссылки)

## Зачем инъекция времени

Прямой вызов `clock_gettime(CLOCK_MONOTONIC, ...)` или
`std::chrono::steady_clock::now()` внутри plugin-логики делает её
тесты зависимыми от физического времени. Симптомы:

- **Flake под санитайзерами.** TSan / ASan замедляют код в 5–20 раз;
  ratelimit'ер с реальным временем начинает срабатывать в неожиданных
  точках.
- **Медленные тесты.** Тест таймаута на 30 секунд — это 30 секунд
  тестового прогона. Сотня таких тестов превращает CI в
  получасовое ожидание.
- **Скрытые баги.** Тест, который проходит на быстрой машине и падает
  на медленной — это тест, который не диагностирует баг, а диагностирует
  CPU.

Решение: компонент принимает источник времени как параметр
конструктора. В продакшене — обёртка над `host_api`. В тестах —
`FakeClock` с методом `advance()`.

## Часы ядра

Ядро не экспортирует прямой `now_us()` через `host_api_t` в v1.0 —
большая часть time-зависимой логики живёт на стороне ядра (таймеры,
backoff'ы, rekey-расписания) и принимает свои часы внутри. Plugin-код
получает свой источник времени двумя путями:

1. **`host_api->set_timer(delay_ms, fn, ud, &id)`** — относительный
   таймер. Плагин не делает абсолютной арифметики времени, ядро само
   считает дедлайн против своих часов.
2. **Свой `Clock`-параметр для логики, которая не сводится к
   таймерам.** Token-bucket с пополнением раз в N миллисекунд требует
   читать время — плагин принимает `Clock&` в конструкторе.

См. [clock contract](../../contracts/clock.en.md) §3 — список
обязательных и освобождённых от инъекции случаев.

## Plugin pattern: концепт `Clock`

Минимальный концепт:

```cpp
#include <chrono>
#include <concepts>
#include <cstdint>

namespace gn {

/// Strict-monotonic клок с микросекундной гранулярностью.
template<class T>
concept Clock = requires(const T& c) {
    { c.now_us() } noexcept -> std::same_as<std::uint64_t>;
};

/// Продакшен-реализация поверх `steady_clock`. Используется как
/// дефолт-конструктор обёртки в реальном плагине.
class SteadyClock {
public:
    [[nodiscard]] std::uint64_t now_us() const noexcept {
        using namespace std::chrono;
        return duration_cast<microseconds>(
            steady_clock::now().time_since_epoch()).count();
    }
};

} // namespace gn
```

Plugin-класс параметризуется `Clock` через шаблон или принимает по
ссылке через интерфейс — выбор зависит от того, нужно ли подменять
часы между инстансами одного класса:

```cpp
template<gn::Clock ClockT = gn::SteadyClock>
class TokenBucket {
public:
    TokenBucket(double rate_per_sec, double burst, ClockT clock = {})
        : rate_{rate_per_sec}, burst_{burst},
          tokens_{burst}, clock_{std::move(clock)},
          last_us_{clock_.now_us()} {}

    bool try_consume(double n) {
        const auto now_us = clock_.now_us();
        const auto delta_s = (now_us - last_us_) / 1'000'000.0;
        last_us_ = now_us;
        tokens_ = std::min(burst_, tokens_ + delta_s * rate_);
        if (tokens_ < n) return false;
        tokens_ -= n;
        return true;
    }

private:
    double  rate_, burst_, tokens_;
    ClockT  clock_;
    std::uint64_t last_us_;
};
```

Шаблон-форма не платит за виртуальный вызов — `now_us()` инлайнится
в `try_consume()` в release-сборке.

## `FakeClock` для тестов

Удовлетворяет тому же концепту, но возвращает время, контролируемое
тестом:

```cpp
class FakeClock {
public:
    [[nodiscard]] std::uint64_t now_us() const noexcept {
        return now_us_.load(std::memory_order_acquire);
    }

    void advance(std::uint64_t delta_us) noexcept {
        now_us_.fetch_add(delta_us, std::memory_order_release);
    }

    void advance_ms(std::uint64_t delta_ms) noexcept {
        advance(delta_ms * 1'000);
    }

    void set_to(std::uint64_t absolute_us) noexcept {
        now_us_.store(absolute_us, std::memory_order_release);
    }

private:
    std::atomic<std::uint64_t> now_us_{0};
};

static_assert(gn::Clock<FakeClock>);
```

`std::atomic` гарантирует §5 контракта — конкурентное чтение из
тестируемого кода видит монотонную последовательность без блокировки.

Тестовый сценарий:

```cpp
TEST(TokenBucket, RefillsAtConfiguredRate) {
    FakeClock clk;                              // t = 0
    TokenBucket<FakeClock&> bucket{1.0, 5.0, clk};  // 1 tok/s, burst 5

    EXPECT_TRUE(bucket.try_consume(5));         // выпил весь burst
    EXPECT_FALSE(bucket.try_consume(1));        // пусто

    clk.advance_ms(2'000);                      // +2 секунды
    EXPECT_TRUE(bucket.try_consume(2));         // дореф'илился на 2 токена
}
```

Тест выполняется за микросекунды: `advance_ms(2'000)` — это `fetch_add`,
а не `sleep`.

## Планирование таймеров

`host_api->set_timer` принимает `delay_ms` — относительное смещение
от момента вызова. Плагин **никогда не считает** `target_us = now_us +
delta`, потому что:

- ядро уже знает свой `now_us`, плагинская копия может отставать;
- разное `now_us` на двух сторонах ABI приводит к таймерам, которые
  стреляют слишком рано или слишком поздно.

Правильно:

```cpp
gn_timer_id_t id = GN_INVALID_TIMER_ID;
auto rc = api->set_timer(api->host_ctx, /*delay_ms=*/250,
                          &MyPlugin::on_timer_trampoline,
                          /*user_data=*/this, &id);
if (rc != GN_OK) { /* handle */ }
```

Если плагин повторяет таймер периодически (re-arm), он перевзводит
его внутри callback'а — снова через `delay_ms`.

## Wall-clock — отдельный вход

Контракт `clock.md` §6: монотоническое время и календарное —
**два разных входа**. Плагин, которому нужен wall-clock для ISO 8601
лога или ротации ключа в полночь UTC, принимает второй параметр
типа `WallClock` рядом с монотоническим `Clock`. `system_clock` под
NTP скачет назад — вычитать одну `system_clock` из другой для
расчёта интервала запрещено.

## Перекрёстные ссылки

- [clock contract](../../contracts/clock.en.md) — авторитетный инвариант.
- [timer contract](../../contracts/timer.en.md) — `set_timer` /
  `cancel_timer` semantics, weak-observer гарантия для callback'а.
- [overview](overview.ru.md) — общий контекст C++ обёрток.
- [error-handling](error-handling.ru.md) — что вернуть, если
  `set_timer` отказал (`GN_ERR_LIMIT_REACHED`).
