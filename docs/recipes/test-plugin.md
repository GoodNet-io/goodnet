# Recipe: test a plugin

## Содержание

- [Цель](#цель)
- [Шаг 1. SDK conformance contracts](#шаг-1-sdk-conformance-contracts)
- [Шаг 2. Plugin test scaffold](#шаг-2-plugin-test-scaffold)
- [Шаг 3. INSTANTIATE_TYPED_TEST_SUITE_P](#шаг-3-instantiate_typed_test_suite_p)
- [Шаг 4. Build и run](#шаг-4-build-и-run)
- [Шаг 5. Kernel internals не exported](#шаг-5-kernel-internals-не-exported)
- [Шаг 6. Integration tests](#шаг-6-integration-tests)
- [Шаг 7. CI invariant — full ctest](#шаг-7-ci-invariant--full-ctest)
- [Cross-refs](#cross-refs)

---

## Цель

Каждый loadable plugin живёт как независимая единица сборки и теста: внутри директории плагина — собственный `flake.nix`, собственный `tests/`, собственный `nix run .#test`. Ядро не запускает cross-plugin runner; failure в conformance плагина появляется в `nix run .#test` его own checkout'а, не в kernel'ной сборке.

Kernel-side conformance contracts — typed-test шаблоны в `sdk/test/conformance/<contract>.hpp`. Плагин instantiate'ит шаблон со своим типом и получает универсальный body теста — kernel-author'ы видят failure под своим именем плагина, не «one anonymous link broke».

Этот рецепт показывает, как написать conformance test для плагина, как разнести его собственный test suite от kernel-internal тестов, как запустить full ctest без anti-pattern'ных фильтров.

---

## Шаг 1. SDK conformance contracts

`sdk/test/conformance/link_teardown.hpp` определяет `LinkTeardownConformance` — typed-test, проверяющий, что `Link::shutdown()` фаерит `notify_disconnect` синхронно на caller-thread'е для каждой опубликованной через `notify_connect` сессии. Это контракт `link.md` §9 step 3.

Шаблон состоит из:

1. `ConformanceHost` — host-stub с in-memory implementation `notify_connect` / `notify_inbound_bytes` / `notify_disconnect` / `kick_handshake`.
2. `LinkPlugin` concept — compile-time gate, проверяющий, что plugin type выставляет `listen` / `connect` / `shutdown` / `set_host_api` с правильной signature'ой.
3. `LinkTraits<L>` — traits-template, который плагин специализирует: `scheme`, `make()`, `listen_uri()`, `connect_uri(port)`, `wire_credentials(server, client)`.
4. `LinkTeardownConformance<L>` — fixture с одним `TYPED_TEST_P` body'ем `ShutdownReleasesEverySession`.

Other conformance headers будут добавляться по мере вырастания SDK; pattern одинаковый — header в `sdk/test/conformance/`, плагин instantiate'ит со своим типом.

---

## Шаг 2. Plugin test scaffold

Шаблон создаётся `nix run .#plugin -- new` (см. apps store): команда раскладывает базовый `tests/test_<plugin>_conformance.cpp` с stub'ом и matching `tests/CMakeLists.txt`.

Внутри директории плагина layout выглядит так:

```text
plugins/links/mylink/
├── flake.nix
├── default.nix
├── CMakeLists.txt
├── src/
│   └── mylink.cpp
├── include/
│   └── mylink/
│       └── mylink.hpp
└── tests/
    ├── CMakeLists.txt
    └── test_mylink_conformance.cpp
```

`tests/CMakeLists.txt` подцепляет gtest, sdk headers, kernel-static-archive (для doctested SDK utilities) и собственный source plugin'а как library под test'ом.

---

## Шаг 3. INSTANTIATE_TYPED_TEST_SUITE_P

Body теста живёт в SDK header'е — плагин выписывает только trait specialisation и instantiation:

```cpp
// tests/test_mylink_conformance.cpp
#include <gtest/gtest.h>

#include <sdk/test/conformance/link_teardown.hpp>
#include <mylink/mylink.hpp>

namespace gn::test::link::conformance {

template <>
struct LinkTraits<::MyLink> {
    static constexpr const char* scheme = "my";

    static std::shared_ptr<::MyLink> make() {
        return std::make_shared<::MyLink>();
    }

    static std::string listen_uri() {
        return "my://127.0.0.1:0";
    }

    static std::string connect_uri(std::uint16_t port) {
        return "my://127.0.0.1:" + std::to_string(port);
    }

    static bool wire_credentials(::MyLink& server, ::MyLink& client) {
        // если link требует pre-shared креды (TLS cert, Noise static key) —
        // выписать их сюда. Plain TCP / IPC — return true без работы.
        (void)server; (void)client;
        return true;
    }
};

}  // namespace gn::test::link::conformance

INSTANTIATE_TYPED_TEST_SUITE_P(MyLink,
                               gn::test::link::conformance::LinkTeardownConformance,
                               ::testing::Types<::MyLink>);
```

`*_P` family (parameterised typed test) использован специально, чтобы body жил в SDK header без ODR-violation — каждый instantiating translation unit получает собственный suite name через первый макро-аргумент.

`LinkTraits<L>::wire_credentials` обязателен даже для link'ов без креденшалов (возвращает `true` как no-op). `listen_uri()` для TCP-class transport'а кладёт `:0` чтобы kernel allocate'ил порт; `connect_uri(port)` затем подставляет actual port из `server->listen_port()`. IPC bind'ит path, не порт — fixture знает про этот special case через `if constexpr (requires { server->listen_port(); })`.

---

## Шаг 4. Build и run

Внутри plugin checkout'а:

```bash
nix run .#test
```

Vanilla Release-build, full ctest. Output должен быть зелёным под `100% tests passed`.

ASan / TSan варианты — отдельные subcommand'ы:

```bash
nix run .#test -- asan      # AddressSanitizer
nix run .#test -- tsan      # ThreadSanitizer
nix run .#test -- all       # release + asan + tsan последовательно
```

Каждый sanitizer вариант пере-собирает плагин с соответствующими флагами и прогоняет full ctest. Sanitizer fail в conformance test (e.g. teardown race под TSan) появляется в plugin's own gate'е, не в kernel sweep'е.

Под капотом app-runner — это умbrella `flake.nix` с одинаковым shape'ом для всех плагинов; команда `nix run .#test -- tsan` делает `cmake -DCMAKE_BUILD_TYPE=TSan` и затем `ctest --output-on-failure`.

---

## Шаг 5. Kernel internals не exported

Часть тестов остаётся в kernel git-tree, потому что они дёргают приватный kernel-internal API, который не выставлен через SDK:

| Test | Где живёт | Почему не в плагине |
|---|---|---|
| `tests/unit/plugin/test_plugin_manager.cpp` | kernel | дёргает `PluginManager` напрямую |
| `tests/unit/integration/test_router_*.cpp` | kernel | внутренний `Router` API |
| `tests/unit/test_signal_channel.cpp` | kernel | internal SignalChannel template |

Эти тесты прогоняются с kernel'ьного `nix run .#test` и часто требуют `GOODNET_NULL_PLUGIN_PATH` env, указывающего на собранный null-security `.so` для loader-side smoke test'ов.

Плагин не имеет доступа к этим внутренностям — это and's design: plugin author пишет conformance против опубликованных SDK contract'ов, kernel author верифицирует internal API через kernel-side тесты.

---

## Шаг 6. Integration tests

Cross-plugin integration tests — в отдельном sibling git'е `goodnet-integration-tests`. Он pull'ится в kernel checkout'а в `tests/integration/` slot тем же `install-plugins` mechanism'ом, что и обычные плагины.

Тесты, которые требуют `noise + tcp + kernel` или другой комбинации больше одного плагина, живут там. Они не привязаны к одному плагин-owner'у; failure требует расследования у обоих участников.

Запускаются тем же `nix run .#test` из kernel checkout'а — kernel CMake glob подхватывает их автоматически после `setup`.

```bash
# в kernel checkout'е
nix run .#setup    # подтянет integration-tests sibling
nix run .#test     # full ctest, включая integration
```

---

## Шаг 7. CI invariant — full ctest

**Никаких фильтров.**

Запрещено:

```bash
ctest -E SlowTests              # exclude pattern
ctest -L unit                   # label filter
GTEST_FILTER='-Slow.*' ctest    # gtest exclude
ctest 2>&1 | grep -v warning    # output filter
ctest 2>&1 | head -50           # output truncation
```

Эти паттерны прячут проблемы. Sanitizer-only race, который воспроизводится только под TSan, ляжет в `--gtest_filter='-Race.*'` и release-only race, который проявляется только в parallel run, ляжет в `ctest -j 1`. Filtering = anti-pattern.

Если test медленный, есть три легальные опции:

1. **Терпеть.** Full ctest ~ minutes — это бюджет, не блокер.
2. **Пускать в фоне.** `nix run .#test &` — и работать с другими задачами.
3. **Сделать тест быстрее.** Если test тратит секунды на sleep'ах — переписать на event-driven.

Skipping медленных tests — нет.

---

## Cross-refs

- [plugin-lifetime.md](../contracts/plugin-lifetime.md) — фазы init/register/unregister/shutdown, что валидно тестировать на каждой.
- [link.md](../contracts/link.md) — `link.md §9` shutdown contract, проверяемый `LinkTeardownConformance`.
- [plugin-model](../architecture/plugin-model.md) — почему плагин = independent unit, как layout dictates test placement.
- [host-api.md](../contracts/host-api.md) — host stub'ам нужно implement'ить эти entries для conformance fixture'ов.
- [signal-channel.md §6](../contracts/signal-channel.md) — exception catch / re-entry правила, которые conformance тесты проверяют под TSan.
