# Экосистема и процесс разработки

GoodNet — это не один репозиторий. Это семейство независимых единиц,
живущих каждая в своём git'е, собирающихся каждая своим Nix flake,
выходящих каждая своим темпом. Эта глава описывает, как они
сочетаются, и как выбрать правильную единицу под конкретную задачу.

Существующие
[`overview`](overview.ru.md), [`plugin-model`](plugin-model.ru.md) и
[`host-api-model`](host-api-model.ru.md) описывают компоненты при
взгляде «как они уложены в работающий узел». Здесь — взгляд «как
они появляются на свет».

## Содержание

- [Шесть единиц](#шесть-единиц)
- [Дерево решения «куда писать»](#дерево-решения-куда-писать)
- [Почему каждая единица — отдельный git](#почему-каждая-единица---отдельный-git)
- [Цикл разработки плагина](#цикл-разработки-плагина)
- [Цикл разработки app'а](#цикл-разработки-appа)
- [Цикл разработки binding'а](#цикл-разработки-bindingа)
- [Композиция узла оператором](#композиция-узла-оператором)
- [Auto-discover и тесты](#auto-discover-и-тесты)
- [Релизный паттерн](#релизный-паттерн)
- [Что пока не закрыто](#что-пока-не-закрыто)

## Шесть единиц

| Единица | Где живёт | Лицензия | Чему служит |
|---|---|---|---|
| **Kernel** | `goodnet-io/kernel` (репо платформы) | GPL-2 + linking exception | C ABI таблица + 4 vtable-реестра + executor + signal bus |
| **Static plugin** | внутри kernel git'а под `plugins/protocols/<name>/` | GPL-2 (часть kernel binary) | Обязательные wire-слои: gnet (mesh-framing), raw (passthrough) |
| **Loadable plugin** | `goodnet-io/<kind>-<name>/` per плагин | GPL-2 + LE (стратегические) или MIT (периферия) или Apache-2 (TLS-OpenSSL) | handler / link / security / extension через `register_*`, dlopen'ятся ядром при старте |
| **App** | `goodnet-io/<app-name>/` per app | MIT по умолчанию | Operator-side бинари: используют kernel как library через `sdk/core.h` + `bridges/<lang>/`. Например `gssh`, `goodnet-panel`, `goodnet-store`. |
| **Binding** | `goodnet-io/bridges-<lang>/` per язык | MIT | Per-language consumer wrapper над capi (RAII в C++, ownership-transfer в Rust, etc). Сейчас shipped: `bridges/cpp/` |
| **Integration-tests** | `goodnet-io/integration-tests` | MIT | Cross-plugin + cross-app тесты что требуют нескольких компонентов поднять одновременно |

Все шесть слотов чекаут'ятся внутри kernel checkout'а — в
`plugins/<kind>/<name>/`, `bridges/<lang>/`, `tests/integration/`.
Каждый имеет собственный `.git/`, собственный `flake.nix`,
собственный `LICENSE`. Kernel git их `.gitignore`'ит — nested .git
не auto-register'ятся как submodule'ы.

## Дерево решения «куда писать»

```
Хочу добавить <thing>. Куда?
│
├─ <thing> = новый wire-протокол (gnet/raw альтернатива)?
│  → static plugin: kernel git, plugins/protocols/<name>/
│
├─ <thing> = новый transport (TCP/UDP/WS/IPC/TLS/ICE альтернатива)?
│  → loadable plugin, kind=link: goodnet-io/link-<name>/
│
├─ <thing> = новый security provider (Noise alternative)?
│  → loadable plugin, kind=security: goodnet-io/security-<name>/
│
├─ <thing> = новый message handler (heartbeat/discovery/dht style)?
│  → loadable plugin, kind=handler: goodnet-io/handler-<name>/
│
├─ <thing> = plugin-to-plugin coordination API (peer-info, autonat,
│            relay-control)?
│  → extension в существующем плагине (если он его публикует) ИЛИ
│    standalone handler-плагин с extension surface
│
├─ <thing> = operator-facing binary (CLI tool, daemon, demo)?
│  → app: goodnet-io/<app-name>/, использует sdk/core.h + bridges/<lang>/
│
├─ <thing> = язычный wrapper для capi (Rust / Python / Zig client)?
│  → binding: goodnet-io/bridges-<lang>/
│
└─ <thing> = тест требующий нескольких плагинов одновременно?
   → integration-tests: goodnet-io/integration-tests, под tests/<topic>/
```

Если ответ ни один не подошёл — обычно это значит, что предлагаемая
вещь должна быть несколькими отдельными единицами. Например
«rich peer-discovery system» = handler-plugin (mDNS scanner) +
extension `gn.peer-info` + app `goodnet-explore`.

## Почему каждая единица — отдельный git

Разные темпы разработки. Plugin для нового transport может
иметь rapid iteration (несколько раз в день), kernel ABI
заморожен после rc1 — релизный темп раз в полгода. Если они в
одном git'е — каждый rebase плагина тащит kernel и наоборот.

Разные лицензии. Strategic плагины (tcp/noise/heartbeat) под GPL-2
для anti-enclosure. Apps и bindings — MIT чтобы downstream пользователи
не вынуждены отдавать свой код. TLS plugin — Apache-2 для совместимости
с OpenSSL. Один монорепо смешает лицензии — путаница для contributor'а.

Разные контрибьютеры. Plugin для proprietary corporate transport
может разрабатываться внутри компании. Если он fork'ится из
kernel monorepo, любая правка тащит всю историю.

Разные deployment'ы. Operator может встроить только нужные плагины
через `goodnet.lib.compose`. Один монорепо означал бы что operator
тащит все source'ы независимо от того что включает в свой image.

[Plugin standalone pilot 2026-05-05](../../README.md) — pilot
доказал модель: standalone flake ~120 LOC, monorepo build ✅,
plugin-own тесты ✅. После него mass-applied на все 8 loadable
плагинов + bridges/cpp + integration-tests.

## Цикл разработки плагина

```
                    new-plugin scaffold
                            │
                            ↓
                  plugin own git initialised
                            │
                            ↓
                Bare mirror at ~/.local/share/goodnet-mirrors/
                            │
                            ↓
   ┌────────────────────────────────────────────────────────┐
   │  Внутри plugin checkout, итерация:                     │
   │   • write code in <plugin>.cpp                         │
   │   • nix run .#test (plugin's own ctest)                │
   │   • nix run .#test-tsan (TSan stress)                  │
   │   • commit на dev                                      │
   │  Kernel suite от этого ничего не пересобирает.         │
   └────────────────────────────────────────────────────────┘
                            │
                            ↓
                  feat/<topic> ветка → --no-ff → dev
                            │
                            ↓
                  push origin dev (на mirror)
                            │
                            ↓
   ┌────────────────────────────────────────────────────────┐
   │  В kernel checkout (`~/Desktop/projects/GoodNet/`):    │
   │   • plugins/CMakeLists.txt уже знает про слот          │
   │   • nix run .#test от kernel root запускает все:       │
   │     kernel + 8 plugin'ов + integration-tests           │
   │   • если plugin сломал contract — kernel suite falls   │
   └────────────────────────────────────────────────────────┘
                            │
                            ↓
            при rc1: dev → main + tag в plugin git'е
                            │
                            ↓
          push origin main → goodnet-io/<repo>
```

### Конкретные команды

```bash
# 1. Scaffold нового плагина (создаёт plugins/<kind>/<name>/ skeleton)
nix run .#new-plugin -- links my-transport
# или: handler / security / protocols (для статических wire layers)

# 2. Зайти в plugin checkout
cd plugins/links/my-transport

# 3. Итерация
nix run .#test           # vanilla ctest
nix run .#test-asan      # ASan + UBSan
nix run .#test-tsan      # TSan
nix run .#build          # Release build only

# 4. Коммиты в plugin's own git (dev branch по умолчанию)
git add . && git commit -m "..."

# 5. Bare mirror setup один раз
git clone --bare $(pwd) ~/.local/share/goodnet-mirrors/link-my-transport.git
git remote add origin ~/.local/share/goodnet-mirrors/link-my-transport.git

# 6. Из kernel root — full suite
cd ../../..
nix run .#test  # kernel + все плагины + integration-tests
```

Подробный walkthrough: см.
[`recipes/write-link-plugin.md`](../recipes/write-link-plugin.ru.md),
[`write-handler-plugin.md`](../recipes/write-handler-plugin.ru.md),
[`write-security-plugin.md`](../recipes/write-security-plugin.ru.md).

### Контракты, которые плагин должен соблюдать

- [`link.md`](../contracts/link.en.md) — link плагин: vtable shape,
  shutdown semantics, single-writer, trust class declaration
- [`handler-registration.md`](../contracts/handler-registration.en.md) —
  handler плагин: msg_id range, propagation values, lifetime
- [`security-trust.md`](../contracts/security-trust.en.md) — security
  plugin: handshake driver, single-active-per-trust-class,
  attestation hooks
- [`plugin-lifetime.md`](../contracts/plugin-lifetime.en.md) — все
  плагины: 5 entry symbols, init/register/run/unregister/shutdown
- [`plugin-manifest.md`](../contracts/plugin-manifest.en.md) — manifest
  + Ed25519 signature, signed-by-vendor verify

## Цикл разработки app'а

App — это operator-side binary. Использует kernel как library через
capi (`sdk/core.h`) или через C++ binding (`bridges/cpp/`). Не
плагин — kernel не dlopen'ит app, app dlopen'ит kernel.

```
                    app's own git initialised
                            │
                            ↓
   ┌────────────────────────────────────────────────────────┐
   │  В app checkout:                                       │
   │   • flake.nix имеет goodnet input → kernel-only        │
   │     subflake. Ровно так же как plugin.                 │
   │   • app/CMakeLists.txt: find_package(GoodNet) +        │
   │     target_link_libraries(my-app PRIVATE               │
   │         GoodNet::cpp GoodNet::sdk goodnet_kernel)      │
   │   • main.cpp: gn::cpp::Core core; core.init(); ...     │
   │   • nix run .#build / nix run .#test                   │
   └────────────────────────────────────────────────────────┘
                            │
                            ↓
            при rc1: dev → main + tag в app git'е
                            │
                            ↓
          push origin main → goodnet-io/<app-name>
```

App не register'ит handlers через kernel registry runtime. App
получает уже работающий kernel и:

- Открывает соединения через `gn_core_connect` или
  `Core::connect(uri, scheme)`
- Подписывается на conn-events через `subscribe_conn_state`
- Регистрирует свой handler через `gn_core_register_handler` —
  это handler app'а в kernel'е, отдельно от loadable плагинов
- Регистрирует свой extension через `gn_core_register_extension`,
  если хочет exposed'ить API другим плагинам / app'ам

App'ы что shipped:

- **`goodnet`** (operator multicall) — kernel-side ops:
  `run`, `identity gen|show`, `manifest gen`, `plugin hash`,
  `config validate`, `version`. Этот один — внутри kernel git'а
  потому что работает с kernel internals, не consumer.
- **`gssh`** — SSH-over-GoodNet tunnel: `gssh user@<peer-pk>`,
  `gssh --bridge`, `gssh --listen`. Свой git, MIT, использует
  `bridges/cpp` + `sdk/core.h`.

Подробный walkthrough: см.
[`recipes/test-plugin.md`](../recipes/test-plugin.ru.md) +
[`impl/cpp/cmake-integration.md`](../impl/cpp/cmake-integration.ru.md).

## Цикл разработки binding'а

Binding — это per-language consumer wrapper над `sdk/core.h`. Делает
capi идиоматичной для целевого языка: RAII в C++, ownership-transfer
в Rust, GIL-aware в Python.

`bridges/cpp/` — header-only INTERFACE target, MIT, exposes
`gn::cpp::Core`, `Connection`, `Subscription`, `Error`. App'ы
линкуются через `target_link_libraries(my-app PRIVATE GoodNet::cpp)`.

```
                    binding's own git initialised
                            │
                            ↓
   ┌────────────────────────────────────────────────────────┐
   │  В binding checkout:                                   │
   │   • flake.nix → kernel-only subflake input             │
   │   • CMakeLists.txt INTERFACE target                    │
   │   • headers (или модуль для языка) — wraps capi        │
   │   • tests/test_compile.cpp (или ekvivalent) —          │
   │     standalone smoke что каждый header компилируется   │
   │   • nix run .#test — отдельный compile-test            │
   └────────────────────────────────────────────────────────┘
                            │
                            ↓
   ┌────────────────────────────────────────────────────────┐
   │  В kernel root: kernel CMakeLists подбирает binding:   │
   │   if(EXISTS bridges/cpp/CMakeLists.txt)                │
   │       add_subdirectory(bridges/cpp)                    │
   │   endif()                                              │
   │   ↓                                                    │
   │   GoodNet::cpp target живёт когда binding checkout'ан, │
   │   и app'ы которые его требуют (gssh) собираются        │
   │   автоматически. Без binding checkout'а apps просто    │
   │   skip'аются (их CMakeLists guard'ятся через           │
   │   TARGET GoodNet::cpp).                                │
   └────────────────────────────────────────────────────────┘
```

Сейчас shipped: `cpp`. Roadmap: `rust`, `python`, `zig`, `go`.

Конвенция repo naming: `bridges-<lang>` (без `goodnet-` префикса
per [`feedback_goodnet_repo_naming`](../../README.md)).

## Композиция узла оператором

Оператор не пишет код. Он пишет **flake** который собирает узел из
готовых единиц. Пример типичного operator flake:

```nix
{
  description = "my-corporate-mesh node";

  inputs = {
    goodnet.url = "github:goodnet-io/kernel";
    link-tcp.url = "github:goodnet-io/link-tcp";
    link-ice.url = "github:goodnet-io/link-ice";
    security-noise.url = "github:goodnet-io/security-noise";
    handler-heartbeat.url = "github:goodnet-io/handler-heartbeat";
    # Custom in-house transport plugin
    link-corporate-fabric.url = "github:my-org/link-fabric";
  };

  outputs = { self, goodnet, link-tcp, link-ice, security-noise,
              handler-heartbeat, link-corporate-fabric, ... }:
    let
      pkgs = import goodnet.inputs.nixpkgs { system = "x86_64-linux"; };
    in {
      packages.x86_64-linux.default = goodnet.lib.compose pkgs {
        kernel  = goodnet.packages.x86_64-linux.goodnet-core;
        plugins = [
          link-tcp.packages.x86_64-linux.default
          link-ice.packages.x86_64-linux.default
          security-noise.packages.x86_64-linux.default
          handler-heartbeat.packages.x86_64-linux.default
          link-corporate-fabric.packages.x86_64-linux.default
        ];
        config   = ./config/node.json;
        identity = ./secrets/identity.bin;
      };
    };
}
```

`goodnet.lib.compose` собирает derivation который:

- Кладёт kernel binary в `bin/goodnet`
- Кладёт plugin .so файлы в `lib/goodnet/plugins/`
- Bundlers config + identity рядом
- Wrapper скрипт `bin/goodnet-node` invoke'ит binary с
  правильными путями

`nix run .#default` стартует узел. `nix build .#default` даёт
ready-to-deploy artifact для systemd / docker / kubernetes.

## Auto-discover и тесты

Kernel ctest pool **автоматически подбирает тесты** из всех
checked-out единиц рядом с собой:

- `plugins/<kind>/<name>/CMakeLists.txt` — kernel root's
  `plugins/CMakeLists.txt` имеет `if(EXISTS ...) add_subdirectory(...)`
  ladder, который пропускает отсутствующие слоты и подключает
  присутствующие. Plugin's own tests/ → `tests/CMakeLists.txt` →
  `gtest_discover_tests` → ctest.
- `bridges/<lang>/CMakeLists.txt` — kernel root has
  `if(EXISTS bridges/cpp/CMakeLists.txt) add_subdirectory(bridges/cpp)`.
  Binding's tests добавляются в общий pool.
- `tests/integration/CMakeLists.txt` — integration-tests overlay,
  pulled via setup script. Kernel ctest видит integration tests
  как обычные тесты.

Запуск `nix run .#test` от kernel root прогоняет всё что
checked-out: kernel-only тесты + 8 plugin тестов + bindings smoke
+ integration suite. Без чекаут'а каких-то — просто skipped через
`if(EXISTS)` guard. Без фейков, без mocks — каждый тест запускается
в своей реальной среде.

Plugin author работает в plugin checkout: `nix run .#test` там
прогоняет ТОЛЬКО plugin's own тесты + kernel-only subflake build —
быстрая итерация.

`feedback_no_test_filters` правило сюда применимо: всегда full
run, никаких `ctest -E` / `--gtest_filter` exclude'ов. Тест либо
есть и запускается, либо нет вообще.

## Релизный паттерн

Kernel и каждая loadable единица версионятся независимо.

| Тэг | Что означает |
|---|---|
| `kernel/v1.0.0-rc1` | ABI freeze. После этого тэга `host_api_t`, `gn_link_vtable_t`, `gn_handler_vtable_t`, `gn_security_provider_vtable_t`, `gn_message_t` shape — стабильны. Любая правка идёт через `_reserved` слот + `api_size` gating per [`abi-evolution.md`](../contracts/abi-evolution.en.md) |
| `link-tcp/v0.5.0` | Plugin's own version. Plugin может бампать без kernel rebump'а пока остаётся compatible с kernel ABI |
| `bridges-cpp/v0.1.0` | Binding's version. Может опережать или отставать от kernel — пока его headers компилируются с kernel ABI |
| `gssh/v0.1.0` | App's version. Зависит от binding ABI и kernel capi |

При `rc1` каждая единица:

1. Замораживает свой ABI (если у неё public ABI — kernel,
   plugin extension surface, binding header)
2. Закрывает open backlog (memory's known issues)
3. Tag в local mirror: `git tag rc1`
4. Push на github org: `git push github rc1`
5. github org repo создаётся (`goodnet-io/<kind>-<name>`) если
   ещё нет

Composition (operator flake'и) после rc1 ссылаются на
`github:goodnet-io/kernel/v1.0.0-rc1` и т.д. до этого — на local
mirror'ах через `git+file:` (deprecated Nix форма, но pre-rc1
acceptable).

Domain `goodnet-io` зарегистрируется как `goodnet.io` parallel.
Org doc + landing page при rc1.

## Что пока не закрыто

Из видимых пробелов в экосистеме на момент write'а этой главы:

**Tooling:**
- [ ] `nix run .#scaffold-binding -- <lang>` для bridges/<lang>/
  scaffold по аналогии с `new-plugin`
- [ ] `nix run .#scaffold-app -- <name>` для apps/<name>/ scaffold
- [ ] `nix run .#publish` который автоматизирует push на github org

**Bindings:**
- [ ] `bridges/rust/` (пакет `goodnet-rs`) — Rust crate с RAII
  wrappers
- [ ] `bridges/python/` (модуль `goodnet`) — Python ctypes / cffi
- [ ] `bridges/zig/` — Zig wrapper, header-only
- [ ] `bridges/go/` — Go wrapper через cgo

**Apps:**
- [ ] `goodnet-store` — distributed key-value (port из legacy)
- [ ] `goodnet-panel` — операторская dashboard на Crow + HTMX
- [ ] `goodnet-explore` — peer discovery TUI

**Plugins:**
- [ ] `link-quic` — UDP-based stream transport, low-latency
  alternative TCP'ю
- [ ] `link-bluetooth` — BT/BLE scatternet для local-first mesh
- [ ] `handler-dht` — distributed peer-info store
- [ ] `security-pq` — post-quantum kex (Kyber)

**Documentation:**
- [ ] Глава про operator deployment (systemd unit'ы, docker,
  kubernetes operator)
- [ ] Глава про monitoring / observability surface
- [ ] Глава про testing strategy: unit + integration + conformance

**Composition:**
- [ ] `goodnet.lib.composeMultiNode` — собирает test-кластер из N
  узлов в single derivation для regression testing
- [ ] `goodnet.lib.bench` — стандартный bench harness для
  cross-plugin perf comparison

Эти TBD-пункты документируют, куда экосистема растёт. Все они —
независимые единицы, каждая может быть запущена параллельно.

## Cross-references

- [`overview`](overview.ru.md) — kernel = ABI table + 4 vtable kinds + executor
- [`plugin-model`](plugin-model.ru.md) — четыре роли плагина
- [`host-api-model`](host-api-model.ru.md) — KIND-tagged minimalism
- [`extension-model`](extension-model.ru.md) — plugin↔plugin coordination
- [`recipes/write-handler-plugin.md`](../recipes/write-handler-plugin.ru.md) —
  пошаговое создание handler плагина
- [`recipes/write-link-plugin.md`](../recipes/write-link-plugin.ru.md) —
  link plugin walkthrough
- [`impl/cpp/cmake-integration.md`](../impl/cpp/cmake-integration.ru.md) —
  как app или binding линкуются с kernel/SDK
- [`contracts/plugin-lifetime.md`](../contracts/plugin-lifetime.en.md) —
  lifecycle invariants
- [`contracts/abi-evolution.md`](../contracts/abi-evolution.en.md) — ABI
  правила pre-rc1 vs post-rc1
