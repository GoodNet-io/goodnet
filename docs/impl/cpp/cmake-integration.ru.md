# C++ implementation guide — интеграция с CMake

GoodNet поставляет CMake package config, поэтому plugin-автор пишет
короткий `CMakeLists.txt` и получает готовый `.so` с правильными
флагами компиляции, скрытой видимостью, install-правилами. Документ
описывает, как этим пользоваться.

## Содержание

- [`CMakeLists.txt` плагина](#cmakeliststxt-плагина)
- [Экспортируемые таргеты](#экспортируемые-таргеты)
- [`add_plugin()` — собрать `.so`](#add_plugin--собрать-so)
- [Версионирование](#версионирование)
- [Манифест плагина](#манифест-плагина)
- [Статически линкуемые kernel-internal плагины](#статически-линкуемые-kernel-internal-плагины)
- [Standalone Nix-flake на плагин](#standalone-nix-flake-на-плагин)
- [Перекрёстные ссылки](#перекрёстные-ссылки)

## `CMakeLists.txt` плагина

Минимальный out-of-tree плагин:

```cmake
cmake_minimum_required(VERSION 3.28)
project(my_link_plugin CXX)

find_package(GoodNet 1.0 CONFIG REQUIRED)

add_plugin(my_link
    src/my_link.cpp
    src/plugin_entry.cpp
)

# Автор может добавить свои зависимости поверх SDK:
target_link_libraries(my_link PRIVATE OpenSSL::SSL)
```

`find_package(GoodNet 1.0 CONFIG REQUIRED)` подтягивает:

- header-only SDK (`GoodNet::sdk`),
- helper-функцию `add_plugin()`,
- testing-helpers (`GoodNet::test`, `gtest`, и т. д.) — опционально через
  `GoodNetTesting.cmake`.

`CONFIG`-режим обязателен: ядро не предоставляет
FindModule-скрипта. Если ядро установлено в нестандартный prefix,
оператор задаёт `-DCMAKE_PREFIX_PATH=/opt/goodnet` или
`-DGoodNet_DIR=/opt/goodnet/lib/cmake/GoodNet`.

## Экспортируемые таргеты

`GoodNetConfig.cmake` экспортирует три таргета:

| Таргет | Содержимое | Когда линковать |
|---|---|---|
| `GoodNet::sdk` | header-only заголовки `sdk/*.h` и `sdk/cpp/*.hpp` | каждый out-of-tree плагин (handler, link, security, protocol-layer) |
| `GoodNet::kernel` | статическая библиотека ядра + транзитивные deps (asio, libsodium, spdlog, fmt, nlohmann_json, OpenSSL, Threads, dl) | host'ы, которые встраивают ядро в свой бинарник (демо-приложения, embedded-сценарии) |
| `GoodNet::test` | gtest-обёртки и conformance-template'ы из `sdk/test/` | unit-тесты плагина |

`GoodNet::sdk` — `INTERFACE`-таргет: линковка нулевая, путь к заголовкам
плюс минимум флагов компиляции (`cxx_std_23`).

`GoodNet::kernel` нужен только тем, кто собирает свой узел.
Plugin-автору он **не нужен**: плагин загружается ядром в runtime
через `dlopen`, символы ядра разрешаются динамически.

## `add_plugin()` — собрать `.so`

Helper из `cmake/AddPlugin.cmake`:

```cmake
add_plugin(NAME source1 [source2 ...])
```

Что делает:

1. Создаёт SHARED-библиотеку с именем `lib<NAME>.so` (так её
   ищет PluginManager ядра по `dlopen`).
2. Линкует `GoodNet::sdk` — путь к заголовкам ставится автоматически.
3. Включает скрытую видимость (`CXX_VISIBILITY_PRESET hidden`,
   `VISIBILITY_INLINES_HIDDEN ON`) для out-of-tree сборок. Только
   пять `gn_plugin_*` экспортируется.
4. Добавляет flags размера: `-Os -ffunction-sections -fdata-sections
   -Wl,--gc-sections`. Это типично уменьшает `.so` в 2–3 раза по
   сравнению с дефолтом.
5. Включает PIC, ставит `cxx_std_23`.
6. Включает базовые warning-флаги: `-Wall -Wextra -Wpedantic`.
7. Добавляет правило `install(TARGETS … LIBRARY DESTINATION
   lib/goodnet/plugins)`.

Расширять таргет можно после вызова — `target_link_libraries(my_link
PRIVATE Foo::Bar)`, `target_compile_definitions`, и т. д.

Под `-DGOODNET_STATIC_PLUGINS=ON` тот же исходник компилируется в
`OBJECT`-библиотеку, которую ядро линкует статически. Это для
embedded / sanitizer-тестов, где `dlopen` нежелателен.

## Версионирование

`find_package(GoodNet 1.0 CONFIG REQUIRED)` отказывается на любом
несовместимом ABI:

- Major-несовпадение: `find_package` падает.
- Minor — выше, чем у плагина — OK (плагин видит подмножество).
- Minor — ниже, чем у плагина — `GN_ERR_VERSION_MISMATCH` на
  `query_extension_checked`, см. [abi-evolution](../../contracts/abi-evolution.en.md).

Плагин также экспортирует свой ABI через
`gn_plugin_sdk_version(major, minor, patch)` — entry, которое макрос
`GN_LINK_PLUGIN` определяет автоматически. Ядро при `dlopen` сравнивает
с собственным major и отказывает на несовпадении.

## Манифест плагина

`add_plugin()` создаёт только `.so`. Манифест (имя, версия, kind,
SHA-256 бинарника, опциональная Ed25519-подпись) — отдельный
артефакт, см. [plugin-manifest](../../contracts/plugin-manifest.en.md).

Helper `goodnet_add_plugin_manifest(<NAME> ...)` генерирует
`<plugin>.manifest.json` рядом с `.so` на этапе `cmake --build`.
Сигнатура (если задан ключ) ставится тем же шагом. Без манифеста
ядро в strict-mode откажет: `GN_ERR_INTEGRITY_FAILED`.

```cmake
add_plugin(my_link src/my_link.cpp src/plugin_entry.cpp)

goodnet_add_plugin_manifest(my_link
    KIND   link
    PROVIDES "gn.link.tcp"
    LICENSE  "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE"
)
```

## Статически линкуемые kernel-internal плагины

Не каждый «плагин» — это `.so`. Внутрипакетные protocol-layer
имплементации (`plugins/protocols/gnet/`, `plugins/protocols/raw/`)
линкуются статически в kernel-binary через обычный
`add_library(<name> STATIC ...)` без `add_plugin()` и без
`find_package`. Они не загружаются `dlopen`'ом, не имеют манифеста,
не подпадают под GPL-linking-exception (живут под лицензией ядра).

Out-of-tree автор такие плагины **не пишет** — это структурные
части framework'а.

## Standalone Nix-flake на плагин

В монорепе каждый загружаемый плагин (handler-heartbeat,
link-{tcp,udp,ws,ipc,tls}, security-{noise,null}) имеет собственный
`flake.nix` и независимую сборку. Шаблон:

```nix
{
  inputs.goodnet.url = "git+file:../../..?dir=nix/kernel-only";

  outputs = { self, nixpkgs, goodnet, ... }: let
    system = "x86_64-linux";
    pkgs = nixpkgs.legacyPackages.${system};
  in {
    packages.${system}.default =
      pkgs.stdenv.mkDerivation {
        pname = "goodnet-link-tcp";
        version = "1.0.0-rc1";
        src = ./.;
        nativeBuildInputs = [ pkgs.cmake pkgs.ninja ];
        buildInputs = [ goodnet.packages.${system}.kernel-headers ];
      };
  };
}
```

`goodnet.url = "git+file:../../..?dir=nix/kernel-only"` —
slim-subflake, который экспортирует только `kernel-headers`
(SDK + CMake config). Полный root-flake не подгружается; цикл
plugin → monorepo → plugin не возникает.

В release-сборке URL переключается на
`github:goodnet-io/<plugin-repo>` после публикации в org.

## Перекрёстные ссылки

- [plugin-lifetime contract](../../contracts/plugin-lifetime.en.md) —
  что ядро ожидает от `.so`-формата.
- [plugin-manifest contract](../../contracts/plugin-manifest.en.md) —
  что попадает в `<plugin>.manifest.json`.
- [abi-evolution contract](../../contracts/abi-evolution.en.md) —
  правила major/minor SDK-версионирования.
- [overview](overview.ru.md) — общий контекст C++ обёрток.
- [write-handler-plugin recipe](../../recipes/write-handler-plugin.ru.md) —
  пошаговый рецепт первого плагина с готовым `CMakeLists.txt`.
