# GoodNet

Сетевой фреймворк по образцу Linux: маленькое ядро, плагины для
транспортов, провайдеров безопасности, протокольных слоёв и
обработчиков. Приложение либо встраивает ядро как библиотеку,
либо запускает standalone-демон. Стабильна только C ABI между
ядром и плагинами, всё остальное — композиция.

**Статус: pre-1.0, идёт стабилизация.** Wire-format, публичная API
и плагин-контракты всё ещё двигаются. Pin против этого дерева в
продакшен пока нельзя. Первая стабильная поверхность — `v1.0.0-rc1`.

English: см. [`README.md`](README.md).

## Сборка из исходников

Поддерживаемый путь — Nix. Flake пинит toolchain (gcc 15,
libsodium, OpenSSL, asio, spdlog, gtest, rapidcheck, clang-tidy 21),
поэтому чистый клон собирается одинаково на любом хосте.

```bash
git clone https://github.com/GoodNet-io/goodnet.git
cd goodnet
nix develop                     # вход в shell с пин-toolchain
cmake -B build -G Ninja
cmake --build build
ctest --test-dir build          # на dev ожидается 856/856
```

Удобные алиасы через flake:

```bash
nix run .#               # debug-сборка (инкрементальная)
nix run .#build          # release с LTO
nix run .#test           # debug-сборка + ctest
nix run .#test-asan      # sanitizer-сборка + ctest
nix run .#test-tsan
nix run .#demo           # двухнодовый Noise-over-TCP quickstart
nix run .#goodnet -- version
```

Без Nix собрать тоже можно, если на хосте уже есть gcc ≥ 15,
зависимости из списка выше и CMake ≥ 3.25, но flake — референс.

## Попробовать

Демо двух нод поднимает Noise XX handshake по loopback TCP и
обменивается одним сообщением:

```bash
nix run .#demo
```

Bench-харнесс меряет throughput по encrypted-каналу:

```bash
nix run .# -- build/bin/goodnet-bench 1000 16 1
# ожидаемо ~6 Gbps single-conn loopback на ноуте 2024
```

## CLI оператора

`goodnet` — это бинарник демона плюс несколько админ-команд:

```bash
goodnet version
goodnet identity gen --out node.id
goodnet config validate dist/example/node.json
goodnet manifest gen build/plugins/libgoodnet_*.so > plugins.json
goodnet run --config dist/example/node.json \
            --manifest plugins.json \
            --identity node.id
```

Рабочий пример operator-сетапа лежит в
[`dist/example/`](dist/example/).

## Раскладка дерева

- [`core/`](core/) — ядро
- [`sdk/`](sdk/) — публичные C ABI заголовки (host_api, security,
  link, protocol, handler, conn_events, …) плюс C++ обёртки в
  `sdk/cpp/`
- [`plugins/`](plugins/) — встроенные плагины (транспорты,
  провайдеры, протокольные слои, обработчики); каждый —
  самостоятельная единица с собственным `CMakeLists.txt` и
  `default.nix`
- [`apps/`](apps/) — бинарник `goodnet` демона и друзья
- [`examples/`](examples/) — `bench` (throughput-харнесс) и
  `two_node` (Noise-over-TCP демо)
- [`docs/contracts/`](docs/contracts/) — поведенческие правила
  ядра и плагинов; контракт меняется первым, код за ним
- [`tests/`](tests/) — kernel-side unit + integration тесты
- [`dist/`](dist/) — пример operator-конфига, systemd-юнит,
  заметки по миграциям

## Документация

- [`docs/contracts/`](docs/contracts/) — авторитетные контракты
  (начни с [`host-api.md`](docs/contracts/host-api.md))
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — workflow разработки,
  branch-модель, audit-pass
- [`SECURITY.md`](SECURITY.md) — threat-модель, канал репортинга
- [`GOVERNANCE.md`](GOVERNANCE.md) — принятие решений, процесс
  amendment контрактов

## Лицензия

GPL-2.0 с linking exception для стратегического baseline (ядро,
TCP / UDP / WS / Noise / Heartbeat). Периферийные плагины (raw
protocol, null security, IPC link) — MIT. TLS link — Apache-2.0
для совместимости с OpenSSL. См. [`LICENSE`](LICENSE) и
per-plugin `LICENSE` в каждом плагине.

## Что вне scope (сегодня)

- Готовые бинарные релизы — до `v1.0.0-rc1` нет.
- API stability — до `v1.0.0-rc1` нет.
- Out-of-tree plugin distribution channel — пока только встроенные;
  per-plugin репозитории появятся на `rc1`.
