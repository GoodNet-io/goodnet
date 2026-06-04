# GoodNet

Интеграторное сетевое ядро с подключаемыми транспортами,
криптопровайдерами, протокольными слоями и обработчиками.
Приложения встраивают его как библиотеку или запускают
standalone-демон. Стабильна ровно одна граница — C ABI между
ядром и плагинами; всё остальное — композиция.

Опорная аналогия — Linux. Ядро не знает что такое TCP, что
такое Noise, что такое приложение. Оно ведёт логические
соединения, типизированные сообщения, адреса-публичные-ключи и
зарегистрированные обработчики. Каждый транспорт, каждый шифр,
каждый wire-формат живёт в плагине, загружаемом через один из
трёх встроенных runtime-ов — `dynamic` (dlopen .so), `static`
(плагин слинкован в kernel binary на этапе сборки) или `remote`
(subprocess worker, общается через wire codec). Интерфейс
`IPluginRuntime` открыт: hosting-программа с собственным runtime
(WebAssembly host, FFI-IPC bridge, sandbox-менеджер) регистрирует
его через `PluginManager::register_runtime`, и ядро диспетчит
дальнейшие записи манифеста через него без правок в
`PluginManager`.

## Quickstart

```bash
git clone https://github.com/GoodNet-io/goodnet.git
cd goodnet
nix run .#setup                # bootstrap зеркал и плагинов
nix run .#build -- release     # release-сборка с LTO → build-release/
nix run .#run -- demo          # два узла, Noise-over-TCP, одно сообщение
```

Без Nix: gcc 16 (x86_64-linux) / gcc 15 (прочие платформы),
libsodium, OpenSSL, asio, spdlog, gtest, rapidcheck, CMake 3.25 —
поставить через свой пакетник, потом
`cmake -B build -G Ninja && cmake --build build && ctest --test-dir build`.

### Локальный тест-гейт и CI

`nix run .#setup` прописывает `core.hooksPath` в `.githooks/`, устанавливая два хука:

- **`pre-commit`** — `clang-tidy --warnings-as-errors=*` на каждый staged C++-файл
  плюс ABI / banlist / livedoc-drift проверки.
- **`pre-push`** — при push в `refs/heads/main` перезапускает дешёвый CI-subset
  локально (`tools/livedoc.py --check`, `pytest tests/livedoc tests/tools`,
  vanilla debug `ctest`) до отправки. Для других веток — no-op.

Обойти один раз стандартным Git-хэчем:

```bash
git commit --no-verify
git push   --no-verify
```

CI работает на self-hosted Forgejo Actions
([`.forgejo/workflows/ci.yml`](.forgejo/workflows/ci.yml)).
GitHub Actions не используется. Release-артефакты публикуются на GitHub Releases
через `gh` CLI по тегу.

| Гейт | Когда | Где |
|---|---|---|
| `flake-check` | каждый PR + push to main | Forgejo |
| `livedoc-check` | каждый PR + push to main | Forgejo |
| `build-and-test` | каждый PR + push to main | Forgejo |
| `plugin-verify` | каждый PR + push to main | Forgejo |
| `windows-cross-build` | каждый PR + push to main | Forgejo |
| `bench-smoke` | push to main или PR label `bench` | Forgejo |
| `ice-3node` | push to main или PR label `ice-test` | Forgejo |
| `fuzz-smoke` | push to main или PR label `fuzz` | Forgejo |
| `asan-smoke` | push to main или PR label `sanitizer` | Forgejo |
| `tsan-smoke` | push to main или PR label `sanitizer` | Forgejo |

## Чем отличается

- **Multi-path транспорт, runtime-адаптивный.** Все транспорты
  работают одновременно под одним peer-identity (один публичный ключ,
  три живых соединения через TCP + UDP + IPC). Strategy-плагин выбирает
  несущую **per-send** по живым RTT-сэмплам, не в момент connect. Тот же
  `conn_id` переживает миграцию несущей — мобильное устройство
  переходит с 4G на домашний Wi-Fi, ICE находит LAN-кандидата, стратегия
  переключает победителя, identity не переаутентифицируется.
- **Параллельная крипта, масштабируется по ядрам.** `CryptoWorkerPool`
  распределяет AEAD-jobs по worker-thread-ам на каждый send. WireGuard
  в mainline пинит один softirq-CPU на peer — single-tunnel throughput
  упирается в одно ядро независимо от числа доступных. Multi-conn
  aggregate на 12-поточном ноутбуке достигает **~60 Gb/s** parody
  (static + LTO, CPU `performance` governor) — уже в 12× потолок
  single-tunnel WireGuard на том же железе.
- **Relay → direct upgrade.** Соединение начинается через relay
  когда нужно и за несколько секунд переходит в прямое, пробивая
  NAT получателя. Приложение видит один `conn_id` через весь переход.
- **Plugin-first экосистема.** Транспорты, криптопровайдеры, протокольные
  слои, обработчики, стратегии — каждый это загружаемый `.so` со своим
  git-ом, своей лицензией, своим релизным темпом. Bundled-набор — стартовый
  kit, не запечатанный монолит.
- **Смена криптопровайдера в runtime.** После установки peer-identity
  через Noise XX GoodNet может поменять активный security-провайдер на
  живом соединении — убрать AEAD на loopback где trust class позволяет,
  оставить на wire-стороне. Identity-binding переживает; per-frame
  seal/open исчезает. WireGuard / TLS / libp2p Noise — монолитные: или
  всё, или ничего.
- **C ABI через языки.** Ядро экспонирует один surface — указатель +
  размер, никаких STL-типов через границу — поэтому биндинги на Python,
  Rust, Go, Java ложатся на один контракт. Плагины на разных языках
  работают в одном процессе.

## Сравнение

| | GoodNet | libp2p | WireGuard | Matrix |
|---|---|---|---|---|
| **Форма** | Ядро + C ABI | Библиотека | Kernel-модуль | Приложение (чат) |
| **Транспорты** | Все одновременно (multi-path) | По одному на conn | Только UDP | Homeserver HTTP |
| **Выбор несущей** | Runtime, strategy-плагин per `send()` | В момент connect | Нет (один туннель) | Нет |
| **Aggregate scaling** | Линейно по ядрам (CryptoWorkerPool) | Per-conn | Пинит один softirq-CPU per peer | Server-bound |
| **Языки** | Любой (C ABI) | Go/Rust/JS форки несовместимы | C / kernel | Python/JS/Go |
| **NAT** | Heartbeat-observed + AutoNAT + relay → direct | Ручной relay | Нет | Pivot через homeserver |
| **Pluggable security** | Да (Noise XX/IK, Null, TLS); **меняется post-handshake** | Да (Noise) | Нет (только Noise IK) | TLS до homeserver |
| **Mobility** | ICE-restart на новом интерфейсе, тот же `conn_id`, без переаутентификации | Нет | Нет | Сессия на сервере |
| **Лицензия** | GPL-2 + linking exception (strategic), MIT (periphery) | MIT/Apache | GPL-2 | Apache |

## Производительность

**TL;DR на этой машине** (i5-1235U, 6-core / 12-thread,
loopback, CPU `performance` governor): single-conn с полной криптой
(Noise XX + gnet framing) — **~3 Gb/s** dynamic / **~5 Gb/s** static+LTO
(TCP, 64 KiB payload); 4-conn static+LTO достигает **~10 Gb/s** —
уже 2× потолок single WireGuard-туннеля (**~4.9 Gb/s**, один softirq-CPU).
No-crypto aggregate — **~60 Gb/s** static-LTO parody, 12× потолок
WireGuard single-tunnel.

| Payload | TCP one-way | TCP echo RT | UDP one-way | IPC one-way | IPC echo RT |
|---|---|---|---|---|---|
| 64 B    | 20 μs / 3.0 MiB/s  | 39 μs / 3.2 MiB/s  | 17 μs / 3.5 MiB/s | 15 μs / 4.2 MiB/s  | 27 μs / 4.5 MiB/s |
| 1 KiB   | 19 μs / 50 MiB/s   | 43 μs / 46 MiB/s   | 19 μs / 51 MiB/s  | 16 μs / 60 MiB/s   | 32 μs / 62 MiB/s |
| 8 KiB   | 33 μs / 235 MiB/s  | 75 μs / 207 MiB/s  | —                 | 32 μs / 241 MiB/s  | 66 μs / 236 MiB/s |
| 32 KiB  | 91 μs / 344 MiB/s  | 197 μs / 317 MiB/s | —                 | 86 μs / 362 MiB/s  | 184 μs / 340 MiB/s |

UDP упирается в 1 KiB по MTU-полу (`kDefaultMtu = 1200`).

Воспроизвести: `nix run .#build -- release`, потом числа из
[`bench/reports/`](bench/reports/).

## Архитектура

Ядро — набор реестров и шин одного уровня, каждый владеет
`Kernel` напрямую (`core/kernel/kernel.hpp` — источник истины).
Реестры: connection, link, handler, protocol-layer, security,
session (security state), send-queue, extension, local-identity.
Шины и диспетчеры: signal-канал событий соединений, signal-канал
перезагрузки конфига, attestation dispatcher, capability-blob bus.
Плюс router, timer registry, metrics registry. Ни один не знает
имени конкретного плагина; `PluginManager` (в `core/plugin/`)
грузит shared objects через C ABI, не называя плагинов.
Единственные точки входа — контракты в [`docs/contracts/`](docs/contracts/),
которые дерево считает авторитетными: контракт меняется
первым, код подтягивается.

Layout:

```
core/        ядро и примитивы
sdk/         публичный C ABI (host_api, link, security, protocol, handler, ...)
plugins/     in-tree шимы плагинов + тестовые заглушки (реальные транспорты,
             security и handlers — в отдельных org-репо, см. таблицу ниже)
examples/    bench harness, two-node демо
docs/        contracts (авторитет), architecture (narrative), operator
tests/       unit, integration, property, conformance
dist/        пример operator-конфига + systemd unit
```

Бинарь `goodnetd`, SSH-туннель `gssh`, и остальные operator-facing apps
живут в отдельных репозиториях под `GoodNet-io/` — kernel tree
остаётся library-only.

## Демон

`goodnetd` — multicall-бинарь:

```bash
goodnetd identity gen --out /etc/goodnet/identity.bin
goodnetd manifest gen build/plugins/libgoodnet_*.so > plugins.json
goodnetd config validate dist/example/node.json
goodnetd run --config dist/example/node.json \
            --manifest plugins.json \
            --identity /etc/goodnet/identity.bin
```

Рабочий operator-setup с systemd-юнитом и примером `node.json`
лежит в [`dist/example/`](dist/example/). Operator-гайд —
[`docs/operator/deployment.en.md`](docs/operator/deployment.en.md).

## Статус

Дерево в release-candidate-кондиции: 1510 тестов зелёные под Release,
ASan и TSan на референсной машине, контракты в `docs/contracts/`
описывают поверхность, operator-бинарь поднимается end-to-end по
сгенерированному identity и подписанному plugin manifest-у.

Wire-формат, публичный C ABI и плагин-контракты **не** заморожены —
RC-итерации могут переделать любой из них по результатам интеграции.
Reshape window в [`docs/contracts/abi-evolution.en.md`](docs/contracts/abi-evolution.en.md)
§3b открыт на весь rc-цикл и закрывается только на plain-теге
`v1.0.0` без `-rcN` суффикса. Ветки: `dev` для разработки,
`main` для релизов (между тегами `main` стоит).

### rc6

- **Identity 5-phase HSM refactor.** Phase 1 — абстракция `IdentitySigner`.
  Phase 2 — C ABI для plugin-provided signers через `gn_core_install_identity_from_provider`.
  Phase 3 — `security-pkcs11` двойной expose (`gn.identity.pkcs11` + `gn.security.pkcs11`).
  Phase 4 — UX в `goodnetd` (`identity import-hsm`, `doctor`, `quickstart`).
  Phase 5 — `gn::sdk::Core::Identity::from_hsm()`.
- **`gssh` v0.2.0 — реальный SSH-2.0.** `gssh --listen` теперь нативный
  SSH-2.0 сервер на libssh; host key IS the GoodNet device pubkey.
  Vanilla openssh-клиенты подключаются.
- **Bridges в sub-репо.** `bridges/{cpp,python,rust,js}` — у каждого свой
  git и релизный темп. Rust bridge получил trait `WireSchema`. JS bridge
  говорит с `handler-web-api-proxy` через WS.
- **`handler-web-api-proxy`.** Browser-as-thin-client gateway: JSON-RPC
  через gnet-конверты в WS-endpoint.
- **Forgejo CI — единственный.** GitHub Actions не используется в CI.
- **Полный WASM-kernel.** `nix build .#goodnet-wasm-emscripten` — kernel
  в браузере через Emscripten, тот же C ABI.
- **C ABI для внешних plugin-runtime-ов.** `sdk/plugin_runtime.h` публикует
  контракт `IPluginRuntime`.

## Экосистема

| Репо | Роль |
|---|---|
| **[goodnet](https://github.com/GoodNet-io/goodnet)** | Kernel, SDK, bundled plugin shims. Этот репо. |
| **[goodnetd](https://github.com/GoodNet-io/goodnetd)** | Operator daemon + multicall CLI. |
| **[gssh](https://github.com/GoodNet-io/gssh)** | Нативный SSH-2.0 сервер + клиент с peer-pubkey identity. |
| [link-tcp](https://github.com/GoodNet-io/link-tcp) · [link-udp](https://github.com/GoodNet-io/link-udp) · [link-ws](https://github.com/GoodNet-io/link-ws) · [link-tls](https://github.com/GoodNet-io/link-tls) · [link-ipc](https://github.com/GoodNet-io/link-ipc) | Однопротокольные транспортные плагины. |
| **[link-ice](https://github.com/GoodNet-io/link-ice)** | NAT-traversal — RFC 8445, STUN, TURN, Trickle ICE, mDNS, auto-restart. |
| **[security-noise](https://github.com/GoodNet-io/security-noise)** | Noise XX security provider (libsodium). |
| **[security-null](https://github.com/GoodNet-io/security-null)** | Loopback / IntraNode pass-through provider. |
| **[security-pkcs11](https://github.com/GoodNet-io/security-pkcs11)** | Hardware key store — PKCS#11 dual-expose. |
| **[handler-store](https://github.com/GoodNet-io/handler-store)** | Distributed key-value store (Memory + SQLite). |
| **[handler-dns](https://github.com/GoodNet-io/handler-dns)** | Typed RR storage + three-tier resolver. |
| **[handler-heartbeat](https://github.com/GoodNet-io/handler-heartbeat)** | Two-way liveness + RTT measurement. |
| **[handler-web-api-proxy](https://github.com/GoodNet-io/handler-web-api-proxy)** | Browser-gateway handler — WS + JSON-RPC. |
| **[strategy-float-send-rtt](https://github.com/GoodNet-io/strategy-float-send-rtt)** | RTT-optimal multi-path picker. |
| **[bridges-rust](https://github.com/GoodNet-io/bridges-rust)** | Rust bindings с `WireSchema` trait. |
| **[bridges-python](https://github.com/GoodNet-io/bridges-python)** | Python bindings (cffi ABI mode). |
| **[bridges-js](https://github.com/GoodNet-io/bridges-js)** | TypeScript/JS клиент для goodnetd WS gateway. |

## Документация

- [`docs/contracts/`](docs/contracts/) — авторитетные behavioural-контракты.
  Старт: [`host-api.en.md`](docs/contracts/host-api.en.md) если встраиваешь ядро,
  [`link.en.md`](docs/contracts/link.en.md) если пишешь транспорт.
- [`docs/architecture/`](docs/architecture/) — narrative объяснения по-русски:
  routing, multi-path, wire-protocol.
- [`docs/operator/`](docs/operator/) — deployment, troubleshooting.
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — workflow разработки, branch-модель, audit-pass.
- [`SECURITY.md`](SECURITY.md) — threat-модель, канал репортинга.
- [`GOVERNANCE.md`](GOVERNANCE.md) — принятие решений, процедура изменения контрактов.

English: see [`README.md`](README.md).

## Лицензия

GPL-2.0 с linking exception для strategic-базы: ядро, gnet
protocol layer, in-tree plugin shims. Linking exception разрешает
out-of-tree плагинам жить под любой лицензией — граница это C ABI,
не лицензия. Periphery-плагины (raw protocol, null security, IPC link) —
MIT для широты экосистемы. OpenSSL-tied плагины (TLS link, QUIC link) и
reference-strategy (float-send-rtt) — Apache-2.0.

Стратегический rationale тот же что Linux в 1991: GPL на ядре
держит субстрат открытым, linking exception оставляет приложения
свободными. См. [`LICENSE`](LICENSE) и `LICENSE` в каждом плагине.
