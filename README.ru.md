# GoodNet

Маленькое сетевое ядро с подключаемыми транспортами,
криптопровайдерами, протокольными слоями и обработчиками.
Приложения встраивают его как библиотеку или запускают
standalone-демон. Стабильна ровно одна граница — C ABI между
ядром и плагинами; всё остальное — композиция.

Опорная аналогия — Linux. Ядро не знает что такое TCP, что
такое Noise, что такое приложение. Оно ведёт логические
соединения, типизированные сообщения, адреса-публичные-ключи и
зарегистрированные обработчики. Каждый транспорт, каждый шифр,
каждый wire-формат живёт в плагине, загружаемом через `dlopen`
по версионированному C ABI.

## Quickstart

```bash
git clone https://github.com/GoodNet-io/goodnet.git
cd goodnet
nix run .#setup            # bootstrap зеркал и плагинов
nix run .#build            # release-сборка с LTO → build-release/
nix run .#run -- demo      # два узла, Noise-over-TCP, одно сообщение
```

Без Nix: gcc 15, libsodium, OpenSSL, asio, spdlog, gtest,
rapidcheck, CMake 3.25 — поставить через свой пакетник, потом
`cmake -B build -G Ninja && cmake --build build && ctest --test-dir build`.

## Чем отличается

- **Multi-path транспорт.** Все транспорты работают
  одновременно. Соединение через TCP мигрирует на ICE или IPC
  без того чтобы приложение увидело шов. Скоринг путей выбирает
  лучший в реальном времени.
- **Relay → direct upgrade.** Соединение начинается через
  relay когда нужно и за несколько секунд переходит в прямое,
  пробивая NAT приёмника. Приложение видит один и тот же
  `conn_id` через переход.
- **Plugin-first экосистема.** Транспорты, криптопровайдеры,
  протокольные слои и обработчики — загружаемые `.so` со своим
  гитом, своей лицензией, своим релизным темпом. Bundled-набор
  это стартовый kit, а не запечатанный монолит.
- **C ABI стабильности через языки.** Ядро экспонирует один
  surface — указатель + размер, никаких STL-типов через
  границу — поэтому биндинги на Python, Rust, Go, Java
  ложатся на один контракт. Плагины на разных языках
  работают в одном процессе.

## Сравнение

| | GoodNet | libp2p | WireGuard | Matrix |
|---|---|---|---|---|
| **Форма** | Ядро + C ABI | Библиотека | Kernel-модуль | Приложение (чат) |
| **Транспорты** | Все одновременно (multi-path) | По одному на conn | Только UDP | Homeserver HTTP |
| **Языки** | Любой (через C ABI) | Go/Rust/JS форки несовместимы | C / kernel | Python/JS/Go |
| **NAT** | Heartbeat-observed + AutoNAT + relay → direct | Ручной relay | Никак | Pivot через homeserver |
| **Pluggable security** | Да (Noise XX/IK, Null, TLS planned) | Да (Noise) | Нет (только Noise IK) | TLS до homeserver |
| **Лицензия** | GPL-2 + linking exception (strategic), MIT (periphery) | MIT/Apache | GPL-2 | Apache |

## Производительность

Референсная машина: i5-1235U, loopback, 16 KiB payload, после
fix'а AEAD-batch в `dev`. ChaCha20-Poly1305 через libsodium.

| Сценарий | Среднее (5 запусков) | Разброс |
|---|---|---|
| 1 conn, burst (1000 фреймов) | 7.05 Gbps | 5.1 – 9.0 |
| 1 conn, sustained (5000 фреймов) | 6.01 Gbps | 5.7 – 6.3 |
| 4 conn, sustained agg | 19.84 Gbps | 17.8 – 20.8 |
| 8 conn, burst agg | 20.49 Gbps | 15.8 – 30.6 |

Single-conn сидит на ~75 % потолка одного ядра libsodium ChaCha
(`perf record`: 42 % циклов в `chacha20_encrypt_bytes`, 30 % в
`poly1305_blocks`). Multi-conn масштабируется потому что
`CryptoWorkerPool` распределяет AEAD-jobs параллельно по ядрам;
у каждого conn'а свой asio-strand и своя per-conn drain CAS.

### vs WireGuard

Та же машина, тот же kernel, тот же ChaCha20-Poly1305.
WireGuard через veth между двумя network-namespaces, GoodNet —
loopback TCP. iperf3 vs goodnet-bench, 5 секунд.

| | Throughput |
|---|---|
| veth-bridge (без crypto, baseline) | 80.4 Gbps |
| WireGuard single tunnel (kernel, single-thread) | 4.94 Gbps |
| **GoodNet single connection (userspace, multi-thread crypto)** | **6.01 Gbps** |
| **GoodNet 4 conn aggregate** | **19.84 Gbps** |

Замечания: data plane WireGuard в mainline Linux работает в
одном softirq-контексте — encrypt пинит одно ядро. GoodNet
распределяет AEAD по worker-thread'ам пула. На реальной 10 Gbps
NIC расклад смещается: zero-copy kernel-path WireGuard'a сложно
переиграть из userspace. Это loopback-only evidence.

Воспроизвести: `nix run .#build && build-release/bin/goodnet-bench 5000 16 4`.

## Архитектура

Ядро — восемь подсистем одного уровня: connection registry,
signal bus, plugin manager, service resolver, session registry
(security state), send-queue manager, extension registry,
metrics exporter. Ни одна не знает имени конкретного плагина.
Единственные точки входа — контракты в [`docs/contracts/`](docs/contracts/),
которые дерево считает авторитетными: контракт меняется
первым, код подтягивается.

Layout:

```
core/        ядро и примитивы
sdk/         публичный C ABI (host_api, link, security, protocol, handler, ...)
plugins/     bundled link / security / protocol / handler плагины
apps/        бинарь демона goodnet, gssh, demo
examples/    bench harness, two-node демо
docs/        contracts (авторитет), architecture (narrative), operator
tests/       unit, integration, property, conformance
dist/        пример operator-конфига + systemd unit
```

Каждый плагин под `plugins/<kind>/<name>/` — самодостаточная
единица: свой `CMakeLists.txt`, свой `default.nix`, свой git,
своя лицензия. Грузится в ядро через `PluginManager::load`
против SHA-256 манифеста (`/etc/goodnet/plugins.json`).

## Демон

`goodnet` — multicall-бинарь:

```bash
goodnet identity gen --out /etc/goodnet/identity.bin
goodnet manifest gen build/plugins/libgoodnet_*.so > plugins.json
goodnet config validate dist/example/node.json
goodnet run --config dist/example/node.json \
            --manifest plugins.json \
            --identity /etc/goodnet/identity.bin
```

Рабочий operator-setup с systemd-юнитом и примером `node.json`
лежит в [`dist/example/`](dist/example/). Operator-гайд —
[`docs/operator/deployment.en.md`](docs/operator/deployment.en.md).

## Статус

Дерево в release-candidate-кондиции: тесты зелёные под Release,
ASan и TSan на референсной машине, контракты в
`docs/contracts/` описывают поверхность, operator-бинарь
поднимается end-to-end по сгенерированному identity и
подписанному plugin manifest'у.

Wire-формат, публичный C ABI и плагин-контракты RC-frozen —
каждая release-candidate итерация может сломать что-то одно по
результатам интеграции; поверхность стабилизируется на первом
plain-теге `v1.0.0` без `-rcN` суффикса. Ветки: `dev` для
разработки, `main` для релизов (между тегами `main` стоит).

## Документация

- [`docs/contracts/`](docs/contracts/) — авторитетные
  behavioural-контракты. Старт: [`host-api.en.md`](docs/contracts/host-api.en.md)
  если встраиваешь ядро, [`link.en.md`](docs/contracts/link.en.md)
  если пишешь транспорт.
- [`docs/architecture/`](docs/architecture/) — narrative
  объяснения по-русски: routing, multi-path, wire-protocol.
- [`docs/operator/`](docs/operator/) — deployment,
  troubleshooting.
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — workflow разработки,
  branch-модель, audit-pass.
- [`SECURITY.md`](SECURITY.md) — threat-модель, канал
  репортинга.
- [`GOVERNANCE.md`](GOVERNANCE.md) — принятие решений,
  процедура изменения контрактов.

English: see [`README.md`](README.md).

## Лицензия

GPL-2.0 с linking exception для strategic-базы: ядро,
bundled-плагины TCP / UDP / WS / Noise / Heartbeat. Linking
exception разрешает out-of-tree плагинам жить под любой
лицензией — граница это C ABI, не лицензия. Periphery-плагины
(raw protocol, null security, IPC link) — MIT для широты
экосистемы. TLS-плагин — Apache-2.0 ради совместимости с
OpenSSL.

Стратегический rationale тот же что Linux в 1991: GPL на ядре
держит субстрат открытым, linking exception оставляет
приложения свободными. См. [`LICENSE`](LICENSE) и `LICENSE` в
каждом плагине.

## Чего пока нет

- Готовых release-бинарей. Сборка из исходников через Nix или
  стандартный CMake путь выше.
- Per-plugin GitHub-репозиториев. Bundled-плагины живут в
  дереве под `plugins/`; org-repos `goodnet-io/<kind>-<name>`
  встанут когда плагин уезжает наружу.
- Зарегистрированного домена. Документация ссылается на
  GitHub-организацию напрямую.
