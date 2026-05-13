# Cross-platform posture

GoodNet проектируется как kernel + плагины над переносимым реактором
(Asio). Ядро не цепляется за специфические системные вызовы Linux,
кроме одного места — `core/plugin/plugin_manager.cpp` использует
`openat2(RESOLVE_NO_SYMLINKS)` под `__linux__`, и сразу же есть
fallback на `O_NOFOLLOW` для не-Linux POSIX (macOS, FreeBSD,
NetBSD, DragonFly). На Windows вместо `dlopen` подключается
`LoadLibrary` через `core/plugin/dl_compat.hpp`.

Полная матрица по платформам:

| Цель              | Kernel + SDK + GNET | IPC plugin | Прочие plugins | Workers | Сборка через Nix |
|-------------------|---------------------|------------|----------------|---------|-------------------|
| Linux x86_64      | ✓                   | ✓          | ✓              | ✓       | `nix build .#packages.x86_64-linux.goodnet-core` |
| Linux aarch64     | ✓                   | ✓          | ✓              | ✓       | `nix build .#packages.aarch64-linux.goodnet-core` |
| macOS x86_64      | ✓ (kernel only)     | ✓ (LOCAL_PEERCRED) | per-plugin port | ✓ | `nix build .#packages.x86_64-darwin.goodnet-core` |
| macOS aarch64     | ✓ (kernel only)     | ✓ (LOCAL_PEERCRED) | per-plugin port | ✓ | `nix build .#packages.aarch64-darwin.goodnet-core` |
| Windows MSVC      | compile-time guards | stub       | stub           | stub    | `cmake -G Ninja` (manual) |

## macOS

Ядро на macOS строится через `gcc15Stdenv` из nixpkgs (Apple Silicon
поддерживается через cross-compile хост). Asio's portable reactor
работает поверх kqueue без правок. `plugin_manager.cpp` идёт по
ветке `#else`: `verify` через `sha256_of_file`, `dlopen` через
канонический путь — TOCTOU-окно чуть шире, чем под Linux с
openat2, но интегриристика остаётся.

Bundled плагины (tcp/udp/ws/ice/quic/tls/heartbeat/noise/null/
strategies) живут в своих гитах. Каждый плагин ставит
`meta.platforms = lib.platforms.linux` в своём `flake.nix`, пока
не сделан явный darwin-порт. На macOS bundled-плагины поэтому не
попадают в `goodnet.compose`, и оператор получает kernel-only
сборку. IPC plugin уже портирован (см. `query_peer_cred()` в
`plugins/links/ipc/ipc.cpp` — `LOCAL_PEERCRED` под
`__APPLE__`/`__FreeBSD__`/`__NetBSD__`/`__DragonFly__`).

CI gates пока только linux x86_64 / aarch64. Реальная macOS
сборка требует darwin-builder'a у оператора:

```bash
# На macOS-машине после `nix flake update`:
nix build .#packages.aarch64-darwin.goodnet-core
# или
nix build .#packages.x86_64-darwin.goodnet-core
./result/bin/goodnet version
```

## Windows

Wire-протокол subprocess-плагинов (`sdk/remote/wire.h`) и
CBOR-кодек (`core/plugin/wire_codec.{hpp,cpp}`) платформонезависимы.
`core/plugin/remote_host.cpp` гардирует POSIX-специфичные
`socketpair`/`fork`/`execve` под `_WIN32` — стабы возвращают
`GN_ERR_NOT_IMPLEMENTED`, до тех пор пока кто-то с Windows-
тулчейном не дропнет в место named-pipe carrier + Win32
cred-helper. То же относится к IPC-плагину
(`plugins/links/ipc/CMakeLists.txt` имеет `if(WIN32) return()`).

Ручной recipe для контрибьюторов с Windows-машиной:

```powershell
# В Developer Command Prompt for VS:
cmake -B build -G "Ninja" `
  -DCMAKE_BUILD_TYPE=Release `
  -DGOODNET_BUILD_BUNDLED_PLUGINS=OFF
cmake --build build
```

Ядро соберётся (по гардам), плагины — нет; запустить
интеграционный smoke не выйдет без named-pipe carrier'а.

## Что портировать дальше

Приоритеты по порядку использования у операторов:

1. **macOS bundled plugins** — `gn.link.tcp`, `gn.link.udp`,
   `gn.link.ws`. Все три уже сидят на Asio, нужен только
   `meta.platforms = lib.platforms.unix` в plugin's flake.nix и
   обновление CMakeLists, чтобы не падать на platform-specific
   деталях. `gn.security.noise` и `gn.security.null` тоже легко
   портируются (libsodium кроссплатформенный).
2. **macOS strategy plugins** — `float_send_rtt` не использует
   sys-specific API, нужен только meta.platforms.
3. **Windows runtime** — named-pipe carrier для IPC, Win32
   cred-helper, отдельный план в `goodnet-windows.md`.
4. **macOS ICE / QUIC** — потребуется проверка libnice/OpenSSL
   3.5+ под darwin; quic-зависимости тяжёлые.
