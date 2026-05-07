# gssh — operator guide

Эта страница описывает рабочий цикл `gssh` — единственного бинаря,
через который оператор подключается по SSH через GoodNet-туннель.
Здесь не объясняется как устроено ядро или плагины: для этого есть
[ecosystem](../architecture/ecosystem.ru.md). Здесь — что положить
на диск, как обменяться адресами, какие команды набирать и какие
ошибки означают, что что-то поломалось.

## Содержание

- [Что такое gssh](#что-такое-gssh)
- [Установка identity](#установка-identity)
- [peers.json](#peersjson)
- [Plugin discovery](#plugin-discovery)
- [Wrap mode — обёртка вокруг ssh](#wrap-mode--обёртка-вокруг-ssh)
- [Bridge mode — ProxyCommand callee](#bridge-mode--proxycommand-callee)
- [Listen mode — серверный демон](#listen-mode--серверный-демон)
- [Семантика trust class](#семантика-trust-class)
- [Диагностика](#диагностика)
- [Cross-references](#cross-references)

---

## Что такое gssh

`gssh` — один бинарь, в котором живут три режима. Шаблон тот же, что у
`openssh`: один source собирает `ssh` и `sshd` в две утилиты, а тут
три режима в одном файле, выбор по argv.

Бинарь использует `bridges/cpp` и `sdk/core.h` — те же стабильные
интерфейсы, что и для других apps. SSH-2 идёт поверх transport-слоя
GoodNet: link-плагин (по умолчанию TCP) дозванивается до пира,
security-плагин (Noise) поднимает encrypted-канал, а сверху туннелируются
байты openssh-клиента в openssh-сервер.

| Режим | argv | Назначение |
|---|---|---|
| `wrap` | `gssh user@<peer-pk>` | Operator UX: запускает `ssh` с правильным `ProxyCommand` |
| `bridge` | `gssh --bridge <peer-pk>` | Внутренний: openssh запускает его как `ProxyCommand` callee |
| `listen` | `gssh --listen [opts]` | Серверная сторона: слушает inbound и форвардит на `127.0.0.1:22` |

Оператор обычно набирает только `gssh user@<peer-pk>`. `bridge`
запускается openssh самостоятельно; `listen` ставится systemd unit'ом
один раз на сервере.

---

## Установка identity

Identity — persistent Ed25519 keypair. Public key (32 байта) — постоянный
адрес узла; private-производная лежит на диске и реиспользуется между
сессиями. Вся аттестация GoodNet висит на этом файле — генерировать
один раз, беречь.

```
$ goodnet identity gen --out ~/.config/goodnet/identity.bin
```

Файл создаётся с правами `0600`. Это default path — bridge и listen
ищут его, если не передан `--identity <path>`. Если `$HOME` пуст
(typical systemd unit без `Environment=HOME=...`), `gssh` падает на
`getpwuid(getuid())->pw_dir`.

Адрес узла — base32-кодированный public key. `goodnet identity show`
печатает 52-символьную строку вида `QFK4...XYZ7`. Этими адресами
обмениваются out-of-band: chat, paper, signed e-mail. Knowing peer-pk
== knowing how to dial; обратный процесс невозможен.

Identity нужен на обоих концах. Server-side обычно генерится под
dedicated UID `gssh` (см. [deployment](./deployment.en.md)).

---

## peers.json

`~/.config/goodnet/peers.json` — operator's address book. Каталог
плоский, парсится при каждом invocation bridge'а — никаких
stale-cache багов при ручной правке.

Схема:

```json
{
  "peers": [
    {
      "pk":   "QFK4ABCD0EF1GH2IJ3KL4MN5OP6QR7ST8UV9WX0YZ1ABCDXYZ7",
      "name": "alice-laptop",
      "uris": ["tcp://192.168.1.5:9001", "ice://"]
    }
  ]
}
```

Поля:

- **`pk`** — обязательный. Base32-encoded 32-байтный public key пира,
  ровно то, что выдаёт `goodnet identity show` на пировой стороне.
- **`name`** — optional. Label для diagnostics; помогает оператору не
  путать пиров.
- **`uris`** — массив транспортных URI. Первая URI в списке wins;
  каталог operator-curated, порядок имеет значение.

URI schemes, которые `gssh` понимает (зависит от загруженных плагинов):

| Scheme | Plugin | Когда использовать |
|---|---|---|
| `tcp://<host>:<port>` | `link-tcp` | Дефолт. Реализует прямой TCP dial |
| `udp://<host>:<port>` | `link-udp` | Не для SSH — UDP без reliability порвёт сессию |
| `ws://<host>:<port>/path` | `link-ws` | За corporate HTTP-proxy |
| `ipc://<path>` | `link-ipc` | Loopback на одной машине через UNIX socket |
| `tls://<host>:<port>` | `link-tls` | Если transport-уровню нужен TLS поверх TCP |
| `ice://<peer-pk>` | `link-ice` | За NAT, требует ICE-плагина и signal channel |

`gssh` не валидирует scheme сам; передаёт URI в kernel link-registry и
смотрит `gn_result_t`. Если плагина нет, `connect` вернёт
`GN_ERR_NOT_FOUND`. Каталог редактируется руками — отсутствие пира
выдаёт diagnostic с резолвед путём peers.json.

Одноразовый shortcut: `--uri tcp://1.2.3.4:9001` в bridge режиме
переопределяет lookup. Полезно для adhoc проверок до записи в
каталог.

---

## Plugin discovery

Bridge и listen ищут `.so`-файлы относительно бинаря. Алгоритм:

1. `realpath` `/proc/self/exe` → directory of binary.
2. `parent_dir / "lib" / "libgoodnet_security_noise.so"` — production
   install (`<prefix>/bin/gssh` рядом с `<prefix>/lib/*.so`).
3. `parent_dir / "lib" / "libgoodnet_link_tcp.so"`.
4. Те же два пути под `parent_dir / "plugins" / "..."` — in-tree
   development build (`build/plugins/`).

Минимум: один link-плагин (`tcp` по дефолту) и один security-плагин
(`noise`). Без noise handshake не пройдёт; без link нечем дозвониться.
`gssh listen` без обоих печатает «no plugins discovered next to the
executable» и exit 1.

Дополнительные схемы (`udp`, `ws`, `ipc`, `tls`, `ice`) — копированием
`.so` в `<prefix>/lib/`. Discovery идёт через kernel link-registry:
плагин сам регистрирует свою scheme, `gssh` находит через
`kernel.links().find_by_scheme(scheme)`.

`LD_LIBRARY_PATH` не нужен — RPATH в production-сборке указывает на
`$ORIGIN/../lib`, и `dlopen` с absolute path обходит loader полностью.

---

## Wrap mode — обёртка вокруг ssh

Удобный фронтенд:

```
$ gssh alice@QFK4ABCD0EF1GH2IJ3KL4MN5OP6QR7ST8UV9WX0YZ1ABCDXYZ7
```

Под капотом `wrap` режим строит `ProxyCommand` и `execvp`-ит
`ssh`. Эффективно эквивалентно:

```
$ ssh -o ProxyCommand="<self-path> --bridge <peer-pk>" \
      -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile=/dev/null \
      alice@dummy
```

Детали:

- **`<self-path>`** — absolute path этого же бинаря через
  `/proc/self/exe`. openssh запустит ровно тот же gssh; PATH-collision'ы
  невозможны.
- **`dummy`** — fake hostname. DNS не делается, потому что
  `ProxyCommand` уже взял на себя транспорт. Hostname нужен только
  чтобы ssh не выдал «no host given».
- **`StrictHostKeyChecking=no` + `UserKnownHostsFile=/dev/null`**
  отключают SSH-уровневую host-key верификацию намеренно. Noise
  handshake уже доказал, что peer-pk владеет private key. SSH-овский
  known_hosts поверх этого пинит ту же сущность дважды без security
  gain. Принцип «one address, one identity»: peer-pk — единственный
  fingerprint, который нужно держать.
- **Нет ассоциации pk ↔ DNS hostname**. `~/.ssh/config` секции с `Host`
  игнорируются — wrap всегда передаёт `dummy`.

`execvp` заменяет процесс — wrap не возвращает control. Если `ssh`
отсутствует в `PATH`, `execvp` возвращает `ENOENT`, и gssh печатает
hint про `openssh-client`.

---

## Bridge mode — ProxyCommand callee

Bridge поднимает openssh сам — оператор обычно не запускает его
напрямую. Понимание поведения нужно для диагностики.

Что делает bridge:

1. Загружает identity из `--identity <path>` или
   `~/.config/goodnet/identity.bin`. Без identity — exit 1.
2. Поднимает kernel, цепляет `gnet`-protocol layer, грузит плагины.
3. Резолвит URI: `--uri <uri>` overrides peers.json; иначе lookup по pk.
4. Subscribes на conn-events, ставит kernel в `Running`, вызывает
   `link.connect(uri)`.
5. Ждёт `TRUST_UPGRADED` (или `CONNECTED` с trust-class выше Untrusted
   для loopback). Hard timeout 15 секунд — openssh не понимает
   «handshake идёт», лучше быстрый fail чем висящая команда.
6. Регистрирует handler на `kSshAppMsgId` (значение `0x10000`).
7. Pump: `read(stdin)` → `host_api.send(conn, msg_id, bytes)`; обратно —
   handler trampoline в `stdout` через `write_all`.

stdin переключается в non-blocking, чтобы read-loop проверял флаги
`disconnected` и `stdout_broken` без зависания.

stdout — output stream openssh-клиента; всё что bridge туда пишет
интерпретируется как байты SSH-протокола. **Logging strict to stderr**.
Одна лишняя `printf` в stdout сломает SSH-сессию с ошибкой «bad packet
length».

---

## Listen mode — серверный демон

Listen — server side. Слушает GoodNet inbound, форвардит каждое
соединение в локальный TCP target.

```
$ gssh --listen \
       --listen-uri tcp://0.0.0.0:9001 \
       --target 127.0.0.1:22
```

Дефолты:
- `--listen-uri tcp://0.0.0.0:9001`
- `--target 127.0.0.1:22`
- `--identity ~/.config/goodnet/identity.bin`

Логика:

1. Identity, kernel, plugins — то же что у bridge.
2. Subscribe на conn-events ДО listen — первый inbound `DISCONNECTED`
   не теряется.
3. Регистрация handler на `kSshAppMsgId`.
4. `kernel.advance_to(Running)` → `link.listen(uri)`.
5. `SIGINT`/`SIGTERM` ПОСЛЕ того как listen socket поднят (signal во
   время plugin load должен убивать процесс сразу, а не идти
   half-loaded shutdown path).
6. Idle loop. На inbound conn handler trampoline лениво открывает
   `connect_tcp(target_host, target_port)` — fresh upstream socket,
   fresh reader thread.
7. На `DISCONNECTED` — закрывает upstream и убирает запись из map'а.

Lazy upstream open: `notify_connect` появляется до handshake; bridge
сначала проходит Noise, потом шлёт первый envelope. Получение
envelope = implicit proof что handshake завершился. Так upstream-сокет
не тратится на abandoned handshakes.

Per-connection isolation: каждый inbound peer получает свой TCP-сокет к
`target`. Один backend (`127.0.0.1:22`) обслуживает параллельных
пиров — openssh-демон видит каждое соединение как обычный TCP-клиент.

systemd unit detail и user-account hardening описаны в
[deployment](./deployment.en.md). Минимальный пример:

```ini
[Unit]
Description=GoodNet SSH listen forwarder
After=network-online.target

[Service]
ExecStart=/usr/bin/gssh --listen
Environment=HOME=/var/lib/gssh
User=gssh
Group=gssh
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
```

Операторская сторона на клиентах: создать `gssh` user account,
сгенерить identity под ним, выложить server's pk + URI в каждый
client's peers.json.

---

## Семантика trust class

Kernel присваивает каждому соединению trust class при `notify_connect`:

| Trust class | Когда выставляется | Что значит для bridge |
|---|---|---|
| `Untrusted` | По умолчанию для cross-machine connect | Sends заблокированы; ждать `TRUST_UPGRADED` |
| `LOOPBACK` | При connect на `127.0.0.1` / `::1` / `ipc://` | Sends разрешены сразу с `notify_connect` |
| `PEER` | После успешного Noise handshake | Sends разрешены, transport phase active |

Bridge ждёт ИЛИ `TRUST_UPGRADED` (Untrusted → Peer переход), ИЛИ
`CONNECTED` с trust-class **выше** Untrusted. LOOPBACK разблокирует
pipe немедленно — для loopback-тестов на `tcp://127.0.0.1:9001`
kernel выставляет class сразу при `notify_connect`, без ожидания crypto.

Cross-machine соединения всегда стартуют с Untrusted. Если за 15 секунд
handshake не дошёл до `TRUST_UPGRADED`, bridge печатает «trust upgrade
timed out» и exit 1. Чаще всего peer недоступен по сети, либо
listen-side не загрузил Noise plugin.

---

## Диагностика

Список сообщений stderr от `gssh` и что они на практике означают.

### `listen on tcp://0.0.0.0:9001 failed (rc=...)`

Чаще всего port уже занят другим процессом (`lsof -i :9001` покажет
кем). Реже — link-tcp плагин не загрузился (см. предыдущее сообщение в
выводе: «scheme 'tcp' has no registered link»).

### `scheme 'tcp' has no registered link with a connect slot`

Текущая версия bridge использует kernel link-registry напрямую (раньше
шёл через extension-API, который возвращает `GN_ERR_NOT_IMPLEMENTED`
by design per `link.md` §8). Если эта диагностика появилась — значит
link-плагин не загрузился или bin/lib не в одном prefix'е. Проверить
discovery paths (см. выше).

### `trust upgrade timed out (15s)`

Peer недоступен либо его identity не в peers.json. Либо у peer нет
noise-плагина — handshake не стартует. Проверить: `ping <ip>`,
`nc <ip> 9001`, на peer-стороне `gssh --listen` слушает правильный
URI.

### `identity ~/.config/goodnet/identity.bin — load_from_file: ...`

Identity файл повреждён или wrong size: сбой записи, неправильный chmod
(permission variant), accidental truncation. Решение: regen через
`goodnet identity gen --out ~/.config/goodnet/identity.bin` или
восстановление из бекапа. После regen pk меняется, peers нужно
уведомить out-of-band.

### `peer ... not in /home/.../peers.json; add an entry or pass --uri`

Bridge не нашёл pk. Либо вписать вручную (см.
[peers.json schema](#peersjson)), либо передать `--uri tcp://host:port`
для one-shot connect.

### `upstream 127.0.0.1:22 open failed: Connection refused`

`gssh --listen` принял GoodNet-соединение, но локальный sshd на target
не работает. Стартовать: `systemctl start sshd`. Если target другой —
передать `--target host:port`.

### Лишние данные в stdout (bridge mode)

Если вы патчите bridge: stdout — это SSH wire bytes. Любой лишний
`printf` ломает сессию с диагностикой openssh «bad packet length». Все
логи строго в stderr.

---

## Cross-references

- [install](../install.en.md) — production install бинарей и systemd unit'ов.
- [deployment](./deployment.en.md) — server-side hardening, dedicated UID, file mode.
- [gssh README](../../apps/gssh/README.md) — sibling repo doc, плотный command reference.
- [ecosystem](../architecture/ecosystem.ru.md) — где живёт gssh в семействе apps + plugins.
- [security-flow](../architecture/security-flow.ru.md) — что именно делает Noise handshake.
- [host-api-model](../architecture/host-api-model.ru.md) — почему bridge регистрирует
  handler через `host_api`, а не напрямую в kernel.
