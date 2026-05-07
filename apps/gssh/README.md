# gssh

Один бинарник, три режима. Похоже на то, как openssh делит исходники
между `ssh` и `sshd` — у нас три режима в одном `gssh`, а
выбор режима делается по argv.

## Режимы

### `gssh user@<peer-pk>` — wrap

Удобная обёртка. Вы запускаете её как обычный `ssh user@host`, а
утилита подменяет транспорт openssh: запускает себя же в режиме
`--bridge` через `ProxyCommand` openssh-клиента.

```
$ gssh alice@QFK4...XYZ7   # 52-символьный base32 peer-pk
```

`ssh` стартует с опциями:
- `-o ProxyCommand="<self> --bridge <peer-pk>"`
- `-o StrictHostKeyChecking=no` — handshake Noise уже подтвердил
  личность peer-pk; double-check через known_hosts SSH ничего не
  добавляет.
- `-o UserKnownHostsFile=/dev/null` — по той же причине.

### `gssh --bridge <peer-pk>` — bridge

Внутренний режим. Запускается openssh-клиентом как `ProxyCommand`.
Поднимает kernel, читает identity из `~/.config/goodnet/identity.bin`,
ищет URI пира в `~/.config/goodnet/peers.json`, дозванивается,
ждёт `TRUST_UPGRADED`, после чего пробрасывает stdin↔conn.

Все логи строго в stderr — stdout считывается openssh как байты SSH-
протокола, любая лишняя строка сломает сессию.

### `gssh --listen [opts]` — listen

Серверная часть. Слушает входящие GoodNet-соединения, на каждое
открывает локальный TCP-сокет к target (по умолчанию `127.0.0.1:22`)
и пробрасывает байты в обе стороны.

```
$ gssh --listen --listen-uri tcp://0.0.0.0:9001 --target 127.0.0.1:22
```

Опции:
- `--identity <path>` — operator identity (default: XDG path).
- `--listen-uri <uri>` — URI для bind (default `tcp://0.0.0.0:9001`).
- `--target host:port` — куда пробрасывать (default `127.0.0.1:22`).

## Конфигурация

### Identity

Persistent identity лежит в `~/.config/goodnet/identity.bin`. Создаётся
через `goodnet identity gen --out ~/.config/goodnet/identity.bin`.

### Peers catalogue

`~/.config/goodnet/peers.json`:

```json
{
  "peers": [
    {
      "pk":   "QFK4...XYZ7",
      "name": "alice-laptop",
      "uris": ["tcp://192.168.1.5:9001", "ice://"]
    }
  ]
}
```

Ловится первая URI из списка. Каталог редактируется руками — это
осознанный choice, не авто-discovery.

## systemd unit

```ini
# /etc/systemd/system/gssh.service
[Unit]
Description=GoodNet SSH listen forwarder
After=network-online.target

[Service]
ExecStart=/usr/bin/gssh --listen
Environment=HOME=/var/lib/gssh
Restart=on-failure
RestartSec=5s
User=gssh
Group=gssh

[Install]
WantedBy=multi-user.target
```

На клиенте нужно `goodnet identity gen` под operator-user'ом и
peers.json с pk и URI сервера.

## Plugin discovery

Bridge и listen режимы ищут плагины относительно бинаря:
- `<prefix>/lib/libgoodnet_security_noise.so`
- `<prefix>/lib/libgoodnet_link_tcp.so`
- `<prefix>/plugins/...` (in-tree build path)

Без noise (для handshake) и tcp (для дозвона) бинарь упадёт сразу.

## License

MIT — см. `LICENSE`. Зависимости (kernel GPL-2 + LE, SDK MIT) не
проникают в этот бинарь.
