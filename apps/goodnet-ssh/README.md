# goodnet-ssh

Один бинарник, три режима. Похоже на то, как openssh делит исходники
между `ssh` и `sshd` — у нас три режима в одном `goodnet-ssh`, а
выбор режима делается по argv.

## Режимы

### `goodnet-ssh user@<peer-pk>` — wrap

Удобная обёртка. Вы запускаете её как обычный `ssh user@host`, а
утилита подменяет транспорт openssh: запускает себя же в режиме
`--bridge` через `ProxyCommand` openssh-клиента.

```
$ goodnet-ssh alice@QFK4...XYZ7   # 52-символьный base32 peer-pk
```

`ssh` стартует с опциями:
- `-o ProxyCommand="<self> --bridge <peer-pk>"`
- `-o StrictHostKeyChecking=no` — handshake Noise уже подтвердил
  личность peer-pk; double-check через known_hosts SSH ничего не
  добавляет.
- `-o UserKnownHostsFile=/dev/null` — по той же причине.

### `goodnet-ssh --bridge <peer-pk>` — bridge

Внутренний режим. Запускается openssh-клиентом как `ProxyCommand`.
Поднимает kernel, читает identity из `~/.config/goodnet/identity.bin`,
ищет URI пира в `~/.config/goodnet/peers.json`, дозванивается,
ждёт `TRUST_UPGRADED`, после чего пробрасывает stdin↔conn.

Все логи строго в stderr — stdout считывается openssh как байты SSH-
протокола, любая лишняя строка сломает сессию.

### `goodnet-ssh --listen [opts]` — listen

Серверная часть. Слушает входящие GoodNet-соединения, на каждое
открывает локальный TCP-сокет к target (по умолчанию `127.0.0.1:22`)
и пробрасывает байты в обе стороны.

```
$ goodnet-ssh --listen --listen-uri tcp://0.0.0.0:9001 --target 127.0.0.1:22
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
# /etc/systemd/system/goodnet-ssh-listen.service
[Unit]
Description=GoodNet SSH listen forwarder
After=network-online.target

[Service]
ExecStart=/usr/bin/goodnet-ssh --listen
Environment=HOME=/var/lib/goodnet-ssh
Restart=on-failure
RestartSec=5s
User=goodnet-ssh
Group=goodnet-ssh

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
