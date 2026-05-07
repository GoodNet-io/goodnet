# Архитектура: upgrade с relay-маршрута на прямой

## Содержание

- [Сценарий](#сценарий)
- [Действующие лица](#действующие-лица)
- [Pseudo-code policy plugin](#pseudo-code-policy-plugin)
- [Что делает kernel в этом сценарии](#что-делает-kernel-в-этом-сценарии)
- [Что делает peer-info plugin](#что-делает-peer-info-plugin)
- [Hysteresis](#hysteresis)
- [Нет ICE-плагина в kernel](#нет-ice-плагина-в-kernel)
- [Cross-refs](#cross-refs)

---

## Сценарий

Два узла A и B сидят за разными NAT'ами. Прямой dial из A в B по публичному IP падает: входящий пакет не проходит трансляцию, потому что у B нет открытого port-mapping'а под флоу из A. Но в сети есть третий узел R с публичным адресом, который оба видят и которому оба доверяют — relay. A дозваниваться до B через `relay://R/<pubkey-of-B>`: link-плагин relay-схемы открывает TCP-соединение до R, R по своей внутренней таблице находит уже существующее соединение с B и tunnel'ит фреймы между A и B. Соединение установлено, Noise handshake сходится поверх relay-туннеля, attestation подтверждается, trust-class перешёл `Untrusted → Peer`.

В этот момент A узнаёт через `gn.peer-info` расширение, что у B известны альтернативные URI: один из них — `tcp://203.0.113.42:5050`, опубликованный B'ом во время handshake'а как «вот мой external IP, такой меня видит мир». На NAT-условиях этот IP может оказаться достижимым (B через STUN-on-the-wire узнал, что его port-mapping видим снаружи и стабилен). A пробует прямой dial. Если получается — A переключается с relay на прямой путь и закрывает relay-conn. Если нет — A остаётся на relay; relay не идеален, но работоспособен.

Этот сценарий — каноничный пример plugin self-direction в GoodNet. Ни ядро, ни какой-либо «менеджер путей» не принимает решение «попробовать direct». Плагин видит trust-upgrade event, query'ит peer-info расширение, сам зовёт dial, сам сравнивает результаты, сам закрывает старое соединение. Все четыре шага живут в одном файле плагина-policy.

---

## Действующие лица

**Relay-плагин** — handler-роль, обслуживает входящие фреймы под `(protocol_id = "gnet-v1", msg_id = RELAY_MSG_ID)` и forward'ит их между двумя зарегистрированными у себя в таблице соединениями. Он же — link-роль на схеме `relay://`: при `connect(self, "relay://R/<pubkey>")` он опционально dial'ит R, шлёт relay-init с targeting на pubkey, и через `host_api->notify_connect` рапортует ядру о готовом виртуальном соединении с trust-class'ом `Untrusted` (после handshake'а — `Peer`). Для kernel'а relay-conn — это обычный link-conn, ничем структурно не отличающийся от tcp-conn.

**Peer-info plugin** — отдельный плагин, обычно handler-роль, который собирает у себя информацию об известных peer'ах: множество URI, через которые peer объявлял себя достижимым. Источники — три: announce-сообщения внутри Noise-handshake'а на специально зарезервированном `msg_id`, broadcast discovery с тех же handler'ов (peer кричит «я есть, вот мои адреса» периодически), persistent peer-cache на диске (последняя успешная конфигурация со времени прошлого запуска). Плагин публикует своё знание через расширение `gn.peer-info` с методами вроде `get_direct_uri(ctx, peer_pk, out_buf, sz)`. Конкретный layout vtable определяется автором плагина; никакого канонического `gn_peer_info_api_t` ядро не диктует.

**Upgrade plugin** — orchestrator-as-handler. У него тоже `gn_plugin_kind_t = HANDLER` в descriptor'е, но в handler-chain он мало что делает (или зарегистрирован под no-op `msg_id`). Главная его ответственность — подписка на `GN_SUBSCRIBE_CONN_STATE` и реакция на trust-upgrade event'ы через query peer-info и dial direct. Он один умеет соединять три источника: ядерный сигнал, plugin-published vtable, plugin-driven action.

---

## Pseudo-code policy plugin

Логика plugin'а-orchestrator'а:

```c
/* on TRUST_UPGRADED for relay-routed conn */
void on_conn_state_change(void* ud, const gn_conn_event_t* ev) {
    if (ev->kind != GN_CONN_EVENT_TRUST_UPGRADED) return;
    if (ev->trust != GN_TRUST_PEER) return;

    /* Только relay-conn'ы являются кандидатами на upgrade. */
    gn_endpoint_t ep;
    if (host_api->get_endpoint(host_ctx, ev->conn, &ep) != GN_OK) return;
    if (!is_relay_scheme(ep.link_scheme)) return;

    const gn_peer_info_api_t* pi = NULL;
    if (host_api->query_extension_checked(host_ctx, "gn.peer-info", 0x00010000u,
                                          (const void**)&pi) != GN_OK)
        return;

    char direct_uri[256];
    if (pi->get_direct_uri(pi->ctx, ev->remote_pk,
                           direct_uri, sizeof(direct_uri)) != 0)
        return;

    gn_conn_id_t new_conn;
    if (host_api->dial(host_ctx, direct_uri, "tcp", &new_conn) != GN_OK)
        return;

    record_pending_swap(ev->remote_pk, ev->conn /* relay */, new_conn);
}

/* on TRUST_UPGRADED of new direct conn — promote, drop relay */
void on_direct_upgraded(void* ud, const gn_conn_event_t* ev) {
    if (ev->kind != GN_CONN_EVENT_TRUST_UPGRADED) return;
    if (ev->trust != GN_TRUST_PEER) return;

    gn_conn_id_t relay = lookup_relay_for(ev->conn);
    if (relay == GN_INVALID_ID) return;

    host_api->disconnect(host_ctx, relay);
    record_swap_complete(ev->remote_pk, ev->conn);
}
```

Оба callback'а — это один и тот же subscriber на `GN_SUBSCRIBE_CONN_STATE`, который различает ситуации по записи в собственной локальной таблице `pending_swap`. Подписка существует с момента `gn_plugin_init` плагина-orchestrator'а; отдельная подписка для «direct conn'а» не нужна, потому что событие `TRUST_UPGRADED` приходит на тот же канал.

![Connection lifecycle](../img/connection_lifecycle.svg)

`record_pending_swap` сохраняет тройку `(peer_pk, relay_conn_id, new_conn_id)` в локальной структуре плагина. Когда приходит `TRUST_UPGRADED` для `new_conn_id`, плагин по этому id'у поднимает запись и узнаёт, какой relay закрывать. После закрытия — запись стирается. Если `new_conn_id` сменил `DISCONNECTED` без upgrade'а (dial'ился, но handshake провалился) — запись тоже стирается, relay остаётся.

Threading: callback бежит на нити publisher'а (transport's strand для `CONNECTED` / `TRUST_UPGRADED`); локальная таблица `pending_swap` живёт под mutex'ом, потому что `dial` нового и `disconnect` старого могут прийти из разных нитей. Долгая работа из callback'а уходит через `host_api->set_timer(0, fn, ud, NULL)` на сервисный executor — пушать в шину callback'ом нельзя.

---

## Что делает kernel в этом сценарии

Ядро в этом сценарии выполняет три операции и больше ничего:

1. Публикует events на `GN_SUBSCRIBE_CONN_STATE` канал. `CONNECTED` уходит, когда link зовёт `notify_connect` для нового relay-conn'а. `TRUST_UPGRADED` уходит, когда attestation-payload верифицирован и kernel перевёл связь из `Untrusted` в `Peer`. `DISCONNECTED` уходит, когда плагин-orchestrator зовёт `disconnect(relay)`. Все три события — fire-and-forget, fan-out на каждого подписчика синхронно на нити publisher'а.

2. Регистрирует расширение `gn.peer-info` от плагина-публикатора. Запись `(name, version, vtable)` лежит в `ExtensionRegistry`, lookup через `query_extension_checked` бьёт по name'у с major-check'ом версии. Vtable — opaque void* для ядра.

3. Регистрирует connection-record'ы. `notify_connect` от relay-link'а аллоцирует `relay_conn_id`. `notify_connect` от tcp-link'а под direct-dial'ом аллоцирует независимый `direct_conn_id`. Между ними у ядра нет знания о связи; сопоставление peer_pk → activate connection держит плагин-orchestrator у себя в `pending_swap`.

Ядро не оценивает «relay лучше или direct лучше». Не считает RTT по relay-conn'у и не сравнивает с direct'ом. Не имеет встроенной политики «после N секунд upgrade'нись». Не walk'ит расширения и не зовёт сам какой-нибудь slot вроде `should_upgrade`. Не держит у себя списка known peers и их URI. Вся policy — на стороне плагина-orchestrator'а; ядро лишь даёт ему три точки опоры (events, registry-query, link-dial).

---

## Что делает peer-info plugin

Плагин публикует `gn.peer-info`. Метод `get_direct_uri(ctx, peer_pk, out_buf, sz)` отвечает на вопрос «куда я могу попробовать дозвонить direct'ом до этого peer'а». Возврат `0` — буфер заполнен NUL-terminated URI; возврат `-1` — нет данных или peer не известен.

Источник данных — выбор автора плагина:

- **Announce во время handshake'а**. Канонический Noise-handshake несёт payload-поле, в котором инициатор публикует свои известные external addresses. Peer-info плагин подписан на handler с этим `msg_id` и парсит payload в свой in-memory map `peer_pk → vector<URI>`. На relay-conn'е A узнаёт через handshake адреса B так же, как узнал бы при прямом dial'е.
- **Broadcast discovery**. Плагин периодически шлёт по всем активным conn'ам собственный `msg_id` с list'ом URI. Соседи парсят, обновляют свои таблицы. Плотность зависит от настроек: для маленькой сети — раз в минуту, для больших mesh'ов — реже плюс epidemic propagation.
- **Persistent peer-cache**. Плагин при выгрузке сохраняет таблицу на диск, при загрузке — читает обратно. Cache stale'ится по timestamp'у; адрес не возвращается, если ему больше N часов без подтверждения.

Все три источника комбинируются по политике плагина. Один популярный вариант — fresh-first: сначала вернуть URI из последнего handshake'а, fallback на discovery, fallback на cache. Второй вариант — confidence-based: плагин держит счётчик успешных dial'ов на каждый URI и возвращает наиболее надёжный.

Ядро эту политику не видит. Для него `gn.peer-info` — vtable с методами; что внутри — забота плагина-публикатора.

---

## Hysteresis

Плагин-orchestrator владеет policy на тему «когда upgrade ретраить» и «после fail'а на сколько забывать direct»:

- **Direct dial fail после `TRUST_UPGRADED` relay-conn'а**. Если `dial(direct_uri)` сразу вернул error (link-плагин tcp отказал на parse-stage'е), policy плагина решает: пометить адрес как «не пробовать ещё N минут» или сразу retry. Стандартный приём — exponential backoff на peer_pk-ключе с reset'ом после успешного direct'а.
- **Direct conn упал в `DISCONNECTED` до `TRUST_UPGRADED`**. Handshake начался, но не завершился. Может быть NAT'у не хватило времени, может peer закрылся. Policy: попробовать снова через 30 секунд, после третьего провала — забыть direct на час, оставаться на relay.
- **Direct conn'у `TRUST_UPGRADED`, но через минуту он схлопнулся**. Это уже не «не получается», это «получается ненадолго». Policy: вернуться на relay через `dial("relay://...")`, держать счётчик «direct stable interval» и не пробовать direct, пока relay-сессия не будет дольше прошлой direct-сессии в M раз.

Все эти решения — plugin-side. Ядро не помогает: оно не предоставляет «попробовать снова через X», нет ABI-slot'а с `retry_after`. Плагин держит свою таблицу `peer_pk → next_retry_at` и сам ставит `set_timer(delta_ms, ...)`.

Симметричная сторона. Если плагин решил «вернуться на relay» — он зовёт `disconnect(direct_conn)` и `dial("relay://R/<pk>")`, ровно тем же шаблоном последовательного переключения, что и upgrade в обратную сторону. Ничего нового; см. [multi-path](multi-path.ru.md) §«Шаблон последовательного переключения».

---

## Нет ICE-плагина в kernel

ICE — interactive connectivity establishment, classical NAT-traversal protocol на UDP с STUN/TURN-пробами. В GoodNet'овой v1 baseline он отсутствует и в ядре, и в plugin tree.

Минимум, который покрывает большую часть NAT-сценариев в локальных и semi-local setup'ах — relay плюс STUN-on-the-wire через `gn.heartbeat` (PONG-payload содержит external IP, как peer его наблюдает). Этой пары достаточно для домашних сетей, для mesh'а внутри одной AS, для большинства cellular-NAT'ов. UPnP / NAT-PMP теоретически могут лечь поверх через отдельный плагин, но не входят в канонический набор.

Для реальной cross-NAT traversal нужен ICE: hole-punching по UDP с симметричной логикой обоих peer'ов, координация через third-party signaling. Если этот сценарий когда-либо приедет — он приедет как отдельный link-плагин на схеме `ice://`. URI вида `ice://peer-pk?ice-config=...` будет приниматься grammar'ом ([uri.md](../contracts/uri.en.md) §2), `LinkRegistry` найдёт ice-плагин по scheme'у, ICE-FSM с собственным state machine'ом будет жить внутри него и закроется наружу через `notify_connect` ровно так же, как любая другая транспортная связь. Ядро об ICE FSM по-прежнему ничего не узнает; для него — `notify_connect` от link'а, дальше как у tcp.

До такого плагина — relay плюс direct upgrade покрывают сценарии, в которых GoodNet pretends играть. Это сознательный narrow scope: не пытаться быть universal P2P framework'ом, а решать задачу «два узла в LAN'е плюс гость через relay» хорошо.

---

## Cross-refs

- Архитектура: [multi-path](multi-path.ru.md) — общий шаблон последовательного переключения путей.
- Архитектура: [extension-model](extension-model.ru.md) — публикация и query расширений `gn.peer-info` / `gn.heartbeat`.
- Архитектура: [security-flow](security-flow.ru.md) — handshake, attestation, переход trust class в `Peer`.
- Контракт: [conn-events.md](../contracts/conn-events.en.md) — `TRUST_UPGRADED` / `DISCONNECTED` event payload, ordering, threading.
- Контракт: [host-api.md](../contracts/host-api.en.md) — slot'ы `subscribe_conn_state`, `query_extension_checked`, `disconnect`.
- Контракт: [security-trust.md](../contracts/security-trust.en.md) — one-way upgrade `Untrusted → Peer`, attestation-gate.
- Контракт: [link.md](../contracts/link.en.md) — `connect(self, uri)` slot, `notify_connect` от link'а.
- Контракт: [uri.md](../contracts/uri.en.md) — grammar для URI-схем, включая `relay://` и гипотетический `ice://`.
