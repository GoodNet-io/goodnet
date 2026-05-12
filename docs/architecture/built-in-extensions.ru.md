# Архитектура: built-in extensions

## Содержание

- [Что считается built-in](#что-считается-built-in)
- [gn.heartbeat](#gnheartbeat)
- [gn.link.\<scheme\>](#gnlinkscheme)
- [gn.strategy.\<name\>](#gnstrategyname)
- [Future extensions (TBD)](#future-extensions-tbd)
- [Plugin author convention](#plugin-author-convention)
- [Cross-references](#cross-references)

---

## Что считается built-in

Я не управляю каталогом расширений как реестром.
Моя пара `register_extension` / `query_extension_checked` работает по
строковому имени и major-версии (см.
[extension-model](./extension-model.ru.md)).
Любой плагин может опубликовать произвольный vtable под произвольным
namespace'ом, и я отдам этот vtable любому, кто его явно запросит.
С точки зрения ABI «встроенных» расширений у меня нет — все плагины равны.

Термин «built-in extension» в этой статье обозначает другое: расширение,
которое выставляет canonical-in-tree плагин — тот, что живёт в основном
дереве GoodNet и идёт в качестве baseline-комплекта.
Если оператор загрузил такой плагин, он может рассчитывать, что
соответствующее имя зарегистрировано и vtable за ним держит
зафиксированную в SDK-header'е семантику.
Каталог нужен, чтобы автору плагина-консьюмера не пришлось читать
исходники heartbeat'а или TCP'шника, чтобы понять, на что он подписывается.

В каталог попадает то, что одновременно удовлетворяет трём условиям:

- выставляется каноническим плагином внутри `plugins/`;
- имеет публичный header под `sdk/extensions/<area>.h`;
- подписано macro-константой имени и macro-константой версии в этом header'е.

Если все три условия выполнены, имя расширения становится частью
baseline-поверхности GoodNet; изменение этой поверхности — нарушение
совместимости и идёт по правилам
[abi-evolution.en.md](../contracts/abi-evolution.en.md).

В каталог не попадают одноразовые plugin-specific расширения, которые
vendor поднял у себя для собственного оркестратора: они живут в
собственном vendor-namespace (`acme.metrics-export`, `myorg.dht`),
и их имена/версии — внутреннее дело автора.

---

## gn.heartbeat

**Producer.**
`plugins/handlers/heartbeat/` — плагин роли HANDLER.
Он сидит на `(protocol_id = "gnet-v1", msg_id = HEARTBEAT_MSG_ID)`,
отправляет PING-ы по своему расписанию, ловит PONG-и в ответ,
замеряет round-trip time, и отдельно собирает peer'овые reflection'ы
своего external endpoint'а (STUN-on-the-wire — отдельного
STUN-сервера не нужно, peer возвращает в PONG-payload то, что он видит).
Имя `gn.heartbeat` бронирует первая успешная регистрация плагина;
пока плагин загружен, имя занято.

**Consumer pattern.**
Расширение query'ит любой плагин, которому нужен сигнал о живости
peer'а или RTT-снэпшот.
Канонические потребители — relay-direct-upgrade оркестратор
(см. [relay-direct](./relay-direct.ru.md)),
peer-discovery плагин, monitoring/metrics экспортёр.
Все они дёргают пару:

```c
const gn_heartbeat_api_t* hb = NULL;
gn_result_t r = host_api->query_extension_checked(
    host_ctx, GN_EXT_HEARTBEAT, GN_EXT_HEARTBEAT_VERSION,
    (const void**)&hb);
if (r == GN_OK) {
    /* call hb->get_rtt / hb->get_observed_address / hb->get_stats */
}
```

`NOT_FOUND` означает «оператор не загрузил heartbeat-плагин»;
консьюмер обязан иметь fallback (обычно — консервативное
«не upgrade'ить»).
`VERSION_MISMATCH` — major разъехался; консьюмер либо ждёт обновления,
либо переключается на старую совместимую ветку.
Различимость кодов — намеренная, см. [host-api.en.md](../contracts/host-api.en.md)
§query_extension_checked.

**API-сводка.**

| Slot | Семантика |
|---|---|
| `get_stats(ctx, *out)` | snapshot агрегатных RTT-счётчиков по всем живым peer'ам |
| `get_rtt(ctx, conn, *out_rtt_us)` | RTT последнего PONG для конкретного `gn_conn_id_t`, в микросекундах |
| `get_observed_address(ctx, conn, buf, sz, *port)` | адрес, который peer прислал назад в PONG-payload (моё внешнее, как peer его видит) |

`get_stats` пишет в caller-allocated `gn_heartbeat_stats_t`:
`peer_count`, `avg_rtt_us`, `min_rtt_us`, `max_rtt_us`.
Все четыре — uint32.
`get_rtt` возвращает `-1` если соединение неизвестно или ни одного
PONG ещё не пришло; `get_observed_address` возвращает `-1` ещё и
при недостаточном размере буфера, при этом NUL-терминирует выход
на границе truncation'а, чтобы потребитель не получил нечитаемую строку.

**Семантика статистики.**
`peer_count` — количество peer'ов, для которых наблюдался хотя бы один
PONG за всё время жизни плагина; это не «сейчас живые», а «трекаются».
Удаление peer'а из таблицы — отдельная политика плагина (typically —
TTL по последнему PONG).
`avg_rtt_us` — арифметическое среднее по последнему PONG каждого peer'а
(sliding-window не глубже одного семпла на peer'а в baseline-реализации).
Оператор, которому нужен глубокий sliding window, поднимает sidecar-плагин
или подписывается на handler-channel и считает сам.

**Семантика observed-address.**
`get_observed_address` отвечает на вопрос «что peer на той стороне
видит как мой external endpoint».
В типовой топологии — это публичный IP:port, на который peer отправил
PONG; за NAT-ом этот адрес отличается от любого локального интерфейса.
Buffer-truncation NUL-терминируется на границе обрезки: consumer
получает корректную C-строку (укороченную), а не undefined-bytes,
и автодиагностика печатает `truncated:1.2.3.` вместо краша на `strlen`.
AutoNAT-логика, сравнившая ответы пары независимых peer'ов, ставит
«reachable» либо «behind NAT» — это пример композиции `gn.heartbeat`
с будущим `gn.autonat`.

**Версионная семантика.**
`GN_EXT_HEARTBEAT_VERSION = 0x00010000u` — v1.0.
Старшие 16 бит — major, младшие 16 бит — minor.
Major bump — breaking: сменили signature `get_rtt`, переименовали
поле в `gn_heartbeat_stats_t`, поменяли инвариант возврата.
Minor bump — append-only: добавили слот в конец vtable, добавили
поле в конец stats-структуры.
Старый консьюмер собран против меньшего `api_size`, новые поля
для него просто за хвостом, он их не читает.
См. [abi-evolution.en.md](../contracts/abi-evolution.en.md) §3.

**Сценарий relay→direct upgrade.**
Канонический потребитель — оркестратор upgrade'а relay-routed
соединения в direct.
Соединение с peer'ом установлено через relay-узел (RTT обычно 80–200 мс).
Оркестратор подписан на conn-state канал, для каждого живого peer'а
раз в N секунд query'ит `gn.heartbeat`, читает `get_rtt` по relay-conn'у
и `get_observed_address` для reflective external endpoint обеих сторон,
и при dial-able endpoint'ах пытается direct-dial через TCP/UDP.
Если `query_extension_checked` вернул `NOT_FOUND` (heartbeat-плагин
не загружен), оркестратор остаётся на relay'е, потому что без RTT-снэпшота
критерий upgrade'а недоступен.
Это пример того, как `NOT_FOUND` ветка реально влияет на функциональность
стека, не оборачиваясь крашем — см. [relay-direct](./relay-direct.ru.md).

**Metrics-экспортёр.**
Второй канонический консьюмер — плагин-экспортёр в Prometheus или OTLP.
Он query'ит `gn.heartbeat` один раз на инициализации, кэширует vtable
до собственного shutdown'а, и в scrape-callback'е дёргает `get_stats` —
снимает агрегат по всем peer'ам.
Vtable-pointer остаётся валидным, пока heartbeat-плагин зарегистрирован;
если оператор unloaded'ит heartbeat в runtime, экспортёр должен
сбрасывать кэш по сигналу через handler-channel (см.
[extension-model](./extension-model.ru.md) §lifecycle).

---

## gn.link.\<scheme\>

**Producer.**
Каждый link-плагин публикует собственное расширение под своим scheme'ом:
TCP-плагин — `gn.link.tcp`, UDP-плагин — `gn.link.udp`,
IPC-плагин — `gn.link.ipc`, WS-плагин — `gn.link.ws`,
TLS-плагин — `gn.link.tls`, ICE-плагин — `gn.link.ice`.
Имя строится по convention `GN_EXT_LINK_PREFIX + scheme`, lowercase.
Регистрация происходит автоматически: link-плагин возвращает свою пару
`(name, vtable)` через `extension_name()` / `extension_vtable()`
slot'ы своего link-vtable'а ([link.en.md](../contracts/link.en.md) §8),
и я регистрирую её во время `register_link`.

**Consumer pattern.**
Два случая.
Первый — composer-плагины, строящие layer-2 поверх layer-1:
WSS-over-TCP, TLS-over-TCP, ICE-over-UDP.
Composer query'ит `gn.link.tcp` или `gn.link.udp`, чтобы получить
доступ к `send` / `subscribe_data` / `connect` / `listen` — слотам,
которые в baseline-link'е не реализованы (см. ниже), но которые
composer'у нужны для управления L1-conn'ом независимо от
kernel'ного `notify_connect`.
Второй случай — monitoring/metrics: оператор query'ит
`gn.link.<scheme>` каждого активного link'а, читает `get_stats`
и `get_capabilities`, экспортирует во внешний коллектор
(Prometheus, OTLP).
Здесь composer-слоты не нужны — read-only Steady-набор покрывает
observability.

**API-сводка.** vtable `gn_link_api_t` делится на две группы:

| Группа | Slot | Семантика |
|---|---|---|
| Steady | `get_stats` | snapshot `gn_link_stats_t` (bytes_in/out, frames_in/out, active_connections) |
| Steady | `get_capabilities` | snapshot `gn_link_caps_t` (флаги + max_payload) |
| Steady | `send` | байты на kernel-managed `gn_conn_id_t`, single-writer per [link.en.md](../contracts/link.en.md) §4 |
| Steady | `send_batch` | scatter-gather, single-writer covers весь батч |
| Steady | `close` | idempotent; `hard=1` — RST без graceful drain, `hard=0` — graceful |
| Composer | `listen` | bind URI без kernel'ного `notify_connect`; baseline = `NOT_IMPLEMENTED` |
| Composer | `connect` | dial URI с composer-owned lifecycle; baseline = `NOT_IMPLEMENTED` |
| Composer | `subscribe_data` | install receive callback на L1 conn для L2 framing'а; baseline = `NOT_IMPLEMENTED` |
| Composer | `unsubscribe_data` | снять подписку, idempotent; baseline = `NOT_IMPLEMENTED` |

Steady-слоты функционируют у всех baseline-link'ов в v1.0.x.
Composer-слоты — резерв для L2-семейства (WSS, TLS, ICE).
До того как первый composer-плагин выйдет и контракт будет
проверен end-to-end, baseline возвращает `GN_ERR_NOT_IMPLEMENTED`.
Указатели в vtable всегда не-NULL: невыставленное поведение
всплывает через return-code, а не через NULL-slot
([link.en.md](../contracts/link.en.md) §8).
Это держит ABI-форму таблицы стабильной между релизами.

**Capability flags.** В `gn_link_caps_t::flags` лежит OR-комбинация:

| Флаг | Смысл |
|---|---|
| `GN_LINK_CAP_STREAM` | unframed byte stream; consumer накладывает свои message boundaries |
| `GN_LINK_CAP_DATAGRAM` | OS сохраняет каждый `send` как одну единицу доставки |
| `GN_LINK_CAP_RELIABLE` | OS-уровень reliability (retransmit + ack) |
| `GN_LINK_CAP_ORDERED` | OS-уровень ordering по соединению |
| `GN_LINK_CAP_ENCRYPTED_PATH` | producer утверждает, что байты на проводе уже зашифрованы (TLS-терминатор) |
| `GN_LINK_CAP_LOCAL_ONLY` | producer отказывается биндить публичный адрес независимо от URI (loopback, AF_UNIX) |

`Reliable` и `Ordered` описывают именно OS-level гарантии, а не
end-to-end, которые добавляет security-слой.
`EncryptedPath` — link-level утверждение «эти байты уже под
TLS-обёрткой»; consumer-плагин решает, нужно ли ему всё ещё
разворачивать noise-канал поверх.
`LocalOnly` — security-релевантный сигнал: `gn.link.ipc` его
выставляет, потому что AF_UNIX не уйдёт за пределы хоста,
и оператор может опираться на это в trust-классификации.

**Per-scheme baseline assignments.**

| Scheme | Capability flags | `max_payload` |
|---|---|---|
| `gn.link.tcp` | `Stream | Reliable | Ordered` | 0 (unlimited; gate — kernel `limits.max_frame_bytes`) |
| `gn.link.udp` | `Datagram` | конфигурируемый MTU |
| `gn.link.ipc` | `Stream | Reliable | Ordered | LocalOnly` | 0 |
| `gn.link.ws` | `Stream | Reliable | Ordered` | 0 |
| `gn.link.tls` | `Stream | Reliable | Ordered | EncryptedPath` | 0 |
| `gn.link.ice` | `Datagram` | следует за UDP MTU |

Composer-плагины ORят свои флаги поверх producer'овских.
Фактическая ассоциация снимается через `get_capabilities` в runtime —
consumer кэширует результат на одно registration'е плагина, так как
`gn_link_caps_t` стабилен на lifetime'е плагина (см.
[link.en.md](../contracts/link.en.md) §8).

**Сценарий TLS-over-TCP.**
Канонический пример composer'а — `gn.link.tls`, поднимающий
TLS-handshake поверх TCP-conn'а.
Composer query'ит `gn.link.tcp`, получает `gn_link_api_t* tcp`,
и для каждого incoming TLS-URI вызывает `tcp->listen` —
а не kernel'ный `register_link`.
После `listen` composer'у нужно перехватывать сырые байты с
TCP-conn'а до того, как они уйдут в kernel'ный handler-pipeline;
для этого он зовёт `tcp->subscribe_data(tcp->ctx, conn, &on_raw_bytes, self)`.
Callback `on_raw_bytes` приходит в context'е tcp-плагина
(typically — на его io_context'е); composer прокидывает байты в свой
OpenSSL state-machine, и когда handshake завершился — публикует
уже-зашифрованный конец через собственный `notify_connect`
под scheme'ом `tls`.
Steady-слоты `send` / `close` ему тоже нужны, чтобы прокидывать
ciphertext обратно.
Именно поэтому composer-слоты помечены `NOT_IMPLEMENTED` у
baseline-link'а до момента, пока первый composer-плагин не пройдёт
end-to-end: контракт `subscribe_data` тонкий (single-writer на
read-side, lifetime callback'а до `unsubscribe_data`), и обкатать
его без реального consumer'а — значит зафиксировать угадки.

**Сценарий ICE-over-UDP.**
Аналогичная композиция, но датаграммная.
ICE-плагин query'ит `gn.link.udp`, через composer-слоты шлёт STUN
binding-request'ы и ловит binding-response'ы.
Datagram-семантика снимает требование framing'а.
Capability-флаг `GN_LINK_CAP_DATAGRAM` для composer'а — sanity check:
ICE против `gn.link.tcp` не запускается, потому что Stream + ICE —
категориальная ошибка; composer проверяет `get_capabilities` до
`subscribe_data` и ругается понятным error code'ом.

**Версионная семантика.**
`GN_EXT_LINK_VERSION = 0x00010000u` — v1.0, общий на все scheme'ы.
Один major на всю семью link-расширений: добавление поля в
`gn_link_stats_t` или нового capability-флага — minor bump для
всех link'ов сразу.
Это держит composer-код, который полиморфно работает поверх любого
`gn.link.*`, в одном compat-окне; иначе composer'у пришлось бы
держать матрицу major'ов по schem'ам.
`GN_LINK_CAP_*` константы ставятся на чёткие, никогда не
перевыпускаются.
Reserved-bits в `flags` (биты выше шестого) и хвост `_reserved[4]`
в `gn_link_caps_t` / `gn_link_stats_t` оставлены ровно для того,
чтобы добавить новые флаги или новый счётчик в minor-релизе без
bump'а major'а.

---

## gn.strategy.\<name\>

Каркас для strategy plugins, выбирающих исходящий conn из набора
живых соединений к одному peer'у. Контракт описан в
`sdk/extensions/strategy.h`; SDK-side macro `GN_STRATEGY_PLUGIN`
из `sdk/cpp/strategy_plugin.hpp` собирает thunk'и автоматически.

**Имена.** `gn.strategy.<plugin-name>` — например
`gn.strategy.rtt-optimal`, `gn.strategy.cost-aware` (last не
landed). Каждый strategy plugin регистрируется под собственным
именем; kernel-side dispatch (когда landed, Слайс 9-KERNEL)
выберет одну активную strategy на узел по operator-config'у.

**API-сводка.** vtable `gn_strategy_api_t`:

| Слот | Назначение |
|---|---|
| `pick_conn` | выбрать conn_id из массива `gn_path_sample_t` кандидатов для peer'а |
| `on_path_event` | snapshot path-events (CONN_UP/DOWN, RTT_UPDATE, LOSS_DETECTED, CAPABILITY_REFRESH) |
| `ctx` | self-pointer плагина |

`gn_path_sample_t` карьерит conn_id + smoothed RTT (микросекунды)
+ loss percentage (×100) + capability flags.

Что отличает `gn.strategy.*` от reserved-под-будущее
`gn.float-send.*` (раздел [Future extensions](#future-extensions-tbd)):

| Family | Send pipe | Conn map | Когда использовать |
|---|---|---|---|
| `gn.strategy.*` | kernel | kernel | простой picker, kernel-mediated routing |
| `gn.float-send.*` | plugin | plugin | rich behaviours — cache, retry, fallback |

`gn.float-send.*` может построиться поверх `gn.strategy.*` как
обёртка, добавляющая send pipe + per-peer state. Pre-v1 — только
`gn.strategy.*` shipped.

**Reference impl.** `plugins/strategies/float_send_rtt/`
регистрирует `gn.strategy.rtt-optimal` (v1.0). Минимум-RTT picker
с EWMA α=1/8, hysteresis 0.75x, encrypted-path tie-breaker
в пределах ±5 % RTT band.

---

## Future extensions (TBD)

В namespace'е `gn.<area>` я заранее зарезервировал несколько имён,
которые baseline-стек должен будет выставить, когда соответствующая
функциональность пройдёт дизайн и оседёт в каноническом плагине.
Эти имена пока не зарегистрированы, и `query_extension_checked`
на них вернёт `NOT_FOUND` — но я документирую их здесь, чтобы
vendor'ы не занимали эти имена под свои частные расширения.

| Имя | Назначение |
|---|---|
| `gn.peer-info` | каталог известных альтернативных URI на peer'а (по identity), пополняемый peer-discovery плагинами |
| `gn.autonat` | определение reachability-статуса локального узла на основе peer-наблюдений (за NAT'ом или нет) |

Дополнительно зарезервированы четыре namespace-категории под
strategy plugins (см. [`strategies`](./strategies.ru.md) — каждая
категория содержит несколько конкретных strategies, выбираемых
оператором по name):

| Категория | Назначение |
|---|---|
| `gn.float-send.<strategy>` | smart routing: какой путь выбрать для исходящего сообщения, когда несколько available |
| `gn.dht.<strategy>` | distributed key-value lookup поверх mesh'а |
| `gn.relay.<strategy>` | multi-hop forwarding через intermediates (NAT traversal, censorship resistance) |
| `gn.discovery.<strategy>` | peer-finding (mDNS, DHT walk, gossip, static bootstrap list) |

Семантика этих имён зафиксируется в момент, когда первый канонический
плагин под каждое из них пройдёт дизайн-цикл и попадёт в `plugins/`.
Пока этого не произошло, vendor может писать prototype-плагин под
собственным namespace'ом (`acme.dht-experimental`), а потом
переключиться на `gn.dht`, когда контракт будет согласован.

Резервирование имени — социальная договорённость, не техническая
гарантия: если vendor успеет зарегистрировать `gn.dht` раньше
канонического плагина, я отдам его vtable любому query'ующему,
а канонический плагин при загрузке получит `GN_ERR_LIMIT_REACHED`
от `register_extension`.

---

## Plugin author convention

**Namespace.**
Если расширение проектируется как открытая часть экосистемы и
претендует на каноничность — namespace `gn.<area>`.
Пример: `gn.heartbeat`, `gn.link.tcp`, `gn.peer-info`.
Vendor-specific расширения, которые не претендуют на интеграцию
в baseline-стек, живут под `<vendor>.<product>.<area>`:
`acme.metrics-export`, `myorg.dht`.
Namespace `gn.` я не валидирую программно; convention — социальная,
нарушать её — значит занимать имя, которое потом не получится отдать
каноническому плагину без миграции консьюмеров.

**Версионирование.**
Одно `uint32_t` поле, верхние 16 бит — major, младшие 16 бит — minor.
Patch-уровень в эту схему не вкладывается (растворяется в minor'е) —
для baseline-расширений я не вижу use-case'а, в котором patch имел
бы смысл отдельно от minor'а.
Bump major'а — breaking change: смена signature, переименование enum,
изменение invariant'а.
Bump minor'а — append-only: добавление поля в конец vtable или в
конец payload-структуры.
Major bump через смену имени (`gn.peer-info` → `gn.peer-info.v2`) —
каноническая трактовка; обе версии живут параллельно, пока трафик
старого имени не иссякнет, потом старое снимается через
`unregister_extension`.
См. [extension-model](./extension-model.ru.md) §versioned-upgrade.

**Header location.**
Открытое/публичное расширение получает header под
`sdk/extensions/<area>.h` — примеры выше: `sdk/extensions/heartbeat.h`,
`sdk/extensions/link.h`.
Header содержит macro-константу имени (`GN_EXT_<AREA>`),
macro-константу версии (`GN_EXT_<AREA>_VERSION`),
typedef vtable-структуры с обязательным `uint32_t api_size` первым
полем и `void* ctx` + `void* _reserved[N]` хвостом, и любые
payload-структуры с собственным `_reserved[N]` хвостом.
Vendor-специфичное расширение прячется в собственном include'е
плагина; consumer берёт header у автора, не у меня.

**Layout.**
Первое поле vtable — `uint32_t api_size`, заполняемое
`sizeof(gn_<X>_api_t)` на момент сборки producer'а.
Macro `GN_VTABLE_API_SIZE_FIRST` (см. `sdk/abi.h`) проверяет offset
compile-time'но.
Хвост — `void* ctx` и `void* _reserved[N]`; payload-структуры тоже
завершаются `_reserved[N]` (см. `gn_link_stats_t`, `gn_link_caps_t`).
Полная схема — [extension-model](./extension-model.ru.md) §vtable-shape.

**Регистрация.**
Producer аллоцирует структуру (typically — статически), заполняет
указатели на функции, прописывает `ctx = self`, и вызывает
`host_api->register_extension(host_ctx, GN_EXT_<AREA>, GN_EXT_<AREA>_VERSION, &g_<area>_api_instance)`.
Consumer после `query_extension_checked` cast'ит `*out_vtable`
обратно к `const gn_<X>_api_t*`, обязательно проверяет
`GN_API_HAS(vt, slot)` чтобы гейтить slot из более нового minor'а,
и зовёт `vt->method(vt->ctx, ...)`.

---

## Cross-references

- Архитектура: [extension-model](./extension-model.ru.md) — общая модель plugin↔plugin расширений, namespace, version compat, vtable shape.
- Архитектура: [plugin-model](./plugin-model.ru.md) — четыре роли плагина и точки регистрации.
- Архитектура: [host-api-model](./host-api-model.ru.md) — KIND-tagged primitives, ABI evolution.
- Архитектура: [relay-direct](./relay-direct.ru.md) — пример консьюмера `gn.heartbeat`.
- Контракт: [host-api.en.md](../contracts/host-api.en.md) §extension API — `register_extension` / `query_extension_checked` / `unregister_extension`, error semantics.
- Контракт: [link.en.md](../contracts/link.en.md) §8 — per-link extension surface, capability flags, baseline assignments.
- Контракт: [abi-evolution.en.md](../contracts/abi-evolution.en.md) §3 — `api_size` prefix evolution внутри vtable.
- Контракт: [plugin-lifetime.en.md](../contracts/plugin-lifetime.en.md) §4 — auto-reap расширений на shutdown'е плагина.
