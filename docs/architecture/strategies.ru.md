# Strategies как plugin family

Routing, peer discovery, connectivity upgrade, NAT traversal — это
**кросс-режущие** задачи, которые не имеют единственно-правильного
ответа. RTT-оптимальный путь не всегда дешёвый по трафику.
Kademlia подходит под одни топологии, Chord — под другие. mDNS
работает в LAN'е, DHT — в global mesh, gossip — где-то между.

Эта глава описывает класс **strategies as plugin family**:
как GoodNet выносит подобные задачи целиком на plugin layer,
оставляя kernel agnostic к конкретным алгоритмам.

[`extension-model`](./extension-model.ru.md) описывает primitive
`register_extension` / `query_extension_checked`. Эта глава —
о категории extensions, которая использует primitive по
характерному паттерну: pluggable strategy.

## Содержание

- [Что такое strategy plugin](#что-такое-strategy-plugin)
- [Reserved категории](#reserved-категории)
- [Адресация по peer_pk](#адресация-по-peer_pk)
- [Bootstrap dependencies](#bootstrap-dependencies)
- [Composition pattern](#composition-pattern)
- [Switch granularity](#switch-granularity)
- [Failure semantics](#failure-semantics)
- [Receive-side passive](#receive-side-passive)
- [Принцип transparency](#принцип-transparency)
- [Cross-references](#cross-references)

## Что такое strategy plugin

Strategy plugin — handler-плагин (или handler+extension combo),
который реализует **одну конкретную policy** для cross-cutting
задачи и expose'ит её через extension под предсказуемым
namespace.

Конкретность важна. «Smart routing» — не strategy, потому что не
объявляет что считает «smart». `gn.float-send.rtt` — strategy:
«я переключаюсь на путь с минимальным observed RTT, измеряя через
gn.heartbeat extension, switch threshold 25% degradation за 3
seconds». Operator может выбрать или не выбрать эту конкретную
policy сознательно.

Каждая strategy:

- Имеет **отдельный namespace** в форме `gn.<category>.<name>`
- Реализуется отдельным plugin git'ом (`goodnet-io/handler-<strategy>`)
- Документирует what it optimises, what signals it consumes,
  switch heuristic, failure modes — в plugin's own README
- Регистрируется через `host_api->register_extension` со своим
  vtable
- Композится app'ом через `host_api->query_extension_checked`

Kernel не знает что strategies существуют. Не выбирает между
ними. Не координирует. Per
[`feedback_goodnet_no_orchestrator`](../../README.md) — kernel
agnostic, plugins сами координируются.

## Reserved категории

Четыре namespace зарезервированы под известные strategy categories:

| Namespace | Категория | Что решает | Reserved with rc1 |
|---|---|---|---|
| `gn.float-send.<strategy>` | smart routing | какой путь выбрать для исходящего сообщения, когда несколько доступны | да |
| `gn.dht.<strategy>` | distributed routing | как найти peer'а или ресурс по ключу через сеть peer'ов | да |
| `gn.relay.<strategy>` | multi-hop forwarding | как достичь peer'а через промежуточные узлы (NAT traversal, censorship resistance) | да |
| `gn.discovery.<strategy>` | peer finding | как обнаружить новых peer'ов (mDNS LAN scan, DHT lookup, gossip walk) | да |

Внутри каждой категории — конкретные strategies. Примеры
будущих:

- `gn.float-send.rtt-optimal` — minimum RTT
- `gn.float-send.cost-aware` — operator-supplied cost weights
- `gn.float-send.privacy-preserving` — predictable hop pattern
- `gn.dht.kademlia` — k-bucket routing per Kademlia paper
- `gn.dht.chord` — Chord-style finger table
- `gn.relay.first-hop` — single intermediate
- `gn.relay.onion` — multi-hop with layered encryption
- `gn.discovery.mdns` — local network multicast
- `gn.discovery.bootstrap-list` — static peer list
- `gn.discovery.dht-walk` — built on top of `gn.dht.*`

Конкретные strategy specs живут в plugin gits, не в kernel
corpus.

## Адресация по peer_pk

Static `host_api->send(conn_id, msg_id, payload)` адресуется по
`gn_conn_id_t` — kernel-side connection identifier.

Strategy plugins адресуют по `peer_pk[32]` — Ed25519 public key
peer'а.

Причины:

- Conn_id может смениться, когда strategy переключает путь
  (sequential switch). Identity peer'а не меняется.
- App'у не нужно tracking'ить, какой именно conn сейчас
  активен — это plugin's domain.
- Continuity: app зовёт `float_send(peer_pk, msg_id, payload)`,
  plugin maps `peer_pk → current best conn` внутри. Map
  обновляется на conn-events.

Strategy extension API типично:

```c
typedef struct gn_float_send_api_s {
    uint32_t api_size;
    void* ctx;
    /* Send a message to peer; the strategy picks the conn. */
    gn_result_t (*send)(void* ctx,
                         const uint8_t peer_pk[GN_PUBLIC_KEY_BYTES],
                         uint32_t msg_id,
                         const uint8_t* payload,
                         size_t payload_size);
    /* Hint: register a known reachable URI for this peer. */
    gn_result_t (*hint_uri)(void* ctx,
                             const uint8_t peer_pk[GN_PUBLIC_KEY_BYTES],
                             const char* uri,
                             uint32_t weight);
    /* Stats — current best conn id, RTT estimate, switch count. */
    gn_result_t (*get_state)(void* ctx,
                              const uint8_t peer_pk[GN_PUBLIC_KEY_BYTES],
                              gn_float_send_state_t* out);
} gn_float_send_api_t;
```

App видит peer_pk-level surface, не conn_id-level.

## Bootstrap dependencies

Strategy plugins часто зависят от других strategies или от
kernel-side primitives. Зависимости документируются в plugin's
README.

Типичная цепочка:

- `gn.float-send.rtt` → требует `gn.heartbeat` (для RTT signal) +
  `gn.peer-info` (для known reachable URIs)
- `gn.peer-info` → требует `gn.discovery.*` (для bootstrap peer
  list)
- `gn.discovery.dht-walk` → требует `gn.dht.*` (для underlying
  routing)
- `gn.dht.kademlia` → требует `gn.peer-info` (для seed nodes) —
  potential cycle

Plugin author resolves cycle'ы через graceful degradation:

- DHT plugin при init читает seed list из config (operator
  supplies); если `gn.peer-info` появляется позже, DHT
  переключается на её данные.
- float-send при init проверяет наличие `gn.heartbeat`; если
  нет — fallback на конфигурируемый RTT estimate.

Composition contract'ом фиксируется в plugin's `manifest.json`
under `requires` / `optional` keys (eventually; pre-rc1 — в
README).

## Composition pattern

App выбирает конкретный strategy namespace явно:

```cpp
const gn_float_send_api_t* fs = nullptr;
if (host_api->query_extension_checked(host_ctx,
                                       "gn.float-send.rtt-optimal",
                                       0x00010000,
                                       (const void**)&fs) != GN_OK) {
    /* Strategy not loaded; fallback to static send by URI lookup. */
}
```

Несколько strategies в одном app:

```cpp
const gn_float_send_api_t* fs_rtt = lookup("gn.float-send.rtt-optimal");
const gn_float_send_api_t* fs_cost = lookup("gn.float-send.cost-aware");

void on_rpc_request(...) {
    fs_rtt->send(peer_pk, RPC_MSG_ID, payload, sz);  // latency-sensitive
}

void on_bulk_upload(...) {
    fs_cost->send(peer_pk, BULK_MSG_ID, payload, sz);  // bandwidth-sensitive
}
```

Kernel не выбирает между strategies — app выбирает по namespace
для каждого call site'а.

Operator выбирает что load'ить через свой compose flake:

```nix
plugins = [
    handler-heartbeat
    handler-peer-info
    handler-float-send-rtt-optimal
    # cost-aware variant НЕ грузим — этому узлу не нужно
];
```

Если не loaded — `query_extension_checked` возвращает
`GN_ERR_NOT_FOUND`, app падает на fallback.

## Switch granularity

Per [`multi-path`](./multi-path.ru.md) — sequential switch
between connections, никакой aggregation. Strategy plugins
наследуют этот контракт.

Atomic per message: одно сообщение пишется через текущий best
conn целиком; switch может произойти ТОЛЬКО между сообщениями,
не в середине.

```
fs->send(peer, msg_id, payload)  ← uses conn A
fs->send(peer, msg_id, payload)  ← strategy detected better path,
                                    swapped to conn B
fs->send(peer, msg_id, payload)  ← uses conn B
```

Между двумя `send` calls strategy может dial new conn, wait
TRUST_UPGRADED (или CONNECTED for loopback), update internal
map, disconnect old. Но никогда не разрывает payload пополам.

## Failure semantics

`fs->send(peer_pk, msg_id, payload)` возвращает `gn_result_t`:

- `GN_OK` — сообщение поставлено в send queue текущего best conn
- `GN_ERR_NOT_FOUND` — peer_pk неизвестен (нет URI hint, нет
  active conn, нет alternatives через peer-info / DHT / discovery)
- `GN_ERR_LIMIT_REACHED` — все известные пути отвалились или
  под backpressure
- `GN_ERR_TIMEOUT` — initial dial не успел до timeout'а

Strategy не магия. Если все пути отвалились — app получает error
и решает что делать (queue для retry, drop, escalate).

Plugin's README документирует max retry timing, threshold
конфигурацию, fallback поведение.

## Receive-side passive

Sender's strategy переключает conn'ы под капотом. Receiver
видит inbound сообщения на любой active conn от того же peer'а.
Kernel router'у конн всё равно — он dispatch'ит handler по
`(protocol_id, msg_id)`, не по conn_id.

Receiver-side strategy (если loaded) maintain'ит свою собственную
карту peer_pk → conn для return path. Sender-side и receiver-side
strategies могут быть **разные** — RTT-optimal на одной стороне,
cost-aware на другой. Координации между ними нет — каждая сторона
оптимизирует свой исходящий путь самостоятельно.

Bootstrap'ом для receiver-side служит та же цепочка
peer-info / DHT / discovery: receiver узнаёт reachable URIs
sender'а через те же extensions, что использует sender для
обратного процесса.

Это асимметрично, но симметрия не требуется. Сети где path A→B
быстрее чем B→A — нормальное явление (asymmetric NAT, asymmetric
routing). Strategy plugins это естественно поддерживают.

## Принцип transparency

Foundations §1: «каждый компонент либо переносит точку решений
ближе к узлу-человеку, либо отдаляет её».

Strategy plugin **усиливает суверенитет** только если operator
осознанно понимает что выбирает. Доку:

- Что стратегия optimize'ит (RTT? throughput? cost? privacy?)
- Какие signals consumes (heartbeat RTT? user-supplied weight
  map? jitter histogram?)
- Switch heuristic в чётких числах (threshold X% degradation
  за Y seconds — не «когда станет лучше»)
- Failure modes (что значит «не нашёл путь»)

«Smart routing» что прячет heuristics — anti-pattern. Operator
не понимает почему конкретное сообщение пошло куда пошло →
теряет контроль над собственным узлом.

Strategy plugins что explicitly декларируют trade-off'ы оставляют
operator'у sovereignty над выбором между strategies.

## Cross-references

- [`extension-model`](./extension-model.ru.md) — primitive
  `register_extension` / `query_extension_checked`, на котором
  strategies построены
- [`built-in-extensions`](./built-in-extensions.ru.md) — каталог
  exposed extensions; reserved namespaces для strategy categories
  перечислены здесь
- [`multi-path`](./multi-path.ru.md) — sequential-switch
  primitive, который float-send и relay strategies наследуют
- [`relay-direct`](./relay-direct.ru.md) — concrete pattern что
  будущая `gn.relay.*` strategy формализует
- [`overview`](./overview.ru.md) §«Что не делает ядро» — почему
  kernel agnostic к routing strategies
- [`plugin-model`](./plugin-model.ru.md) — handler+extension
  combo pattern, на котором каждый strategy plugin построен
