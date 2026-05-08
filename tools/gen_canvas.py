#!/usr/bin/env python3
"""Generate Obsidian-compatible architecture.canvas for the rebuild.

Usage:
    python3 tools/gen_canvas.py            # default → docs/architecture.canvas
    python3 tools/gen_canvas.py --out PATH

Reads the architecture description from this file, computes a layout via
Graphviz `dot`, and writes a JSON Canvas document. The shape matches the
current code:

  * 8 loadable plugin units + kernel + integration-tests, drawn as
    independent cells (each lives in its own git checkout under
    plugins/<kind>/<name>/, with goodnet-integration-tests as the 9th
    sibling).
  * Kernel as a pure registry: handlers / links / security providers /
    extensions are all owned by plugins and reach the kernel through
    `host_api->register_*`.
  * No orchestrator, no path manager, no reconnect manager, no
    optimizer. Multi-path is sequential link switch (dial new, drop
    old), not aggregation.
  * `host_api_t` ~21 named slots, KIND-tagged register/unregister with
    two families: HANDLER and LINK. Security providers and extensions
    have their own typed slots.
  * Trust classes: Untrusted → Peer (one-way upgrade after
    attestation), Loopback / IntraNode set on connect and immutable.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUT = REPO_ROOT / "docs" / "architecture.canvas"

# ── Catppuccin Mocha canvas colors ──────────────────────────────────────────
# Obsidian canvas color indices: 1=red, 2=orange, 3=yellow, 4=green, 5=cyan, 6=purple
C_RED = "1"
C_ORANGE = "2"
C_YELLOW = "3"
C_GREEN = "4"
C_CYAN = "5"
C_PURPLE = "6"


# ── Architecture definition ─────────────────────────────────────────────────

# Groups: id, label, color, member_node_ids
GROUPS = [
    ("g_public",  "PUBLIC C ABI (sdk/core.h)",            C_CYAN,
        ["n_core_c", "n_config", "n_error"]),
    ("g_sdk",     "SDK INTERFACES (sdk/*.h)",             C_YELLOW,
        ["n_host_api", "n_handler_iface", "n_link_iface",
         "n_security_iface", "n_protocol_iface", "n_trust", "n_limits"]),
    ("g_kernel",  "KERNEL (core/, agnostic to wire formats)", C_RED,
        ["n_kernel", "n_router", "n_attest"]),
    ("g_registry", "REGISTRIES (core/registry/)",         C_GREEN,
        ["n_conn_reg", "n_handler_reg", "n_link_reg",
         "n_sec_reg", "n_ext_reg", "n_session_reg"]),
    ("g_plugin",  "PLUGIN MANAGEMENT (core/plugin/, core/kernel/)", C_GREEN,
        ["n_plug_mgr", "n_svc_res", "n_anchor"]),
    ("g_signal",  "SIGNAL INFRASTRUCTURE (core/kernel/)",  C_PURPLE,
        ["n_conn_events", "n_metrics", "n_timer"]),
    # ── Plugin units (each ships in its own git, see goodnet-io/<kind>-<name>) ──
    ("g_proto",   "PROTOCOL PLUGINS (kernel-static)",      C_ORANGE,
        ["n_gnet_proto", "n_raw_proto"]),
    ("g_security", "SECURITY PLUGINS",                     C_ORANGE,
        ["n_noise_plugin", "n_null_plugin"]),
    ("g_links",   "LINK PLUGINS",                          C_ORANGE,
        ["n_tcp_plugin", "n_udp_plugin", "n_ws_plugin",
         "n_ipc_plugin", "n_tls_plugin"]),
    ("g_handlers", "HANDLER PLUGINS",                      C_ORANGE,
        ["n_heartbeat_plugin"]),
    ("g_ext_tests", "INTEGRATION TESTS (sibling repo)",    C_YELLOW,
        ["n_int_tests"]),
]

# Nodes: id → (short_label, full_card_text)
NODES: dict[str, tuple[str, str]] = {
    # ── Public C ABI ────────────────────────────────────────────────────────
    "n_core_c": (
        "gn_core (sdk/core.h)",
        "# gn_core — public C ABI\n"
        "`sdk/core.h` → `core/kernel/core_c.cpp`\n\n"
        "**Single entry point**\n\n"
        "```c\n"
        "gn_result_t gn_core_create(const gn_core_config_t*, gn_core_t**);\n"
        "gn_result_t gn_core_start(gn_core_t*);\n"
        "void        gn_core_stop(gn_core_t*);\n"
        "void        gn_core_destroy(gn_core_t*);\n"
        "```\n\n"
        "Все языковые биндинги встают сверху одного C ABI.\n"
        "C++ удобства в `sdk/convenience.h` — header-only inline."
    ),
    "n_config": (
        "Config (JSON)",
        "# Config\n`sdk/types.h` (gn_config_value_type_t) →\n"
        "`core/config/`\n\n"
        "Plain JSON документ, валидируется на load.\n"
        "Доступ через `host_api->config_get(key, type, index, ...)`:\n"
        "- dotted-path (`links.tcp.listen`)\n"
        "- typed read с явной проверкой\n"
        "- reload через subscribe_config_reload\n\n"
        "Limits подмножеством — `host_api->limits()` отдаёт готовый\n"
        "`gn_limits_t*` на всю жизнь плагина."
    ),
    "n_error": (
        "gn_result_t",
        "# gn_result_t\n`sdk/types.h`\n\n"
        "```c\n"
        "typedef enum {\n"
        "  GN_OK = 0,\n"
        "  GN_ERR_NULL_ARG, GN_ERR_NOT_FOUND,\n"
        "  GN_ERR_INVALID_ENVELOPE,\n"
        "  GN_ERR_VERSION_MISMATCH,\n"
        "  GN_ERR_LIMIT_REACHED,\n"
        "  GN_ERR_OUT_OF_RANGE, GN_ERR_INVALID_STATE,\n"
        "  ...\n"
        "} gn_result_t;\n"
        "```\n\n"
        "Один enum для каждого failure mode.\n"
        "Контракт `host-api.md` фиксирует возврат на каждом slot'е."
    ),

    # ── SDK interfaces ──────────────────────────────────────────────────────
    "n_host_api": (
        "host_api_t",
        "# host_api_t\n`sdk/host_api.h`\n\n"
        "Public host vtable — всё, что плагин запрашивает у ядра, идёт через "
        "один size-prefixed C struct (~21 named slot + 8 reserved).\n\n"
        "**Семейства slot'ов:**\n"
        "- Messaging: `send`, `disconnect`\n"
        "- Registration (KIND-tagged): `register_vtable(kind, meta, vt, self, &id)` "
        "+ `unregister_vtable(id)`. KINDs: `HANDLER`, `LINK`.\n"
        "- Security: `register_security` / `unregister_security` (один активный провайдер v1)\n"
        "- Queries: `find_conn_by_pk`, `get_endpoint`, `for_each_connection`\n"
        "- Extensions: `register_extension`, `query_extension_checked`, `unregister_extension`\n"
        "- Config + limits: `config_get`, `limits()`\n"
        "- Link callbacks: `notify_connect`, `notify_inbound_bytes`, "
        "`notify_disconnect`, `notify_backpressure`, `kick_handshake`\n"
        "- Channels: `subscribe_conn_state`, `subscribe_config_reload`, `unsubscribe`\n"
        "- Service: `set_timer`, `cancel_timer`, `inject(LAYER_*)`\n"
        "- Metrics: `emit_counter`, `iterate_counters`, plus `log` sub-vtable\n"
        "- Cooperative shutdown: `is_shutdown_requested`\n\n"
        "Каждая запись принимает `host_ctx` первым аргументом — тот же\n"
        "указатель, что плагин получил на init."
    ),
    "n_handler_iface": (
        "gn_handler_vtable_t",
        "# gn_handler_vtable_t\n`sdk/handler.h`\n\n"
        "Handler — обработчик envelope'ов на конкретный `msg_id` или wildcard.\n\n"
        "```c\n"
        "gn_propagation_t (*on_message)(void* self,\n"
        "                                const gn_message_header_t*,\n"
        "                                const gn_endpoint_t*,\n"
        "                                const uint8_t* payload, size_t);\n"
        "void (*on_conn_state)(void* self, gn_conn_id_t,\n"
        "                       const char* uri, gn_conn_state_t);\n"
        "```\n\n"
        "Регистрируется через\n"
        "`register_vtable(GN_REGISTER_HANDLER, meta{name, msg_id, priority}, vt, self, &id)`."
    ),
    "n_link_iface": (
        "gn_link_vtable_t",
        "# gn_link_vtable_t\n`sdk/link.h`\n\n"
        "Link — единица «открыть/закрыть/отправить» поверх какого-то транспорта.\n\n"
        "```c\n"
        "gn_result_t (*listen)(void* self, const char* uri);\n"
        "gn_result_t (*connect)(void* self, const char* uri,\n"
        "                       const uint8_t pk[GN_PUBLIC_KEY_BYTES]);\n"
        "gn_result_t (*send)(void* self, gn_conn_id_t,\n"
        "                    const uint8_t* bytes, size_t);\n"
        "gn_result_t (*close)(void* self, gn_conn_id_t);\n"
        "void        (*shutdown)(void* self);\n"
        "uint32_t    (*properties)(void* self);  // stream/datagram/...\n"
        "```\n\n"
        "Регистрируется по URI scheme (`tcp://`, `udp://`, `ws://`, `ipc://`, `tls://`).\n"
        "Conn-id ownership gate: только владелец схемы может звать\n"
        "`notify_inbound_bytes` / `notify_disconnect` для своих conn_id\n"
        "(`security-trust.md` §6a)."
    ),
    "n_security_iface": (
        "gn_security_provider_vtable_t",
        "# gn_security_provider_vtable_t\n`sdk/security.h`\n\n"
        "Security provider — handshake + AEAD.\n\n"
        "```c\n"
        "handshake_open(self, conn, trust, role,\n"
        "               local_sk, local_pk, remote_pk, &state);\n"
        "handshake_step(self, state, in, in_size, &out_msg);\n"
        "handshake_complete(self, state) -> int;\n"
        "export_transport_keys(self, state, &keys);\n"
        "encrypt(self, state, plain, plain_size, &out);\n"
        "decrypt(self, state, cipher, cipher_size, &out);\n"
        "rekey(self, state); handshake_close(self, state);\n"
        "allowed_trust_mask(self) -> uint32_t;\n"
        "```\n\n"
        "v1: один активный провайдер на ядро. Per-trust-class селекция\n"
        "уезжает в StackRegistry в v1.x."
    ),
    "n_protocol_iface": (
        "gn_protocol_layer_t",
        "# gn_protocol_layer_t\n`sdk/protocol.h`\n\n"
        "Framing layer — режет байтовый поток на envelope'ы.\n\n"
        "Реализаций две, обе линкуются в kernel binary как STATIC\n"
        "(не отдельные `.so`):\n"
        "- **GnetProtocol** — каноничный wire-формат (header + payload)\n"
        "- **RawProtocol** — passthrough для локальных стеков (loopback / intra-node).\n\n"
        "`allowed_trust_mask()` ограничивает класс trust, на который\n"
        "формат соглашается принять конн (raw — только Loopback / IntraNode)."
    ),
    "n_trust": (
        "TrustClass",
        "# TrustClass\n`sdk/trust.h` + `docs/contracts/security-trust.md`\n\n"
        "```c\n"
        "GN_TRUST_UNTRUSTED  = 0,  // публичный TCP/UDP до handshake\n"
        "GN_TRUST_PEER       = 1,  // pk известен + Noise complete + attestation\n"
        "GN_TRUST_LOOPBACK   = 2,  // 127.0.0.1 / IPC\n"
        "GN_TRUST_INTRA_NODE = 3   // bridge IPC, между плагинами одного ядра\n"
        "```\n\n"
        "**Один путь апгрейда:** `Untrusted → Peer` после успешной\n"
        "взаимной аттестации (см. `attestation.md`). Любой другой\n"
        "переход отбит ядром синхронно.\n\n"
        "Loopback и IntraNode фиксируются на `notify_connect`\n"
        "и не меняются."
    ),
    "n_limits": (
        "gn_limits_t",
        "# gn_limits_t\n`sdk/limits.h`\n\n"
        "Resource bounds: max_connections, pending_queue_bytes_high/low/hard,\n"
        "max_payload_bytes, max_handlers_per_msg_id, max_relay_ttl,\n"
        "max_plugins, max_extensions, max_timers, max_counter_names,\n"
        "inject_rate_per_source/burst/lru_cap, ...\n\n"
        "Доступен через `host_api->limits()` — borrowed `const`-указатель\n"
        "на всё время жизни плагина. Hard-coded параллельные пороги в\n"
        "core/plugins запрещены."
    ),

    # ── Kernel ───────────────────────────────────────────────────────────────
    "n_kernel": (
        "Kernel",
        "# Kernel\n`core/kernel/kernel.{hpp,cpp}`\n\n"
        "Тонкая оркестрация фаз — никаких знаний о wire-форматах,\n"
        "транспортах или security политиках. Ядро держит регистры и\n"
        "позволяет плагинам слать сообщения друг другу.\n\n"
        "**Lifecycle FSM** (`plugin-lifetime.md` §2):\n"
        "```\n"
        "discover → dlopen → version-check →\n"
        "init_all → register_all → on_running →\n"
        "pre_shutdown → unregister_all → shutdown_all → dlclose\n"
        "```\n\n"
        "Two-phase activation: все плагины сначала `init`, потом `register`.\n"
        "При сбое — clean rollback без выхода в dispatch.\n\n"
        "Ядро владеет: PluginManager, ServiceResolver, Router,\n"
        "AttestationDispatcher, MetricsRegistry, TimerRegistry, и набор\n"
        "регистров справа."
    ),
    "n_router": (
        "Router",
        "# Router\n`core/kernel/router.{hpp,cpp}`\n\n"
        "**Data path** (один на ядро, без orchestrator):\n"
        "```\n"
        "link.notify_inbound_bytes(conn, bytes)\n"
        "  → security.decrypt(state, bytes)\n"
        "  → protocol.deframe(buf) → envelopes[]\n"
        "  → for each envelope:\n"
        "      lookup handlers by msg_id (priority sorted)\n"
        "      dispatch chain: CONTINUE / CONSUMED / REJECT\n"
        "send(conn, msg_id, payload)\n"
        "  → protocol.frame() → security.encrypt() → link.send()\n"
        "```\n\n"
        "Inline crypto fast-path: после handshake'а\n"
        "`InlineCrypto` шунтирует security vtable для post-handshake\n"
        "AEAD по горячему пути."
    ),
    "n_attest": (
        "AttestationDispatcher",
        "# AttestationDispatcher\n`core/kernel/attestation_dispatcher.{hpp,cpp}`\n\n"
        "Внутренний обработчик 232-байтового attestation envelope.\n"
        "Запускается **после** Noise (или эквивалента), удерживает trust class\n"
        "на `Untrusted` пока обе стороны не отправили и не проверили payload\n"
        "(`docs/contracts/attestation.md`).\n\n"
        "Только успешная взаимная аттестация переводит conn в `Peer`."
    ),

    # ── Registries ───────────────────────────────────────────────────────────
    "n_conn_reg": (
        "ConnectionRegistry",
        "# ConnectionRegistry\n`core/registry/connection.{hpp,cpp}`\n\n"
        "16 шардованных bucket'ов под shared_mutex.\n"
        "Хранит `ConnectionContext`: conn_id, link_scheme, remote_pk, trust,\n"
        "state, security session, pending counters.\n\n"
        "Вторичные индексы: pubkey → conn_id (для `find_conn_by_pk`)."
    ),
    "n_handler_reg": (
        "HandlerRegistry",
        "# HandlerRegistry\n`core/registry/handler.{hpp,cpp}`\n\n"
        "Registry для KIND_HANDLER. Поиск по `msg_id` →\n"
        "приоритетно отсортированный список. `lookup` возвращает snapshot\n"
        "by-value, чьи lifetime_anchor копии держат плагин загруженным\n"
        "до конца dispatch'а."
    ),
    "n_link_reg": (
        "LinkRegistry",
        "# LinkRegistry\n`core/registry/link.{hpp,cpp}`\n\n"
        "Registry для KIND_LINK. Ключ — URI scheme (`tcp`, `udp`, `ws`,\n"
        "`ipc`, `tls`).\n\n"
        "**Conn-id ownership gate** (`security-trust.md` §6a):\n"
        "хранит маппинг scheme → lifetime_anchor зарегистрировавшего плагина.\n"
        "Любая попытка чужого link'а позвать `notify_*` для conn_id, чей\n"
        "scheme принадлежит другому плагину, ловит `GN_ERR_NOT_FOUND`."
    ),
    "n_sec_reg": (
        "SecurityRegistry",
        "# SecurityRegistry\n`core/registry/security.{hpp,cpp}`\n\n"
        "Один активный provider'ный slot v1 (`security-trust.md` §6).\n"
        "Второй `register_security` возвращает `GN_ERR_LIMIT_REACHED`.\n\n"
        "При `Sessions::create` ядро сверяет `trust` конна с\n"
        "`provider->allowed_trust_mask()`; mismatch → синхронный отказ +\n"
        "`metrics.drop.trust_class_mismatch`."
    ),
    "n_ext_reg": (
        "ExtensionRegistry",
        "# ExtensionRegistry\n`core/registry/extension.{hpp,cpp}`\n\n"
        "Глобальный namespace для plugin↔plugin контрактов\n"
        "(`heartbeat.peer.miss`, `link.upgrade.tls`, ...).\n\n"
        "`register_extension(name, version, vtable)` —\n"
        "`query_extension_checked(name, version, &vtable)` —\n"
        "версия сверяется по semver-major + min-minor (`abi-evolution.md`).\n\n"
        "Ядро — pure registry; никаких встроенных extension'ов."
    ),
    "n_session_reg": (
        "SessionRegistry",
        "# SessionRegistry\n`core/security/session.{hpp,cpp}`\n\n"
        "Per-conn security state: handshake state-machine + AEAD ключи\n"
        "post-handshake. Хранит `gn_secure_buffer_t`-ownership ссылки на\n"
        "выходные сообщения handshake'а до коммита."
    ),

    # ── Plugin management ────────────────────────────────────────────────────
    "n_plug_mgr": (
        "PluginManager",
        "# PluginManager\n`core/plugin/plugin_manager.{hpp,cpp}`\n\n"
        "dlopen + ABI version check (`gn_plugin_sdk_version`).\n\n"
        "Two-phase activation (`plugin-lifetime.md` §5):\n"
        "1. `init_all` — все плагины строят локальный state\n"
        "2. `register_all` — плагины зовут `register_vtable` / `register_security` /\n"
        "    `register_extension` под отсортированным порядком зависимостей\n\n"
        "Teardown — зеркально, c quiescence через **weak observer** на\n"
        "lifetime_anchor каждого плагина. Если плагин не отозвал свои\n"
        "in-flight async задачи за drain timeout — ядро **leak'ает\n"
        "dlclose**, не вырубает живой код."
    ),
    "n_svc_res": (
        "ServiceResolver",
        "# ServiceResolver\n`core/kernel/service_resolver.{hpp,cpp}`\n\n"
        "Kahn'овский topo-sort по `plugin-manifest.{provides, requires}`.\n"
        "Решает порядок `register_all`. Цикл — fail при `pre-running`,\n"
        "ядро не уходит в `running` с неудовлетворённым графом."
    ),
    "n_anchor": (
        "PluginAnchor",
        "# PluginAnchor\n`core/kernel/plugin_anchor.hpp`\n\n"
        "Ref-counted handle на «плагин жив». Каждая registry-запись\n"
        "(handler, link, security, extension) держит **strong** копию.\n"
        "Каждый async callback (timer fire, posted task,\n"
        "subscribe_conn_state coroutine) держит **weak**.\n\n"
        "Перед dispatch'ом callback пытается `upgrade()` weak → strong;\n"
        "null → silent drop. Это закрывает UAF между `unregister`-ом\n"
        "плагина и поздним коллбеком."
    ),

    # ── Signal infrastructure ────────────────────────────────────────────────
    "n_conn_events": (
        "ConnEvents channel",
        "# ConnEvents\n`sdk/conn_events.h` + `core/kernel/conn_event.hpp`\n\n"
        "Один pub/sub поток — `subscribe_conn_state(cb, ud, &id)`.\n"
        "Несёт state-машину conn'а: `Connecting → Handshake → Established →\n"
        "Closing → Closed` плюс backpressure soft/clear.\n\n"
        "Подписки парятся с lifetime_anchor подписчика —\n"
        "`unsubscribe(id)` идемпотентен, и weak-кратко срабатывает,\n"
        "если плагин уже выгрузился."
    ),
    "n_metrics": (
        "MetricsRegistry",
        "# MetricsRegistry\n`core/kernel/metrics_registry.{hpp,cpp}`\n\n"
        "Плоский UTF-8 keyed counter store. Плагины зовут\n"
        "`emit_counter(name)` для cross-cutting телеметрии,\n"
        "exporter (отдельный плагин) ходит через `iterate_counters`.\n\n"
        "Cardinality cap = `limits.max_counter_names` (8192 default);\n"
        "через cliff — `metrics.cardinality_rejected` поднимается."
    ),
    "n_timer": (
        "TimerRegistry",
        "# TimerRegistry\n`core/kernel/timer_registry.{hpp,cpp}`\n\n"
        "Один shared service executor (`timer.md`). Все таймеры\n"
        "плагинов парятся с их lifetime_anchor.\n"
        "После shutdown_requested — pending fire'ы дропаются\n"
        "до того как зайдут в плагин."
    ),

    # ── Protocol plugins (kernel-static) ────────────────────────────────────
    "n_gnet_proto": (
        "gnet protocol",
        "# gnet protocol\n`plugins/protocols/gnet/`\n\n"
        "Каноничный wire-формат — header + payload + framing.\n"
        "Линкуется как **STATIC** в kernel binary (kernel-internal),\n"
        "не отдельный `.so`.\n\n"
        "`allowed_trust_mask = Untrusted | Peer | Loopback | IntraNode`."
    ),
    "n_raw_proto": (
        "raw protocol",
        "# raw protocol\n`plugins/protocols/raw/`\n\n"
        "Passthrough — payload = envelope. Без framing'а, без reassembly.\n"
        "Только для локальных стеков.\n\n"
        "`allowed_trust_mask = Loopback | IntraNode` —\n"
        "ядро отбивает попытки использовать raw на `Untrusted`."
    ),

    # ── Security plugins ─────────────────────────────────────────────────────
    "n_noise_plugin": (
        "security-noise",
        "# security-noise\n`plugins/security/noise/`\n\n"
        "Independent git unit (mirror `goodnet-io/security-noise`).\n"
        "GPL-2 + linking exception.\n\n"
        "Реализует `gn_security_provider_vtable_t`:\n"
        "- Noise_XX_25519_ChaChaPoly_BLAKE2b (3-message handshake)\n"
        "- libsodium для AEAD / KDF / random\n"
        "- export_transport_keys → передаёт ключи в kernel-side\n"
        "  `InlineCrypto` для post-handshake fast path\n\n"
        "`allowed_trust_mask = Untrusted | Peer` — ставится на провайдера\n"
        "и проверяется ядром на каждый `Sessions::create`."
    ),
    "n_null_plugin": (
        "security-null",
        "# security-null\n`plugins/security/null/`\n\n"
        "Independent git unit. MIT.\n\n"
        "Passthrough provider — `needs_handshake = false`,\n"
        "encrypt/decrypt = identity copy.\n\n"
        "`allowed_trust_mask = Loopback | IntraNode` —\n"
        "под канонический v1 stack включается **только** для локальных\n"
        "конн'ов; попытка взять null на `Untrusted` отбивается ядром\n"
        "синхронно. Plain-text-on-untrusted в v1 unreachable."
    ),

    # ── Link plugins ─────────────────────────────────────────────────────────
    "n_tcp_plugin": (
        "link-tcp",
        "# link-tcp\n`plugins/links/tcp/`\n\n"
        "Independent git unit (`goodnet-io/link-tcp`). GPL-2 + lex.\n\n"
        "`scheme = \"tcp\"`. Boost.Asio:\n"
        "- async accept / connect / read / write\n"
        "- per-connection strand + send queue\n"
        "- TrustClass из observable: 127.0.0.1 → Loopback, иначе → Untrusted\n\n"
        "Bench (post inline-crypto Phase 1): 6.42 Gbps single-conn 16KB×1000."
    ),
    "n_udp_plugin": (
        "link-udp",
        "# link-udp\n`plugins/links/udp/`\n\n"
        "Independent git unit. GPL-2 + lex.\n\n"
        "`scheme = \"udp\"`. Datagram link — без reliability, без ordering.\n"
        "Application-level reassembly через protocol layer."
    ),
    "n_ws_plugin": (
        "link-ws",
        "# link-ws\n`plugins/links/ws/`\n\n"
        "Independent git unit. GPL-2 + lex.\n\n"
        "`scheme = \"ws\"` / `\"wss\"`. Boost.Beast — binary frames только.\n"
        "Browser-friendly путь к ядру."
    ),
    "n_ipc_plugin": (
        "link-ipc",
        "# link-ipc\n`plugins/links/ipc/`\n\n"
        "Independent git unit. MIT.\n\n"
        "`scheme = \"ipc\"`. Unix domain socket. Default trust = `Loopback`.\n\n"
        "Bridge-плагины поверх IPC объявляют `IntraNode` на\n"
        "`notify_connect` — null security их пропустит без handshake'а\n"
        "(`security-trust.md` §3, bridge-плагины)."
    ),
    "n_tls_plugin": (
        "link-tls",
        "# link-tls\n`plugins/links/tls/`\n\n"
        "Independent git unit. Apache-2.0 (OpenSSL compat).\n\n"
        "`scheme = \"tls\"`. Identity authentication — задача security pipeline'а,\n"
        "не TLS. По умолчанию `verify_peer = true` (OpenSSL trust store);\n"
        "`links.tls.verify_peer = false` — opt-out для случая, когда Noise\n"
        "поверху берёт identity на себя."
    ),

    # ── Handler plugins ──────────────────────────────────────────────────────
    "n_heartbeat_plugin": (
        "handler-heartbeat",
        "# handler-heartbeat\n`plugins/handlers/heartbeat/`\n\n"
        "Independent git unit (`goodnet-io/handler-heartbeat`). GPL-2 + lex.\n\n"
        "Реализует `gn_handler_vtable_t`:\n"
        "- per-peer ping/pong на таймере\n"
        "- jitter `hash(conn_id) % 5s`\n"
        "- max_missed → `host_api->disconnect(conn)`\n"
        "- регистрирует extension `heartbeat.peer.miss` для соседних плагинов\n\n"
        "Cooperative shutdown через `is_shutdown_requested` —\n"
        "ре-arm таймера прекращается."
    ),

    # ── Sibling test repo ────────────────────────────────────────────────────
    "n_int_tests": (
        "goodnet-integration-tests",
        "# goodnet-integration-tests\n`tests/integration/` (sibling repo,\n"
        "mirror `goodnet-io/integration-tests`).\n\n"
        "Cross-plugin тесты — где живой сценарий нужен поверх двух+ плагинов\n"
        "(например, noise+tcp end-to-end). 5 plugin-bound тестов на текущий\n"
        "момент.\n\n"
        "Подтягивается тем же `nix run .#setup` через slot map.\n"
        "Чисто-kernel \"integration\" тесты живут в `tests/unit/integration/`\n"
        "и линкуются с kernel напрямую."
    ),
}

# Edges: (from, to, label, style "solid"|"dashed")
EDGES = [
    # Public ABI → kernel
    ("n_core_c", "n_kernel", "embeds", "solid"),

    # Kernel ownership of registries / signal infra
    ("n_kernel", "n_router", "owns", "solid"),
    ("n_kernel", "n_attest", "owns", "solid"),
    ("n_kernel", "n_conn_reg", "owns", "solid"),
    ("n_kernel", "n_handler_reg", "owns", "solid"),
    ("n_kernel", "n_link_reg", "owns", "solid"),
    ("n_kernel", "n_sec_reg", "owns", "solid"),
    ("n_kernel", "n_ext_reg", "owns", "solid"),
    ("n_kernel", "n_session_reg", "owns", "solid"),
    ("n_kernel", "n_plug_mgr", "owns", "solid"),
    ("n_kernel", "n_svc_res", "owns", "solid"),
    ("n_kernel", "n_metrics", "owns", "solid"),
    ("n_kernel", "n_timer", "owns", "solid"),
    ("n_kernel", "n_conn_events", "owns", "solid"),

    # host_api builds on top of registries
    ("n_host_api", "n_handler_reg", "register_vtable(HANDLER)", "dashed"),
    ("n_host_api", "n_link_reg",    "register_vtable(LINK)",    "dashed"),
    ("n_host_api", "n_sec_reg",     "register_security",         "dashed"),
    ("n_host_api", "n_ext_reg",     "register_extension",        "dashed"),
    ("n_host_api", "n_metrics",     "emit_counter",              "dashed"),
    ("n_host_api", "n_timer",       "set_timer",                 "dashed"),
    ("n_host_api", "n_conn_events", "subscribe_conn_state",      "dashed"),

    # Anchor weaves through every registry
    ("n_anchor", "n_handler_reg", "lifetime", "dashed"),
    ("n_anchor", "n_link_reg",    "lifetime", "dashed"),
    ("n_anchor", "n_sec_reg",     "lifetime", "dashed"),
    ("n_anchor", "n_ext_reg",     "lifetime", "dashed"),

    # Two-phase activation
    ("n_plug_mgr", "n_svc_res", "consults", "solid"),
    ("n_plug_mgr", "n_anchor",  "owns one per plugin", "solid"),

    # Router data path
    ("n_router", "n_session_reg", "decrypt/encrypt", "solid"),
    ("n_router", "n_handler_reg", "dispatch chain",  "solid"),
    ("n_router", "n_link_reg",    "send via owner",   "solid"),

    # Attestation guards trust upgrade
    ("n_attest", "n_conn_reg", "Untrusted → Peer", "solid"),
    ("n_attest", "n_trust",     "implements rule",   "dashed"),

    # Protocol plugins implement the protocol interface
    ("n_gnet_proto", "n_protocol_iface", "implements", "solid"),
    ("n_raw_proto",  "n_protocol_iface", "implements", "solid"),

    # Security plugins implement security_provider_vtable
    ("n_noise_plugin", "n_security_iface", "implements", "solid"),
    ("n_null_plugin",  "n_security_iface", "implements", "solid"),
    ("n_noise_plugin", "n_sec_reg",        "register_security", "dashed"),
    ("n_null_plugin",  "n_sec_reg",        "register_security", "dashed"),

    # Link plugins implement link_vtable
    ("n_tcp_plugin", "n_link_iface", "implements", "solid"),
    ("n_udp_plugin", "n_link_iface", "implements", "solid"),
    ("n_ws_plugin",  "n_link_iface", "implements", "solid"),
    ("n_ipc_plugin", "n_link_iface", "implements", "solid"),
    ("n_tls_plugin", "n_link_iface", "implements", "solid"),
    ("n_tcp_plugin", "n_link_reg",   "register_vtable(LINK,'tcp')", "dashed"),
    ("n_udp_plugin", "n_link_reg",   "register_vtable(LINK,'udp')", "dashed"),
    ("n_ws_plugin",  "n_link_reg",   "register_vtable(LINK,'ws')",  "dashed"),
    ("n_ipc_plugin", "n_link_reg",   "register_vtable(LINK,'ipc')", "dashed"),
    ("n_tls_plugin", "n_link_reg",   "register_vtable(LINK,'tls')", "dashed"),

    # Handler plugins
    ("n_heartbeat_plugin", "n_handler_iface", "implements", "solid"),
    ("n_heartbeat_plugin", "n_handler_reg",   "register_vtable(HANDLER)", "dashed"),
    ("n_heartbeat_plugin", "n_ext_reg",       "register_extension", "dashed"),

    # Integration tests live next to plugins
    ("n_int_tests", "n_kernel",          "drives end-to-end", "dashed"),
    ("n_int_tests", "n_noise_plugin",    "loads", "dashed"),
    ("n_int_tests", "n_tcp_plugin",      "loads", "dashed"),

    # Trust + limits feed everywhere
    ("n_trust",  "n_sec_reg",  "mask check", "dashed"),
    ("n_trust",  "n_link_iface", "set on connect", "dashed"),
    ("n_limits", "n_kernel",   "all bounds",  "dashed"),
    ("n_config", "n_kernel",   "load + reload", "dashed"),
    ("n_error",  "n_host_api", "every slot returns", "dashed"),
]


# ── Layout computation via Graphviz ─────────────────────────────────────────


def compute_layout_plain() -> dict[str, tuple[float, float, float, float]]:
    """Use `dot -Tplain` to get node positions + widths/heights in inches."""
    DPI = 96.0
    lines = ["digraph G {"]
    lines.append("  rankdir=TB; nodesep=0.8; ranksep=1.5;")
    lines.append("  node [shape=box];")

    for gid, label, _, members in GROUPS:
        lines.append(f"  subgraph cluster_{gid} {{")
        lines.append(f'    label="{label}";')
        for m in members:
            w_px, h_px = get_size(m)
            w_in = w_px / DPI
            h_in = h_px / DPI
            short = NODES[m][0].replace('"', r"\"").replace("\n", r"\n")
            lines.append(
                f'    {m} [label="{short}", '
                f"width={w_in:.2f}, height={h_in:.2f}];"
            )
        lines.append("  }")

    for src, dst, _label, style in EDGES:
        s = "dashed" if style == "dashed" else "solid"
        lines.append(f"  {src} -> {dst} [style={s}];")

    lines.append("}")
    dot_src = "\n".join(lines)

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".dot", delete=False
    ) as f:
        f.write(dot_src)
        dot_path = f.name

    try:
        result = subprocess.run(
            ["dot", "-Tplain", dot_path],
            capture_output=True,
            text=True,
            check=True,
        )
    finally:
        Path(dot_path).unlink(missing_ok=True)

    positions: dict[str, tuple[float, float, float, float]] = {}
    for line in result.stdout.splitlines():
        parts = line.split()
        if not parts or parts[0] != "node":
            continue
        if len(parts) < 6 or parts[1] not in NODES:
            continue
        cx, cy = float(parts[2]), float(parts[3])
        w, h = float(parts[4]), float(parts[5])
        positions[parts[1]] = (cx, cy, w, h)

    return positions


# ── Canvas card sizing ──────────────────────────────────────────────────────

CHAR_W = 7.5
LINE_H = 20
PAD_W = 40
PAD_H = 60
MIN_W = 280
MAX_W = 540
MIN_H = 160

GROUP_PAD_X = 50
GROUP_PAD_TOP = 70
GROUP_PAD_BOT = 50

_SIZE_CACHE: dict[str, tuple[int, int]] = {}


def auto_size(node_id: str) -> tuple[int, int]:
    text = NODES[node_id][1]
    lines = text.split("\n")
    max_line = max((len(line) for line in lines), default=10)
    w = int(max_line * CHAR_W + PAD_W)
    w = max(MIN_W, min(MAX_W, w))
    h = int(len(lines) * LINE_H + PAD_H)
    h = max(MIN_H, h)
    return w, h


def get_size(nid: str) -> tuple[int, int]:
    if nid not in _SIZE_CACHE:
        _SIZE_CACHE[nid] = auto_size(nid)
    return _SIZE_CACHE[nid]


# ── Canvas building ─────────────────────────────────────────────────────────


def build_canvas(positions: dict[str, tuple[float, float]]) -> dict:
    nodes: list[dict] = []
    edges_out: list[dict] = []

    # Group bounds.
    group_bounds: dict[str, tuple[float, float, float, float]] = {}
    for gid, _label, _color, members in GROUPS:
        present = [m for m in members if m in positions]
        if not present:
            continue
        coords = []
        for m in present:
            cx, cy = positions[m]
            w, h = get_size(m)
            coords.append((cx - w / 2, cy - h / 2, cx + w / 2, cy + h / 2))
        min_x = min(c[0] for c in coords) - GROUP_PAD_X
        min_y = min(c[1] for c in coords) - GROUP_PAD_TOP
        max_x = max(c[2] for c in coords) + GROUP_PAD_X
        max_y = max(c[3] for c in coords) + GROUP_PAD_BOT
        group_bounds[gid] = (min_x, min_y, max_x - min_x, max_y - min_y)

    for gid, label, color, _members in GROUPS:
        if gid not in group_bounds:
            continue
        x, y, w, h = group_bounds[gid]
        nodes.append(
            {
                "id": gid,
                "type": "group",
                "x": int(x),
                "y": int(y),
                "width": max(int(w), 320),
                "height": max(int(h), 220),
                "color": color,
                "label": label,
            }
        )

    for nid in NODES:
        if nid not in positions:
            print(f"  WARN: {nid} has no computed position, skipping")
            continue
        cx, cy = positions[nid]
        w, h = get_size(nid)
        nodes.append(
            {
                "id": nid,
                "type": "text",
                "text": NODES[nid][1],
                "x": int(cx - w / 2),
                "y": int(cy - h / 2),
                "width": w,
                "height": h,
            }
        )

    for src, dst, label, _style in EDGES:
        if src not in positions or dst not in positions:
            continue
        sx, sy = positions[src]
        dx, dy = positions[dst]
        ady = abs(sy - dy)
        adx = abs(sx - dx)
        if ady < 50 and adx > 100:
            from_side, to_side = ("right", "left") if sx < dx else ("left", "right")
        elif sy < dy:
            from_side, to_side = "bottom", "top"
        else:
            from_side, to_side = "top", "bottom"

        edges_out.append(
            {
                "id": f"e_{src}_{dst}",
                "fromNode": src,
                "fromSide": from_side,
                "toNode": dst,
                "toSide": to_side,
                "label": label,
            }
        )

    return {"nodes": nodes, "edges": edges_out}


# ── Entry point ─────────────────────────────────────────────────────────────


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out",
        type=Path,
        default=DEFAULT_OUT,
        help=f"output path (default: {DEFAULT_OUT.relative_to(REPO_ROOT)})",
    )
    args = parser.parse_args()

    DPI = 96.0
    print("Computing auto-sized layout via Graphviz dot...")

    for nid in NODES:
        get_size(nid)
    print(f"  Auto-sized {len(_SIZE_CACHE)} cards")

    positions_raw = compute_layout_plain()
    print(f"  Got positions for {len(positions_raw)}/{len(NODES)} nodes")
    if len(positions_raw) < len(NODES) * 0.8:
        print("  WARN: many nodes missing — check DOT source / Graphviz install")

    # inches → pixels
    positions = {k: (v[0] * DPI, v[1] * DPI) for k, v in positions_raw.items()}

    # Graphviz Y is bottom-up; canvas is top-down.
    if positions:
        max_y = max(cy for _, cy in positions.values())
        positions = {k: (cx, max_y - cy) for k, (cx, cy) in positions.items()}

    canvas = build_canvas(positions)
    print(
        f"  Canvas: {len(canvas['nodes'])} nodes, "
        f"{len(canvas['edges'])} edges"
    )

    out: Path = args.out
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as f:
        json.dump(canvas, f, indent="\t", ensure_ascii=False)
    print(f"  Written to {out}")


if __name__ == "__main__":
    main()
