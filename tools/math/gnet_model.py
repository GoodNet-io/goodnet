#!/usr/bin/env python3
"""
GNET Mathematical Model v2 — constants, formulas, ICE upgrade dynamics.

All values derived from the actual GoodNet codebase:
  - include/config.hpp
  - plugins/handlers/relay/relay.hpp + relay.cpp (directed-first relay!)
  - plugins/handlers/dht/routing_table.hpp
  - plugins/transports/ice/ice.cpp (ICE upgrade API)
  - core/orchestrator/path_manager.hpp
  - plugins/transports/*/
"""

from dataclasses import dataclass
from enum import Enum
from math import log2, log, ceil, prod, exp
from typing import List


# ── Transport definitions ────────────────────────────────────────────────────

class TransportType(Enum):
    TCP  = "tcp"
    UDP  = "udp"
    QUIC = "quic"
    ICE  = "ice"
    IPC  = "ipc"
    BLE  = "ble"
    BT   = "bt"
    MQTT = "mqtt"


@dataclass
class TransportProps:
    name: str
    mtu: int            # 0 = stream (no limit)
    reliable: bool
    nat_traversal: bool
    range_m: float      # approx range in meters, inf for WAN
    mode: str           # "stream" | "datagram" | "pubsub"
    bandwidth_mbps: float  # typical link bandwidth
    handshake_us: float = 0.0  # P50 measured loopback (852c20a), 0 = connectionless

    @property
    def effective_payload(self) -> int:
        """Usable payload after GNET header (20B) + Noise overhead (32B)."""
        if self.mtu == 0:
            return 65536
        return max(0, self.mtu - 20 - 32)


TRANSPORTS = {
    # bandwidth_mbps = typical link capacity (WAN/LAN deployment, not loopback).
    # Loopback latency/overhead numbers live in BenchMeasurements — don't mix.
    TransportType.TCP:  TransportProps("tcp",  0,    True,  False, float('inf'), "stream",   10_000, handshake_us=65.5),
    TransportType.UDP:  TransportProps("udp",  1200, False, False, float('inf'), "datagram",  5_000),
    # QUIC link capacity matches TCP on real networks.  The 3–9× RTT gap in
    # loopback benchmarks (issue #43) is a loopback artefact: CUBIC/BBR arm
    # congestion timers and PTO even on 127.0.0.1 — not representative of WAN.
    TransportType.QUIC: TransportProps("quic", 1200, True,  True,  float('inf'), "stream",   10_000, handshake_us=22_700.0),
    TransportType.ICE:  TransportProps("ice",  1200, False, True,  float('inf'), "datagram",    100),
    # IPC = AF_UNIX; range_m=0 means same host only
    TransportType.IPC:  TransportProps("ipc",  0,    True,  False, 0,            "stream",    9_000),
    TransportType.BLE:  TransportProps("ble",  247,  False, False, 30,           "datagram",      1),
    TransportType.BT:   TransportProps("bt",   0,    True,  False, 100,          "stream",        3),
    TransportType.MQTT: TransportProps("mqtt", 0,    True,  False, float('inf'), "pubsub",      100),
}


# ── Node configuration (from config.hpp) ────────────────────────────────────

@dataclass
class NodeConfig:
    max_connections: int = 1024
    send_queue_limit: int = 8 * 1024 * 1024    # 8 MiB per connection
    heartbeat_interval_ms: int = 30_000
    handshake_timeout_ms: int = 10_000
    shutdown_drain_ms: int = 5_000
    registry_shard_count: int = 16
    reconnect_initial_delay_ms: int = 1_000
    reconnect_max_delay_ms: int = 60_000
    reconnect_max_retries: int = 10


# ── DHT parameters (from routing_table.hpp, dht.hpp) ────────────────────────

@dataclass
class DhtConfig:
    k: int = 20
    buckets: int = 256
    refresh_interval_s: int = 3600

    @property
    def max_routing_entries(self) -> int:
        return self.buckets * self.k

    def filled_buckets(self, n: int) -> int:
        if n <= 1:
            return 0
        return ceil(log2(n))

    def actual_entries(self, n: int) -> int:
        return min(self.k * self.filled_buckets(n), self.max_routing_entries)

    def lookup_hops(self, n: int) -> float:
        if n <= 1:
            return 0
        return log2(n) / log2(self.k)

    def bootstrap_time_ms(self, n: int, avg_rtt_ms: float = 50.0) -> float:
        handshake = 10_000
        lookup = self.lookup_hops(n) * avg_rtt_ms
        return handshake + lookup


# ── Relay parameters (from relay.hpp, relay.cpp) ─────────────────────────────

@dataclass
class RelayConfig:
    dedup_capacity: int = 8192
    dedup_ttl_s: int = 30

    @property
    def max_relay_msg_per_sec(self) -> float:
        return self.dedup_capacity / self.dedup_ttl_s

    def gossip_messages(self, avg_degree: float, ttl: int) -> int:
        """Total messages for FULL gossip (worst case, no directed hops)."""
        d = avg_degree - 1
        if d <= 1:
            return ttl
        return int((d ** (ttl + 1) - 1) / (d - 1))

    def directed_relay_probability(self, n: int, k: int, hops: int) -> float:
        """Probability that at least one relay hop has direct path to dest.
        From relay.cpp:112 — find_conn_by_pubkey() is tried FIRST."""
        if n <= 0:
            return 0.0
        p_per_hop = min(1.0, k * ceil(log2(max(n, 2))) / n)
        return 1.0 - (1.0 - p_per_hop) ** hops


# ── ICE upgrade model (from ice.cpp) ─────────────────────────────────────────

@dataclass
class IceUpgradeConfig:
    """Models the relay→direct upgrade via ICE (ice.cpp:s_upgrade)."""
    # NAT type distribution (real-world estimates)
    nat_full_cone:       float = 0.30  # p_ice = 0.95
    nat_restricted:      float = 0.25  # p_ice = 0.90
    nat_port_restricted: float = 0.25  # p_ice = 0.80
    nat_symmetric:       float = 0.15  # p_ice = 0.30 (needs TURN)
    nat_public:          float = 0.05  # p_ice = 1.00

    # Timing — from session.hpp defaults
    signal_roundtrip_ms: float = 300    # ICE_SIGNAL via relay
    ice_gather_ms:       float = 1_000  # STUN gathering
    # Per-pair pacing (session.hpp:137); 500 pairs × 50ms = 25s check phase
    # → total theoretical upgrade time ≈ 26.3s ("25→27s" regime)
    check_interval_ms:   float = 50     # session.hpp:137 default
    n_candidate_pairs:   int   = 500    # typical many-peer scenario
    # Hard deadline from session.hpp:105; cuts off at 10s regardless of n_pairs
    session_timeout_s:   int   = 10

    @property
    def avg_ice_success_rate(self) -> float:
        """Weighted average ICE success probability (theoretical, when working)."""
        return (self.nat_full_cone * 0.95 +
                self.nat_restricted * 0.90 +
                self.nat_port_restricted * 0.80 +
                self.nat_symmetric * 0.30 +
                self.nat_public * 1.00)

    @property
    def ice_check_ms(self) -> float:
        """Total check phase: n_candidate_pairs × check_interval_ms pacing."""
        return self.n_candidate_pairs * self.check_interval_ms

    @property
    def upgrade_time_s(self) -> float:
        """Theoretical time for one ICE upgrade attempt (may exceed session_timeout_s)."""
        return (self.signal_roundtrip_ms + self.ice_gather_ms + self.ice_check_ms) / 1000

    @property
    def effective_upgrade_time_s(self) -> float:
        """Actual allowed time: capped at session_timeout_s."""
        return min(self.upgrade_time_s, float(self.session_timeout_s))

    @property
    def effective_success_rate(self) -> float:
        """Success rate accounting for session_timeout cutoff."""
        if self.upgrade_time_s > self.session_timeout_s:
            # Only pairs checked within the window can succeed
            return self.avg_ice_success_rate * (self.session_timeout_s / self.upgrade_time_s)
        return self.avg_ice_success_rate

    @property
    def upgrade_rate(self) -> float:
        """Lambda: effective successful upgrades per second."""
        t = self.effective_upgrade_time_s
        if t <= 0:
            return 0.0
        return self.effective_success_rate / t

    def relay_fraction(self, t: float, r0: float = 1.0) -> float:
        """Fraction of connections still using relay at time t."""
        lam = self.upgrade_rate
        if lam <= 0:
            return r0
        return r0 * exp(-lam * t)

    def time_to_percent_direct(self, target_direct: float = 0.95) -> float:
        """Seconds until target% of connections are direct."""
        target_relay = 1.0 - target_direct
        if target_relay <= 0:
            return float('inf')
        lam = self.upgrade_rate
        if lam <= 0:
            return float('inf')
        return -log(target_relay) / lam

    def amortized_cost(self, session_duration_s: float, msg_rate: float,
                       gossip_cost: float) -> float:
        """Amortized message cost over a session.
        Returns average messages-per-message (1.0 = perfect direct)."""
        t95 = self.time_to_percent_direct(0.95)
        total_msgs = session_duration_s * msg_rate
        if total_msgs <= 0:
            return gossip_cost

        # Relay phase: integral of R(t) * gossip_cost from 0 to t95
        # ∫₀^t95 e^(-λt) dt = (1 - e^(-λ*t95)) / λ
        lam = self.upgrade_rate
        if lam <= 0:
            return gossip_cost
        relay_integral = (1 - exp(-lam * t95)) / lam
        relay_msgs = msg_rate * gossip_cost * relay_integral

        # Direct phase: remaining time at cost=1
        direct_msgs = msg_rate * max(0, session_duration_s - t95) * 1.0

        # Bootstrap overhead (one-time)
        bootstrap = gossip_cost

        return (bootstrap + relay_msgs + direct_msgs) / total_msgs


# ── Measured bench values (report 852c20a, i5-1235U, loopback) ───────────────

@dataclass
class BenchMeasurements:
    """Real loopback numbers from bench/reports/852c20a (1024 B payload).

    Production stack = kernel + gnet protocol + Noise XX security.
    Parody = raw link plugin, no security, no protocol layer.
    """
    # One-way latency (production, μs)
    tcp_oneway_p50_us:  float = 21.1
    tcp_oneway_p99_us:  float = 43.2
    udp_oneway_p50_us:  float = 20.3
    udp_oneway_p99_us:  float = 41.6
    ipc_oneway_p50_us:  float = 18.1
    ipc_oneway_p99_us:  float = 32.8

    # RTT (production, μs)
    tcp_rtt_p50_us:     float = 43.6
    tcp_rtt_p99_us:     float = 82.1
    udp_rtt_p50_us:     float = 44.7
    udp_rtt_p99_us:     float = 89.3
    ipc_rtt_p50_us:     float = 33.3
    ipc_rtt_p99_us:     float = 57.0

    # QUIC+Noise RTT — 3–9× TCP (issue #43)
    quic_noise_rtt_p50_us:  float = 137.9
    quic_noise_rtt_p99_us:  float = 2_400.0

    # QUIC+TLS RTT — fixture broken (issue #44); P5=P95=0 ns, values invalid
    quic_tls_rtt_invalid: bool = True

    # Throughput, production stack, 1024 B (MiB/s)
    tcp_throughput_mbs:   float = 43.66
    udp_throughput_mbs:   float = 45.35
    ipc_throughput_mbs:   float = 51.95
    quic_noise_tput_mbs:  float = 8.32   # ~66 Mbit/s; 5× below TCP

    # Handshake P50 (μs)
    tcp_handshake_us:     float = 65.5
    tls_handshake_us:     float = 3_500.0
    dtls_handshake_us:    float = 22_100.0
    quic_handshake_us:    float = 22_700.0
    noise_xx_us:          float = 271.3
    noise_ik_us:          float = 340.7

    # ICE kernel-dispatch cost (not real wire ICE — bench_ice.cpp fixtures)
    ice_cid_alloc_ns:     float = 109.0   # ComposerConnectCidAllocation
    ice_metrics_lookup_ns: float = 20.0   # NominationMetricsLookup
    ice_fresh_session_us:  float = 8.2    # ComposerConnectFreshSession

    # examples/bench: TCP+Noise+gnet, 64 KB payload, LOOPBACK ONLY.
    # Linear scaling 1→8 connections because each connection has its own AEAD
    # pipeline with no shared lock on the hot path.
    # Numbers are loopback-only and CPU-scheduler-dependent (i5-1235U):
    #   typical avg ~20 Gbit/s at 8 conns; peak 30–40 when P-cores are assigned.
    # These do NOT represent real network deployment capacity.
    tcp_64k_per_conn_loopback_gbps: float = 5.0   # ~5 Gbit/s per connection (loopback)
    tcp_64k_linear_cap_conns:       int   = 8      # linear up to ~8 (CPU-bound after)
    tcp_64k_8conn_avg_gbps:         float = 20.0   # typical avg on i5-1235U
    tcp_64k_8conn_peak_gbps:        float = 40.0   # peak when hitting P-cores


# ── Multi-path reliability ───────────────────────────────────────────────────

def multipath_availability(path_availabilities: List[float]) -> float:
    """A = 1 - prod(1 - a_i)"""
    return 1.0 - prod(1.0 - a for a in path_availabilities)


class PathStrategy(Enum):
    LowestLatency = "lowest_latency"
    RoundRobin = "round_robin"
    Redundant = "redundant"


def effective_rtt(rtts_us: List[float], strategy: PathStrategy) -> float:
    active = [r for r in rtts_us if r > 0]
    if not active:
        return float('inf')
    if strategy == PathStrategy.LowestLatency:
        return min(active)
    elif strategy == PathStrategy.RoundRobin:
        return sum(active) / len(active)
    elif strategy == PathStrategy.Redundant:
        return min(active)
    return min(active)


def multipath_bandwidth(bandwidths_mbps: List[float], strategy: PathStrategy) -> float:
    """Effective bandwidth depending on strategy."""
    active = [b for b in bandwidths_mbps if b > 0]
    if not active:
        return 0
    if strategy == PathStrategy.LowestLatency:
        return max(active)  # use best path
    elif strategy == PathStrategy.RoundRobin:
        return sum(active)  # aggregate
    elif strategy == PathStrategy.Redundant:
        return max(active)  # duplicate, but no BW gain
    return max(active)


# ── Churn model ──────────────────────────────────────────────────────────────

def churn_relay_survival(churn_rate: float, hops: int, dt: float = 1.0) -> float:
    """Probability a relay path survives given churn.
    All intermediate nodes must stay alive."""
    p_alive = max(0, 1.0 - churn_rate * dt)
    return p_alive ** hops


def churn_direct_survival(churn_rate: float, dt: float = 1.0) -> float:
    """Probability a direct connection survives (only peer must be alive)."""
    return max(0, 1.0 - churn_rate * dt)


def churn_connectivity_threshold(n: int, churn_rate: float) -> float:
    """Minimum average degree to stay connected under churn.
    After losing churn_rate fraction of nodes, remaining graph needs ln(n') degree."""
    n_remaining = n * (1 - churn_rate)
    if n_remaining <= 1:
        return float('inf')
    return log(n_remaining)


# ── Reconnect ────────────────────────────────────────────────────────────────

def reconnect_delays(config: NodeConfig = NodeConfig()) -> List[int]:
    delays = []
    for i in range(config.reconnect_max_retries):
        d = min(config.reconnect_initial_delay_ms * (2 ** i),
                config.reconnect_max_delay_ms)
        delays.append(d)
    return delays


def reconnect_recovery_probability(p_success: float, max_retries: int = 10) -> float:
    return 1.0 - (1.0 - p_success) ** max_retries


# ── Network scale ────────────────────────────────────────────────────────────

def network_diameter(n: int, avg_degree: float) -> float:
    if n <= 1 or avg_degree <= 1:
        return float('inf')
    return log(n) / log(avg_degree)


def min_degree_for_connectivity(n: int) -> float:
    return log(n)


def max_edges(n: int, c_max: int = 1024) -> int:
    return n * c_max // 2


def buffer_memory_bytes(degree: int, q_max: int = 8 * 1024 * 1024) -> int:
    return degree * q_max


# ── Main ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import math

    dht = DhtConfig()
    relay = RelayConfig()
    node = NodeConfig()
    ice = IceUpgradeConfig()

    print("=" * 70)
    print("  GNET Mathematical Model v2 — with ICE upgrade dynamics")
    print("=" * 70)

    bench = BenchMeasurements()

    # ── Transports ──
    print("\n── Transport Properties ──")
    print(f"  {'Name':<6} {'MTU':>6} {'Payload':>8} {'Reliable':>9} {'NAT':>5} {'BW(Mbps)':>9} {'HS(μs)':>9}")
    print("  " + "-" * 58)
    for t, p in TRANSPORTS.items():
        mtu_s = "stream" if p.mtu == 0 else str(p.mtu)
        rel_s = "yes" if p.reliable else "no"
        nat_s = "yes" if p.nat_traversal else "no"
        hs_s  = f"{p.handshake_us:.0f}" if p.handshake_us > 0 else "—"
        print(f"  {p.name:<6} {mtu_s:>6} {p.effective_payload:>8} "
              f"{rel_s:>9} {nat_s:>5} {p.bandwidth_mbps:>9.0f} {hs_s:>9}")

    # ── Bench measurements ──
    print("\n── Measured Latency (loopback, production stack, 1024 B, 852c20a) ──")
    print(f"  {'Transport':<10} {'One-way P50':>13} {'One-way P99':>13} {'RTT P50':>9} {'RTT P99':>9}")
    print("  " + "-" * 57)
    rows = [
        ("TCP+Noise",  bench.tcp_oneway_p50_us, bench.tcp_oneway_p99_us, bench.tcp_rtt_p50_us, bench.tcp_rtt_p99_us),
        ("UDP+Noise",  bench.udp_oneway_p50_us, bench.udp_oneway_p99_us, bench.udp_rtt_p50_us, bench.udp_rtt_p99_us),
        ("IPC+Noise",  bench.ipc_oneway_p50_us, bench.ipc_oneway_p99_us, bench.ipc_rtt_p50_us, bench.ipc_rtt_p99_us),
        ("QUIC+Noise", None,                    None,                    bench.quic_noise_rtt_p50_us, bench.quic_noise_rtt_p99_us),
    ]
    for name, ow50, ow99, rtt50, rtt99 in rows:
        ow50_s = f"{ow50:.1f} μs" if ow50 else "—"
        ow99_s = f"{ow99:.1f} μs" if ow99 else "—"
        print(f"  {name:<10} {ow50_s:>13} {ow99_s:>13} {rtt50:>6.1f} μs {rtt99:>6.0f} μs")
    print(f"  QUIC+TLS: fixture broken (issue #44) — P5=P95=0 ns, all values invalid")

    # ── ICE upgrade ──
    print("\n── ICE Upgrade Model (session.hpp defaults) ──")
    print(f"  State:                 ok")
    print(f"  check_interval_ms:     {ice.check_interval_ms:.0f} ms  (session.hpp:137)")
    print(f"  n_candidate_pairs:     {ice.n_candidate_pairs}")
    print(f"  session_timeout_s:     {ice.session_timeout_s} s  (session.hpp:105, hard deadline)")
    print(f"  Theoretical upgrade:   {ice.upgrade_time_s:.1f} s  "
          f"({ice.signal_roundtrip_ms:.0f}+{ice.ice_gather_ms:.0f}+{ice.ice_check_ms:.0f} ms)")
    print(f"  Effective upgrade:     {ice.effective_upgrade_time_s:.1f} s  (capped at session_timeout_s)")
    print(f"  Avg ICE success (th):  {ice.avg_ice_success_rate:.2%}  (theoretical, when working)")
    print(f"  Effective success:     {ice.effective_success_rate:.2%}")
    print(f"  Upgrade rate (lambda): {ice.upgrade_rate:.4f} /s")
    print(f"  Time to 95% direct:    {ice.time_to_percent_direct(0.95):.1f} s")

    print("\n  Relay fraction over time:")
    for t in [0, 1, 2, 3, 5, 7, 10, 15, 20, 30]:
        r = ice.relay_fraction(t)
        d = 1 - r
        bar = "#" * int(d * 40) + "." * int(r * 40)
        print(f"    t={t:>3d}s  relay={r:>5.1%}  direct={d:>5.1%}  [{bar}]")

    # ── Amortized cost ──
    print("\n  Amortized relay cost per message (gossip_cost=100):")
    print(f"  {'Session':>10} {'Cost/msg':>10} {'Overhead':>10}")
    print("  " + "-" * 32)
    for dur in [10, 60, 300, 3600, 86400]:
        c = ice.amortized_cost(dur, 10, 100)
        dur_s = f"{dur}s" if dur < 60 else f"{dur//60}min" if dur < 3600 else f"{dur//3600}hr"
        print(f"  {dur_s:>10} {c:>10.2f} {(c-1)*100:>9.1f}%")

    # ── Directed relay ──
    print("\n── Directed Relay (relay.cpp:110 — find_conn_by_pubkey first) ──")
    print(f"  {'n':>8} {'P(direct_hop)':>14} {'P(directed,h=3)':>16} {'P(directed,h=5)':>16}")
    print("  " + "-" * 58)
    for n in [50, 100, 500, 1_000, 5_000, 10_000, 100_000]:
        p1 = min(1.0, dht.k * ceil(log2(n)) / n)
        p3 = relay.directed_relay_probability(n, dht.k, 3)
        p5 = relay.directed_relay_probability(n, dht.k, 5)
        print(f"  {n:>8,d} {p1:>14.1%} {p3:>16.1%} {p5:>16.1%}")

    # ── Churn ──
    print("\n── Churn Resilience ──")
    print(f"  {'Churn/hr':>9} {'Relay(h=3)':>11} {'Direct':>8} {'MinDeg(n=1K)':>13}")
    print("  " + "-" * 45)
    for mu in [0.01, 0.05, 0.10, 0.20, 0.30, 0.50]:
        rs = churn_relay_survival(mu, 3)
        ds = churn_direct_survival(mu)
        md = churn_connectivity_threshold(1000, mu)
        print(f"  {mu:>8.0%} {rs:>11.1%} {ds:>8.1%} {md:>13.1f}")

    # ── Multi-path ──
    print("\n── Multi-path Availability ──")
    scenarios = [
        ("TCP only",            [0.95]),
        ("TCP + ICE",           [0.95, 0.88]),
        ("TCP + ICE + UDP",     [0.95, 0.88, 0.85]),
        ("TCP+ICE+UDP+BLE",     [0.95, 0.88, 0.85, 0.85]),
    ]
    print(f"  {'Scenario':<20} {'A':>12} {'Downtime/yr':>14} {'Nines':>6}")
    print("  " + "-" * 56)
    for name, avails in scenarios:
        a = multipath_availability(avails)
        nines = -math.log10(1 - a) if a < 1 else float('inf')
        dt_hrs = (1 - a) * 365.25 * 24
        dt_s = f"{dt_hrs:.1f}h" if dt_hrs >= 1 else f"{dt_hrs*60:.0f}min"
        print(f"  {name:<20} {a:>12.8f} {dt_s:>14} {nines:>6.2f}")

    # ── Bandwidth aggregation ──
    print("\n── Bandwidth Aggregation ──")
    bws = [100, 50, 10]  # WiFi, LTE, BLE in Mbit/s
    for s in PathStrategy:
        bw = multipath_bandwidth(bws, s)
        print(f"  {s.value:<16} WiFi(100)+LTE(50)+BLE(10) = {bw:.0f} Mbit/s")

    # ── TCP multi-connection scaling (examples/bench, 64 KB, LOOPBACK) ──
    print("\n── TCP Multi-Connection Scaling (examples/bench, 64 KB, LOOPBACK ONLY) ──")
    print(f"  Context: both kernels in the same process, loopback TCP, no real network.")
    print(f"  One AEAD pipeline per connection — no shared lock on hot path.")
    print(f"  Linear to ~{bench.tcp_64k_linear_cap_conns} conns, then CPU-bound (i5-1235U: avg ~{bench.tcp_64k_8conn_avg_gbps:.0f}, peak ~{bench.tcp_64k_8conn_peak_gbps:.0f} Gbit/s).")
    print(f"  These numbers do NOT model real network deployment throughput.")
    print(f"  {'Conns':>6} {'Model (n×5)':>12} {'Measured avg':>14} {'Note':>12}")
    print("  " + "-" * 48)
    per = bench.tcp_64k_per_conn_loopback_gbps
    for n in [1, 2, 4, 8, 16]:
        expected = per * n
        if n == bench.tcp_64k_linear_cap_conns:
            meas_s = f"~{bench.tcp_64k_8conn_avg_gbps:.0f} (pk {bench.tcp_64k_8conn_peak_gbps:.0f})"
        elif n == 1:
            meas_s = f"~{per:.0f}"
        else:
            meas_s = "—"
        note = "linear" if n <= bench.tcp_64k_linear_cap_conns else "CPU-sat"
        print(f"  {n:>6} {expected:>10.0f} G  {meas_s:>14}  {note}")

    # ── Network scale ──
    print("\n── Network Scale ──")
    for n in [100, 1_000, 10_000, 100_000, 1_000_000]:
        d_min = min_degree_for_connectivity(n)
        diam = network_diameter(n, 10)
        hops = dht.lookup_hops(n)
        print(f"  n={n:>9,d}  min_deg={d_min:>5.1f}  diameter={diam:>4.1f}"
              f"  DHT_hops={hops:>4.1f}  RT={dht.actual_entries(n):>4d}")
