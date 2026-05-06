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
    ICE  = "ice"
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
    bandwidth_mbps: float  # typical bandwidth

    @property
    def effective_payload(self) -> int:
        """Usable payload after GNET header (20B) + Noise overhead (32B)."""
        if self.mtu == 0:
            return 65536
        return max(0, self.mtu - 20 - 32)


TRANSPORTS = {
    TransportType.TCP:  TransportProps("tcp",  0,    True,  False, float('inf'), "stream",   10_000),
    TransportType.UDP:  TransportProps("udp",  1200, False, False, float('inf'), "datagram",  5_000),
    TransportType.ICE:  TransportProps("ice",  1200, False, True,  float('inf'), "datagram",    100),
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
    nat_full_cone:      float = 0.30  # p_ice = 0.95
    nat_restricted:     float = 0.25  # p_ice = 0.90
    nat_port_restricted: float = 0.25  # p_ice = 0.80
    nat_symmetric:      float = 0.15  # p_ice = 0.30 (needs TURN)
    nat_public:         float = 0.05  # p_ice = 1.00

    # Timing
    signal_roundtrip_ms: float = 300   # ICE_SIGNAL via relay
    ice_gather_ms: float = 1000        # STUN gathering
    ice_check_ms: float = 500          # connectivity checks

    @property
    def avg_ice_success_rate(self) -> float:
        """Weighted average ICE success probability."""
        return (self.nat_full_cone * 0.95 +
                self.nat_restricted * 0.90 +
                self.nat_port_restricted * 0.80 +
                self.nat_symmetric * 0.30 +
                self.nat_public * 1.00)

    @property
    def upgrade_time_s(self) -> float:
        """Time for one ICE upgrade attempt."""
        return (self.signal_roundtrip_ms + self.ice_gather_ms + self.ice_check_ms) / 1000

    @property
    def upgrade_rate(self) -> float:
        """Lambda: successful upgrades per second."""
        return self.avg_ice_success_rate / self.upgrade_time_s

    def relay_fraction(self, t: float, r0: float = 1.0) -> float:
        """Fraction of connections still using relay at time t."""
        return r0 * exp(-self.upgrade_rate * t)

    def time_to_percent_direct(self, target_direct: float = 0.95) -> float:
        """Seconds until target% of connections are direct."""
        target_relay = 1.0 - target_direct
        if target_relay <= 0:
            return float('inf')
        return -log(target_relay) / self.upgrade_rate

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
        relay_integral = (1 - exp(-lam * t95)) / lam
        relay_msgs = msg_rate * gossip_cost * relay_integral

        # Direct phase: remaining time at cost=1
        direct_msgs = msg_rate * max(0, session_duration_s - t95) * 1.0

        # Bootstrap overhead (one-time)
        bootstrap = gossip_cost

        return (bootstrap + relay_msgs + direct_msgs) / total_msgs


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

    # ── Transports ──
    print("\n── Transport Properties ──")
    print(f"  {'Name':<6} {'MTU':>6} {'Payload':>8} {'Reliable':>9} {'NAT':>5} {'BW(Mbps)':>9}")
    print("  " + "-" * 48)
    for t, p in TRANSPORTS.items():
        mtu_s = "stream" if p.mtu == 0 else str(p.mtu)
        rel_s = "yes" if p.reliable else "no"
        nat_s = "yes" if p.nat_traversal else "no"
        print(f"  {p.name:<6} {mtu_s:>6} {p.effective_payload:>8} "
              f"{rel_s:>9} {nat_s:>5} {p.bandwidth_mbps:>9.0f}")

    # ── ICE upgrade ──
    print("\n── ICE Upgrade Model (from ice.cpp:s_upgrade) ──")
    print(f"  Avg ICE success rate:  {ice.avg_ice_success_rate:.2%}")
    print(f"  Upgrade time:          {ice.upgrade_time_s:.1f} s")
    print(f"  Upgrade rate (lambda): {ice.upgrade_rate:.3f} /s")
    print(f"  Time to 90% direct:    {ice.time_to_percent_direct(0.90):.1f} s")
    print(f"  Time to 95% direct:    {ice.time_to_percent_direct(0.95):.1f} s")
    print(f"  Time to 99% direct:    {ice.time_to_percent_direct(0.99):.1f} s")

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

    # ── Network scale ──
    print("\n── Network Scale ──")
    for n in [100, 1_000, 10_000, 100_000, 1_000_000]:
        d_min = min_degree_for_connectivity(n)
        diam = network_diameter(n, 10)
        hops = dht.lookup_hops(n)
        print(f"  n={n:>9,d}  min_deg={d_min:>5.1f}  diameter={diam:>4.1f}"
              f"  DHT_hops={hops:>4.1f}  RT={dht.actual_entries(n):>4d}")
