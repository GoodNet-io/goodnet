#!/usr/bin/env python3
"""
GNET Network Simulator v2 — with ICE upgrade, churn, directed relay.

Models the real behavior from code:
  - relay.cpp: directed-first (find_conn_by_pubkey), gossip fallback
  - ice.cpp: s_upgrade() — relay→direct conversion
  - routing_table.hpp: Kademlia DHT for peer knowledge

Usage:
    python gnet_simulate.py [--nodes 500] [--avg-degree 8] [--ttl 5]
    python gnet_simulate.py --section upgrade    # just ICE upgrade dynamics
    python gnet_simulate.py --section churn      # churn resilience
"""

import argparse
import random
import math
from collections import defaultdict, deque
from typing import Dict, List, Set, Tuple

from gnet_model import (
    NodeConfig, DhtConfig, RelayConfig, IceUpgradeConfig, TransportType,
    TRANSPORTS, multipath_availability, multipath_bandwidth, PathStrategy,
    reconnect_delays, reconnect_recovery_probability,
    network_diameter, min_degree_for_connectivity,
    churn_relay_survival, churn_direct_survival, churn_connectivity_threshold,
)


# ── Simple graph ─────────────────────────────────────────────────────────────

class Graph:
    """Undirected graph with edge attributes."""

    def __init__(self):
        self.adj: Dict[int, Set[int]] = defaultdict(set)
        self._edge_data: Dict[Tuple[int,int], dict] = {}
        self._node_data: Dict[int, dict] = {}

    def add_node(self, n, **attrs):
        if n not in self.adj:
            self.adj[n] = set()
        self._node_data[n] = attrs

    def add_edge(self, u, v, **attrs):
        self.adj[u].add(v)
        self.adj[v].add(u)
        self._edge_data[(min(u,v), max(u,v))] = attrs

    def get_edge(self, u, v) -> dict:
        return self._edge_data.get((min(u,v), max(u,v)), {})

    def set_edge(self, u, v, **attrs):
        key = (min(u,v), max(u,v))
        if key in self._edge_data:
            self._edge_data[key].update(attrs)

    def nodes(self): return list(self.adj.keys())
    def neighbors(self, n): return self.adj.get(n, set())
    def degree(self, n): return len(self.adj.get(n, set()))
    def number_of_nodes(self): return len(self.adj)

    def number_of_edges(self):
        return sum(len(nb) for nb in self.adj.values()) // 2

    def remove_node(self, n):
        for nb in list(self.adj.get(n, set())):
            self.adj[nb].discard(n)
            self._edge_data.pop((min(n,nb), max(n,nb)), None)
        del self.adj[n]
        self._node_data.pop(n, None)

    def edges(self):
        seen = set()
        for u, nbs in self.adj.items():
            for v in nbs:
                key = (min(u,v), max(u,v))
                if key not in seen:
                    seen.add(key)
                    yield u, v

    def is_connected(self):
        if not self.adj:
            return True
        start = next(iter(self.adj))
        visited = set()
        queue = [start]
        while queue:
            n = queue.pop()
            if n in visited:
                continue
            visited.add(n)
            for nb in self.adj[n]:
                if nb not in visited:
                    queue.append(nb)
        return len(visited) == len(self.adj)

    def shortest_path_length(self, source, target):
        visited = {source: 0}
        queue = deque([source])
        while queue:
            n = queue.popleft()
            if n == target:
                return visited[n]
            for nb in self.adj[n]:
                if nb not in visited:
                    visited[nb] = visited[n] + 1
                    queue.append(nb)
        return float('inf')

    def largest_component_size(self):
        visited = set()
        max_size = 0
        for start in self.adj:
            if start in visited:
                continue
            comp = set()
            queue = [start]
            while queue:
                n = queue.pop()
                if n in comp:
                    continue
                comp.add(n)
                for nb in self.adj[n]:
                    if nb not in comp:
                        queue.append(nb)
            visited |= comp
            max_size = max(max_size, len(comp))
        return max_size


# ── Network builder ──────────────────────────────────────────────────────────

def build_network(n: int, avg_degree: float, c_max: int = 1024,
                  seed: int = 42) -> Graph:
    """Build a GNET-like random network. All edges start as relay."""
    random.seed(seed)
    G = Graph()

    for i in range(n):
        G.add_node(i, rt_knowledge=set())  # DHT routing table simulation

    target_edges = int(n * avg_degree / 2)
    edges_added = 0
    attempts = 0

    while edges_added < target_edges and attempts < target_edges * 10:
        u = random.randint(0, n - 1)
        v = random.randint(0, n - 1)
        if u == v:
            attempts += 1
            continue
        if v in G.neighbors(u):
            attempts += 1
            continue
        if G.degree(u) >= c_max or G.degree(v) >= c_max:
            attempts += 1
            continue

        # All edges start as relay, will upgrade
        G.add_edge(u, v, edge_type="relay", transport="tcp",
                   rtt_ms=random.uniform(10, 200))
        # Add to each other's RT knowledge
        G._node_data[u].setdefault("rt_knowledge", set()).add(v)
        G._node_data[v].setdefault("rt_knowledge", set()).add(u)
        edges_added += 1
        attempts += 1

    return G


# ── Relay simulation with directed-first ─────────────────────────────────────

def simulate_relay_realistic(G: Graph, source: int, dest: int, ttl: int = 5) -> dict:
    """
    Simulate relay using REAL algorithm from relay.cpp:
      1. Check if direct path exists (find_conn_by_pubkey)
      2. If yes → O(1) directed forward
      3. If no → broadcast (gossip)
    """
    seen_nodes: Set[int] = set()
    total_messages = 0
    directed_hops = 0
    gossip_hops = 0
    reached = False
    hops_to_dest = -1

    queue = deque([(source, ttl, 0, -1)])

    while queue:
        node, remaining_ttl, hops, from_node = queue.popleft()

        if node in seen_nodes:
            continue
        seen_nodes.add(node)

        if node == dest:
            hops_to_dest = hops
            reached = True
            break  # delivered

        if remaining_ttl <= 0:
            continue

        # Does this node know the dest? (simulates find_conn_by_pubkey)
        rt = G._node_data.get(node, {}).get("rt_knowledge", set())

        if dest in G.neighbors(node):
            # DIRECTED: send directly to dest
            total_messages += 1
            directed_hops += 1
            queue.append((dest, remaining_ttl - 1, hops + 1, node))
        elif dest in rt:
            # DIRECTED via RT knowledge: find shortest bridge
            # In real code this is find_conn_by_pubkey — needs direct conn
            # But if we know about dest via RT, we might have a direct conn
            total_messages += 1
            directed_hops += 1
            queue.append((dest, remaining_ttl - 1, hops + 1, node))
        else:
            # GOSSIP fallback: broadcast to all neighbors except sender
            gossip_hops += 1
            for nb in G.neighbors(node):
                if nb == from_node:
                    continue
                total_messages += 1
                queue.append((nb, remaining_ttl - 1, hops + 1, node))

    return {
        "reached": reached,
        "hops": hops_to_dest,
        "total_messages": total_messages,
        "directed_hops": directed_hops,
        "gossip_hops": gossip_hops,
        "nodes_reached": len(seen_nodes),
    }


# ── ICE upgrade simulation ──────────────────────────────────────────────────

def simulate_ice_upgrade(G: Graph, ice_cfg: IceUpgradeConfig,
                          time_steps: int = 30) -> List[dict]:
    """Simulate relay→direct upgrade over time."""
    edges = list(G.edges())
    n_edges = len(edges)

    # Track edge states
    is_direct = {(min(u,v), max(u,v)): False for u, v in edges}

    results = []
    for t in range(time_steps + 1):
        n_direct = sum(1 for d in is_direct.values() if d)
        n_relay = n_edges - n_direct
        frac_direct = n_direct / max(n_edges, 1)

        results.append({
            "t": t,
            "direct": n_direct,
            "relay": n_relay,
            "frac_direct": frac_direct,
        })

        # Attempt upgrade for each relay edge
        for u, v in edges:
            key = (min(u,v), max(u,v))
            if is_direct[key]:
                continue
            # ICE upgrade attempt with probability based on NAT mix
            if random.random() < ice_cfg.avg_ice_success_rate:
                is_direct[key] = True
                G.set_edge(u, v, edge_type="direct")

    return results


# ── Churn simulation ─────────────────────────────────────────────────────────

def simulate_churn(n: int, avg_degree: float, churn_rate: float,
                   join_rate: float, steps: int = 20, seed: int = 42) -> List[dict]:
    """Simulate node churn: nodes leave and join over time."""
    random.seed(seed)
    G = build_network(n, avg_degree, seed=seed)
    next_id = n

    results = []
    for step in range(steps + 1):
        n_nodes = G.number_of_nodes()
        n_edges = G.number_of_edges()
        avg_deg = 2 * n_edges / max(n_nodes, 1)
        connected = G.is_connected()
        largest = G.largest_component_size()

        results.append({
            "step": step,
            "nodes": n_nodes,
            "edges": n_edges,
            "avg_degree": avg_deg,
            "connected": connected,
            "largest_component": largest,
            "largest_pct": largest / max(n_nodes, 1),
        })

        # Remove nodes (churn)
        nodes = list(G.nodes())
        n_remove = int(len(nodes) * churn_rate)
        for node in random.sample(nodes, min(n_remove, len(nodes))):
            G.remove_node(node)

        # Add new nodes (join)
        n_join = int(n * join_rate)
        remaining_nodes = G.nodes()
        for _ in range(n_join):
            if not remaining_nodes:
                break
            new_id = next_id
            next_id += 1
            G.add_node(new_id, rt_knowledge=set())

            # Connect to random existing nodes (bootstrap)
            n_conns = min(int(avg_degree), len(remaining_nodes))
            targets = random.sample(remaining_nodes, n_conns)
            for t in targets:
                G.add_edge(new_id, t, edge_type="relay")
                G._node_data[new_id].setdefault("rt_knowledge", set()).add(t)
                G._node_data.get(t, {}).setdefault("rt_knowledge", set()).add(new_id)
            remaining_nodes = G.nodes()

    return results


# ── Analysis functions ───────────────────────────────────────────────────────

def analyze_upgrade_dynamics():
    """Show ICE upgrade timeline and amortized cost."""
    ice = IceUpgradeConfig()

    print("\n" + "=" * 70)
    print("  ICE Upgrade Dynamics (relay→direct self-optimization)")
    print("=" * 70)

    print(f"\n  ICE success rate: {ice.avg_ice_success_rate:.1%}")
    print(f"  Upgrade time:     {ice.upgrade_time_s:.1f}s")
    print(f"  Lambda:           {ice.upgrade_rate:.3f}/s")

    # Theoretical decay
    print("\n  Theoretical relay fraction R(t) = e^(-λt):")
    print(f"  {'Time':>6} {'Relay%':>8} {'Direct%':>9} {'Visual':>42}")
    print("  " + "-" * 68)
    for t in [0, 1, 2, 3, 5, 7, 10, 15, 20, 30, 60]:
        r = ice.relay_fraction(t)
        d = 1 - r
        bar_d = "#" * int(d * 40)
        bar_r = "." * (40 - len(bar_d))
        t_s = f"{t}s" if t < 60 else f"{t//60}min"
        print(f"  {t_s:>6} {r:>7.1%} {d:>8.1%}  [{bar_d}{bar_r}]")

    # Simulation
    print(f"\n  Simulating upgrade on 500-node network...")
    G = build_network(500, 8)
    results = simulate_ice_upgrade(G, ice, time_steps=15)

    print(f"  {'Step':>4} {'Direct':>8} {'Relay':>8} {'Direct%':>9}")
    print("  " + "-" * 32)
    for r in results:
        print(f"  {r['t']:>4} {r['direct']:>8} {r['relay']:>8} {r['frac_direct']:>8.1%}")

    # Amortized cost
    print("\n  Amortized cost (gossip=100 msgs, 10 msg/s):")
    print(f"  {'Session':>12} {'Cost/msg':>10} {'Overhead':>10} {'Verdict':>20}")
    print("  " + "-" * 56)
    for dur, label in [(10, "10s"), (60, "1min"), (600, "10min"),
                        (3600, "1hr"), (86400, "1day")]:
        c = ice.amortized_cost(dur, 10, 100)
        over = (c - 1) * 100
        verdict = "high relay" if over > 50 else "acceptable" if over > 5 else "near-direct"
        print(f"  {label:>12} {c:>10.2f} {over:>9.1f}% {verdict:>20}")


def analyze_directed_relay():
    """Compare directed vs gossip relay."""
    dht = DhtConfig()
    relay = RelayConfig()

    print("\n" + "=" * 70)
    print("  Directed vs Gossip Relay (relay.cpp:110-118)")
    print("=" * 70)

    print("\n  relay.cpp algorithm:")
    print("    1. find_conn_by_pubkey(dest)  → if found: send_response (1 msg)")
    print("    2. else: broadcast()          → gossip (d-1 msgs per hop)")

    print(f"\n  Probability of directed relay by network size:")
    print(f"  {'n':>8} {'RT_size':>8} {'P(directed/hop)':>16} "
          f"{'P(directed,h=3)':>16} {'Gossip cost':>12}")
    print("  " + "-" * 66)
    for n in [10, 50, 100, 500, 1000, 5000, 10000, 100000]:
        rt = dht.actual_entries(n)
        p_hop = min(1.0, rt / n)
        p_3 = relay.directed_relay_probability(n, dht.k, 3)
        gcost = relay.gossip_messages(8, 5)
        print(f"  {n:>8,d} {rt:>8} {p_hop:>16.1%} {p_3:>16.1%} {gcost:>12,d}")

    # Simulation comparison
    print(f"\n  Simulation: 500 nodes, avg_degree=8, TTL=5")
    G = build_network(500, 8)
    nodes = G.nodes()

    results = []
    for _ in range(50):
        src, dst = random.sample(nodes, 2)
        r = simulate_relay_realistic(G, src, dst, ttl=5)
        results.append(r)

    reached = sum(1 for r in results if r["reached"])
    avg_msgs = sum(r["total_messages"] for r in results) / len(results)
    avg_hops = sum(r["hops"] for r in results if r["reached"]) / max(reached, 1)
    avg_dir = sum(r["directed_hops"] for r in results) / len(results)
    avg_gos = sum(r["gossip_hops"] for r in results) / len(results)

    print(f"\n  Results (50 random pairs):")
    print(f"    Delivery rate:    {reached}/{len(results)} ({reached/len(results)*100:.0f}%)")
    print(f"    Avg hops:         {avg_hops:.1f}")
    print(f"    Avg messages:     {avg_msgs:.0f}")
    print(f"    Avg directed hops:{avg_dir:.1f}")
    print(f"    Avg gossip hops:  {avg_gos:.1f}")
    print(f"    Directed ratio:   {avg_dir/(avg_dir+avg_gos)*100:.0f}%"
          if (avg_dir+avg_gos) > 0 else "    N/A")

    # Compare with pure gossip
    gossip_cost = relay.gossip_messages(8, 5)
    print(f"\n    Pure gossip cost: {gossip_cost:,d} msgs/delivery")
    print(f"    Directed cost:    {avg_msgs:.0f} msgs/delivery")
    print(f"    Improvement:      {gossip_cost/max(avg_msgs,1):.0f}x less overhead")


def analyze_churn():
    """Simulate network behavior under churn."""
    print("\n" + "=" * 70)
    print("  Churn Resilience (nodes leaving and joining)")
    print("=" * 70)

    # Theoretical
    print("\n  Theoretical: relay path survival (3 hops) vs direct:")
    print(f"  {'Churn/step':>11} {'Relay(h=3)':>11} {'Direct':>8} {'Ratio':>7}")
    print("  " + "-" * 40)
    for mu in [0.01, 0.05, 0.10, 0.20, 0.30, 0.50]:
        rs = churn_relay_survival(mu, 3)
        ds = churn_direct_survival(mu)
        ratio = ds / max(rs, 0.001)
        print(f"  {mu:>10.0%} {rs:>11.1%} {ds:>8.1%} {ratio:>6.1f}x")

    # Simulation: different churn rates, with equal join rate
    print(f"\n  Simulation: n=200, avg_degree=8, 20 steps, join=churn")
    for churn in [0.05, 0.10, 0.20]:
        results = simulate_churn(200, 8, churn, churn, steps=20)
        print(f"\n  Churn = {churn:.0%}:")
        print(f"  {'Step':>4} {'Nodes':>6} {'Edges':>6} {'AvgDeg':>7} "
              f"{'Connected':>10} {'Largest%':>9}")
        print("  " + "-" * 50)
        for r in results[::4]:  # every 4th step
            conn_s = "yes" if r["connected"] else "NO"
            print(f"  {r['step']:>4} {r['nodes']:>6} {r['edges']:>6} "
                  f"{r['avg_degree']:>7.1f} {conn_s:>10} {r['largest_pct']:>8.0%}")

    # Critical: churn without replacement
    print(f"\n  Catastrophic churn (no replacement):")
    for churn in [0.05, 0.10, 0.20, 0.30]:
        results = simulate_churn(200, 8, churn, 0.0, steps=10)
        final = results[-1]
        print(f"    churn={churn:.0%}: {final['nodes']} nodes left, "
              f"largest={final['largest_pct']:.0%}, "
              f"connected={'yes' if final['connected'] else 'NO'}")


def analyze_bandwidth():
    """Bandwidth analysis by transport and multi-path strategy."""
    print("\n" + "=" * 70)
    print("  Bandwidth Analysis")
    print("=" * 70)

    print("\n  Transport bandwidth (typical):")
    print(f"  {'Transport':<8} {'BW (Mbit/s)':>12} {'With Noise':>11} {'Eff BW':>10}")
    print("  " + "-" * 44)
    for t, p in TRANSPORTS.items():
        # Noise overhead ~5-10% for stream, ~5% per packet for datagram
        noise_overhead = 0.95 if p.mode == "stream" else 0.90
        eff = p.bandwidth_mbps * noise_overhead
        print(f"  {p.name:<8} {p.bandwidth_mbps:>12,.0f} {noise_overhead:>10.0%} {eff:>10,.0f}")

    print("\n  Multi-path bandwidth aggregation:")
    configs = [
        ("WiFi only",          [100]),
        ("WiFi + LTE",         [100, 50]),
        ("WiFi + LTE + BLE",   [100, 50, 1]),
        ("LAN + LAN (bonded)", [1000, 1000]),
    ]
    for name, bws in configs:
        for s in PathStrategy:
            bw = multipath_bandwidth(bws, s)
            print(f"  {name:<22} {s.value:<16} = {bw:>6.0f} Mbit/s")
        print()

    # Relay bandwidth overhead timeline
    print("  Relay BW overhead over time (100 msg/s, 1KB msgs, degree=10):")
    ice = IceUpgradeConfig()
    msg_rate = 100
    msg_size_kb = 1
    degree = 10

    print(f"  {'Time':>6} {'Relay%':>8} {'BW overhead':>14} {'Direct BW':>12}")
    print("  " + "-" * 44)
    for t in [0, 1, 3, 5, 10, 30, 60]:
        r = ice.relay_fraction(t)
        # Relay: each msg fanned out to degree-1 neighbors
        relay_bw = msg_rate * msg_size_kb * (degree - 1) * r  # KB/s from gossip
        direct_bw = msg_rate * msg_size_kb * (1 - r)  # KB/s from direct
        t_s = f"{t}s" if t < 60 else f"{t//60}min"
        print(f"  {t_s:>6} {r:>7.1%} {relay_bw:>11.0f} KB/s {direct_bw:>9.0f} KB/s")


def analyze_growth():
    """Network growth phases with upgrade dynamics."""
    dht = DhtConfig()
    ice = IceUpgradeConfig()
    relay = RelayConfig()

    print("\n" + "=" * 70)
    print("  Growth Phase Analysis (with self-optimization)")
    print("=" * 70)

    print(f"\n  {'Phase':<10} {'n':>8} {'DHT hops':>9} {'Diameter':>9} "
          f"{'Direct relay%':>14} {'t(95%direct)':>13}")
    print("  " + "-" * 68)

    n = 2
    while n <= 200_000:
        hops = dht.lookup_hops(n)
        avg_d = max(min_degree_for_connectivity(n) + 2, 8)
        diam = network_diameter(n, avg_d)
        p_dir = relay.directed_relay_probability(n, dht.k, int(diam))
        t95 = ice.time_to_percent_direct(0.95)

        if n <= 10:     phase = "Seed"
        elif n <= 100:  phase = "Cluster"
        elif n <= 1000: phase = "Growth"
        elif n <= 100000: phase = "Scale"
        else:           phase = "Mass"

        print(f"  {phase:<10} {n:>8,d} {hops:>9.1f} {diam:>9.1f} "
              f"{p_dir:>13.0%} {t95:>12.1f}s")
        n = int(n * 3)


def analyze_self_optimization():
    """Show how the network improves over time."""
    ice = IceUpgradeConfig()
    relay = RelayConfig()

    print("\n" + "=" * 70)
    print("  Network Self-Optimization (the key GNET property)")
    print("=" * 70)

    print("""
  The lifecycle of a GNET connection:

  Phase 1: DISCOVERY  (DHT lookup)
    └─ O(log n) messages, ~100-300ms

  Phase 2: RELAY      (directed-first, gossip fallback)
    └─ O(1) if intermediate knows dest, else O(d^h) gossip
    └─ TEMPORARY — triggers ICE upgrade

  Phase 3: DIRECT     (ICE upgrade complete)
    └─ 1 msg = 1 msg, direct RTT, multi-path capable
    └─ PERMANENT for lifetime of both nodes

  Positive feedback loop:
    more direct → less gossip → more dedup capacity → faster bootstrap → more direct
""")

    # Steady-state comparison
    print("  Steady-state metrics (network age > 30s):")
    print(f"  {'Metric':<30} {'Bootstrap (t=0)':>16} {'Steady (t>30s)':>16}")
    print("  " + "-" * 65)

    r0 = ice.relay_fraction(0)
    r30 = ice.relay_fraction(30)
    gc = relay.gossip_messages(8, 5)

    metrics = [
        ("Relay fraction", f"{r0:.0%}", f"{r30:.1%}"),
        ("Msg cost (avg_d=8,TTL=5)", f"{gc:,d} msgs", "~1 msg"),
        ("Dedup utilization", "HIGH", f"<{r30:.0%}"),
        ("Network RTT", "100-500ms (relay)", "1-50ms (direct)"),
        ("BW overhead", f"{(8-1)*100:.0f}% (fanout)", f"~{r30*700:.0f}%"),
        ("ICE paths available", "0%", f"{1-r30:.1%}"),
    ]
    for name, v0, v30 in metrics:
        print(f"  {name:<30} {v0:>16} {v30:>16}")


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="GNET Network Simulator v2")
    parser.add_argument("--nodes", type=int, default=500)
    parser.add_argument("--avg-degree", type=float, default=8.0)
    parser.add_argument("--ttl", type=int, default=5)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--section", type=str, default="all",
                        choices=["all", "upgrade", "directed", "churn",
                                 "bandwidth", "growth", "optimization"])
    args = parser.parse_args()
    random.seed(args.seed)

    sections = {
        "upgrade": analyze_upgrade_dynamics,
        "directed": analyze_directed_relay,
        "churn": analyze_churn,
        "bandwidth": analyze_bandwidth,
        "growth": analyze_growth,
        "optimization": analyze_self_optimization,
    }

    if args.section == "all":
        for fn in sections.values():
            fn()
    else:
        sections[args.section]()


if __name__ == "__main__":
    main()
