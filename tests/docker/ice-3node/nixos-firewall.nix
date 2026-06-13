# NixOS host firewall snippet for the ICE 3-node docker integration test.
#
# Why this exists:
#   The compose stack relies on docker bridges 10.10.0.0/24 (net),
#   10.20.0.0/24 (lan_a) and 10.30.0.0/24 (lan_b). With
#   `bridge-nf-call-iptables=1` (default once br_netfilter is loaded),
#   docker inter-bridge IP frames traverse the host nftables hooks
#   before they ever reach the NAT containers. NixOS' default
#   `inet nixos-fw forward` chain has policy=drop, so peer_a's UDP
#   to peer_b is silently dropped at the host hook and the
#   container-side iptables FORWARD counters (see commit b845fa8)
#   stay at 0.
#
# What this snippet does:
#   Adds six surgical accept rules covering every inter-subnet
#   direction the compose stack actually needs. No other forwarded
#   traffic is affected; the rest of the nixos-fw forward policy
#   remains drop.
#
# Usage:
#   In your flake / configuration.nix:
#
#     imports = [ ./tests/docker/ice-3node/nixos-firewall.nix ];
#
#   Then `sudo nixos-rebuild switch` and re-run a scenario:
#
#     cd tests/docker/ice-3node
#     docker compose -f docker-compose.yml \
#         -f scenarios/full_cone.yml up
#
#   Verify: `docker exec ice-3node-nat-a-1 iptables -L FORWARD -n -v`
#   should show the per-rule packet counts climbing above 0 once
#   peer_a starts transmitting.
#
# Alternative (wider) operator options are documented in README.md
# under "Prerequisites — NixOS hosts".

{
  networking.firewall.extraForwardRules = ''
    ip saddr 10.10.0.0/24 ip daddr 10.20.0.0/24 accept
    ip saddr 10.10.0.0/24 ip daddr 10.30.0.0/24 accept
    ip saddr 10.20.0.0/24 ip daddr 10.10.0.0/24 accept
    ip saddr 10.30.0.0/24 ip daddr 10.10.0.0/24 accept
    ip saddr 10.20.0.0/24 ip daddr 10.30.0.0/24 accept
    ip saddr 10.30.0.0/24 ip daddr 10.20.0.0/24 accept
  '';
}
