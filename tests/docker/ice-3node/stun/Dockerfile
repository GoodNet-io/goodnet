# Minimal STUN-only `coturn` image. Used as the public STUN reflector
# in the 3-node ICE compose stack — every peer's `gather_srflx` step
# bounces a STUN Binding Request off this container to learn its own
# external address as seen from the `net` subnet (10.10.0.0/24).
FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends coturn netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

# STUN-only config: no TURN allocations, no auth — peers bind to the
# coordinator subnet IP and the firewall fence keeps it harmless even
# if a container leaked outside the docker network. Logs to stdout so
# `docker compose logs stun` shows the running BINDING-REQUEST traffic.
RUN printf '%s\n' \
    'no-tls' \
    'no-dtls' \
    'no-auth' \
    'fingerprint' \
    'listening-port=3478' \
    'verbose' \
    'no-stdout-log' \
    'syslog' \
    > /etc/turnserver.conf

EXPOSE 3478/udp

ENTRYPOINT ["turnserver", "-c", "/etc/turnserver.conf"]
