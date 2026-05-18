# TURN coturn image with TLS-over-TCP enabled. Used by the
# no-UDP-fallback scenario where every UDP flow between the two
# peers is dropped in transit; the only remaining viable
# transport is `turns://` (TURN-over-TLS-TCP), and the rc5
# strategy chain has to skip UDP candidates and converge on a
# relay-TCP+TLS pair.
#
# A self-signed cert is generated at image-build time; the
# harness disables peer-cert verification for the bench-only
# allocation surface so the cert chain is incidental — the
# point is that the TLS handshake succeeds and the allocation
# rides over TCP+TLS, not UDP.
FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        coturn netcat-openbsd openssl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

ARG TURN_USER=goodnet
ARG TURN_PASS=bench-only-credentials
ARG TURN_REALM=ice3.local

ENV TURN_USER=${TURN_USER}
ENV TURN_PASS=${TURN_PASS}
ENV TURN_REALM=${TURN_REALM}

# Generate a self-signed cert for the TLS listener.
RUN openssl req -x509 -newkey rsa:2048 -nodes -days 30 \
        -subj "/CN=ice3-turn-tls" \
        -keyout /etc/coturn/key.pem \
        -out /etc/coturn/cert.pem \
    && chmod 640 /etc/coturn/key.pem /etc/coturn/cert.pem

# TLS on 5349/tcp (per RFC 5766 default); plain UDP listener is
# deliberately disabled so the scenario surface only exposes the
# TLS-TCP path. min/max-port left at defaults for relay
# allocations; the relay-side traffic still rides whatever the
# peers' allocations resolve to (TCP in this scenario).
RUN printf '%s\n' \
    'fingerprint' \
    'lt-cred-mech' \
    'listening-port=3478' \
    'tls-listening-port=5349' \
    'min-port=49152' \
    'max-port=49251' \
    'realm=${TURN_REALM}' \
    "user=${TURN_USER}:${TURN_PASS}" \
    'no-udp' \
    'cert=/etc/coturn/cert.pem' \
    'pkey=/etc/coturn/key.pem' \
    'verbose' \
    'no-stdout-log' \
    'syslog' \
    > /etc/turnserver.conf

EXPOSE 3478/tcp
EXPOSE 5349/tcp

ENTRYPOINT ["turnserver", "-c", "/etc/turnserver.conf"]
