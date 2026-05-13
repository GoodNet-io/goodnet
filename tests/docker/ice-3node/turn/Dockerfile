# Full TURN coturn image. Allocations gated by long-term credentials
# (RFC 5389 §15.4) baked from build-time env vars; the peer harness
# uses the same creds via `ice.turn_username` / `ice.turn_password`.
FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends coturn netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

# Bench-only credentials. Operators running the suite outside the
# scenario sandbox should override these via compose env to keep the
# TURN allocation surface from being usable elsewhere.
ARG TURN_USER=goodnet
ARG TURN_PASS=bench-only-credentials
ARG TURN_REALM=ice3.local

# Build-time bake — runtime overrides land via ENV in docker-compose.
ENV TURN_USER=${TURN_USER}
ENV TURN_PASS=${TURN_PASS}
ENV TURN_REALM=${TURN_REALM}

RUN printf '%s\n' \
    'fingerprint' \
    'lt-cred-mech' \
    'listening-port=3478' \
    'min-port=49152' \
    'max-port=49251' \
    'realm=${TURN_REALM}' \
    "user=${TURN_USER}:${TURN_PASS}" \
    'no-tls' \
    'no-dtls' \
    'verbose' \
    'no-stdout-log' \
    'syslog' \
    > /etc/turnserver.conf

EXPOSE 3478/udp
EXPOSE 3478/tcp
EXPOSE 49152-49251/udp

ENTRYPOINT ["turnserver", "-c", "/etc/turnserver.conf"]
