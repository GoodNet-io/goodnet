# Secondary TURN server for the multi-TURN failover scenario.
#
# Mirrors the primary `turn/` image but with a shim in front of
# `coturn` that simulates a flaky upstream: the first
# TURN_FAIL_COUNT (default 5) STUN/TURN Allocate requests get a
# 500-class error reply from the shim; subsequent requests are
# forwarded straight to the real coturn process which serves them
# normally. Lets the harness assert that the multi-TURN fallback
# code path picks the secondary server after the primary is
# externally driven into failure mid-allocation.
#
# The shim listens on 3478/udp on the container's primary IP and
# proxies to coturn on 127.0.0.1:3479. The init script binds the
# loopback override and execs the shim under supervisord-style
# `wait` semantics.
FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        coturn netcat-openbsd python3 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

ARG TURN_USER=goodnet
ARG TURN_PASS=bench-only-credentials
ARG TURN_REALM=ice3.local

ENV TURN_USER=${TURN_USER}
ENV TURN_PASS=${TURN_PASS}
ENV TURN_REALM=${TURN_REALM}
ENV TURN_FAIL_COUNT=5

# coturn listens on loopback 3479; the shim listens on 3478 and
# either errors or proxies through. The shim flips state after
# TURN_FAIL_COUNT requests so the harness can drive the failover.
RUN printf '%s\n' \
    'fingerprint' \
    'lt-cred-mech' \
    'listening-ip=127.0.0.1' \
    'listening-port=3479' \
    'min-port=49252' \
    'max-port=49351' \
    'realm=${TURN_REALM}' \
    "user=${TURN_USER}:${TURN_PASS}" \
    'no-tls' \
    'no-dtls' \
    'verbose' \
    'no-stdout-log' \
    'syslog' \
    > /etc/turnserver.conf

COPY flaky-shim.py /usr/local/bin/flaky-shim.py
COPY run.sh /usr/local/bin/run.sh
RUN chmod +x /usr/local/bin/flaky-shim.py /usr/local/bin/run.sh

EXPOSE 3478/udp
EXPOSE 49252-49351/udp

ENTRYPOINT ["/usr/local/bin/run.sh"]
