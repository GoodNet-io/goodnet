# TURN coturn image with TLS-over-TCP enabled. Uses the pre-built
# coturn/coturn image to avoid apt-get network access at build time.
FROM coturn/coturn:latest

ARG TURN_USER=goodnet
ARG TURN_PASS=bench-only-credentials
ARG TURN_REALM=ice3.local

ENV TURN_USER=${TURN_USER}
ENV TURN_PASS=${TURN_PASS}
ENV TURN_REALM=${TURN_REALM}

USER root

# Generate a self-signed cert for the TLS listener.
RUN mkdir -p /etc/coturn \
    && openssl req -x509 -newkey rsa:2048 -nodes -days 30 \
        -subj "/CN=ice3-turn-tls" \
        -keyout /etc/coturn/key.pem \
        -out /etc/coturn/cert.pem \
    && chmod 640 /etc/coturn/key.pem /etc/coturn/cert.pem

# TLS on 5349/tcp; plain UDP disabled to force TLS-TCP path.
RUN printf '%s\n' \
    'fingerprint' \
    'lt-cred-mech' \
    'listening-port=3478' \
    'tls-listening-port=5349' \
    'min-port=49152' \
    'max-port=49251' \
    "realm=${TURN_REALM}" \
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
