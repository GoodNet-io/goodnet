#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Stage Rust rust-libp2p as a comparison baseline: cargo project that
# echoes a length-prefixed payload over a TCP + Noise + Yamux stack
# using libp2p-stream. Output is a release-mode binary that the
# runner script (`runners/libp2p_rs.sh`) executes over the same
# payload sweep as bench_udp/bench_ws EchoRoundtrip.
#
# Source for the upstream LOC count points at the canonical
# `examples/ping/src/main.rs` (libp2p's hello-world example) so the
# DX bench treats libp2p with the same yardstick as openssl, libuv,
# libssh.

set -euo pipefail

cache="${GN_BENCH_REFS_DIR:-$HOME/.cache/goodnet-bench-refs}/libp2p-rs"
mkdir -p "$cache"

if [[ ! -d "$cache/upstream/.git" ]]; then
    git clone --depth 1 https://github.com/libp2p/rust-libp2p "$cache/upstream"
else
    (cd "$cache/upstream" && git fetch --depth 1 origin && git reset --hard origin/HEAD) >/dev/null
fi

# Symlink the canonical hello-world for the DX LOC count. libp2p
# ships ping as the smallest end-to-end example; client + server is
# one file because the ping behaviour is symmetric (both sides
# implement initiate + respond on the same protocol).
ln -sf "$cache/upstream/examples/ping/src/main.rs" "$cache/echo_example.rs"

# Build our minimal echo bin in /tmp so the runner has something to
# execute. Kept out of the project tree per the user's "non-public,
# just for measurement" directive — bench/comparison/ only ships the
# scripts.
proj="${GN_BENCH_P2P_DIR:-/tmp/p2p-bench}/libp2p-echo"
mkdir -p "$proj/src"

cat > "$proj/Cargo.toml" <<'TOML'
[package]
name    = "libp2p-echo"
version = "0.1.0"
edition = "2021"

[dependencies]
libp2p = { version = "0.55", features = [
    "tokio", "tcp", "noise", "yamux", "macros",
] }
libp2p-stream = "=0.3.0-alpha"
tokio   = { version = "1", features = ["full"] }
futures = "0.3"

[profile.release]
opt-level     = 3
lto           = "thin"
codegen-units = 1
TOML

cat > "$proj/src/main.rs" <<'RS'
// libp2p loopback echo bench. TCP + Noise + Yamux + libp2p-stream.
use std::time::{Duration, Instant};
use futures::{AsyncReadExt, AsyncWriteExt, StreamExt};
use libp2p::{identity, swarm::SwarmEvent, Multiaddr, PeerId, StreamProtocol};
use libp2p_stream as stream;

const PROTO: StreamProtocol = StreamProtocol::new("/echo/1");

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let payload_size: usize = std::env::var("ECHO_PAYLOAD").ok().and_then(|s| s.parse().ok()).unwrap_or(8192);
    let duration_s: u64    = std::env::var("ECHO_DURATION").ok().and_then(|s| s.parse().ok()).unwrap_or(3);

    let server_kp = identity::Keypair::generate_ed25519();
    let server_id = PeerId::from(server_kp.public());
    let client_kp = identity::Keypair::generate_ed25519();

    let mk = |kp: identity::Keypair| {
        libp2p::SwarmBuilder::with_existing_identity(kp)
            .with_tokio()
            .with_tcp(libp2p::tcp::Config::default().nodelay(true),
                      libp2p::noise::Config::new,
                      libp2p::yamux::Config::default)
            .unwrap()
            .with_behaviour(|_| stream::Behaviour::new()).unwrap()
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(120)))
            .build()
    };
    let mut server = mk(server_kp);
    let mut client = mk(client_kp);

    server.listen_on("/ip4/127.0.0.1/tcp/0".parse()?)?;
    let server_addr: Multiaddr = loop {
        if let Some(SwarmEvent::NewListenAddr { address, .. }) = server.next().await { break address; }
    };

    let server_ctrl = server.behaviour().new_control();
    let server_task = {
        let mut server = server;
        let mut server_ctrl = server_ctrl;
        let mut incoming = server_ctrl.accept(PROTO)?;
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = server.next() => {}
                    Some((_peer, mut s)) = incoming.next() => {
                        tokio::spawn(async move {
                            let mut buf = vec![0u8; 65536];
                            loop {
                                match s.read(&mut buf).await {
                                    Ok(0) | Err(_) => break,
                                    Ok(n) => if s.write_all(&buf[..n]).await.is_err() { break; }
                                }
                            }
                        });
                    }
                }
            }
        })
    };

    let mut client_ctrl = client.behaviour().new_control();
    let dial_started = Instant::now();
    client.dial(server_addr.with(libp2p::multiaddr::Protocol::P2p(server_id)))?;

    let mut handshake = None;
    loop {
        match client.next().await {
            Some(SwarmEvent::ConnectionEstablished { peer_id, .. }) if peer_id == server_id => {
                handshake = Some(dial_started.elapsed()); break;
            }
            Some(_) => {}
            None => return Err("client swarm closed".into()),
        }
    }
    let driver = tokio::spawn(async move { while let Some(_) = client.next().await {} });

    let mut s = client_ctrl.open_stream(server_id, PROTO).await?;
    let payload = vec![0xAAu8; payload_size];
    let mut buf = vec![0u8; payload_size];
    let t_start = Instant::now();
    let deadline = t_start + Duration::from_secs(duration_s);
    let mut sent: u64 = 0;
    while Instant::now() < deadline {
        s.write_all(&payload).await?;
        let mut got = 0;
        while got < payload_size {
            let n = s.read(&mut buf[got..]).await?;
            if n == 0 { break; }
            got += n;
        }
        sent += payload_size as u64;
    }
    let elapsed = t_start.elapsed();
    let bps = sent as f64 / elapsed.as_secs_f64();
    println!("libp2p-echo payload={}B duration={:.3}s bytes={} bps={:.2}MiB/s handshake_ms={:.2}",
        payload_size, elapsed.as_secs_f64(), sent, bps / 1024.0 / 1024.0,
        handshake.map(|d| d.as_secs_f64() * 1000.0).unwrap_or(-1.0));
    driver.abort();
    server_task.abort();
    Ok(())
}
RS

(
    cd "$proj"
    CARGO_TARGET_DIR="${GN_BENCH_P2P_DIR:-/tmp/p2p-bench}/target" \
        cargo build --release 2>&1 | tail -5
)

echo "libp2p baseline ready:"
echo "  dx-source = $cache/echo_example.rs"
echo "  bin       = ${GN_BENCH_P2P_DIR:-/tmp/p2p-bench}/target/release/libp2p-echo"
