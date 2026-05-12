#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Stage iroh as a comparison baseline. Cargo project that echoes a
# payload over QUIC (TLS 1.3, iroh keypair). Output is a release
# binary the runner executes over the standard payload sweep.

set -euo pipefail

cache="${GN_BENCH_REFS_DIR:-$HOME/.cache/goodnet-bench-refs}/iroh"
mkdir -p "$cache"

if [[ ! -d "$cache/upstream/.git" ]]; then
    git clone --depth 1 https://github.com/n0-computer/iroh "$cache/upstream"
else
    (cd "$cache/upstream" && git fetch --depth 1 origin && git reset --hard origin/HEAD) >/dev/null
fi

# iroh's `iroh/examples/echo.rs` is the canonical hello-world.
if [[ -f "$cache/upstream/iroh/examples/echo.rs" ]]; then
    ln -sf "$cache/upstream/iroh/examples/echo.rs" "$cache/echo_example.rs"
elif [[ -f "$cache/upstream/examples/echo.rs" ]]; then
    ln -sf "$cache/upstream/examples/echo.rs" "$cache/echo_example.rs"
fi

proj="${GN_BENCH_P2P_DIR:-/tmp/p2p-bench}/iroh-echo"
mkdir -p "$proj/src"

cat > "$proj/Cargo.toml" <<'TOML'
[package]
name    = "iroh-echo"
version = "0.1.0"
edition = "2021"

[dependencies]
iroh   = "0.32"
tokio  = { version = "1", features = ["full"] }
anyhow = "1"
rand   = "0.8"

[profile.release]
opt-level     = 3
lto           = "thin"
codegen-units = 1
TOML

cat > "$proj/src/main.rs" <<'RS'
use std::time::{Duration, Instant};
use iroh::{Endpoint, NodeAddr, RelayMode, SecretKey};
const ALPN: &[u8] = b"/echo/1";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let payload_size: usize = std::env::var("ECHO_PAYLOAD").ok().and_then(|s| s.parse().ok()).unwrap_or(8192);
    let duration_s: u64    = std::env::var("ECHO_DURATION").ok().and_then(|s| s.parse().ok()).unwrap_or(3);
    let mut rng = rand::thread_rng();

    let server = Endpoint::builder()
        .secret_key(SecretKey::generate(&mut rng))
        .alpns(vec![ALPN.to_vec()])
        .relay_mode(RelayMode::Disabled)
        .clear_discovery()
        .bind().await?;
    let server_id = server.node_id();
    let (server_sock_v4, _) = server.bound_sockets();
    let server_addr = NodeAddr::new(server_id).with_direct_addresses([server_sock_v4]);

    let server_task = { let server = server.clone(); tokio::spawn(async move {
        while let Some(incoming) = server.accept().await {
            tokio::spawn(async move {
                let conn = incoming.await?;
                loop {
                    let (mut send, mut recv) = match conn.accept_bi().await {
                        Ok(p) => p, Err(_) => return Ok::<(), anyhow::Error>(()),
                    };
                    let buf = recv.read_to_end(64 * 1024 * 1024).await?;
                    send.write_all(&buf).await?;
                    send.finish()?;
                    send.stopped().await?;
                }
            });
        }
    })};

    let client = Endpoint::builder()
        .secret_key(SecretKey::generate(&mut rng))
        .alpns(vec![ALPN.to_vec()])
        .relay_mode(RelayMode::Disabled)
        .clear_discovery()
        .bind().await?;

    let t_dial = Instant::now();
    let conn = client.connect(server_addr, ALPN).await?;
    let handshake = t_dial.elapsed();

    let payload = vec![0xAAu8; payload_size];
    let t_start = Instant::now();
    let deadline = t_start + Duration::from_secs(duration_s);
    let mut sent: u64 = 0;
    while Instant::now() < deadline {
        let (mut send, mut recv) = conn.open_bi().await?;
        send.write_all(&payload).await?;
        send.finish()?;
        let got = recv.read_to_end(payload_size * 2).await?;
        sent += got.len() as u64;
    }
    let elapsed = t_start.elapsed();
    let bps = sent as f64 / elapsed.as_secs_f64();
    println!("iroh-echo payload={}B duration={:.3}s bytes={} bps={:.2}MiB/s handshake_ms={:.2}",
        payload_size, elapsed.as_secs_f64(), sent, bps / 1024.0 / 1024.0,
        handshake.as_secs_f64() * 1000.0);
    drop(conn);
    server_task.abort();
    Ok(())
}
RS

(
    cd "$proj"
    CARGO_TARGET_DIR="${GN_BENCH_P2P_DIR:-/tmp/p2p-bench}/target" \
        cargo build --release 2>&1 | tail -5
)

echo "iroh baseline ready:"
echo "  dx-source = $cache/echo_example.rs"
echo "  bin       = ${GN_BENCH_P2P_DIR:-/tmp/p2p-bench}/target/release/iroh-echo"
