// iroh loopback echo benchmark. QUIC underneath, TLS 1.3, iroh keypair.
// Both endpoints on 127.0.0.1, relay disabled, no discovery — pure direct path.
// Uses ONE persistent bi-directional stream (same methodology as libp2p-echo).

use std::time::{Duration, Instant};
use iroh::{Endpoint, NodeAddr, RelayMode, SecretKey};

const ALPN: &[u8] = b"/echo/1";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let payload_size: usize = std::env::var("ECHO_PAYLOAD")
        .ok().and_then(|s| s.parse().ok()).unwrap_or(8192);
    let duration_s: u64 = std::env::var("ECHO_DURATION")
        .ok().and_then(|s| s.parse().ok()).unwrap_or(3);

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

    let server_task = {
        let server = server.clone();
        tokio::spawn(async move {
            while let Some(incoming) = server.accept().await {
                tokio::spawn(async move {
                    let conn = incoming.await?;
                    // Accept ONE stream and echo persistently — mirrors libp2p-echo.
                    let (mut send, mut recv) = match conn.accept_bi().await {
                        Ok(p) => p,
                        Err(_) => return Ok::<(), anyhow::Error>(()),
                    };
                    let mut buf = vec![0u8; 65536];
                    loop {
                        match recv.read(&mut buf).await {
                            Ok(Some(n)) => {
                                if send.write_all(&buf[..n]).await.is_err() {
                                    break;
                                }
                            }
                            _ => break,
                        }
                    }
                    Ok(())
                });
            }
        })
    };

    let client = Endpoint::builder()
        .secret_key(SecretKey::generate(&mut rng))
        .alpns(vec![ALPN.to_vec()])
        .relay_mode(RelayMode::Disabled)
        .clear_discovery()
        .bind().await?;

    let t_dial = Instant::now();
    let conn = client.connect(server_addr, ALPN).await?;
    let handshake = t_dial.elapsed();

    // Open ONE stream outside the loop — persistent stream, same methodology as libp2p.
    let (mut send, mut recv) = conn.open_bi().await?;
    let payload = vec![0xAAu8; payload_size];
    let mut buf = vec![0u8; payload_size];
    let t_start = Instant::now();
    let deadline = t_start + Duration::from_secs(duration_s);
    let mut sent: u64 = 0;
    while Instant::now() < deadline {
        send.write_all(&payload).await?;
        let mut got = 0usize;
        while got < payload_size {
            match recv.read(&mut buf[got..]).await? {
                Some(n) => got += n,
                None => break,
            }
        }
        sent += payload_size as u64;
    }
    let elapsed = t_start.elapsed();
    let bps = sent as f64 / elapsed.as_secs_f64();
    println!(
        "iroh-echo payload={}B duration={:.3}s bytes={} bps={:.2}MiB/s handshake_ms={:.2}",
        payload_size, elapsed.as_secs_f64(), sent,
        bps / 1024.0 / 1024.0,
        handshake.as_secs_f64() * 1000.0
    );
    drop(send);
    drop(conn);
    server_task.abort();
    Ok(())
}
