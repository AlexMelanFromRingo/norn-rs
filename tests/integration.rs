// Integration tests for norn-rs

use ed25519_dalek::SigningKey;
use norn_rs::PacketConn;
use rand::rngs::OsRng;
use std::time::Duration;
use tokio::io::duplex;

/// Create a pair of connected PacketConns using tokio duplex pipes.
async fn make_connected_pair() -> (PacketConn, PacketConn) {
    let sk_a = SigningKey::generate(&mut OsRng);
    let sk_b = SigningKey::generate(&mut OsRng);
    let pub_a = sk_a.verifying_key().to_bytes();
    let pub_b = sk_b.verifying_key().to_bytes();

    let conn_a = PacketConn::new(sk_a);
    let conn_b = PacketConn::new(sk_b);

    // Create duplex pipes (A's write → B's read, B's write → A's read)
    let (a_to_b_reader, a_to_b_writer) = duplex(65536);
    let (b_to_a_reader, b_to_a_writer) = duplex(65536);

    // A reads from b_to_a_reader, writes to a_to_b_writer
    conn_a.handle_conn(pub_b, b_to_a_reader, a_to_b_writer, 0).await;

    // B reads from a_to_b_reader, writes to b_to_a_writer
    conn_b.handle_conn(pub_a, a_to_b_reader, b_to_a_writer, 0).await;

    (conn_a, conn_b)
}

/// Wait for a session to be established by retrying write_to until success.
async fn wait_for_session(sender: &PacketConn, dst: &[u8; 32]) -> bool {
    let timeout = Duration::from_secs(10);
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if tokio::time::Instant::now() > deadline {
            return false;
        }
        match sender.write_to(b"ping", dst).await {
            Ok(_) => return true,
            Err(_) => {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

#[tokio::test]
async fn two_nodes_connect_and_exchange() {
    let _ = tracing_subscriber::fmt().with_env_filter("warn").try_init();

    let (conn_a, conn_b) = make_connected_pair().await;
    let pub_a = conn_a.pub_key;
    let pub_b = conn_b.pub_key;

    // Wait for A→B session to establish
    assert!(
        wait_for_session(&conn_a, &pub_b).await,
        "A→B session failed to establish within 10s"
    );

    // Drain any ping/warmup messages from B's queue (non-blocking)
    // We use a short timeout to drain any messages that arrived during warmup
    let drain_timeout = Duration::from_millis(200);
    loop {
        match tokio::time::timeout(drain_timeout, conn_b.read_from()).await {
            Ok(Ok(_)) => continue, // discard warmup messages
            _ => break,
        }
    }

    // Wait for B→A session to establish
    assert!(
        wait_for_session(&conn_b, &pub_a).await,
        "B→A session failed to establish within 10s"
    );

    // Drain any warmup messages from A's queue
    loop {
        match tokio::time::timeout(drain_timeout, conn_a.read_from()).await {
            Ok(Ok(_)) => continue,
            _ => break,
        }
    }

    // ── Test A → B: send 5 messages ──────────────────────────────────────────
    let messages_a_to_b: Vec<Vec<u8>> = (0..5)
        .map(|i| format!("hello_from_A_{}", i).into_bytes())
        .collect();

    for msg in &messages_a_to_b {
        conn_a.write_to(msg, &pub_b).await.expect("A→B write failed");
    }

    let received_on_b = tokio::time::timeout(Duration::from_secs(5), async {
        let mut received = Vec::new();
        for _ in 0..5 {
            let pkt = conn_b.read_from().await.expect("B read_from failed");
            assert_eq!(pkt.from, pub_a, "wrong sender on B");
            received.push(pkt.payload);
        }
        received
    })
    .await
    .expect("timed out waiting for B to receive 5 messages");

    for (i, (sent, recv)) in messages_a_to_b.iter().zip(received_on_b.iter()).enumerate() {
        assert_eq!(sent, recv, "message {} mismatch: A→B", i);
    }

    // ── Test B → A: send 5 messages ──────────────────────────────────────────
    let messages_b_to_a: Vec<Vec<u8>> = (0..5)
        .map(|i| format!("hello_from_B_{}", i).into_bytes())
        .collect();

    for msg in &messages_b_to_a {
        conn_b.write_to(msg, &pub_a).await.expect("B→A write failed");
    }

    let received_on_a = tokio::time::timeout(Duration::from_secs(5), async {
        let mut received = Vec::new();
        for _ in 0..5 {
            let pkt = conn_a.read_from().await.expect("A read_from failed");
            assert_eq!(pkt.from, pub_b, "wrong sender on A");
            received.push(pkt.payload);
        }
        received
    })
    .await
    .expect("timed out waiting for A to receive 5 messages");

    for (i, (sent, recv)) in messages_b_to_a.iter().zip(received_on_a.iter()).enumerate() {
        assert_eq!(sent, recv, "message {} mismatch: B→A", i);
    }
}

#[tokio::test]
async fn peer_stats_available() {
    let _ = tracing_subscriber::fmt().with_env_filter("warn").try_init();
    let (conn_a, conn_b) = make_connected_pair().await;

    // Give connections a moment
    tokio::time::sleep(Duration::from_millis(100)).await;

    let stats_a = conn_a.get_peer_stats();
    assert_eq!(stats_a.len(), 1, "A should see 1 peer");
    assert_eq!(stats_a[0].key, conn_b.pub_key);

    let stats_b = conn_b.get_peer_stats();
    assert_eq!(stats_b.len(), 1, "B should see 1 peer");
    assert_eq!(stats_b[0].key, conn_a.pub_key);
}

#[tokio::test]
async fn mtu_is_correct() {
    let sk = SigningKey::generate(&mut OsRng);
    let conn = PacketConn::new(sk);
    assert_eq!(conn.mtu(), 65535);
}
