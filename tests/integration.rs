// Integration tests for norn-rs
#![allow(clippy::while_let_loop)]

use ed25519_dalek::SigningKey;
use norn_rs::PacketConn;
use rand::rngs::OsRng;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::duplex;
use norn_rs::hyperbolic::HypCoord;

/// Spawn handle_conn in the background (it now blocks until disconnect).
fn spawn_conn(conn: Arc<PacketConn>, remote_pub: [u8; 32], reader: impl tokio::io::AsyncRead + Unpin + Send + 'static, writer: impl tokio::io::AsyncWrite + Unpin + Send + 'static) {
    tokio::spawn(async move {
        conn.handle_conn(remote_pub, reader, writer, 0).await;
    });
}

/// Create a pair of connected PacketConns using tokio duplex pipes.
async fn make_connected_pair() -> (Arc<PacketConn>, Arc<PacketConn>) {
    let sk_a = SigningKey::generate(&mut OsRng);
    let sk_b = SigningKey::generate(&mut OsRng);
    let pub_a = sk_a.verifying_key().to_bytes();
    let pub_b = sk_b.verifying_key().to_bytes();

    let conn_a = Arc::new(PacketConn::new(sk_a));
    let conn_b = Arc::new(PacketConn::new(sk_b));

    // Create duplex pipes (A's write → B's read, B's write → A's read)
    let (a_to_b_reader, a_to_b_writer) = duplex(65536);
    let (b_to_a_reader, b_to_a_writer) = duplex(65536);

    spawn_conn(conn_a.clone(), pub_b, b_to_a_reader, a_to_b_writer);
    spawn_conn(conn_b.clone(), pub_a, a_to_b_reader, b_to_a_writer);

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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hyperbolic_routing_two_nodes() {
    // Test that the hyperbolic coordinate announce/receive/lookup path works.
    // With 2 nodes the hyperbolic lookup and fallback give the same result,
    // but this exercises the full coord-announce → coord_table → lookup pipeline.
    let _ = tracing_subscriber::fmt().with_env_filter("warn").try_init();

    let (conn_a, conn_b) = make_connected_pair().await;
    let pub_a = conn_a.pub_key;
    let pub_b = conn_b.pub_key;

    // Wait for session A→B
    assert!(
        wait_for_session(&conn_a, &pub_b).await,
        "A→B session failed to establish"
    );

    // Allow maintenance cycle(s) to fire so CoordAnnounces are exchanged
    tokio::time::sleep(Duration::from_millis(1200)).await;

    // Verify coord table: each node should know the other's coord
    // (We check this indirectly by verifying that get_peer_stats returns the peer.)
    let stats_a = conn_a.get_peer_stats();
    assert_eq!(stats_a.len(), 1, "A should see 1 peer after warmup");
    assert_eq!(stats_a[0].key, pub_b);

    let stats_b = conn_b.get_peer_stats();
    assert_eq!(stats_b.len(), 1, "B should see 1 peer after warmup");
    assert_eq!(stats_b[0].key, pub_a);

    // Drain any warmup messages
    let drain_timeout = Duration::from_millis(200);
    loop {
        match tokio::time::timeout(drain_timeout, conn_b.read_from()).await {
            Ok(Ok(_)) => continue,
            _ => break,
        }
    }

    // Wait for B→A session
    assert!(
        wait_for_session(&conn_b, &pub_a).await,
        "B→A session failed to establish"
    );

    loop {
        match tokio::time::timeout(drain_timeout, conn_a.read_from()).await {
            Ok(Ok(_)) => continue,
            _ => break,
        }
    }

    // Send 10 messages A→B and 10 messages B→A
    let msgs_a: Vec<Vec<u8>> = (0..10)
        .map(|i| format!("hyp_a_to_b_{}", i).into_bytes())
        .collect();
    let msgs_b: Vec<Vec<u8>> = (0..10)
        .map(|i| format!("hyp_b_to_a_{}", i).into_bytes())
        .collect();

    for msg in &msgs_a {
        conn_a.write_to(msg, &pub_b).await.expect("A→B write failed");
    }
    for msg in &msgs_b {
        conn_b.write_to(msg, &pub_a).await.expect("B→A write failed");
    }

    // Receive on B
    let recv_b = tokio::time::timeout(Duration::from_secs(5), async {
        let mut received = Vec::new();
        for _ in 0..10 {
            let pkt = conn_b.read_from().await.expect("B read_from failed");
            assert_eq!(pkt.from, pub_a, "wrong sender on B");
            received.push(pkt.payload);
        }
        received
    })
    .await
    .expect("timed out waiting for B to receive 10 messages");

    for (i, (sent, recv)) in msgs_a.iter().zip(recv_b.iter()).enumerate() {
        assert_eq!(sent, recv, "message {} mismatch A→B", i);
    }

    // Receive on A
    let recv_a = tokio::time::timeout(Duration::from_secs(5), async {
        let mut received = Vec::new();
        for _ in 0..10 {
            let pkt = conn_a.read_from().await.expect("A read_from failed");
            assert_eq!(pkt.from, pub_b, "wrong sender on A");
            received.push(pkt.payload);
        }
        received
    })
    .await
    .expect("timed out waiting for A to receive 10 messages");

    for (i, (sent, recv)) in msgs_b.iter().zip(recv_a.iter()).enumerate() {
        assert_eq!(sent, recv, "message {} mismatch B→A", i);
    }

    // Verify coord table is populated via get_peer_stats (indirect check)
    let stats_a = conn_a.get_peer_stats();
    assert!(!stats_a.is_empty(), "A should have peer stats after coord exchange");

    // Sanity-check the HypCoord distance function directly
    let origin = HypCoord::origin();
    let far = HypCoord { r: 0.9, theta: 1.0 };
    assert!(
        origin.distance(far) > 0.0,
        "distance from origin to far point should be positive"
    );
    let d_ab = far.distance(origin);
    let d_ba = origin.distance(far);
    assert!(
        (d_ab - d_ba).abs() < 1e-9,
        "distance should be symmetric"
    );
}

/// Three-node test: A -- B -- C (linear chain).
/// A and C are NOT directly connected. Traffic A→C must be forwarded through B.
/// This is the key test for hyperbolic/cuckoo routing: B must route correctly.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn three_nodes_forwarding() {
    let _ = tracing_subscriber::fmt().with_env_filter("warn").try_init();

    let sk_a = SigningKey::generate(&mut OsRng);
    let sk_b = SigningKey::generate(&mut OsRng);
    let sk_c = SigningKey::generate(&mut OsRng);
    let pub_a = sk_a.verifying_key().to_bytes();
    let pub_b = sk_b.verifying_key().to_bytes();
    let pub_c = sk_c.verifying_key().to_bytes();

    let conn_a = Arc::new(PacketConn::new(sk_a));
    let conn_b = Arc::new(PacketConn::new(sk_b));
    let conn_c = Arc::new(PacketConn::new(sk_c));

    // Connect A -- B
    let (a_to_b_r, a_to_b_w) = duplex(65536);
    let (b_to_a_r, b_to_a_w) = duplex(65536);
    spawn_conn(conn_a.clone(), pub_b, b_to_a_r, a_to_b_w);
    spawn_conn(conn_b.clone(), pub_a, a_to_b_r, b_to_a_w);

    // Connect B -- C
    let (b_to_c_r, b_to_c_w) = duplex(65536);
    let (c_to_b_r, c_to_b_w) = duplex(65536);
    spawn_conn(conn_b.clone(), pub_c, c_to_b_r, b_to_c_w);
    spawn_conn(conn_c.clone(), pub_b, b_to_c_r, c_to_b_w);

    // Wait for maintenance cycles: cuckoo filters propagate, coords exchanged
    // A's cuckoo must reach C via B, and C's cuckoo must reach A via B.
    // This takes at least 2 maintenance ticks (1 hop × 1s + propagation).
    tokio::time::sleep(Duration::from_secs(3)).await;

    // Establish A→C session (A sends init, B forwards to C, C acks back)
    assert!(
        wait_for_session(&conn_a, &pub_c).await,
        "A→C session failed to establish (forwarded via B)"
    );

    // Drain warmup messages on C
    let drain = Duration::from_millis(300);
    loop {
        match tokio::time::timeout(drain, conn_c.read_from()).await {
            Ok(Ok(_)) => continue,
            _ => break,
        }
    }

    // Establish C→A session
    assert!(
        wait_for_session(&conn_c, &pub_a).await,
        "C→A session failed to establish (forwarded via B)"
    );

    // Drain warmup on A
    loop {
        match tokio::time::timeout(drain, conn_a.read_from()).await {
            Ok(Ok(_)) => continue,
            _ => break,
        }
    }

    // Send 5 messages A → C (must go through B)
    let msgs: Vec<Vec<u8>> = (0..5)
        .map(|i| format!("A_to_C_{}", i).into_bytes())
        .collect();

    for msg in &msgs {
        conn_a.write_to(msg, &pub_c).await.expect("A→C write failed");
    }

    let recv_c = tokio::time::timeout(Duration::from_secs(5), async {
        let mut out = Vec::new();
        for _ in 0..5 {
            let pkt = conn_c.read_from().await.expect("C read_from failed");
            assert_eq!(pkt.from, pub_a, "wrong sender on C");
            out.push(pkt.payload);
        }
        out
    })
    .await
    .expect("timed out waiting for C to receive 5 messages via B");

    // Forwarding jitter may reorder packets — compare as sets, not ordered sequences.
    let mut sent_sorted = msgs.clone(); sent_sorted.sort();
    let mut recv_c_sorted = recv_c.clone(); recv_c_sorted.sort();
    assert_eq!(sent_sorted, recv_c_sorted, "message set mismatch A→C");

    // Send 5 messages C → A (must go through B)
    let msgs_back: Vec<Vec<u8>> = (0..5)
        .map(|i| format!("C_to_A_{}", i).into_bytes())
        .collect();

    for msg in &msgs_back {
        conn_c.write_to(msg, &pub_a).await.expect("C→A write failed");
    }

    let recv_a = tokio::time::timeout(Duration::from_secs(5), async {
        let mut out = Vec::new();
        for _ in 0..5 {
            let pkt = conn_a.read_from().await.expect("A read_from failed");
            assert_eq!(pkt.from, pub_c, "wrong sender on A");
            out.push(pkt.payload);
        }
        out
    })
    .await
    .expect("timed out waiting for A to receive 5 messages via B");

    let mut sent_back_sorted = msgs_back.clone(); sent_back_sorted.sort();
    let mut recv_a_sorted = recv_a.clone(); recv_a_sorted.sort();
    assert_eq!(sent_back_sorted, recv_a_sorted, "message set mismatch C→A");
}

/// Test onion routing: A sends via B (relay) to C.
/// Topology: A ↔ B ↔ C (linear, same as three_nodes_forwarding)
/// A uses write_to_onion with B as the relay → onion path: A → B(relay) → C(dest)
#[tokio::test]
async fn onion_routing_via_relay() {
    let sk_a = SigningKey::generate(&mut OsRng);
    let sk_b = SigningKey::generate(&mut OsRng);
    let sk_c = SigningKey::generate(&mut OsRng);

    let pub_a = sk_a.verifying_key().to_bytes();
    let pub_b = sk_b.verifying_key().to_bytes();
    let pub_c = sk_c.verifying_key().to_bytes();

    let conn_a = Arc::new(PacketConn::new(sk_a));
    let conn_b = Arc::new(PacketConn::new(sk_b));
    let conn_c = Arc::new(PacketConn::new(sk_c));

    // A ↔ B
    let (ab_r, ab_w) = duplex(65536);
    let (ba_r, ba_w) = duplex(65536);
    spawn_conn(conn_a.clone(), pub_b, ba_r, ab_w);
    spawn_conn(conn_b.clone(), pub_a, ab_r, ba_w);

    // B ↔ C
    let (bc_r, bc_w) = duplex(65536);
    let (cb_r, cb_w) = duplex(65536);
    spawn_conn(conn_b.clone(), pub_c, cb_r, bc_w);
    spawn_conn(conn_c.clone(), pub_b, bc_r, cb_w);

    // Wait for cuckoo filters to propagate so B and A can route to C
    tokio::time::sleep(Duration::from_secs(3)).await;

    // Establish direct A→C session (needed for session encryption inside the onion)
    assert!(
        wait_for_session(&conn_a, &pub_c).await,
        "A→C session failed to establish"
    );

    // Drain warmup messages at C
    let drain = Duration::from_millis(300);
    loop {
        match tokio::time::timeout(drain, conn_c.read_from()).await {
            Ok(Ok(_)) => continue,
            _ => break,
        }
    }

    // Send 3 messages via onion: A → B(relay) → C
    let msgs: Vec<Vec<u8>> = (0..3)
        .map(|i| format!("onion_msg_{}", i).into_bytes())
        .collect();

    for msg in &msgs {
        conn_a
            .write_to_onion(msg, &pub_c, &[pub_b])
            .await
            .expect("write_to_onion failed");
    }

    let recv_c = tokio::time::timeout(Duration::from_secs(5), async {
        let mut out = Vec::new();
        for _ in 0..3 {
            let pkt = conn_c.read_from().await.expect("C read_from failed");
            assert_eq!(pkt.from, pub_a, "wrong sender on C (onion)");
            out.push(pkt.payload);
        }
        out
    })
    .await
    .expect("timed out waiting for onion messages at C");

    let mut sent_s = msgs.clone(); sent_s.sort();
    let mut recv_s = recv_c.clone(); recv_s.sort();
    assert_eq!(sent_s, recv_s, "onion message set mismatch");
}
