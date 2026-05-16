// Microbenchmarks for the hot paths in norn-rs.
//
// Run: `cargo bench`. Each bench reports per-op throughput; criterion writes
// HTML reports under target/criterion/. Use as an anti-regression signal: if
// a refactor halves session encrypt throughput, the bench will tell you.
//
// Bench targets:
//   - packet::{encode,decode}_uvarint
//   - address::address_from_key
//   - cuckoo::add / contains
//   - session encrypt + decrypt round-trip (X25519 + PQ hybrid HKDF)
//   - onion build (1 hop)
//   - onion peel (1 hop)
//
// PQ-handshake setup itself (ML-KEM keypair + encap + decap) is benched
// separately so its cost is visible.

use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

use norn_rs::address::address_from_key;
use norn_rs::cuckoo::CuckooFilter;
use norn_rs::onion::{build_onion, OnionHop, OnionKeyChain, OnionPacket};
use norn_rs::packet::{decode_uvarint, encode_uvarint, routing_tag};
use norn_rs::session::SessionManager;

// ── packet primitives ────────────────────────────────────────────────────

fn bench_uvarint(c: &mut Criterion) {
    let mut g = c.benchmark_group("uvarint");
    for &v in &[0u64, 127, 16383, 1 << 30, u64::MAX / 2] {
        g.bench_function(format!("encode_{v}"), |b| {
            b.iter_batched(
                Vec::new,
                |mut buf| {
                    encode_uvarint(black_box(v), &mut buf);
                    buf
                },
                BatchSize::SmallInput,
            )
        });
        let mut enc = Vec::new();
        encode_uvarint(v, &mut enc);
        g.bench_function(format!("decode_{v}"), |b| {
            b.iter(|| decode_uvarint(black_box(&enc)).unwrap())
        });
    }
    g.finish();
}

// ── address derivation ───────────────────────────────────────────────────

fn bench_address(c: &mut Criterion) {
    let key = [42u8; 32];
    c.bench_function("address_from_key", |b| {
        b.iter(|| address_from_key(black_box(&key)))
    });
}

// ── cuckoo filter ────────────────────────────────────────────────────────

fn bench_cuckoo(c: &mut Criterion) {
    let mut g = c.benchmark_group("cuckoo");
    g.bench_function("add_one", |b| {
        b.iter_batched_ref(
            CuckooFilter::new,
            |cf| {
                cf.add(black_box(b"hello"));
            },
            BatchSize::SmallInput,
        )
    });
    // Pre-fill ~1000 entries then time contains() lookups (hit + miss).
    let mut filled = CuckooFilter::new();
    for i in 0..1000u32 {
        filled.add(&i.to_le_bytes());
    }
    g.bench_function("contains_hit_1k", |b| {
        b.iter(|| filled.contains(black_box(&500u32.to_le_bytes())))
    });
    g.bench_function("contains_miss_1k", |b| {
        b.iter(|| filled.contains(black_box(&999_999u32.to_le_bytes())))
    });
    g.finish();
}

// ── session encrypt/decrypt round-trip ───────────────────────────────────

fn bench_session(c: &mut Criterion) {
    let mut g = c.benchmark_group("session");

    let sk_a = SigningKey::generate(&mut OsRng);
    let sk_b = SigningKey::generate(&mut OsRng);
    let pub_a = sk_a.verifying_key().to_bytes();
    let pub_b = sk_b.verifying_key().to_bytes();

    // PQ handshake setup is expensive (~80μs total); bench it explicitly.
    g.bench_function("pq_handshake", |b| {
        b.iter(|| {
            let mut mgr_a = SessionManager::new(SigningKey::generate(&mut OsRng));
            let mut mgr_b = SessionManager::new(SigningKey::generate(&mut OsRng));
            let pb = mgr_b.our_signing_key().verifying_key().to_bytes();
            let init = mgr_a.initiate(&pb);
            let ack = mgr_b.handle_init(&init).unwrap();
            mgr_a.handle_ack(&ack).unwrap();
            black_box(())
        })
    });

    // Encrypt/decrypt: pre-establish the session, then time per-packet ops.
    let mut mgr_a = SessionManager::new(sk_a);
    let mut mgr_b = SessionManager::new(sk_b);
    let init = mgr_a.initiate(&pub_b);
    let ack = mgr_b.handle_init(&init).unwrap();
    mgr_a.handle_ack(&ack).unwrap();
    // Warm up so internal state is stable.
    let _ = mgr_a.encrypt(&pub_b, b"warmup").unwrap();
    let _ = mgr_b.encrypt(&pub_a, b"warmup").unwrap();

    for &len in &[64usize, 1024, 16384] {
        let plaintext = vec![0xABu8; len];
        g.throughput(Throughput::Bytes(len as u64));
        g.bench_function(format!("encrypt_{len}B"), |b| {
            b.iter(|| {
                let _ = mgr_a.encrypt(black_box(&pub_b), black_box(&plaintext)).unwrap();
            })
        });
    }

    g.finish();
}

// ── onion build + peel ───────────────────────────────────────────────────

fn bench_onion(c: &mut Criterion) {
    let mut g = c.benchmark_group("onion");

    let relay_sk = SigningKey::generate(&mut OsRng);
    let dest_sk = SigningKey::generate(&mut OsRng);
    let relay_chain = OnionKeyChain::with_identity_fallback(&relay_sk);
    let dest_chain = OnionKeyChain::with_identity_fallback(&dest_sk);
    let relay_hop = OnionHop {
        identity_ed_pub: relay_sk.verifying_key().to_bytes(),
        ephemeral_x_pub: *relay_chain.pub_key().as_bytes(),
    };
    let dest_hop = OnionHop {
        identity_ed_pub: dest_sk.verifying_key().to_bytes(),
        ephemeral_x_pub: *dest_chain.pub_key().as_bytes(),
    };
    let traffic = vec![0u8; 256];

    g.bench_function("build_0_relays", |b| {
        b.iter(|| {
            let _ = build_onion(black_box(&[]), black_box(&dest_hop), traffic.clone()).unwrap();
        })
    });
    g.bench_function("build_1_relay", |b| {
        b.iter(|| {
            let _ = build_onion(
                black_box(std::slice::from_ref(&relay_hop)),
                black_box(&dest_hop),
                traffic.clone(),
            ).unwrap();
        })
    });

    let onion = build_onion(std::slice::from_ref(&relay_hop), &dest_hop, traffic).unwrap();
    let onion_bytes = onion.encode();
    g.bench_function("decode", |b| {
        b.iter(|| OnionPacket::decode(black_box(&onion_bytes[1..])).unwrap())
    });
    // Each peel needs a fresh OnionPacket because the chain doesn't track replay
    // here (replay is tracked at RouterState level), but peel itself doesn't
    // mutate the packet — so we can re-use.
    g.bench_function("peel", |b| {
        b.iter(|| {
            let _ = onion.peel(black_box(&relay_chain)).unwrap();
        })
    });
    g.finish();
}

// ── routing tag ──────────────────────────────────────────────────────────

fn bench_routing_tag(c: &mut Criterion) {
    let key = [42u8; 32];
    c.bench_function("routing_tag", |b| b.iter(|| routing_tag(black_box(&key))));
}

criterion_group!(
    benches,
    bench_uvarint,
    bench_address,
    bench_cuckoo,
    bench_session,
    bench_onion,
    bench_routing_tag,
);
criterion_main!(benches);
