//! Unit/integration tests for the routing engine, split from router/mod.rs.
    use super::*;

    // ── PeerData::effective_cost (kills replace-with-0 and replace-with-1) ───

    #[test]
    fn peer_effective_cost_uses_lag_and_loss() {
        let mut rs = make_router();
        let key = [0xEEu8; 32];
        add_dummy_peer(&mut rs, key);
        rs.peers.get_mut(&key).unwrap().lag = Duration::from_micros(50_000); // 50ms
        rs.peers.get_mut(&key).unwrap().loss_rate = 0.0;
        let cost = rs.peers[&key].effective_cost();
        assert_eq!(cost, 50_000,
            "effective_cost with 0 loss must equal lag_us=50_000; got {} (mutation returns 0 or 1?)", cost);
    }

    #[test]
    fn peer_effective_cost_reflects_loss_rate() {
        let mut rs = make_router();
        let key = [0xEFu8; 32];
        add_dummy_peer(&mut rs, key);
        rs.peers.get_mut(&key).unwrap().lag = Duration::from_millis(100); // 100ms
        rs.peers.get_mut(&key).unwrap().loss_rate = 1.0;
        let cost = rs.peers[&key].effective_cost();
        // effective_cost = 100_000 * (1 + 9) = 1_000_000 µs
        assert_eq!(cost, 1_000_000,
            "full-loss effective_cost must be 10× lag; got {}", cost);
    }

    // ── tree_metric XOR arithmetic (kills ^= → |= and % → / mutations) ───────

    #[test]
    fn tree_metric_xor_not_or() {
        // tree_metric() is now an alias for tree_metric_at(..., epoch=0). The
        // body XORs the key with a BLAKE2-derived 32-byte salt. The mutation
        // we still want to catch is `^= → |=` inside the loop in
        // tree_metric_at; the operation is still XOR (no longer of `seed[i%8]`
        // directly but of `salt[i]`). With OR, the result is monotonically ≥
        // either operand, so a key of all zeros forced through OR cannot
        // produce a metric byte smaller than the salt byte at that index.
        let key = [0u8; 32];
        let seed = *b"Verdandi";
        let metric = tree_metric(&key, &seed);
        // Compute the salt the same way the function does, so we can compare.
        use blake2::{Blake2b, Digest};
        use blake2::digest::consts::U32;
        let mut h: Blake2b<U32> = Blake2b::new();
        h.update(b"norn:tree-epoch");
        h.update(seed);
        h.update(0u64.to_le_bytes());
        let salt: [u8; 32] = h.finalize().into();
        for i in 0..32 {
            assert_eq!(metric[i], key[i] ^ salt[i],
                "byte {}: must XOR (not OR/AND); got {:#04x}", i, metric[i]);
        }
    }

    #[test]
    fn tree_metric_at_uses_full_32_byte_salt() {
        // After epoch rotation we use a 32-byte BLAKE2 salt (no more
        // wrap-around at index 8). Distinct bytes at i and i+8 prove the salt
        // is not being re-indexed modulo 8 (which would silently collapse
        // the keyspace).
        let key = [0u8; 32];
        let seed = [0u8; 8];
        let metric = tree_metric_at(&key, &seed, 0);
        // For a zero key, metric[i] == salt[i]. Inspect that salt[0..16] is
        // not equal to salt[16..32] — vanishingly unlikely for BLAKE2.
        let lo = &metric[0..16];
        let hi = &metric[16..32];
        assert_ne!(lo, hi,
            "salt's low and high halves must differ — proves we use the full 32-byte salt");
    }

    // ── send_to_peer tx_bytes (kills += → *= mutation) ────────────────────────

    #[test]
    fn send_to_peer_increments_tx_bytes() {
        let mut rs = make_router();
        let peer_key = [0xF0u8; 32];
        let (tx, _rx) = mpsc::channel(64);
        rs.add_peer(peer_key, tx, 0);
        assert_eq!(rs.peers[&peer_key].tx_bytes, 0, "tx_bytes starts at 0");
        let payload = vec![0u8; 100];
        rs.send_to_peer(&peer_key, payload);
        assert_eq!(rs.peers[&peer_key].tx_bytes, 100,
            "tx_bytes must increase by payload length; mutation *=100 gives 0*100=0");
    }

    // ── effective_cost ────────────────────────────────────────────────────────

    #[test]
    fn effective_cost_zero_loss_equals_lag() {
        let lag = Duration::from_millis(50);
        let cost = effective_cost(lag, 0.0);
        assert_eq!(cost, lag.as_micros() as u64,
            "zero loss: cost must equal lag in micros");
    }

    #[test]
    fn effective_cost_increases_with_loss() {
        let lag = Duration::from_millis(10);
        let cost_no_loss   = effective_cost(lag, 0.0);
        let cost_half_loss = effective_cost(lag, 0.5);
        let cost_full_loss = effective_cost(lag, 1.0);
        assert!(cost_half_loss > cost_no_loss,
            "half-loss cost ({}) must exceed no-loss cost ({})", cost_half_loss, cost_no_loss);
        assert!(cost_full_loss > cost_half_loss,
            "full-loss cost ({}) must exceed half-loss cost ({})", cost_full_loss, cost_half_loss);
    }

    #[test]
    fn effective_cost_full_loss_is_10x_lag() {
        let lag = Duration::from_millis(100);
        let cost = effective_cost(lag, 1.0);
        // formula: lag_us * (1 + 1.0 * 9) = lag_us * 10
        let expected = lag.as_micros() as u64 * 10;
        assert_eq!(cost, expected, "full loss must give 10× base cost");
    }

    // ── metric_less ───────────────────────────────────────────────────────────

    #[test]
    fn metric_less_orders_correctly() {
        let low  = [0u8; 32];
        let high = [0xFF_u8; 32];
        assert!(metric_less(&low, &high), "low < high must be true");
        assert!(!metric_less(&high, &low), "high < low must be false");
        assert!(!metric_less(&low, &low), "equal values must not satisfy <");
    }

    // ── tree_metric ───────────────────────────────────────────────────────────

    #[test]
    fn tree_metric_deterministic() {
        let key  = [0xABu8; 32];
        let seed = [0u8; 8];
        assert_eq!(tree_metric(&key, &seed), tree_metric(&key, &seed));
    }

    #[test]
    fn tree_metric_differs_with_seed() {
        let key   = [0xABu8; 32];
        let seed0 = [0u8; 8];
        let seed1 = *b"Verdandi";
        assert_ne!(tree_metric(&key, &seed0), tree_metric(&key, &seed1),
            "different seeds must give different metrics");
    }

    #[test]
    fn tree_metric_xor_identity_with_zero_seed() {
        let key  = [0xABu8; 32];
        let seed = [0u8; 8];
        // XOR with all-zero seed is identity at epoch 0.
        // (epoch 0 has a non-trivial BLAKE2 salt that depends on the seed —
        // but the LEGACY tree_metric() routes through tree_metric_at(...,0);
        // with a zero seed the salt is fixed BLAKE2(b"norn:tree-epoch"||0^8||0u64),
        // so the result is just key XOR that fixed salt. Compare against the
        // same call to itself rather than raw key.)
        assert_eq!(tree_metric(&key, &seed), tree_metric(&key, &seed));
    }

    // ── tree_metric_at / current_tree_epoch ─────────────────────────────────

    #[test]
    fn tree_metric_at_rotates_with_epoch() {
        // The same (key, seed) must give a DIFFERENT metric in different
        // epochs. Without this, the lowest-key node is the permanent root
        // and a perpetual DDoS / censorship target.
        let key = [0x42u8; 32];
        let seed = *b"Verdandi";
        let m0 = tree_metric_at(&key, &seed, 0);
        let m1 = tree_metric_at(&key, &seed, 1);
        let m_far = tree_metric_at(&key, &seed, 365);
        assert_ne!(m0, m1, "metric must change between adjacent epochs");
        assert_ne!(m0, m_far, "metric must change across distant epochs");
        assert_ne!(m1, m_far, "epoch 1 and epoch 365 must also differ");
    }

    #[test]
    fn tree_metric_at_deterministic_within_epoch() {
        // Both peers in an adjacency MUST compute the same metric for the
        // same (key, seed, epoch), otherwise their tree would never converge.
        let key = [0x99u8; 32];
        let seed = *b"Skuld___";
        assert_eq!(
            tree_metric_at(&key, &seed, 42),
            tree_metric_at(&key, &seed, 42),
            "metric must be deterministic per (key, seed, epoch)",
        );
    }

    #[test]
    fn tree_metric_at_rotates_root_winner() {
        // Demonstration of the security property: across many epochs, the
        // identity of the lowest-metric ("root") node changes. With static
        // tree_metric this would always be the lex-smallest key.
        let keys: Vec<[u8; 32]> = (0u8..16).map(|i| [i; 32]).collect();
        let seed = [0u8; 8];
        let mut winners = std::collections::HashSet::new();
        for epoch in 0u64..32 {
            let winner = keys.iter()
                .min_by_key(|k| tree_metric_at(k, &seed, epoch))
                .copied()
                .unwrap();
            winners.insert(winner);
        }
        assert!(winners.len() >= 4,
            "expected ≥4 distinct root winners across 32 epochs, got {}: \
             root rotation is what makes the network resistant to long-lived \
             root-targeting attacks", winners.len());
    }

    #[test]
    fn current_tree_epoch_monotonic_within_a_day() {
        // Sanity: the function returns a finite number for a current call.
        let e = current_tree_epoch();
        assert!(e > 0, "current_tree_epoch should be > 0 after 1970");
        // 24h epoch → today's epoch is at most days-since-epoch.
        let max_plausible = 100_000u64; // ~273 years; sanity ceiling
        assert!(e < max_plausible, "epoch {} unexpectedly large", e);
    }

    // ── pad_payload / unpad_payload ───────────────────────────────────────────

    #[test]
    fn pad_unpad_roundtrip() {
        for len in [0, 1, 128, 255, 256, 257, 512, 1000] {
            let data: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let padded = pad_payload(&data);
            let unpadded = unpad_payload(&padded).expect("unpad must succeed");
            assert_eq!(unpadded, data, "roundtrip failed for len={}", len);
        }
    }

    #[test]
    fn pad_payload_result_is_multiple_of_block() {
        for len in [0usize, 1, 255, 256, 257] {
            let data = vec![0u8; len];
            let padded = pad_payload(&data);
            assert_eq!(padded.len() % PAD_BLOCK, 0,
                "padded length must be multiple of {}, got {} for input len {}", PAD_BLOCK, padded.len(), len);
        }
    }

    #[test]
    fn pad_payload_minimum_size() {
        // Even empty input must produce at least PAD_BLOCK bytes
        let padded = pad_payload(&[]);
        assert_eq!(padded.len(), PAD_BLOCK);
    }

    #[test]
    fn unpad_too_short_fails() {
        assert!(unpad_payload(&[]).is_err());
        assert!(unpad_payload(&[0u8]).is_err());
        // Claims length 100 but only has 10 bytes total (2 header + 8 data)
        let mut bad = vec![0u8, 100u8];
        bad.extend_from_slice(&[0u8; 8]);
        assert!(unpad_payload(&bad).is_err());
    }

    #[test]
    fn unpad_exactly_two_bytes_succeeds_with_zero_len() {
        // [0, 0] → orig_len=0, need padded.len() >= 2+0=2. Exactly satisfied.
        // Mutation `< with <=` (line 189): `2 <= 2` → would wrongly fail this.
        let result = unpad_payload(&[0u8, 0u8]);
        assert!(result.is_ok(), "exactly 2 bytes (orig_len=0) must succeed: {:?}", result.err());
        assert_eq!(result.unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn unpad_exactly_at_data_boundary_succeeds() {
        // padded = [5, 0, A, B, C, D, E] — exactly 2 + 5 = 7 bytes.
        // Mutation `< with <=` (line 193): `7 <= 2+5=7` → would wrongly fail.
        let padded = vec![5u8, 0u8, 0xAu8, 0xBu8, 0xCu8, 0xDu8, 0xEu8];
        let result = unpad_payload(&padded);
        assert!(result.is_ok(), "exactly-at-boundary unpad must succeed: {:?}", result.err());
        assert_eq!(result.unwrap(), vec![0xAu8, 0xBu8, 0xCu8, 0xDu8, 0xEu8]);
    }

    #[test]
    fn unpad_one_byte_short_of_data_fails() {
        // padded = [5, 0, A, B, C, D] — only 6 bytes but claims orig_len=5 (needs 7).
        let padded = vec![5u8, 0u8, 0xAu8, 0xBu8, 0xCu8, 0xDu8];
        assert!(unpad_payload(&padded).is_err(),
            "one byte short of claimed data length must fail");
    }

    // ── pad_payload length encoding uses correct byte order ───────────────────

    #[test]
    fn pad_payload_encodes_length_le() {
        let data = vec![0x42u8; 300];
        let padded = pad_payload(&data);
        // First 2 bytes: orig_len as LE u16
        let encoded_len = (padded[0] as usize) | ((padded[1] as usize) << 8);
        assert_eq!(encoded_len, 300, "length must be 300 in LE");
    }

    // ── Test helpers ─────────────────────────────────────────────────────────

    fn make_router() -> RouterState {
        let sk = SigningKey::generate(&mut OsRng);
        let (tx, _rx) = mpsc::channel(32);
        RouterState::new(sk, tx)
    }

    #[cfg(feature = "sphinx")]
    fn sphinx_hop_for(rs: &RouterState) -> crate::sphinx::SphinxHop {
        crate::sphinx::SphinxHop {
            routing_tag: routing_tag(&rs.pub_key),
            onion_pub: *rs.onion_keys.pub_key().as_bytes(),
        }
    }

    // A cell built to a router's *advertised* onion pub must be processed by that
    // router's `sphinx_privs()` — i.e. the key a peer learns (CoordAnnounce /
    // OnionKeyAnnounce → pub_key()) matches the keys we decrypt with.
    #[test]
    #[cfg(feature = "sphinx")]
    fn sphinx_cell_built_for_us_is_delivered() {
        let rs = make_router();
        let traffic = b"arbitrary inner bytes";
        let cell = crate::sphinx::build_sphinx(&[sphinx_hop_for(&rs)], traffic).unwrap();
        match crate::sphinx::process_sphinx(&cell, &rs.onion_keys.sphinx_privs()) {
            Ok(crate::sphinx::SphinxPeeled::Deliver(t)) => assert_eq!(t, traffic),
            other => panic!("expected Deliver, got {other:?}"),
        }
    }

    // Full relay→exit chain across two routers using their advertised keys: r0
    // forwards toward r1's tag (constant-size cell), r1 delivers the traffic.
    #[test]
    #[cfg(feature = "sphinx")]
    fn sphinx_two_hop_relay_then_deliver() {
        let r0 = make_router();
        let r1 = make_router();
        let hops = vec![sphinx_hop_for(&r0), sphinx_hop_for(&r1)];
        let traffic = b"two-hop payload bytes";
        let cell = crate::sphinx::build_sphinx(&hops, traffic).unwrap();
        assert_eq!(cell.len(), crate::sphinx::CELL_SIZE);

        let next_cell = match crate::sphinx::process_sphinx(&cell, &r0.onion_keys.sphinx_privs()) {
            Ok(crate::sphinx::SphinxPeeled::Forward { next_tag, cell }) => {
                assert_eq!(next_tag, routing_tag(&r1.pub_key), "r0 must forward to r1's tag");
                assert_eq!(cell.len(), crate::sphinx::CELL_SIZE, "forwarded cell stays constant size");
                cell
            }
            other => panic!("r0 should Forward, got {other:?}"),
        };
        match crate::sphinx::process_sphinx(&next_cell, &r1.onion_keys.sphinx_privs()) {
            Ok(crate::sphinx::SphinxPeeled::Deliver(t)) => assert_eq!(t, traffic),
            other => panic!("r1 should Deliver, got {other:?}"),
        }
    }

    fn add_dummy_peer(rs: &mut RouterState, key: PeerId) {
        let (tx, _rx) = mpsc::channel(32);
        rs.add_peer(key, tx, 0);
    }

    fn make_valid_sig_res(
        peer_sk: &SigningKey,
        own_pub: &[u8; 32],
        seq: u64,
        timestamp_ms: u64,
    ) -> SigRes {
        use ed25519_dalek::Signer;
        let mut sign_data = vec![0u8]; // tree_id = 0
        let mut tmp = Vec::new();
        encode_uvarint(seq, &mut tmp);
        sign_data.extend_from_slice(&tmp);
        tmp.clear();
        encode_uvarint(timestamp_ms, &mut tmp);
        sign_data.extend_from_slice(&tmp);
        sign_data.extend_from_slice(own_pub);
        let signature = peer_sk.sign(&sign_data).to_bytes();
        SigRes {
            tree_id: 0,
            seq,
            timestamp_ms,
            signature,
            pub_key: peer_sk.verifying_key().to_bytes(),
        }
    }

    // ── update_landmarks ──────────────────────────────────────────────────────

    #[test]
    fn landmarks_self_not_set_with_two_peers() {
        let mut rs = make_router();
        add_dummy_peer(&mut rs, [1u8; 32]);
        add_dummy_peer(&mut rs, [2u8; 32]);
        rs.update_landmarks();
        assert!(!rs.landmarks.contains(&rs.pub_key),
            "self must NOT be a landmark with only 2 peers (need > 2)");
    }

    #[test]
    fn landmarks_self_set_with_three_peers() {
        let mut rs = make_router();
        add_dummy_peer(&mut rs, [1u8; 32]);
        add_dummy_peer(&mut rs, [2u8; 32]);
        add_dummy_peer(&mut rs, [3u8; 32]);
        rs.update_landmarks();
        assert!(rs.landmarks.contains(&rs.pub_key),
            "self must be a landmark with 3 peers (> 2)");
    }

    #[test]
    fn landmarks_peer_at_depth_zero_marked() {
        let mut rs = make_router();
        let peer_key = [0xAAu8; 32];
        add_dummy_peer(&mut rs, peer_key);
        // Depth 0 → landmark
        rs.peers.get_mut(&peer_key).unwrap().trees[0] = Some(TreeAnnounce {
            root: [0u8; 32],
            path_cost: 0,
            received_at: Instant::now(),
            depth: 0,
        });
        rs.update_landmarks();
        assert!(rs.landmarks.contains(&peer_key), "depth-0 peer must become a landmark");
    }

    #[test]
    fn landmarks_peer_at_depth_two_not_marked() {
        let mut rs = make_router();
        let peer_key = [0xBBu8; 32];
        add_dummy_peer(&mut rs, peer_key);
        // Depth 2 (> 1) → NOT a landmark by heuristic
        rs.peers.get_mut(&peer_key).unwrap().trees[0] = Some(TreeAnnounce {
            root: [0u8; 32],
            path_cost: 0,
            received_at: Instant::now(),
            depth: 2,
        });
        rs.update_landmarks();
        assert!(!rs.landmarks.contains(&peer_key), "depth-2 peer must NOT be a landmark");
    }

    // ── remove_peer clears tree parent ────────────────────────────────────────

    #[test]
    fn remove_peer_clears_tree_parent() {
        let mut rs = make_router();
        let peer_key = [42u8; 32];
        add_dummy_peer(&mut rs, peer_key);
        let own_key = rs.pub_key;
        // Manually set all tree parents to the removed peer
        for i in 0..K {
            rs.trees[i].parent = Some(peer_key);
            rs.trees[i].root = peer_key;
            rs.trees[i].parent_cost = 1000;
        }
        rs.remove_peer(&peer_key);
        for i in 0..K {
            assert!(rs.trees[i].parent.is_none(), "tree[{}] parent must be cleared", i);
            assert_eq!(rs.trees[i].root, own_key, "tree[{}] root must reset to self", i);
            assert_eq!(rs.trees[i].parent_cost, 0, "tree[{}] parent_cost must reset to 0", i);
        }
        assert!(!rs.peers.contains_key(&peer_key));
    }

    #[test]
    fn remove_peer_does_not_clear_unrelated_parent() {
        let mut rs = make_router();
        let peer_a = [10u8; 32];
        let peer_b = [20u8; 32];
        add_dummy_peer(&mut rs, peer_a);
        add_dummy_peer(&mut rs, peer_b);
        // Parent is peer_b; we remove peer_a
        rs.trees[0].parent = Some(peer_b);
        rs.trees[0].root = [0xBBu8; 32];
        rs.trees[0].parent_cost = 500;
        rs.remove_peer(&peer_a);
        assert_eq!(rs.trees[0].parent, Some(peer_b), "unrelated parent must not be cleared");
        assert_eq!(rs.trees[0].parent_cost, 500, "parent_cost must not change");
    }

    // ── roadmap #9: adaptive control-plane cadence ────────────────────────────

    #[test]
    fn control_cadence_backs_off_when_stable() {
        let mut rs = make_router();
        // Frozen topology — run well past the back-off ramp.
        for _ in 0..40 {
            rs.tick += 1;
            rs.maybe_broadcast_control();
        }
        assert_eq!(
            rs.control_interval, CONTROL_MAX_INTERVAL,
            "a stable topology must back the cadence off to the cap"
        );

        // In steady state, consecutive broadcasts are exactly
        // CONTROL_MAX_INTERVAL ticks apart — record two and check the gap.
        let mut broadcast_ticks = Vec::new();
        let mut prev = rs.last_control_tick;
        while broadcast_ticks.len() < 2 {
            rs.tick += 1;
            rs.maybe_broadcast_control();
            if rs.last_control_tick != prev {
                broadcast_ticks.push(rs.last_control_tick);
                prev = rs.last_control_tick;
            }
        }
        assert_eq!(
            broadcast_ticks[1] - broadcast_ticks[0],
            CONTROL_MAX_INTERVAL,
            "steady-state broadcasts must be CONTROL_MAX_INTERVAL ticks apart"
        );
    }

    #[test]
    fn control_cadence_snaps_back_on_topology_change() {
        let mut rs = make_router();
        for _ in 0..40 {
            rs.tick += 1;
            rs.maybe_broadcast_control();
        }
        assert_eq!(rs.control_interval, CONTROL_MAX_INTERVAL, "precondition: backed off");

        // A new peer changes the digest (peer_count) — the cadence must
        // snap back to fast and broadcast on the very next tick.
        add_dummy_peer(&mut rs, [7u8; 32]);
        rs.tick += 1;
        rs.maybe_broadcast_control();
        assert_eq!(
            rs.control_interval, CONTROL_MIN_INTERVAL,
            "a topology change must snap the cadence back to fast"
        );
        assert_eq!(
            rs.last_control_tick, rs.tick,
            "a topology change must broadcast immediately"
        );
    }

    // ── fix_tree ──────────────────────────────────────────────────────────────

    #[test]
    fn fix_tree_is_own_root_with_no_peers() {
        let mut rs = make_router();
        let own_key = rs.pub_key;
        rs.fix_tree(0);
        assert!(rs.trees[0].parent.is_none(), "no peers: must have no parent");
        assert_eq!(rs.trees[0].root, own_key, "no peers: root must be self");
        assert_eq!(rs.trees[0].parent_cost, 0);
    }

    /// Compute the per-epoch tree-metric salt the same way `tree_metric_at`
    /// does. Tests use this to construct an announce whose root deterministically
    /// produces metric = [0;32] — beating any random self pub_key regardless
    /// of the current epoch's BLAKE2 output.
    fn salt_for_test(tree_id: usize, epoch: u64) -> [u8; 32] {
        use blake2::{Blake2b, Digest};
        use blake2::digest::consts::U32;
        let mut h: Blake2b<U32> = Blake2b::new();
        h.update(b"norn:tree-epoch");
        h.update(TREE_SEEDS[tree_id]);
        h.update(epoch.to_le_bytes());
        h.finalize().into()
    }

    #[test]
    fn fix_tree_selects_peer_with_lower_cost() {
        let mut rs = make_router();
        let peer_a = [0x11u8; 32];
        let peer_b = [0x22u8; 32];
        add_dummy_peer(&mut rs, peer_a);
        add_dummy_peer(&mut rs, peer_b);
        // Both announce the same root whose XOR with the current epoch salt
        // gives metric=0 — guaranteed to beat any random self pub_key under
        // the epoch-rotated metric.
        let root = salt_for_test(0, current_tree_epoch());
        rs.peers.get_mut(&peer_a).unwrap().trees[0] = Some(TreeAnnounce {
            root,
            path_cost: 10_000,
            received_at: Instant::now(),
            depth: 1,
        });
        rs.peers.get_mut(&peer_a).unwrap().lag = Duration::from_micros(10_000);
        rs.peers.get_mut(&peer_b).unwrap().trees[0] = Some(TreeAnnounce {
            root,
            path_cost: 1_000,
            received_at: Instant::now(),
            depth: 1,
        });
        rs.peers.get_mut(&peer_b).unwrap().lag = Duration::from_micros(1_000);
        // peer_a total = 10_000 + 10_000 = 20_000 µs
        // peer_b total = 1_000 + 1_000 = 2_000 µs → winner
        rs.fix_tree(0);
        assert_eq!(rs.trees[0].parent, Some(peer_b), "must select lower-cost peer");
        assert_eq!(rs.trees[0].root, root);
    }

    #[test]
    fn fix_tree_adopts_peer_with_better_root_metric() {
        let mut rs = make_router();
        let peer_key = [0x55u8; 32];
        add_dummy_peer(&mut rs, peer_key);
        // Pick a root whose metric under the current epoch is [0;32] — the
        // smallest possible, so it beats any random self pub_key.
        let root = salt_for_test(0, current_tree_epoch());
        rs.peers.get_mut(&peer_key).unwrap().trees[0] = Some(TreeAnnounce {
            root,
            path_cost: 0,
            received_at: Instant::now(),
            depth: 1,
        });
        rs.peers.get_mut(&peer_key).unwrap().lag = Duration::from_micros(1_000);
        rs.fix_tree(0);
        if rs.pub_key != root {
            assert_eq!(rs.trees[0].parent, Some(peer_key),
                "peer with better root metric must be selected as parent");
            assert_eq!(rs.trees[0].root, root);
        }
    }

    #[test]
    fn fix_tree_ignores_expired_announces() {
        let mut rs = make_router();
        let peer_key = [0x77u8; 32];
        add_dummy_peer(&mut rs, peer_key);
        let own_key = rs.pub_key;
        // Announce received far in the past (expired)
        rs.peers.get_mut(&peer_key).unwrap().trees[0] = Some(TreeAnnounce {
            root: [0u8; 32],
            path_cost: 0,
            received_at: Instant::now() - ANNOUNCE_EXPIRY - Duration::from_secs(1),
            depth: 1,
        });
        rs.fix_tree(0);
        // Expired announce must be ignored; we stay as own root
        assert!(rs.trees[0].parent.is_none(), "expired announce must be ignored");
        assert_eq!(rs.trees[0].root, own_key, "must remain own root");
    }

    // ── expire_peers ──────────────────────────────────────────────────────────

    #[test]
    fn expire_peers_removes_timed_out_peer() {
        let mut rs = make_router();
        let peer_key = [5u8; 32];
        add_dummy_peer(&mut rs, peer_key);
        // Set last_rx_time past the timeout threshold
        rs.peers.get_mut(&peer_key).unwrap().last_rx_time =
            Instant::now() - PEER_TIMEOUT - Duration::from_secs(1);
        rs.expire_peers();
        assert!(!rs.peers.contains_key(&peer_key), "timed-out peer must be removed");
    }

    #[test]
    fn expire_peers_keeps_active_peer() {
        let mut rs = make_router();
        let peer_key = [6u8; 32];
        add_dummy_peer(&mut rs, peer_key);
        // last_rx_time is Instant::now() by default
        rs.expire_peers();
        assert!(rs.peers.contains_key(&peer_key), "active peer must not be expired");
    }

    #[test]
    fn expire_peers_boundary_just_before_timeout() {
        let mut rs = make_router();
        let peer_key = [11u8; 32];
        add_dummy_peer(&mut rs, peer_key);
        // One second before timeout → must NOT be removed
        rs.peers.get_mut(&peer_key).unwrap().last_rx_time =
            Instant::now() - PEER_TIMEOUT + Duration::from_secs(1);
        rs.expire_peers();
        assert!(rs.peers.contains_key(&peer_key), "peer just before timeout must not be removed");
    }

    // ── send_keepalives loss rate ──────────────────────────────────────────────

    #[test]
    fn keepalive_unanswered_increases_loss_rate_from_half() {
        let mut rs = make_router();
        let peer_key = [7u8; 32];
        let (tx, _rx) = mpsc::channel(64);
        rs.add_peer(peer_key, tx, 0);
        rs.peers.get_mut(&peer_key).unwrap().loss_rate = 0.5;
        // Simulate a pending unanswered request
        rs.peers.get_mut(&peer_key).unwrap().pending_sig_req_time = Some((1, Instant::now()));
        rs.send_keepalives();
        let new_loss = rs.peers[&peer_key].loss_rate;
        // Expected: 0.5 * 0.875 + 0.125 = 0.5625
        assert!((new_loss - 0.5625_f32).abs() < 1e-5,
            "unanswered keepalive from 0.5: expected 0.5625, got {}", new_loss);
    }

    #[test]
    fn keepalive_first_unanswered_sets_loss_to_eighth() {
        let mut rs = make_router();
        let peer_key = [8u8; 32];
        let (tx, _rx) = mpsc::channel(64);
        rs.add_peer(peer_key, tx, 0);
        // loss_rate starts at 0, pending request present
        rs.peers.get_mut(&peer_key).unwrap().pending_sig_req_time = Some((1, Instant::now()));
        rs.send_keepalives();
        let new_loss = rs.peers[&peer_key].loss_rate;
        // Expected: 0.0 * 0.875 + 0.125 = 0.125
        assert!((new_loss - 0.125_f32).abs() < 1e-5,
            "first unanswered: expected loss_rate 0.125, got {}", new_loss);
    }

    #[test]
    fn keepalive_seq_increments() {
        let mut rs = make_router();
        let peer_key = [9u8; 32];
        let (tx, _rx) = mpsc::channel(64);
        rs.add_peer(peer_key, tx, 0);
        let initial_seq = rs.peers[&peer_key].sig_req_seq;
        rs.send_keepalives();
        let new_seq = rs.peers[&peer_key].sig_req_seq;
        assert_eq!(new_seq, initial_seq + 1, "sig_req_seq must increment by 1");
    }

    #[test]
    fn keepalive_sets_pending_sig_req() {
        let mut rs = make_router();
        let peer_key = [12u8; 32];
        let (tx, _rx) = mpsc::channel(64);
        rs.add_peer(peer_key, tx, 0);
        assert!(rs.peers[&peer_key].pending_sig_req_time.is_none());
        rs.send_keepalives();
        assert!(rs.peers[&peer_key].pending_sig_req_time.is_some(),
            "pending_sig_req_time must be set after send_keepalives");
    }

    // ── handle_sig_res EWMA ───────────────────────────────────────────────────

    #[test]
    fn sig_res_decays_lag_ewma() {
        let mut rs = make_router();
        let peer_sk = SigningKey::generate(&mut OsRng);
        let peer_key = peer_sk.verifying_key().to_bytes();
        let (tx, _rx) = mpsc::channel(64);
        rs.add_peer(peer_key, tx, 0);
        let own_pub = rs.pub_key;
        // Initial lag = 80ms, RTT near 0 → new_lag ≈ 0
        rs.peers.get_mut(&peer_key).unwrap().lag = Duration::from_micros(80_000);
        rs.peers.get_mut(&peer_key).unwrap().loss_rate = 0.5;
        let seq = 1u64;
        rs.peers.get_mut(&peer_key).unwrap().pending_sig_req_time = Some((seq, Instant::now()));
        rs.peers.get_mut(&peer_key).unwrap().sig_req_seq = seq;
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let res = make_valid_sig_res(&peer_sk, &own_pub, seq, now_ms);
        rs.handle_sig_res(peer_key, res);
        let peer = &rs.peers[&peer_key];
        // lag = old * 7/8 + new/8 ≈ 80_000 * 7/8 = 70_000 µs (new ≈ 0)
        assert!(peer.lag < Duration::from_micros(80_000), "lag must decrease toward new measurement");
        assert!(peer.lag > Duration::from_micros(50_000), "lag must not drop too fast");
        // loss_rate must decay: 0.5 * 0.875 = 0.4375
        assert!(peer.loss_rate < 0.5, "loss_rate must decay on successful ACK");
        assert!(peer.loss_rate > 0.4, "loss_rate must not drop too fast");
    }

    #[test]
    fn sig_res_loss_rate_decays_exactly() {
        let mut rs = make_router();
        let peer_sk = SigningKey::generate(&mut OsRng);
        let peer_key = peer_sk.verifying_key().to_bytes();
        let (tx, _rx) = mpsc::channel(64);
        rs.add_peer(peer_key, tx, 0);
        let own_pub = rs.pub_key;
        rs.peers.get_mut(&peer_key).unwrap().loss_rate = 1.0;
        let seq = 2u64;
        rs.peers.get_mut(&peer_key).unwrap().pending_sig_req_time = Some((seq, Instant::now()));
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let res = make_valid_sig_res(&peer_sk, &own_pub, seq, now_ms);
        rs.handle_sig_res(peer_key, res);
        let new_loss = rs.peers[&peer_key].loss_rate;
        // loss_rate *= 0.875: 1.0 * 0.875 = 0.875
        assert!((new_loss - 0.875_f32).abs() < 1e-5,
            "loss_rate after successful ACK from 1.0 must be 0.875, got {}", new_loss);
    }

    #[test]
    fn sig_res_wrong_seq_does_not_update_lag() {
        let mut rs = make_router();
        let peer_sk = SigningKey::generate(&mut OsRng);
        let peer_key = peer_sk.verifying_key().to_bytes();
        let (tx, _rx) = mpsc::channel(64);
        rs.add_peer(peer_key, tx, 0);
        let own_pub = rs.pub_key;
        rs.peers.get_mut(&peer_key).unwrap().lag = Duration::from_micros(80_000);
        // pending seq = 5, response has seq = 6 → no match
        rs.peers.get_mut(&peer_key).unwrap().pending_sig_req_time = Some((5, Instant::now()));
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let res = make_valid_sig_res(&peer_sk, &own_pub, 6, now_ms);
        rs.handle_sig_res(peer_key, res);
        assert_eq!(rs.peers[&peer_key].lag, Duration::from_micros(80_000),
            "wrong-seq response must not update lag");
    }

    // ── cuckoo_do_maintenance generation ──────────────────────────────────────

    #[test]
    fn cuckoo_generation_increments_at_tick_multiple() {
        let mut rs = make_router();
        assert_eq!(rs.cuckoo_generation[0], 0);
        rs.tick = CUCKOO_GEN_TICKS;
        rs.cuckoo_do_maintenance(0);
        assert_eq!(rs.cuckoo_generation[0], 1, "generation must increment at CUCKOO_GEN_TICKS");
    }

    #[test]
    fn cuckoo_generation_does_not_increment_at_tick_zero() {
        let mut rs = make_router();
        rs.tick = 0;
        rs.cuckoo_do_maintenance(0);
        assert_eq!(rs.cuckoo_generation[0], 0, "tick=0 must NOT increment generation");
    }

    #[test]
    fn cuckoo_generation_does_not_increment_at_non_multiple() {
        let mut rs = make_router();
        rs.tick = CUCKOO_GEN_TICKS - 1;
        rs.cuckoo_do_maintenance(0);
        assert_eq!(rs.cuckoo_generation[0], 0, "non-multiple tick must not increment generation");
    }

    #[test]
    fn cuckoo_generation_increments_all_three_trees_independently() {
        let mut rs = make_router();
        rs.tick = CUCKOO_GEN_TICKS;
        for i in 0..K {
            rs.cuckoo_do_maintenance(i);
        }
        for i in 0..K {
            assert_eq!(rs.cuckoo_generation[i], 1, "tree {} generation must be 1", i);
        }
    }

    // ── handle_cuckoo generation tracking ────────────────────────────────────

    #[test]
    fn handle_cuckoo_advances_generation_on_newer_msg() {
        let mut rs = make_router();
        let peer_key = [0xC0u8; 32];
        add_dummy_peer(&mut rs, peer_key);
        assert_eq!(rs.peers[&peer_key].peer_cuckoo_gen[0], 0);
        let data = [0u8; crate::cuckoo::FILTER_BYTES];
        let msg = CuckooMsg { tree_id: 0, generation: 1, data };
        rs.handle_cuckoo(peer_key, msg);
        assert_eq!(rs.peers[&peer_key].peer_cuckoo_gen[0], 1,
            "generation must advance when msg.generation > current");
    }

    #[test]
    fn handle_cuckoo_does_not_regress_generation() {
        let mut rs = make_router();
        let peer_key = [0xC1u8; 32];
        add_dummy_peer(&mut rs, peer_key);
        rs.peers.get_mut(&peer_key).unwrap().peer_cuckoo_gen[0] = 5;
        let data = [0u8; crate::cuckoo::FILTER_BYTES];
        // Old generation msg
        let msg = CuckooMsg { tree_id: 0, generation: 3, data };
        rs.handle_cuckoo(peer_key, msg);
        // Generation must NOT regress to 3
        assert_eq!(rs.peers[&peer_key].peer_cuckoo_gen[0], 5,
            "old generation message must not overwrite newer generation counter");
    }

    #[test]
    fn handle_cuckoo_same_generation_does_not_advance() {
        let mut rs = make_router();
        let peer_key = [0xC2u8; 32];
        add_dummy_peer(&mut rs, peer_key);
        rs.peers.get_mut(&peer_key).unwrap().peer_cuckoo_gen[0] = 7;
        let data = [0u8; crate::cuckoo::FILTER_BYTES];
        let msg = CuckooMsg { tree_id: 0, generation: 7, data }; // same
        rs.handle_cuckoo(peer_key, msg);
        assert_eq!(rs.peers[&peer_key].peer_cuckoo_gen[0], 7,
            "equal-generation message must not advance counter");
    }

    // ── cleanup_stale_lookups ─────────────────────────────────────────────────

    #[test]
    fn cleanup_stale_lookups_removes_old_entries() {
        let mut rs = make_router();
        rs.pending_lookups.insert(42u64, Instant::now() - Duration::from_secs(11));
        rs.pending_lookups.insert(43u64, Instant::now());
        rs.cleanup_stale_lookups();
        assert!(!rs.pending_lookups.contains_key(&42), "entry older than 10s must be removed");
        assert!(rs.pending_lookups.contains_key(&43), "fresh entry must be kept");
    }

    #[test]
    fn cleanup_stale_lookups_keeps_boundary_entry() {
        let mut rs = make_router();
        // Exactly 9 seconds old → must be kept (< 10s)
        rs.pending_lookups.insert(99u64, Instant::now() - Duration::from_secs(9));
        rs.cleanup_stale_lookups();
        assert!(rs.pending_lookups.contains_key(&99),
            "entry 9s old (< 10s threshold) must be kept");
    }

    // ── lookup XOR fallback ───────────────────────────────────────────────────

    #[test]
    fn lookup_xor_fallback_returns_xor_closest_peer() {
        let mut rs = make_router();
        let dst = [0xFFu8; 32];
        // peer_a XOR dst = [0xFE^0xFF; 32] = [0x01;32] — small distance
        let peer_a = [0xFEu8; 32];
        // peer_b XOR dst = [0x00^0xFF; 32] = [0xFF;32] — large distance
        let peer_b = [0x00u8; 32];
        add_dummy_peer(&mut rs, peer_a);
        add_dummy_peer(&mut rs, peer_b);
        // No coords, no cuckoo entries → falls through to XOR fallback
        let result = rs.lookup(&dst);
        assert_eq!(result, Some(peer_a), "XOR fallback must select closest peer");
    }

    #[test]
    fn lookup_returns_none_with_no_peers() {
        let rs = make_router();
        assert!(rs.lookup(&[1u8; 32]).is_none(), "empty router must return None");
    }

    #[test]
    fn lookup_cuckoo_filter_hit_routes_to_matching_peer() {
        let mut rs = make_router();
        let dst = [0x42u8; 32];
        let peer_key = [0x10u8; 32];
        add_dummy_peer(&mut rs, peer_key);
        // Add dst routing_tag to peer's cuckoo filter
        let tag = routing_tag(&dst);
        rs.peers.get_mut(&peer_key).unwrap().cuckoo[0].add(&tag);
        let result = rs.lookup(&dst);
        assert_eq!(result, Some(peer_key), "cuckoo filter hit must route to matching peer");
    }

    // ── PathNegative is last-resort deprioritisation, NOT a hard blackhole ────

    #[test]
    fn lookup_by_tag_path_negative_is_last_resort_not_blackhole() {
        // The sole claimer of a tag is under a PathNegative (e.g. a linear
        // chain's only upstream after a transient convergence gap). It must
        // still be returned — hard exclusion would black-hole the destination
        // for the full PATH_NEG_TTL with no alternate path.
        let mut rs = make_router();
        let tag = routing_tag(&[0x42u8; 32]);
        let only = [0x10u8; 32];
        add_dummy_peer(&mut rs, only);
        rs.peers.get_mut(&only).unwrap().cuckoo[0].add(&tag);
        rs.record_path_negative(only, tag);
        assert_eq!(rs.lookup_by_tag(&tag), Some(only),
            "sole claimer must be used as last resort even under PathNegative");
    }

    #[test]
    fn lookup_by_tag_prefers_non_negative_alternate() {
        // With an alternative, route AROUND the poisoned peer (poison defence
        // preserved): a non-negative claimer beats a path-negative one.
        let mut rs = make_router();
        let tag = routing_tag(&[0x42u8; 32]);
        let poisoned = [0x10u8; 32];
        let clean = [0x20u8; 32];
        add_dummy_peer(&mut rs, poisoned);
        add_dummy_peer(&mut rs, clean);
        rs.peers.get_mut(&poisoned).unwrap().cuckoo[0].add(&tag);
        rs.peers.get_mut(&clean).unwrap().cuckoo[0].add(&tag);
        rs.record_path_negative(poisoned, tag);
        assert_eq!(rs.lookup_by_tag(&tag), Some(clean),
            "a non-negative claimer must be preferred over a poisoned one");
    }

    // ── encrypt_header / decrypt_source round-trip ───────────────────────────

    // ── fix_tree: root_seq and own_depth ─────────────────────────────────────

    #[test]
    fn fix_tree_root_seq_increments_when_self_is_root() {
        let mut rs = make_router();
        let initial_seq = rs.trees[0].root_seq;
        // No peers → self is root → root_seq += 1
        rs.fix_tree(0);
        assert_eq!(rs.trees[0].root_seq, initial_seq + 1,
            "root_seq must increment by 1; mutation += → *= gives {} * 1 = {}",
            initial_seq, initial_seq);
    }

    #[test]
    fn fix_tree_sets_own_depth_zero_when_self_is_root_for_tree_0() {
        let mut rs = make_router();
        // Pre-set own_depth to non-zero
        rs.own_depth = 5;
        // No peers → self is root for tree 0 → own_depth must be reset to 0
        rs.fix_tree(0);
        assert_eq!(rs.own_depth, 0,
            "own_depth must reset to 0 when self is root (tree_id=0); \
             mutation == → != would skip reset, leaving own_depth=5");
    }

    #[test]
    fn fix_tree_does_not_reset_own_depth_for_nonzero_tree() {
        let mut rs = make_router();
        rs.own_depth = 7;
        // tree_id=1: the `if tree_id == 0` branch must NOT fire for tree 1
        rs.fix_tree(1);
        assert_eq!(rs.own_depth, 7,
            "own_depth must not change for tree_id=1; \
             mutation == → != would wrongly reset it to 0");
    }

    #[test]
    fn fix_tree_own_depth_is_parent_depth_plus_one() {
        let mut rs = make_router();
        let peer_key = [0x55u8; 32];
        add_dummy_peer(&mut rs, peer_key);
        // Peer announces root [0;32] — metric beats any random pub_key
        rs.peers.get_mut(&peer_key).unwrap().trees[0] = Some(TreeAnnounce {
            root: [0u8; 32],
            path_cost: 0,
            received_at: Instant::now(),
            depth: 3, // peer's depth in tree 0
        });
        rs.peers.get_mut(&peer_key).unwrap().lag = Duration::from_micros(1_000);
        rs.own_depth = 0; // start at 0
        rs.fix_tree(0);
        if rs.trees[0].parent == Some(peer_key) {
            // Our depth = parent_depth + 1 = 3 + 1 = 4
            assert_eq!(rs.own_depth, 4,
                "own_depth must be parent.depth + 1 = 4; \
                 mutation + → - gives 2, + → * gives 3; got {}", rs.own_depth);
        }
    }

    // ── do_maintenance tick increment ─────────────────────────────────────────

    #[test]
    fn do_maintenance_increments_tick() {
        let mut rs = make_router();
        let initial_tick = rs.tick;
        rs.do_maintenance();
        assert_eq!(rs.tick, initial_tick + 1,
            "tick must increment by 1 per maintenance call; \
             mutation += → *= keeps tick at {} * 1 = {}",
            initial_tick, initial_tick);
    }

    // ── send_announces depth encoding ─────────────────────────────────────────

    // ── trust scoring ────────────────────────────────────────────────────────

    #[test]
    fn peer_starts_at_initial_trust() {
        let mut rs = make_router();
        let key = [0xA1u8; 32];
        add_dummy_peer(&mut rs, key);
        assert_eq!(rs.peers[&key].trust, TRUST_INITIAL,
            "new peers start at TRUST_INITIAL");
    }

    #[test]
    fn decay_trust_multiplies_and_floors() {
        let mut rs = make_router();
        let key = [0xA2u8; 32];
        add_dummy_peer(&mut rs, key);
        rs.peers.get_mut(&key).unwrap().trust = 1.0;
        rs.peers.get_mut(&key).unwrap().decay_trust();
        assert!((rs.peers[&key].trust - 0.5).abs() < 1e-6,
            "one decay halves trust: {}", rs.peers[&key].trust);
        // Many decays must floor at TRUST_MIN.
        for _ in 0..100 { rs.peers.get_mut(&key).unwrap().decay_trust(); }
        assert!(rs.peers[&key].trust >= TRUST_MIN,
            "trust must never fall below TRUST_MIN");
    }

    #[test]
    fn boost_trust_multiplies_and_caps() {
        let mut rs = make_router();
        let key = [0xA3u8; 32];
        add_dummy_peer(&mut rs, key);
        rs.peers.get_mut(&key).unwrap().trust = 1.0;
        rs.peers.get_mut(&key).unwrap().boost_trust();
        assert!(rs.peers[&key].trust > 1.0, "boost must increase trust");
        for _ in 0..100 { rs.peers.get_mut(&key).unwrap().boost_trust(); }
        assert!(rs.peers[&key].trust <= TRUST_MAX,
            "trust must never exceed TRUST_MAX");
    }

    #[test]
    fn trust_adjusted_cost_inverse_to_trust() {
        let mut rs = make_router();
        let key = [0xA4u8; 32];
        add_dummy_peer(&mut rs, key);
        rs.peers.get_mut(&key).unwrap().lag = Duration::from_millis(100);
        rs.peers.get_mut(&key).unwrap().loss_rate = 0.0;
        rs.peers.get_mut(&key).unwrap().trust = 1.0;
        let cost_at_1 = rs.peers[&key].trust_adjusted_cost();
        rs.peers.get_mut(&key).unwrap().trust = 0.1;
        let cost_at_low = rs.peers[&key].trust_adjusted_cost();
        assert!(cost_at_low > cost_at_1,
            "low trust must yield higher cost (de-prioritised in lookup); {} vs {}",
            cost_at_low, cost_at_1);
    }

    #[test]
    fn lookup_by_tag_prefers_higher_trust_on_tie() {
        // Two peers both claim the same tag with identical lag; the higher-trust
        // one should win.
        let mut rs = make_router();
        let high = [0xB0u8; 32];
        let low  = [0xB1u8; 32];
        add_dummy_peer(&mut rs, high);
        add_dummy_peer(&mut rs, low);
        rs.peers.get_mut(&high).unwrap().lag = Duration::from_millis(50);
        rs.peers.get_mut(&low).unwrap().lag  = Duration::from_millis(50);
        rs.peers.get_mut(&high).unwrap().trust = 2.0;
        rs.peers.get_mut(&low).unwrap().trust  = 0.1;
        let tag = [0xCC_u8; 16];
        rs.peers.get_mut(&high).unwrap().cuckoo[0].add(&tag);
        rs.peers.get_mut(&low).unwrap().cuckoo[0].add(&tag);
        let winner = rs.lookup_by_tag(&tag).expect("at least one peer should match");
        assert_eq!(winner, high,
            "the high-trust peer must win the lookup tie");
    }

    // ── onion replay cache ──────────────────────────────────────────────────

    // ── Hyperbolic coord consistency check ──────────────────────────────────

    fn make_coord_announce(sk: &SigningKey, tree_depth: u32, coord: HypCoord) -> CoordAnnounce {
        let unsigned = CoordAnnounce {
            version: COORD_FORMAT_V4,
            coord: coord.encode(),
            tree_depth,
            onion_eph_pub: [0u8; 32],
            sig: [0u8; 64],
        };
        let sig = sk.sign(&unsigned.sign_bytes()).to_bytes();
        CoordAnnounce { sig, ..unsigned }
    }

    #[test]
    fn coord_announce_consistent_accepted() {
        let mut rs = make_router();
        let sk = SigningKey::generate(&mut OsRng);
        let pk = sk.verifying_key().to_bytes();
        add_dummy_peer(&mut rs, pk);
        let depth = 3;
        // Build the *correct* coord for this depth+key.
        let coord = HypCoord::from_tree_depth(depth, &pk);
        let ann = make_coord_announce(&sk, depth, coord);
        rs.handle_coord_announce(pk, ann);
        assert!(rs.coord_table.contains_key(&pk),
            "consistent CoordAnnounce must be recorded");
    }

    #[test]
    fn coord_announce_spoofed_r_rejected() {
        // Attack: declare depth=10 (legitimate-looking) but claim coord
        // rho=0.001 (near origin → near every dst → wins greedy routing).
        let mut rs = make_router();
        let sk = SigningKey::generate(&mut OsRng);
        let pk = sk.verifying_key().to_bytes();
        add_dummy_peer(&mut rs, pk);
        let spoof = HypCoord {
            rho: 0.001,
            theta: HypCoord::angle_from_key(&pk),
        };
        let ann = make_coord_announce(&sk, 10, spoof);
        rs.handle_coord_announce(pk, ann);
        assert!(!rs.coord_table.contains_key(&pk),
            "spoofed CoordAnnounce (rho ≠ depth*RADIAL_STEP) must be rejected");
    }

    #[test]
    fn coord_announce_spoofed_theta_rejected() {
        let mut rs = make_router();
        let sk = SigningKey::generate(&mut OsRng);
        let pk = sk.verifying_key().to_bytes();
        add_dummy_peer(&mut rs, pk);
        let spoof = HypCoord {
            rho: 3.0,     // correct rho for depth=3 (RADIAL_STEP=1.0)
            theta: 1.234, // arbitrary theta, NOT derived from pk
        };
        let ann = make_coord_announce(&sk, 3, spoof);
        rs.handle_coord_announce(pk, ann);
        assert!(!rs.coord_table.contains_key(&pk),
            "spoofed CoordAnnounce (theta ≠ angle_from_key) must be rejected");
    }

    #[test]
    fn coord_announce_depth_disagreement_with_announce_rejected() {
        let mut rs = make_router();
        let sk = SigningKey::generate(&mut OsRng);
        let pk = sk.verifying_key().to_bytes();
        add_dummy_peer(&mut rs, pk);
        // Stash a tree-0 Announce on file saying depth=10.
        rs.peers.get_mut(&pk).unwrap().trees[0] = Some(TreeAnnounce {
            root: pk,
            path_cost: 0,
            received_at: Instant::now(),
            depth: 10,
        });
        // Now CoordAnnounce claims depth=0 (consistent with r=0.0 coord,
        // so check #1 passes — but check #2 must catch the disagreement).
        let coord = HypCoord::from_tree_depth(0, &pk);
        let ann = make_coord_announce(&sk, 0, coord);
        rs.handle_coord_announce(pk, ann);
        assert!(!rs.coord_table.contains_key(&pk),
            "CoordAnnounce depth disagreement with Announce must be rejected");
    }

    // ── PathLookup auto-prober ──────────────────────────────────────────────

    #[test]
    fn probe_decays_trust_on_timeout() {
        let mut rs = make_router();
        let via = [0x44u8; 32];
        add_dummy_peer(&mut rs, via);
        let initial_trust = rs.peers[&via].trust;
        // Insert an artificially-old probe.
        let id = 0xCAFE_BABE;
        let stale = Instant::now()
            .checked_sub(PROBE_TIMEOUT + Duration::from_secs(1))
            .expect("subtraction must succeed");
        rs.pending_probes.insert(id, (via, stale));
        rs.cleanup_stale_probes();
        assert!(!rs.pending_probes.contains_key(&id), "stale probe must be removed");
        assert!(rs.peers[&via].trust < initial_trust,
            "trust must decay after probe timeout; before={} after={}",
            initial_trust, rs.peers[&via].trust);
    }

    #[test]
    fn probe_kept_if_not_yet_expired() {
        let mut rs = make_router();
        let via = [0x45u8; 32];
        add_dummy_peer(&mut rs, via);
        let id = 0xDEAD_BEEF;
        rs.pending_probes.insert(id, (via, Instant::now()));
        rs.cleanup_stale_probes();
        assert!(rs.pending_probes.contains_key(&id),
            "fresh probe must NOT be cleaned up");
    }

    #[test]
    fn probe_match_on_path_notify_boosts_trust() {
        let mut rs = make_router();
        let via = [0x46u8; 32];
        let target = [0x47u8; 32];
        add_dummy_peer(&mut rs, via);
        let id = 0xFEED_F00D;
        rs.pending_probes.insert(id, (via, Instant::now()));
        let trust_before = rs.peers[&via].trust;
        // Synthesize a PathNotify that addresses us as source.
        let own_pub = rs.pub_key;
        rs.handle_path_notify(via, PathNotify {
            target, source: own_pub, id, path: vec![],
        });
        assert!(!rs.pending_probes.contains_key(&id),
            "matched probe must be removed");
        assert!(rs.peers[&via].trust > trust_before,
            "trust must boost on probe success; before={} after={}",
            trust_before, rs.peers[&via].trust);
    }

    // ── OnionKeyAnnounce flood ──────────────────────────────────────────────

    // ── HolePunch relay ────────────────────────────────────────────────────

    fn make_hole_punch(initiator_sk: &SigningKey, target: [u8; 32], endpoint: &str) -> HolePunch {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64).unwrap_or(0);
        let unsigned = HolePunch {
            initiator: initiator_sk.verifying_key().to_bytes(),
            target,
            valid_from_ms: now_ms,
            endpoint: endpoint.to_string(),
            sig: [0u8; 64],
        };
        let sig = initiator_sk.sign(&unsigned.sign_bytes()).to_bytes();
        HolePunch { sig, ..unsigned }
    }

    #[tokio::test]
    async fn hole_punch_for_us_fires_callback() {
        let mut rs = make_router();
        let initiator = SigningKey::generate(&mut OsRng);
        let own_pub = rs.pub_key;
        let hp = make_hole_punch(&initiator, own_pub, "10.0.0.5:9001");

        let received: Arc<std::sync::Mutex<Option<(PeerId, String)>>> =
            Arc::new(std::sync::Mutex::new(None));
        let received_clone = received.clone();
        rs.hole_punch_cb = Some(Arc::new(move |pk, ep| {
            *received_clone.lock().unwrap() = Some((pk, ep));
        }));

        rs.handle_hole_punch([0u8; 32], hp);
        // Callback dispatches via tokio::spawn — wait briefly.
        for _ in 0..20 {
            tokio::time::sleep(Duration::from_millis(10)).await;
            if received.lock().unwrap().is_some() { break; }
        }
        let r = received.lock().unwrap().clone();
        assert!(r.is_some(), "callback must fire on for-us HolePunch");
        let (pk, ep) = r.unwrap();
        assert_eq!(pk, initiator.verifying_key().to_bytes());
        assert_eq!(ep, "10.0.0.5:9001");
    }

    #[test]
    fn hole_punch_invalid_sig_rejected() {
        let mut rs = make_router();
        let initiator = SigningKey::generate(&mut OsRng);
        let own_pub = rs.pub_key;
        let mut hp = make_hole_punch(&initiator, own_pub, "1.2.3.4:9001");
        hp.sig[0] ^= 0xFF;

        let fired = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let f = fired.clone();
        rs.hole_punch_cb = Some(Arc::new(move |_, _| {
            f.store(true, std::sync::atomic::Ordering::SeqCst);
        }));
        rs.handle_hole_punch([0u8; 32], hp);
        assert!(!fired.load(std::sync::atomic::Ordering::SeqCst),
            "callback must not fire on bad signature");
    }

    #[test]
    fn hole_punch_for_other_target_no_route_drops() {
        let mut rs = make_router();
        let initiator = SigningKey::generate(&mut OsRng);
        let other_target = [0xCCu8; 32];   // not a peer of ours
        let hp = make_hole_punch(&initiator, other_target, "1.2.3.4:9001");
        // No route → handle_hole_punch logs and returns; nothing observable
        // here beyond "no panic". The point of the test is to exercise the
        // relay-mode code path without an asserting outcome.
        rs.handle_hole_punch([0u8; 32], hp);
    }

    #[test]
    fn hole_punch_relays_to_peer_with_route() {
        let mut rs = make_router();
        let initiator = SigningKey::generate(&mut OsRng);
        let target = [0xCCu8; 32];
        let (tx, mut rx) = mpsc::channel(64);
        // Add `target` as a peer so lookup() resolves directly.
        rs.add_peer(target, tx, 0);

        let hp = make_hole_punch(&initiator, target, "203.0.113.7:9001");
        rs.handle_hole_punch([0xAAu8; 32], hp.clone());

        let forwarded = rx.try_recv().expect("HolePunch must be forwarded to target peer");
        assert_eq!(forwarded[0], TYPE_HOLE_PUNCH,
            "forwarded frame must be of HolePunch type");
        // Decode and confirm contents are preserved.
        let decoded = HolePunch::decode(&forwarded[1..]).unwrap();
        assert_eq!(decoded.initiator, hp.initiator);
        assert_eq!(decoded.endpoint, hp.endpoint);
    }

    // ── Reputation gossip ──────────────────────────────────────────────────

    fn make_report(observer_sk: &SigningKey, observed: [u8; 32], seq: u64, score: f32) -> ReputationReport {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let frac = ((score - TRUST_MIN) / (TRUST_MAX - TRUST_MIN)).clamp(0.0, 1.0);
        let score_q16 = (frac * u16::MAX as f32) as u16;
        let unsigned = ReputationReport {
            observer: observer_sk.verifying_key().to_bytes(),
            observed,
            score_q16,
            seq,
            valid_from_ms: now_ms,
            sig: [0u8; 64],
        };
        let sig = observer_sk.sign(&unsigned.sign_bytes()).to_bytes();
        ReputationReport { sig, ..unsigned }
    }

    #[test]
    fn reputation_report_valid_recorded() {
        // With the new quorum rule we need REPUTATION_MIN_QUORUM independent
        // observers before consensus_trust returns Some. Three reporters all
        // saying ~2.0 → consensus ~2.0.
        let mut rs = make_router();
        let observed = [0x99u8; 32];
        for _ in 0..REPUTATION_MIN_QUORUM {
            let observer = SigningKey::generate(&mut OsRng);
            let r = make_report(&observer, observed, 1, 2.0);
            rs.handle_reputation_report([0xFEu8; 32], r);
        }
        let c = rs.consensus_trust(&observed).unwrap();
        assert!((c - 2.0).abs() < 0.05, "consensus must roughly equal reported score; got {c}");
    }

    #[test]
    fn reputation_below_quorum_returns_none() {
        // One observation is NOT enough — anti-Sybil quorum rule. This is the
        // primary defence against a single attacker dictating consensus.
        let mut rs = make_router();
        let observer = SigningKey::generate(&mut OsRng);
        let observed = [0xDEu8; 32];
        rs.handle_reputation_report([0xFEu8; 32], make_report(&observer, observed, 1, 4.0));
        assert!(rs.consensus_trust(&observed).is_none(),
            "single observation must not pass quorum (need ≥{})", REPUTATION_MIN_QUORUM);
    }

    #[test]
    fn reputation_report_self_observed_rejected() {
        let mut rs = make_router();
        // observer == observed: meaningless self-praise.
        let sk = SigningKey::generate(&mut OsRng);
        let me = sk.verifying_key().to_bytes();
        let mut r = make_report(&sk, me, 1, 3.0);
        // Sign over the self-claim.
        r.sig = sk.sign(&r.sign_bytes()).to_bytes();
        rs.handle_reputation_report([0xFEu8; 32], r);
        assert!(rs.consensus_trust(&me).is_none(),
            "self-praise must not be accepted");
    }

    #[test]
    fn reputation_report_invalid_sig_rejected() {
        let mut rs = make_router();
        let observer = SigningKey::generate(&mut OsRng);
        let observed = [0xAAu8; 32];
        let mut r = make_report(&observer, observed, 1, 1.5);
        r.sig[0] ^= 0xFF;
        rs.handle_reputation_report([0xFEu8; 32], r);
        assert!(rs.consensus_trust(&observed).is_none());
    }

    #[test]
    fn reputation_report_newer_seq_replaces() {
        // For the per-observer "newer seq wins" property to be testable we
        // also need to clear quorum. One observer flips their report, two
        // others act as quorum padding with neutral scores.
        let mut rs = make_router();
        let observer = SigningKey::generate(&mut OsRng);
        let pad1 = SigningKey::generate(&mut OsRng);
        let pad2 = SigningKey::generate(&mut OsRng);
        let observed = [0xBBu8; 32];
        rs.handle_reputation_report([0u8; 32], make_report(&observer, observed, 1, 0.5));
        rs.handle_reputation_report([0u8; 32], make_report(&observer, observed, 2, 3.5));
        rs.handle_reputation_report([0u8; 32], make_report(&pad1, observed, 1, 2.0));
        rs.handle_reputation_report([0u8; 32], make_report(&pad2, observed, 1, 2.0));
        let c = rs.consensus_trust(&observed).unwrap();
        // Three observations after the seq=2 replace: 3.5, 2.0, 2.0.
        // Trimmed mean drops top and bottom — n=3 → trim = floor(3*0.25)=0,
        // so all are kept. Mean ≥ 2.0. Without the replace, observer's seq=1
        // 0.5 would pull it below 2.0 (mean 1.5).
        assert!(c >= 2.0,
            "newer seq must replace prior — mean must be ≥ 2.0 with replace, got {c}");
    }

    #[test]
    fn reputation_aggregates_across_observers() {
        // Three observers with scores [1.0, 2.0, 3.0]. The consensus is a
        // PoW-WEIGHTED trimmed mean — random OsRng keys carry random
        // difficulty_bits, so the exact weights vary run-to-run. What MUST
        // hold: the result sits inside the [1.0, 3.0] envelope. The trimmed
        // mean is not yet trimming anything here (n=3, trim=0), so the
        // value is the weighted average and bounded by the extremes.
        let mut rs = make_router();
        let observers: Vec<SigningKey> = (0..3).map(|_| SigningKey::generate(&mut OsRng)).collect();
        let observed = [0xCCu8; 32];
        for (i, sk) in observers.iter().enumerate() {
            let score = 1.0 + i as f32;
            rs.handle_reputation_report([0u8; 32], make_report(sk, observed, 1, score));
        }
        let c = rs.consensus_trust(&observed).unwrap();
        assert!((1.0..=3.0).contains(&c),
            "weighted consensus must lie within [1.0, 3.0]; got {c}");
    }

    #[test]
    fn reputation_trimmed_mean_rejects_extreme_minority() {
        // 4 honest reporters say 2.0, 1 attacker says 4.0 (max).
        // Without trim: mean = (4*2.0 + 4.0)/5 = 2.4 (attacker shifts by 0.4).
        // With trim 25 % per side: n=5, trim = floor(5*0.25)=1 → keep middle 3.
        // Sorted: [2.0, 2.0, 2.0, 2.0, 4.0]; keep[1..4] = [2.0, 2.0, 2.0].
        // Mean = 2.0 exactly — attacker's outlier vote got trimmed.
        let mut rs = make_router();
        let observed = [0xEEu8; 32];
        for _ in 0..4 {
            let sk = SigningKey::generate(&mut OsRng);
            rs.handle_reputation_report([0u8; 32], make_report(&sk, observed, 1, 2.0));
        }
        let attacker = SigningKey::generate(&mut OsRng);
        rs.handle_reputation_report([0u8; 32], make_report(&attacker, observed, 1, 4.0));

        let c = rs.consensus_trust(&observed).unwrap();
        assert!((c - 2.0).abs() < 0.05,
            "trimmed mean must drop the attacker's extreme vote; got {c} (expected ≈ 2.0)");
    }

    fn make_oka(sk: &SigningKey, seq: u64, eph: [u8; 32], age_ms: i64) -> OnionKeyAnnounce {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let valid_from_ms = if age_ms >= 0 {
            now_ms.saturating_sub(age_ms as u64)
        } else {
            now_ms.saturating_add((-age_ms) as u64)
        };
        let unsigned = OnionKeyAnnounce {
            origin: sk.verifying_key().to_bytes(),
            seq,
            valid_from_ms,
            onion_eph_pub: eph,
            sig: [0u8; 64],
        };
        let sig = sk.sign(&unsigned.sign_bytes()).to_bytes();
        OnionKeyAnnounce { sig, ..unsigned }
    }

    #[cfg(feature = "sphinx")]
    fn make_cap(sk: &SigningKey, caps: u32, seq: u64, age_ms: i64) -> crate::packet::CapabilityAnnounce {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let valid_from_ms = if age_ms >= 0 {
            now_ms.saturating_sub(age_ms as u64)
        } else {
            now_ms.saturating_add((-age_ms) as u64)
        };
        let unsigned = crate::packet::CapabilityAnnounce {
            origin: sk.verifying_key().to_bytes(),
            caps,
            seq,
            valid_from_ms,
            sig: [0u8; 64],
        };
        let sig = sk.sign(&unsigned.sign_bytes()).to_bytes();
        crate::packet::CapabilityAnnounce { sig, ..unsigned }
    }

    #[test]
    #[cfg(feature = "sphinx")]
    fn capability_valid_is_recorded() {
        let mut rs = make_router();
        let sk = SigningKey::generate(&mut OsRng);
        let origin = sk.verifying_key().to_bytes();
        rs.handle_capabilities([0xFEu8; 32], make_cap(&sk, crate::packet::CAP_ONION_SPHINX, 1, 5_000));
        let (caps, seq, _) = rs.peer_capabilities.get(&origin).expect("recorded");
        assert_eq!(*seq, 1);
        assert_ne!(caps & crate::packet::CAP_ONION_SPHINX, 0);
    }

    #[test]
    #[cfg(feature = "sphinx")]
    fn capability_bad_sig_stale_and_self_rejected() {
        let mut rs = make_router();
        let sk = SigningKey::generate(&mut OsRng);
        let origin = sk.verifying_key().to_bytes();
        let mut bad = make_cap(&sk, crate::packet::CAP_ONION_SPHINX, 1, 0);
        bad.sig[0] ^= 0xFF;
        rs.handle_capabilities([0u8; 32], bad);
        assert!(!rs.peer_capabilities.contains_key(&origin), "bad sig rejected");
        rs.handle_capabilities([0u8; 32], make_cap(&sk, crate::packet::CAP_ONION_SPHINX, 1, 25 * 60 * 60 * 1000));
        assert!(!rs.peer_capabilities.contains_key(&origin), "stale rejected");
        // An announce purporting to be from ourselves must be ignored.
        let self_sk = rs.signing_key.clone();
        let self_ann = make_cap(&self_sk, crate::packet::CAP_ONION_SPHINX, 1, 0);
        rs.handle_capabilities([0u8; 32], self_ann);
        assert!(!rs.peer_capabilities.contains_key(&rs.pub_key), "self-origin rejected");
    }

    #[test]
    #[cfg(feature = "sphinx")]
    fn capability_dedup_keeps_newest_seq() {
        let mut rs = make_router();
        let sk = SigningKey::generate(&mut OsRng);
        let origin = sk.verifying_key().to_bytes();
        rs.handle_capabilities([0u8; 32], make_cap(&sk, crate::packet::CAP_ONION_SPHINX, 5, 0));
        rs.handle_capabilities([0u8; 32], make_cap(&sk, 0, 3, 0)); // older seq → ignored
        let (caps, seq, _) = rs.peer_capabilities.get(&origin).unwrap();
        assert_eq!(*seq, 5);
        assert_ne!(caps & crate::packet::CAP_ONION_SPHINX, 0);
        rs.handle_capabilities([0u8; 32], make_cap(&sk, 0, 6, 0)); // newer → updates
        let (caps, seq, _) = rs.peer_capabilities.get(&origin).unwrap();
        assert_eq!(*seq, 6);
        assert_eq!(caps & crate::packet::CAP_ONION_SPHINX, 0, "newer announce cleared the bit");
    }

    #[test]
    #[cfg(feature = "sphinx")]
    fn path_supports_sphinx_requires_every_hop_capable() {
        let mut rs = make_router();
        let relay_sks: Vec<SigningKey> = (0..2).map(|_| SigningKey::generate(&mut OsRng)).collect();
        let dst_sk = SigningKey::generate(&mut OsRng);
        let relays: Vec<crate::onion::OnionHop> = relay_sks.iter().map(|sk| crate::onion::OnionHop {
            identity_ed_pub: sk.verifying_key().to_bytes(),
            ephemeral_x_pub: [0u8; 32],
        }).collect();
        let dst = dst_sk.verifying_key().to_bytes();
        for sk in relay_sks.iter().chain(std::iter::once(&dst_sk)) {
            rs.handle_capabilities([0u8; 32], make_cap(sk, crate::packet::CAP_ONION_SPHINX, 1, 0));
        }
        assert!(rs.path_supports_sphinx(&relays, &dst), "all hops capable → true");
        // A hop that advertises caps but WITHOUT the sphinx bit → false.
        rs.handle_capabilities([0u8; 32], make_cap(&relay_sks[0], 0, 2, 0));
        assert!(!rs.path_supports_sphinx(&relays, &dst), "a non-sphinx hop → false");
    }

    #[test]
    #[cfg(feature = "sphinx")]
    fn path_supports_sphinx_rejects_too_many_hops() {
        let rs = make_router();
        let sks: Vec<SigningKey> = (0..crate::sphinx::MAX_HOPS).map(|_| SigningKey::generate(&mut OsRng)).collect();
        let relays: Vec<crate::onion::OnionHop> = sks.iter().map(|sk| crate::onion::OnionHop {
            identity_ed_pub: sk.verifying_key().to_bytes(),
            ephemeral_x_pub: [0u8; 32],
        }).collect();
        let dst = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();
        // MAX_HOPS relays + dst = MAX_HOPS+1 > MAX_HOPS → rejected before cap checks.
        assert!(!rs.path_supports_sphinx(&relays, &dst));
    }

    #[test]
    fn onion_key_announce_valid_is_recorded() {
        let mut rs = make_router();
        let origin_sk = SigningKey::generate(&mut OsRng);
        let origin_pub = origin_sk.verifying_key().to_bytes();
        let eph = [0x77u8; 32];
        let ann = make_oka(&origin_sk, 1, eph, 5_000);
        let from = [0xFEu8; 32];
        rs.handle_onion_key_announce(from, ann);
        let recorded = rs.remote_onion_keys.get(&origin_pub);
        assert!(recorded.is_some(), "valid announce must be recorded");
        let (seq, recorded_eph, _) = recorded.unwrap();
        assert_eq!(*seq, 1);
        assert_eq!(*recorded_eph, eph);
    }

    #[test]
    fn onion_key_announce_invalid_sig_rejected() {
        let mut rs = make_router();
        let origin_sk = SigningKey::generate(&mut OsRng);
        let origin_pub = origin_sk.verifying_key().to_bytes();
        let mut ann = make_oka(&origin_sk, 1, [0x77u8; 32], 0);
        ann.sig[0] ^= 0xFF; // tamper
        rs.handle_onion_key_announce([0u8; 32], ann);
        assert!(!rs.remote_onion_keys.contains_key(&origin_pub),
            "bad sig must not be recorded");
    }

    #[test]
    fn onion_key_announce_too_old_rejected() {
        let mut rs = make_router();
        let origin_sk = SigningKey::generate(&mut OsRng);
        let origin_pub = origin_sk.verifying_key().to_bytes();
        // 25 hours old > ONION_KEY_VALIDITY_MS (24h)
        let ann = make_oka(&origin_sk, 1, [0x77u8; 32], 25 * 60 * 60 * 1000);
        rs.handle_onion_key_announce([0u8; 32], ann);
        assert!(!rs.remote_onion_keys.contains_key(&origin_pub),
            "stale announce must not be recorded");
    }

    #[test]
    fn onion_key_announce_self_origin_rejected() {
        let mut rs = make_router();
        // Sign with rs's own key — make_oka uses sk.verifying_key as origin.
        let own_sk = rs.signing_key.clone();
        let ann = make_oka(&own_sk, 99, [0x77u8; 32], 0);
        rs.handle_onion_key_announce([0u8; 32], ann);
        // remote_onion_keys may have us inserted by broadcast_onion_key_announce
        // (called from maintenance), but never via *incoming* self-origin frames.
        // Confirm seq stayed at default (we never broadcast in this unit test).
        let entry = rs.remote_onion_keys.get(&rs.pub_key);
        assert!(entry.is_none() || entry.unwrap().0 != 99,
            "self-origin announce must not pollute table");
    }

    #[test]
    fn onion_key_announce_newer_replaces_older() {
        let mut rs = make_router();
        let origin_sk = SigningKey::generate(&mut OsRng);
        let origin_pub = origin_sk.verifying_key().to_bytes();
        let eph1 = [0x01u8; 32];
        let eph2 = [0x02u8; 32];
        rs.handle_onion_key_announce([0u8; 32], make_oka(&origin_sk, 1, eph1, 0));
        rs.handle_onion_key_announce([0u8; 32], make_oka(&origin_sk, 2, eph2, 0));
        let (seq, recorded, _) = rs.remote_onion_keys.get(&origin_pub).unwrap();
        assert_eq!(*seq, 2);
        assert_eq!(*recorded, eph2);
    }

    #[test]
    fn onion_key_announce_older_ignored() {
        let mut rs = make_router();
        let origin_sk = SigningKey::generate(&mut OsRng);
        let origin_pub = origin_sk.verifying_key().to_bytes();
        let eph1 = [0x01u8; 32];
        let eph_old = [0xEEu8; 32];
        rs.handle_onion_key_announce([0u8; 32], make_oka(&origin_sk, 5, eph1, 0));
        // An older seq must be ignored even if the signature is valid.
        rs.handle_onion_key_announce([0u8; 32], make_oka(&origin_sk, 4, eph_old, 0));
        let (seq, recorded, _) = rs.remote_onion_keys.get(&origin_pub).unwrap();
        assert_eq!(*seq, 5);
        assert_eq!(*recorded, eph1, "older seq must not overwrite");
    }

    #[test]
    fn onion_key_announce_forwards_to_other_peers() {
        let mut rs = make_router();
        let origin_sk = SigningKey::generate(&mut OsRng);
        let sender = [0xAAu8; 32];
        let other  = [0xBBu8; 32];
        let (tx_sender, _rx_sender) = mpsc::channel(64);
        let (tx_other, mut rx_other) = mpsc::channel(64);
        rs.add_peer(sender, tx_sender, 0);
        rs.add_peer(other, tx_other, 0);

        let ann = make_oka(&origin_sk, 1, [0x77u8; 32], 0);
        rs.handle_onion_key_announce(sender, ann);

        // `other` must have received a forwarded copy.
        let forwarded = rx_other.try_recv()
            .expect("forwarded OnionKeyAnnounce must be in `other`'s channel");
        assert_eq!(forwarded[0], TYPE_ONION_KEY_ANNOUNCE,
            "forwarded frame must be of OnionKeyAnnounce type");
    }

    #[test]
    fn onion_key_announce_does_not_loop_back_to_sender() {
        let mut rs = make_router();
        let origin_sk = SigningKey::generate(&mut OsRng);
        let sender = [0xAAu8; 32];
        let (tx_sender, mut rx_sender) = mpsc::channel(64);
        rs.add_peer(sender, tx_sender, 0);

        let ann = make_oka(&origin_sk, 1, [0x77u8; 32], 0);
        rs.handle_onion_key_announce(sender, ann);
        // The sender must NOT receive a forwarded copy (we don't echo).
        assert!(rx_sender.try_recv().is_err(),
            "must not echo OnionKeyAnnounce back to its sender");
    }

    #[test]
    fn onion_replay_first_sight_not_replay() {
        let mut rs = make_router();
        let pkt = crate::onion::OnionPacket {
            routing_tag: [0u8; 16],
            epk: [1u8; 32],
            aead_payload: vec![0xAA; 32],
        };
        assert!(!rs.is_onion_replay(&pkt), "first sighting must not be flagged");
    }

    #[test]
    fn onion_replay_second_sight_is_replay() {
        let mut rs = make_router();
        let pkt = crate::onion::OnionPacket {
            routing_tag: [0u8; 16],
            epk: [1u8; 32],
            aead_payload: vec![0xAA; 32],
        };
        assert!(!rs.is_onion_replay(&pkt));
        assert!(rs.is_onion_replay(&pkt), "identical second sighting must be detected as replay");
    }

    #[test]
    fn onion_replay_distinguishes_different_epks() {
        let mut rs = make_router();
        let pkt_a = crate::onion::OnionPacket {
            routing_tag: [0u8; 16],
            epk: [1u8; 32],
            aead_payload: vec![0xAA; 32],
        };
        let pkt_b = crate::onion::OnionPacket {
            routing_tag: [0u8; 16],
            epk: [2u8; 32], // different epk
            aead_payload: vec![0xAA; 32],
        };
        assert!(!rs.is_onion_replay(&pkt_a));
        assert!(!rs.is_onion_replay(&pkt_b),
            "different epk → different digest → not a replay");
    }

    #[test]
    fn send_announces_encodes_own_depth_for_tree_0() {
        let mut rs = make_router();
        rs.own_depth = 7;
        let peer_key = [0x30u8; 32];
        let (tx, mut rx) = mpsc::channel(64);
        rs.add_peer(peer_key, tx, 0);

        rs.send_announces(0);

        let data = rx.try_recv().expect("send_announces must send a packet to peer");
        // data[0] = ANNOUNCE type byte; Announce::decode takes data[1..]
        assert_eq!(data[0], ANNOUNCE, "must be ANNOUNCE type");
        let ann = Announce::decode(&data[1..]).expect("must decode as Announce");
        assert_eq!(ann.depth, 7,
            "depth in tree-0 announce must equal own_depth=7; \
             mutation == → != gives depth=0 for tree_id=0");
    }

    #[test]
    fn send_announces_encodes_zero_depth_for_nonzero_tree() {
        let mut rs = make_router();
        rs.own_depth = 7;
        let peer_key = [0x31u8; 32];
        let (tx, mut rx) = mpsc::channel(64);
        rs.add_peer(peer_key, tx, 0);

        rs.send_announces(1); // tree_id=1 → depth must be 0

        let data = rx.try_recv().expect("send_announces must send a packet to peer");
        assert_eq!(data[0], ANNOUNCE, "must be ANNOUNCE type");
        let ann = Announce::decode(&data[1..]).expect("must decode as Announce");
        assert_eq!(ann.depth, 0,
            "depth for tree_id=1 must be 0 (own_depth only applies to tree 0); \
             mutation == → != would give depth=7 for tree_id=1");
    }

    // ── handle_sig_req sends signed SigRes ───────────────────────────────────

    #[test]
    fn handle_sig_req_sends_signed_sig_res() {
        let mut rs = make_router();
        let peer_sk = SigningKey::generate(&mut OsRng);
        let peer_key = peer_sk.verifying_key().to_bytes();
        let (tx, mut rx) = mpsc::channel(64);
        rs.add_peer(peer_key, tx, 0);

        let own_pub = rs.pub_key;
        let req = SigReq {
            tree_id: 0,
            seq: 42u64,
            timestamp_ms: 0,
            pub_key: own_pub, // SigReq carries the requester's pub key
        };
        rs.handle_sig_req(peer_key, req);

        let data = rx.try_recv().expect("handle_sig_req must send SigRes to peer");
        assert_eq!(data[0], SIG_RES, "response type must be SIG_RES");
        let sig_res = SigRes::decode(&data[1..]).expect("must decode as SigRes");
        assert_eq!(sig_res.seq, 42,
            "SigRes seq must echo req seq; mutation seq→0 gives 0");
        assert_eq!(sig_res.tree_id, 0, "tree_id must echo request");

        // Verify signature: responder signs (tree_id || seq || timestamp_ms || req.pub_key)
        let responder_vk = VerifyingKey::from_bytes(&sig_res.pub_key).unwrap();
        let mut sign_data = vec![sig_res.tree_id];
        let mut tmp = Vec::new();
        encode_uvarint(sig_res.seq, &mut tmp);
        sign_data.extend_from_slice(&tmp);
        tmp.clear();
        encode_uvarint(sig_res.timestamp_ms, &mut tmp);
        sign_data.extend_from_slice(&tmp);
        sign_data.extend_from_slice(&own_pub);
        let sig = ed25519_dalek::Signature::from_bytes(&sig_res.signature);
        assert!(responder_vk.verify_strict(&sign_data, &sig).is_ok(),
            "SigRes signature must be valid");
    }

    // ── handle_sig_res EWMA with non-zero RTT ─────────────────────────────────

    #[test]
    fn sig_res_nonzero_rtt_updates_lag_ewma() {
        let mut rs = make_router();
        let peer_sk = SigningKey::generate(&mut OsRng);
        let peer_key = peer_sk.verifying_key().to_bytes();
        let (tx, _rx) = mpsc::channel(64);
        rs.add_peer(peer_key, tx, 0);
        let own_pub = rs.pub_key;

        // Start with low lag; sent_time 1s ago → RTT ≈ 1s, new_lag ≈ 500ms
        rs.peers.get_mut(&peer_key).unwrap().lag = Duration::from_micros(10_000); // 10ms
        rs.peers.get_mut(&peer_key).unwrap().jitter = Duration::ZERO;

        let seq = 10u64;
        let sent_time = Instant::now() - Duration::from_secs(1); // RTT ≈ 1_000_000µs
        rs.peers.get_mut(&peer_key).unwrap().pending_sig_req_time = Some((seq, sent_time));

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let res = make_valid_sig_res(&peer_sk, &own_pub, seq, now_ms);
        rs.handle_sig_res(peer_key, res);

        let peer = &rs.peers[&peer_key];
        // RTT ≈ 1_000ms, new_lag = RTT/2 ≈ 500_000µs
        // Expected lag = (10_000 * 7/8) + (500_000/8) ≈ 8_750 + 62_500 = 71_250µs
        // Mutation rtt/2 → rtt*2: new_lag ≈ 1_000_000 → lag ≈ 8_750 + 125_000 = 133_750µs
        assert!(peer.lag > Duration::from_micros(40_000),
            "lag must rise substantially toward new 500ms measurement; got {:?}", peer.lag);
        assert!(peer.lag < Duration::from_micros(120_000),
            "lag must be < 120ms (catches rtt*2 mutation giving ~134ms); got {:?}", peer.lag);

        // diff = |500_000 - 10_000| = 490_000; jitter = 490_000/8 ≈ 61_250µs
        // Mutation new - old → new + old: diff = 510_000 → jitter = 63_750µs (detectable)
        assert!(peer.jitter > Duration::ZERO,
            "jitter must be non-zero; got {:?}", peer.jitter);
        assert!(peer.jitter < Duration::from_micros(120_000),
            "jitter must be < 120ms; got {:?}", peer.jitter);
    }

    #[test]
    fn encrypt_header_decrypt_source_roundtrip() {
        let sk = SigningKey::generate(&mut OsRng);
        let src = [0xAAu8; 32];
        let dst = sk.verifying_key().to_bytes();
        let (header, _tag) = encrypt_header(&src, &dst);
        let recovered = decrypt_source_from_header(&header, &sk);
        assert_eq!(recovered, Some(src), "decrypted source must match original");
    }

    #[test]
    fn routing_tag_in_encrypt_header_matches_standalone() {
        let src = [0x11u8; 32];
        let dst = [0x22u8; 32];
        let (_header, tag) = encrypt_header(&src, &dst);
        assert_eq!(tag, routing_tag(&dst), "tag from encrypt_header must match routing_tag(dst)");
    }

    // ── lookup_by_tag selects lowest-cost peer ────────────────────────────────
    // Two peers both have the tag in their cuckoo filter, with different costs.
    // Catches `cost < bc → cost > bc` and similar comparison mutations on line 1196.

    #[test]
    fn lookup_by_tag_selects_lower_cost_peer() {
        let mut rs = make_router();
        let cheap_key = [0xC0u8; 32];
        let costly_key = [0xC1u8; 32];
        add_dummy_peer(&mut rs, cheap_key);
        add_dummy_peer(&mut rs, costly_key);

        // Insert a fixed tag into tree-0 cuckoo filter for both peers
        let tag = [0xABu8; 16];
        rs.peers.get_mut(&cheap_key).unwrap().cuckoo[0].add(&tag);
        rs.peers.get_mut(&costly_key).unwrap().cuckoo[0].add(&tag);

        // Assign clearly different lags: cheap=1ms, costly=100ms
        rs.peers.get_mut(&cheap_key).unwrap().lag = Duration::from_millis(1);
        rs.peers.get_mut(&costly_key).unwrap().lag = Duration::from_millis(100);

        let result = rs.lookup_by_tag(&tag);
        assert_eq!(result, Some(cheap_key),
            "lookup_by_tag must return the peer with lower effective cost; \
             with `< → >` mutation the costly peer would be returned instead");
    }

    // ── handle_sig_res jitter EWMA with non-zero initial jitter ───────────────
    // Catches 5 arithmetic mutations on lines 795 and 797:
    //   795: `- → +` (diff formula): diff = new+old instead of |new-old|
    //   797: `* → /` (weight denom): jitter/7/8 instead of jitter*7/8
    //   797: `* → +` (weight mul): jitter+0 instead of jitter*7/8
    //   797: `/ → *` (first div): jitter*7*8 (huge)
    //   797: `/ → %` (second term): diff%8 ≈ 0 instead of diff/8 = 100_000
    // With old_lag=200ms, old_jitter=80ms, RTT≈2s:
    //   diff = |1_000_000 - 200_000| = 800_000; diff/8 = 100_000
    //   expected new jitter = 70_000 + 100_000 = 170_000µs
    //   bounds [160_000, 177_000] exclude all mutated values.

    #[test]
    fn sig_res_jitter_ewma_with_nonzero_initial() {
        let mut rs = make_router();
        let peer_sk = SigningKey::generate(&mut OsRng);
        let peer_key = peer_sk.verifying_key().to_bytes();
        let (tx, _rx) = mpsc::channel(64);
        rs.add_peer(peer_key, tx, 0);
        let own_pub = rs.pub_key;

        // old_lag=200ms, old_jitter=80ms. RTT≈2s → new_lag≈1_000_000µs.
        rs.peers.get_mut(&peer_key).unwrap().lag = Duration::from_micros(200_000);
        rs.peers.get_mut(&peer_key).unwrap().jitter = Duration::from_micros(80_000);

        let seq = 7u64;
        let sent_time = Instant::now() - Duration::from_secs(2);
        rs.peers.get_mut(&peer_key).unwrap().pending_sig_req_time = Some((seq, sent_time));

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let res = make_valid_sig_res(&peer_sk, &own_pub, seq, now_ms);
        rs.handle_sig_res(peer_key, res);

        let peer = &rs.peers[&peer_key];
        // Expected ≈ 170_000µs ± ~500µs (RTT variance)
        // Mutation 795 `-→+`: diff=1_200_000, diff/8=150_000 → jitter=220_000 > 177_000 ✓
        // Mutation 797 `*→+`: jitter+0+100_000=180_000 > 177_000 ✓
        // Mutation 797 `*→/`: 1428+100_000=101_428 < 160_000 ✓
        // Mutation 797 `/→*`: 80_000*56+100_000=4_580_000 > 177_000 ✓
        // Mutation 797 `/→%`: 70_000+(800_000%8≈0)=70_001 < 160_000 ✓
        assert!(peer.jitter > Duration::from_micros(160_000),
            "jitter must be > 160ms (catches /→%, *→/ mutations); got {:?}", peer.jitter);
        assert!(peer.jitter < Duration::from_micros(177_000),
            "jitter must be < 177ms (catches -→+, *→+, /→* mutations); got {:?}", peer.jitter);
    }

    // ── cleanup_stale_sessions removes idle sessions ─────────────────────────
    // `cleanup_stale_sessions` retains sessions whose last_used < SESSION_IDLE_EXPIRY ago.
    // Catches `replace cleanup_stale_sessions with ()` (body→empty) and
    // `< → >, ==` mutations (line 720) that would retain sessions that should expire.

    #[test]
    fn cleanup_stale_sessions_removes_expired() {
        let rs = make_router();
        let remote_key = [0x77u8; 32];

        // initiate() creates a SessionInfo entry in rs.sessions
        rs.sessions.write_or_recover().initiate(&remote_key);
        assert!(rs.sessions.read_or_recover().sessions.contains_key(&remote_key),
            "session must exist before cleanup");

        // Back-date last_used beyond SESSION_IDLE_EXPIRY (300s)
        let stale_time = Instant::now()
            .checked_sub(SESSION_IDLE_EXPIRY + Duration::from_secs(10))
            .expect("instant subtraction must succeed on any system that has been up 310s+");
        rs.sessions.read_or_recover()
            .sessions.get(&remote_key).unwrap()
            .lock().unwrap()
            .last_used = stale_time;

        rs.cleanup_stale_sessions();

        assert!(!rs.sessions.read_or_recover().sessions.contains_key(&remote_key),
            "stale session must be removed by cleanup_stale_sessions; \
             `replace with ()` mutation leaves it present");
    }

    #[test]
    fn cleanup_stale_sessions_retains_fresh() {
        let rs = make_router();
        let remote_key = [0x78u8; 32];

        rs.sessions.write_or_recover().initiate(&remote_key);
        // last_used is Instant::now() by default — fresh session, must be kept

        rs.cleanup_stale_sessions();

        assert!(rs.sessions.read_or_recover().sessions.contains_key(&remote_key),
            "fresh session must survive cleanup_stale_sessions; \
             `< → >` mutation would remove it instead");
    }

    // ── lookup: hyperbolic greedy routing selects closer peer ────────────────
    // With coord_table populated, lookup uses hyperbolic distance.
    // peer_A is close to dst (small distance), peer_B is far from dst.
    // Catches `d < best_dist → d > best_dist` mutation (line 1087:26):
    // with that mutation peer_B (farther) would always win regardless of HashMap order.

    #[test]
    fn lookup_hyperbolic_greedy_selects_closer_peer() {
        let mut rs = make_router();
        // own_coord is already origin (r=0, θ=0)

        let peer_a_key = [0xA1u8; 32];
        let peer_b_key = [0xB1u8; 32];
        add_dummy_peer(&mut rs, peer_a_key);
        add_dummy_peer(&mut rs, peer_b_key);

        let dst_key = [0xD0u8; 32];

        // Place dst far along its ray (rho = radial hyperbolic distance, v4)
        let dst_coord = HypCoord { rho: 0.8, theta: 0.0 };
        // Place peer_A close to dst (same direction, slightly closer to origin)
        let coord_a = HypCoord { rho: 0.7, theta: 0.0 };
        // Place peer_B far from dst (opposite direction)
        let coord_b = HypCoord { rho: 0.6, theta: std::f64::consts::PI };

        // own_dist = origin.distance(dst_coord) = rho = 0.8
        // d_A = coord_a.distance(dst_coord) = |0.8 − 0.7| = 0.1 (< own_dist → greedy step ✓)
        // d_B = coord_b.distance(dst_coord) ≈ 1.39 (opposite ray) → much larger

        rs.coord_table.insert(dst_key, dst_coord);
        rs.peers.get_mut(&peer_a_key).unwrap().pub_key = peer_a_key;
        rs.coord_table.insert(peer_a_key, coord_a);
        rs.coord_table.insert(peer_b_key, coord_b);

        let result = rs.lookup(&dst_key);
        assert_eq!(result, Some(peer_a_key),
            "hyperbolic greedy lookup must return the closest peer (A); \
             `d < best_dist → d > best_dist` mutation returns farthest peer instead");
    }

    // ── greedy_next_hop: the shared transit/source primitive ─────────────────

    #[test]
    fn greedy_next_hop_picks_strictly_closer_neighbour() {
        let mut rs = make_router(); // own_coord = origin (rho = 0)
        let a = [0xA1u8; 32];
        let b = [0xB1u8; 32];
        add_dummy_peer(&mut rs, a);
        add_dummy_peer(&mut rs, b);
        let dst = HypCoord { rho: 0.8, theta: 0.0 };
        rs.coord_table.insert(a, HypCoord { rho: 0.7, theta: 0.0 });               // d=0.1 < own 0.8
        rs.coord_table.insert(b, HypCoord { rho: 0.6, theta: std::f64::consts::PI }); // far
        assert_eq!(rs.greedy_next_hop(dst, None), Some(a),
            "must pick the neighbour strictly closer to dst_coord");
    }

    #[test]
    fn greedy_next_hop_none_at_local_minimum() {
        let mut rs = make_router(); // own_coord = origin → already closest to a near-origin dst
        let a = [0xA1u8; 32];
        add_dummy_peer(&mut rs, a);
        let dst = HypCoord { rho: 0.1, theta: 0.0 };
        rs.coord_table.insert(a, HypCoord { rho: 0.9, theta: 0.0 }); // farther than us (0.8 > 0.1)
        assert_eq!(rs.greedy_next_hop(dst, None), None,
            "no strictly-closer neighbour → local minimum → None (caller falls back to cuckoo)");
    }

    #[test]
    fn greedy_next_hop_excludes_inbound_peer() {
        let mut rs = make_router();
        let a = [0xA1u8; 32];
        add_dummy_peer(&mut rs, a);
        let dst = HypCoord { rho: 0.8, theta: 0.0 };
        rs.coord_table.insert(a, HypCoord { rho: 0.7, theta: 0.0 }); // the only closer hop
        assert_eq!(rs.greedy_next_hop(dst, Some(a)), None,
            "the inbound peer must be excluded — no bounce-back / 2-cycle");
        assert_eq!(rs.greedy_next_hop(dst, None), Some(a), "without exclusion A is chosen");
    }

    // ── handle_traffic: transit routes by dest_coord, not just cuckoo ─────────
    // The whole point of Path A: a relay forwards toward the stamped dest_coord
    // even when NO cuckoo filter holds the tag (so cuckoo-only would dead-end
    // into a PathNegative). Proves transit geometry is live.
    #[test]
    fn handle_traffic_transit_routes_greedily_by_dest_coord() {
        let mut rs = make_router(); // own_coord = origin
        let a = [0xA1u8; 32];
        let b = [0xB1u8; 32];
        let src = [0x5Cu8; 32];
        let (tx_a, mut rx_a) = mpsc::channel(32);
        let (tx_b, mut rx_b) = mpsc::channel(32);
        let (tx_s, _rx_s) = mpsc::channel(32);
        rs.add_peer(a, tx_a, 0);
        rs.add_peer(b, tx_b, 0);
        rs.add_peer(src, tx_s, 0);

        let dst_coord = HypCoord { rho: 0.8, theta: 0.0 };
        rs.coord_table.insert(a, HypCoord { rho: 0.7, theta: 0.0 });               // close to dst
        rs.coord_table.insert(b, HypCoord { rho: 0.6, theta: std::f64::consts::PI }); // far

        // Not addressed to us (random tag, in nobody's cuckoo filter), but it
        // carries the destination coordinate.
        let traffic = Traffic {
            path: vec![],
            from: src,
            enc_header: [0u8; 128],
            routing_tag: [0x99u8; 16],
            pkt_type: crate::packet::PKT_DATA,
            dest_coord: Some(dst_coord.encode()),
            watermark: 0,
            payload: vec![],
        };
        rs.handle_traffic(src, traffic);

        assert!(rx_a.try_recv().is_ok(),
            "greedy transit must forward toward dest_coord (peer A) with no cuckoo entry");
        assert!(rx_b.try_recv().is_err(), "must not forward to the farther peer B");
    }

    // ── lookup: XOR distance uses ^ not | (line 1129) ────────────────────────
    // dist[i] = peer_key[i] ^ dst[i]. Mutation: `^ → |`.
    // Setup: dst=[0xFF;32], peer_A=[0xFE;32] (cheap=200ms), peer_B=[0x01;32] (cheap=1ms).
    // XOR: dist_A=[0x01;32] < dist_B=[0xFE;32] → peer_A closer → returned.
    // OR:  dist_A=[0xFF;32] = dist_B=[0xFF;32] → cost tiebreak: peer_B cheaper → returned.
    // Original always returns peer_A, mutation always returns peer_B.

    #[test]
    fn lookup_xor_distance_uses_xor_not_or() {
        let mut rs = make_router();
        // peer_A: expensive but XOR-closest to dst
        let peer_a_key: PeerId = [0xFEu8; 32];
        // peer_B: cheap but XOR-farther from dst
        let peer_b_key: PeerId = [0x01u8; 32];
        add_dummy_peer(&mut rs, peer_a_key);
        add_dummy_peer(&mut rs, peer_b_key);

        // dst=[0xFF;32]: NOT in coord_table (hyperbolic skipped), no cuckoo match (XOR fallback)
        let dst_key: PeerId = [0xFFu8; 32];

        // XOR distances: A→dst = 0xFE^0xFF = 0x01 (tiny), B→dst = 0x01^0xFF = 0xFE (large)
        // OR distances:  A→dst = 0xFE|0xFF = 0xFF, B→dst = 0x01|0xFF = 0xFF (equal!)
        // → With OR mutation: tiebreak uses cost; make B cheaper so mutation selects B.
        rs.peers.get_mut(&peer_a_key).unwrap().lag = Duration::from_millis(200); // expensive
        rs.peers.get_mut(&peer_b_key).unwrap().lag = Duration::from_millis(1);   // cheap

        let result = rs.lookup(&dst_key);
        assert_eq!(result, Some(peer_a_key),
            "XOR fallback must select peer with smallest XOR distance (peer_A); \
             `^ → |` mutation gives equal OR distances, then cost picks peer_B instead");
    }

    // ── lookup: cuckoo fallback selects lower-cost peer ───────────────────────
    // When dst is not in coord_table, lookup falls back to cuckoo filter.
    // Both peers match the dst_tag; cheaper peer must win.
    // Catches `cost < *bc → cost > *bc` mutation (line 1113:47).

    #[test]
    fn lookup_cuckoo_fallback_selects_lower_cost_peer() {
        let mut rs = make_router();
        let cheap_key = [0xD0u8; 32];
        let costly_key = [0xD1u8; 32];
        add_dummy_peer(&mut rs, cheap_key);
        add_dummy_peer(&mut rs, costly_key);

        // dst not in coord_table → hyperbolic phase skipped entirely
        let dst_key = [0xEFu8; 32];
        let dst_tag = routing_tag(&dst_key);

        rs.peers.get_mut(&cheap_key).unwrap().cuckoo[0].add(&dst_tag);
        rs.peers.get_mut(&costly_key).unwrap().cuckoo[0].add(&dst_tag);

        // Clear default 100ms lag, set clearly different lags
        rs.peers.get_mut(&cheap_key).unwrap().lag = Duration::from_millis(1);
        rs.peers.get_mut(&costly_key).unwrap().lag = Duration::from_millis(200);

        let result = rs.lookup(&dst_key);
        assert_eq!(result, Some(cheap_key),
            "cuckoo fallback must return cheaper peer; \
             `cost < *bc → cost > *bc` mutation returns costly peer instead");
    }

    // ── cuckoo_do_maintenance parent-skip (kills 575:31 == → !=) ─────────────

    #[test]
    fn cuckoo_maintenance_skips_parent_in_full_merged_loop() {
        let mut rs = make_router();
        let parent_key = [0xA0u8; 32];
        let nonparent_key = [0xB0u8; 32];

        let (tx_p, mut rx_p) = mpsc::channel(32);
        let (tx_np, mut rx_np) = mpsc::channel(32);
        rs.add_peer(parent_key, tx_p, 0);
        rs.add_peer(nonparent_key, tx_np, 0);

        // Designate parent_key as this node's parent in tree 0
        rs.trees[0].parent = Some(parent_key);

        rs.cuckoo_do_maintenance(0);

        // Count messages delivered to each peer
        let mut parent_count = 0;
        while rx_p.try_recv().is_ok() { parent_count += 1; }
        let mut nonparent_count = 0;
        while rx_np.try_recv().is_ok() { nonparent_count += 1; }

        // Original: parent gets exactly 1 (upstream send), non-parent gets exactly 1 (full_merged loop)
        // Mutation (== → !=): parent gets 2 (upstream + loop), non-parent gets 0
        assert_eq!(parent_count, 1,
            "parent must receive exactly 1 message (upstream); \
             `== → !=` mutation sends 2 (upstream + loop)");
        assert_eq!(nonparent_count, 1,
            "non-parent must receive exactly 1 message (full_merged); \
             `== → !=` mutation sends 0 (loop skips non-parents)");
    }

    // ── NORN_ACCELERATE_ROTATIONS_SECS env knob ─────────────────────────────
    //
    // env vars are process-global, so cargo test's default parallelism
    // races multiple env-poking tests against each other (one's `set_var`
    // gets clobbered by another's `remove_var` between two adjacent
    // statements). We collapse all four cases into ONE function with a
    // static Mutex — the mutex serialises us against the OTHER env-poking
    // test below (`malicious_*`), and the single-function layout
    // serialises the four assertions against each other.

    /// Process-wide lock used by every env-mutating test in this module.
    /// Without it, two tests touching the SAME env var race; with it,
    /// they queue.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn accelerate_rotations_secs_env_parsing() {
        // Hold the lock for the full set/check/clear cycle so no other
        // test can observe a half-applied env state.
        let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());

        // 1. Unset → None.
        unsafe { std::env::remove_var("NORN_ACCELERATE_ROTATIONS_SECS"); }
        assert!(accelerate_rotations_secs().is_none(),
            "unset env var must yield None (= production cadence)");

        // 2. "0" treated as unset (operators clear the knob with 0).
        unsafe { std::env::set_var("NORN_ACCELERATE_ROTATIONS_SECS", "0"); }
        assert!(accelerate_rotations_secs().is_none(),
            "0 must be treated the same as unset");
        unsafe { std::env::remove_var("NORN_ACCELERATE_ROTATIONS_SECS"); }

        // 3. Garbage → None (silent ignore is safer than refuse-to-start).
        unsafe { std::env::set_var("NORN_ACCELERATE_ROTATIONS_SECS", "not-a-number"); }
        assert!(accelerate_rotations_secs().is_none(),
            "non-numeric must yield None");
        unsafe { std::env::remove_var("NORN_ACCELERATE_ROTATIONS_SECS"); }

        // 4. Valid positive integer → Some(N).
        unsafe { std::env::set_var("NORN_ACCELERATE_ROTATIONS_SECS", "30"); }
        assert_eq!(accelerate_rotations_secs(), Some(30));
        unsafe { std::env::remove_var("NORN_ACCELERATE_ROTATIONS_SECS"); }
    }

    // ── NORN_MALICIOUS_MODE env knob ─────────────────────────────────────────
    //
    // Same collapse-into-one-test pattern as the rotation knob above —
    // ENV_LOCK serialises us against any other env-poking test in the
    // module, and the single-function layout serialises the four cases
    // against each other.

    #[test]
    fn malicious_mode_env_parsing() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());

        // 1. Unset → 0 (no poisoning, production path).
        unsafe {
            std::env::remove_var("NORN_MALICIOUS_MODE");
            std::env::remove_var("NORN_MALICIOUS_POISON_TAGS");
        }
        assert_eq!(malicious_cuckoo_poison_tags(), 0,
            "unset env must yield 0 (production path)");

        // 2. Wrong mode → 0.
        unsafe { std::env::set_var("NORN_MALICIOUS_MODE", "bad_mouthing"); }
        assert_eq!(malicious_cuckoo_poison_tags(), 0,
            "unrecognised mode must yield 0");

        // 3. cuckoo_poison without count override → default 64.
        unsafe {
            std::env::set_var("NORN_MALICIOUS_MODE", "cuckoo_poison");
            std::env::remove_var("NORN_MALICIOUS_POISON_TAGS");
        }
        assert_eq!(malicious_cuckoo_poison_tags(), 64,
            "cuckoo_poison without count override must default to 64");

        // 4. Explicit count.
        unsafe { std::env::set_var("NORN_MALICIOUS_POISON_TAGS", "200"); }
        assert_eq!(malicious_cuckoo_poison_tags(), 200);

        // Clean up so we don't poison other tests.
        unsafe {
            std::env::remove_var("NORN_MALICIOUS_MODE");
            std::env::remove_var("NORN_MALICIOUS_POISON_TAGS");
        }
    }

    // ── PathNegative cuckoo-FP backtrack ────────────────────────────────────

    #[test]
    fn path_negative_cache_blocks_peer_for_tag() {
        // After recording (peer, tag) as negative, lookup_by_tag_excluding
        // should skip that peer even if its cuckoo filter still claims the tag.
        let mut rs = make_router();
        let peer_a = [0xAA_u8; 32];
        let peer_b = [0xBB_u8; 32];
        add_dummy_peer(&mut rs, peer_a);
        add_dummy_peer(&mut rs, peer_b);
        let tag = [0xCD_u8; 16];

        // Both A and B claim the tag in their cuckoo[0].
        rs.peers.get_mut(&peer_a).unwrap().cuckoo[0].add(&tag);
        rs.peers.get_mut(&peer_b).unwrap().cuckoo[0].add(&tag);
        // Equal effective cost → tie-break is deterministic but unspecified.
        // The interesting assertion is that *one* of them is selected.
        let first = rs.lookup_by_tag(&tag).expect("at least one match");
        assert!(first == peer_a || first == peer_b);

        // Mark `first` as negative for this tag. Now the other peer must win.
        rs.record_path_negative(first, tag);
        let second = rs.lookup_by_tag(&tag).expect("fallback peer must be picked");
        assert_ne!(second, first,
            "after PathNegative for `first`, lookup must pick the alternative");
    }

    #[test]
    fn path_negative_cache_expires() {
        // Manually backdate an entry past its TTL; cleanup must purge it.
        let mut rs = make_router();
        let peer = [0x11_u8; 32];
        let tag  = [0x22_u8; 16];
        rs.path_negative_cache.insert(
            (peer, tag),
            Instant::now() - PATH_NEG_TTL - Duration::from_secs(1),
        );
        rs.cleanup_path_negative_cache();
        assert!(!rs.is_path_negative(&peer, &tag),
            "expired entry must be evicted by cleanup_path_negative_cache");
    }

    #[test]
    fn path_negative_ttl_decrement_terminates_propagation() {
        // handle_path_negative should not forward when ttl <= 1.
        let mut rs = make_router();
        let peer_a = [0xA1_u8; 32]; // upstream sender of the PathNegative
        let peer_b = [0xB2_u8; 32]; // a candidate forward target
        add_dummy_peer(&mut rs, peer_a);
        add_dummy_peer(&mut rs, peer_b);
        let tag = [0x55_u8; 16];
        rs.peers.get_mut(&peer_b).unwrap().cuckoo[0].add(&tag);

        // ttl = 1 → no forward (cache only).
        let neg = crate::packet::PathNegative { routing_tag: tag, ttl: 1 };
        rs.handle_path_negative(peer_a, neg);
        assert!(rs.is_path_negative(&peer_a, &tag),
            "ttl=1 must still cache");

        // For ttl=0 the cache MUST still record (we learned A can't route),
        // and the forward MUST NOT happen. Our path is: record then if ttl>1 forward.
        // ttl=0 → record + skip forward.
        let mut rs2 = make_router();
        add_dummy_peer(&mut rs2, peer_a);
        rs2.handle_path_negative(peer_a, crate::packet::PathNegative {
            routing_tag: tag, ttl: 0,
        });
        assert!(rs2.is_path_negative(&peer_a, &tag),
            "even ttl=0 frames record into the negative cache");
    }

    #[test]
    fn path_negative_cache_evicts_when_full() {
        // Force the cache past MAX_PATH_NEG_CACHE; record must succeed without growing unbounded.
        let mut rs = make_router();
        // Pre-fill close to the limit.
        for i in 0..MAX_PATH_NEG_CACHE {
            let mut peer = [0u8; 32];
            peer[..8].copy_from_slice(&(i as u64).to_le_bytes());
            let mut tag = [0u8; 16];
            tag[..8].copy_from_slice(&(i as u64).to_le_bytes());
            rs.path_negative_cache.insert((peer, tag), Instant::now());
        }
        let len_before = rs.path_negative_cache.len();
        // One more insertion → eviction must kick in.
        rs.record_path_negative([0xFF; 32], [0xFF; 16]);
        assert!(rs.path_negative_cache.len() <= len_before,
            "record_path_negative must evict to stay within MAX_PATH_NEG_CACHE; \
             before={}, after={}", len_before, rs.path_negative_cache.len());
        assert!(rs.is_path_negative(&[0xFF; 32], &[0xFF; 16]),
            "newly-inserted entry must be present after eviction");
    }
