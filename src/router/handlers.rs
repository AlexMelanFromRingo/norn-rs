//! `handlers` methods of RouterState, split from router/mod.rs.
use super::*;

impl RouterState {
    pub fn handle_sig_req(&mut self, from: PeerId, req: SigReq) {
        // Update last_rx_time
        if let Some(peer) = self.peers.get_mut(&from) {
            peer.last_rx_time = Instant::now();
        }

        // Respond with SigRes
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        // Sign: (tree_id || seq || timestamp_ms || req_pub_key)
        let mut sign_data = vec![req.tree_id];
        let mut tmp = Vec::new();
        encode_uvarint(req.seq, &mut tmp);
        sign_data.extend_from_slice(&tmp);
        tmp.clear();
        encode_uvarint(now_ms, &mut tmp);
        sign_data.extend_from_slice(&tmp);
        sign_data.extend_from_slice(&req.pub_key);
        let signature = self.signing_key.sign(&sign_data).to_bytes();

        let res = SigRes {
            tree_id: req.tree_id,
            seq: req.seq,
            timestamp_ms: now_ms,
            signature,
            pub_key: self.pub_key,
        };
        let encoded = res.encode();
        self.send_to_peer(&from, encoded);
    }

    pub fn handle_sig_res(&mut self, from: PeerId, res: SigRes) {
        // Verify the SigRes signature before using the timestamp for RTT measurement.
        // Without this check an attacker could forge SigRes with a crafted timestamp_ms
        // to manipulate our lag estimate and fool the parent-selection algorithm.
        let vk = match VerifyingKey::from_bytes(&res.pub_key) {
            Ok(v) => v,
            Err(_) => { warn!("sig_res: invalid pub_key from {:?}", &from[..4]); return; }
        };
        let mut sign_data = vec![res.tree_id];
        let mut tmp = Vec::new();
        encode_uvarint(res.seq, &mut tmp);
        sign_data.extend_from_slice(&tmp);
        tmp.clear();
        encode_uvarint(res.timestamp_ms, &mut tmp);
        sign_data.extend_from_slice(&tmp);
        // The responder signed over req.pub_key, which is OUR pub key (we sent it in the SigReq).
        sign_data.extend_from_slice(&self.pub_key);
        let sig = ed25519_dalek::Signature::from_bytes(&res.signature);
        if vk.verify_strict(&sign_data, &sig).is_err() {
            warn!("sig_res: bad signature from {:?}", &from[..4]);
            return;
        }

        if let Some(peer) = self.peers.get_mut(&from) {
            peer.last_rx_time = Instant::now();
            // Measure RTT and update loss rate EWMA
            if let Some((pending_seq, sent_time)) = peer.pending_sig_req_time.take()
                && pending_seq == res.seq {
                    let rtt = Instant::now().duration_since(sent_time);
                    let new_lag = rtt / 2;
                    let old_lag_us = peer.lag.as_micros() as i64;
                    let new_lag_us = new_lag.as_micros() as i64;
                    let diff = (new_lag_us - old_lag_us).unsigned_abs();
                    peer.jitter = Duration::from_micros(
                        (peer.jitter.as_micros() as u64 * 7 / 8) + diff / 8
                    );
                    peer.lag = Duration::from_micros(
                        (old_lag_us as u64 * 7 / 8) + new_lag_us as u64 / 8
                    );
                    peer.loss_rate *= 0.875;
                    // Liveness probe succeeded → boost trust slightly.
                    peer.boost_trust();
                }
        }
    }

    pub fn handle_announce(&mut self, from: PeerId, ann: Announce) {
        // Verify signature
        let vk = match VerifyingKey::from_bytes(&ann.sender) {
            Ok(v) => v,
            Err(_) => return,
        };
        let sign_bytes = ann.sign_bytes();
        let sig = ed25519_dalek::Signature::from_bytes(&ann.signature);
        if vk.verify_strict(&sign_bytes, &sig).is_err() {
            warn!("invalid announce signature from {:?}", &from[..4]);
            return;
        }

        let tree_id = ann.tree_id as usize;
        if tree_id >= K {
            return;
        }

        let mut structural_change = false;
        if let Some(peer) = self.peers.get_mut(&from) {
            peer.last_rx_time = Instant::now();
            // Detect a STRUCTURAL change (root or depth) — not path_cost, which
            // jitters every announce on real links and would pin us at MIN
            // cadence forever. Cost-jitter parent flapping is handled by the
            // fix_tree hysteresis; here we only want genuine tree churn to keep
            // the convergence freshness floor engaged (B-step-3 §2.3).
            structural_change = match &peer.trees[tree_id] {
                Some(prev) => prev.root != ann.root || prev.depth != ann.depth,
                None => true,
            };
            peer.trees[tree_id] = Some(TreeAnnounce {
                root: ann.root,
                path_cost: ann.path_cost,
                received_at: Instant::now(),
                depth: ann.depth,
            });
        }
        if structural_change {
            // A neighbour's tree state moved — keep announcing at MIN so it gets
            // our state promptly while it converges.
            self.last_topology_change_tick = self.tick;
        }
        self.update_landmarks();
    }

    pub fn handle_cuckoo(&mut self, from: PeerId, msg: CuckooMsg) {
        let tree_id = msg.tree_id as usize;
        if tree_id >= K {
            return;
        }
        if let Some(peer) = self.peers.get_mut(&from) {
            peer.last_rx_time = Instant::now();
            if msg.generation > peer.peer_cuckoo_gen[tree_id] {
                // New generation: replace filter entirely — evicts stale entries
                // from nodes that have disconnected from the sender's side.
                peer.peer_cuckoo_gen[tree_id] = msg.generation;
                peer.cuckoo[tree_id] = CuckooFilter::decode(&msg.data);
            } else {
                // Same generation: replace with sender's current view.
                peer.cuckoo[tree_id] = CuckooFilter::decode(&msg.data);
            }
        }
    }

    // Skip mutations: complex forwarding logic (cuckoo lookup, landmark flood,
    // path tracking) requiring a multi-peer integration harness to verify routing.
    #[mutants::skip]
    pub fn handle_path_lookup(&mut self, from: PeerId, lookup: PathLookup) {
        // Dedup + DoS protection: cap pending_lookups to prevent memory exhaustion
        if self.pending_lookups.contains_key(&lookup.id) {
            return;
        }
        if self.pending_lookups.len() >= MAX_PENDING_LOOKUPS {
            debug!("handle_path_lookup: pending_lookups full, dropping lookup {}", lookup.id);
            return;
        }
        self.pending_lookups.insert(lookup.id, Instant::now());

        // Check if target is us
        if lookup.target == self.pub_key {
            // Send PathNotify back
            let notify = PathNotify {
                target: self.pub_key,
                source: lookup.source,
                id: lookup.id,
                path: lookup.path.clone(),
            };
            let encoded = notify.encode();
            // Send back to source along reverse path (simplified: send to from)
            self.send_to_peer(&from, encoded);
            return;
        }

        // Check cuckoo filters for all peers — filters store routing_tags, not raw keys
        let target_tag = routing_tag(&lookup.target);
        let mut candidates: Vec<(PeerId, u64)> = Vec::new();
        for (peer_key, peer) in &self.peers {
            for tree_id in 0..K {
                if peer.cuckoo[tree_id].contains(&target_tag) {
                    let cost = peer.effective_cost();
                    candidates.push((*peer_key, cost));
                    break;
                }
            }
        }

        if !candidates.is_empty() {
            // Forward to best candidate
            candidates.sort_by_key(|(_, c)| *c);
            let (best_peer, _) = candidates[0];
            let mut fwd = lookup.clone();
            fwd.path.push(0); // simplified path tracking
            let encoded = fwd.encode();
            self.send_to_peer(&best_peer, encoded);
        } else {
            // Fallback: send to all landmarks
            let landmarks: Vec<[u8; 32]> = self.landmarks.iter().copied().collect();
            for lm in landmarks {
                if lm != from {
                    let encoded = lookup.encode();
                    self.send_to_peer(&lm, encoded);
                }
            }
            // If no landmarks, flood to all peers except from
            if self.landmarks.is_empty() {
                let peer_keys: Vec<PeerId> = self.peers.keys().copied().collect();
                for pk in peer_keys {
                    if pk != from {
                        let encoded = lookup.encode();
                        self.send_to_peer(&pk, encoded);
                    }
                }
            }
        }
    }

    // Skip mutations: path forwarding with async callback (tokio::spawn) —
    // verifying the callback fires requires an async test harness.
    #[mutants::skip]
    pub fn handle_path_notify(&mut self, from: PeerId, notify: PathNotify) {
        if let Some(peer) = self.peers.get_mut(&from) {
            peer.last_rx_time = Instant::now();
        }

        // If notify is for us, trigger path_notify callback
        if notify.source == self.pub_key {
            // Was this the response to an outstanding probe? If so, boost
            // the via-peer's trust (it actually delivered what its cuckoo claimed).
            if let Some((via, _sent_at)) = self.pending_probes.remove(&notify.id)
                && let Some(peer) = self.peers.get_mut(&via) {
                peer.boost_trust();
                debug!(
                    "probe {} via {:?} confirmed (target={:?}) → trust boosted to {}",
                    notify.id, &via[..4], &notify.target[..4], peer.trust
                );
            }
            if let Some(cb) = &self.path_notify {
                let cb = cb.clone();
                let target = notify.target;
                tokio::spawn(async move { cb(target) });
            }
            return;
        }

        // Forward towards source
        if let Some(next_hop) = self.lookup(&notify.source) {
            let encoded = notify.encode();
            self.send_to_peer(&next_hop, encoded);
        }
    }

    // Skip mutations: broken-path forwarding — mutation detection requires tracing
    // a packet through multiple forwarding hops in a live network.
    #[mutants::skip]
    pub fn handle_path_broken(&mut self, from: PeerId, broken: PathBroken) {
        if let Some(peer) = self.peers.get_mut(&from) {
            peer.last_rx_time = Instant::now();
        }
        // Forward towards source
        if broken.source != self.pub_key
            && let Some(next_hop) = self.lookup(&broken.source) {
                let encoded = broken.encode();
                self.send_to_peer(&next_hop, encoded);
            }
    }

    // Skip mutations: session decryption, unpad, routing, and callback dispatch —
    // requires a full two-node integration test with an established session.
    #[mutants::skip]
    pub fn handle_traffic(&mut self, from: PeerId, traffic: Traffic) {
        if let Some(peer) = self.peers.get_mut(&from) {
            peer.last_rx_time = Instant::now();
            peer.rx_bytes += traffic.payload.len() as u64;
        }

        // Determine if this packet is addressed to us by comparing routing tags.
        let my_tag = routing_tag(&self.pub_key);
        if routing_tag_eq(&traffic.routing_tag, &my_tag) {
            match traffic.pkt_type {
                packet::PKT_CONTROL => {
                    // Session control — padded, NOT session-encrypted.
                    let raw = match unpad_payload(&traffic.payload) {
                        Ok(b) => b,
                        Err(e) => {
                            debug!("unpad control payload failed: {}", e);
                            return;
                        }
                    };
                    if raw.first().copied() == Some(SESSION_INIT_MAGIC) {
                        let ack_opt = self.sessions.write_or_recover().handle_init(&raw).ok();
                        if let Some(ack_bytes) = ack_opt
                            && raw.len() >= 33 {
                                let mut sender = [0u8; 32];
                                sender.copy_from_slice(&raw[1..33]);
                                self.send_traffic_to(&sender, ack_bytes);
                            }
                    } else if raw.first().copied() == Some(SESSION_ACK_MAGIC) {
                        let _ = self.sessions.write_or_recover().handle_ack(&raw);
                    }
                }
                packet::PKT_DATA => {
                    // Session-encrypted data: decrypt enc_header → identify source →
                    // session-decrypt payload → unpad → deliver.
                    let source = match decrypt_source_from_header(&traffic.enc_header, &self.signing_key) {
                        Some(s) => s,
                        None => {
                            debug!("failed to decrypt enc_header from {:?}", &from[..4]);
                            return;
                        }
                    };
                    // Hot path: acquire the SessionManager mutex
                    // only long enough to clone the per-peer
                    // `SessionHandle`, then drop it before the
                    // ChaCha20-Poly1305 work. That way N peers can
                    // decrypt on N cores concurrently — the
                    // contended part is the hashmap lookup, not
                    // the AEAD (Roadmap #2).
                    let handle = self
                        .sessions
                        .read_or_recover()
                        .get_session(&source);
                    let padded_pt = match handle {
                        Some(h) => match h.lock().unwrap().decrypt(&traffic.payload) {
                            Ok(d) => d,
                            Err(e) => {
                                debug!("session decrypt failed from {:?}: {}", &source[..4], e);
                                return;
                            }
                        },
                        None => {
                            debug!("session decrypt: no session for {:?}", &source[..4]);
                            return;
                        }
                    };
                    let payload = match unpad_payload(&padded_pt) {
                        Ok(p) => p,
                        Err(e) => {
                            debug!("unpad plaintext failed: {}", e);
                            return;
                        }
                    };
                    let pkt = InboundPacket { from: source, payload };
                    if self.traffic_tx.try_send(pkt).is_err() {
                        warn!("traffic_rx channel full, dropping inbound packet from {:?}", &source[..4]);
                    }
                }
                t => {
                    debug!("unknown pkt_type {} from {:?}", t, &from[..4]);
                }
            }
        } else {
            // Transit forwarding. enc_header is opaque to us, but the source
            // may have stamped the destination's coordinate so we can route by
            // geometry instead of leaning entirely on cuckoo reachability.

            // TTL: use the previously-unused `watermark` field as a per-packet
            // hop counter. Senders MUST initialise it to 0. Each forwarder
            // increments. Drop when MAX_FORWARD_HOPS is reached.
            // Without this guard, two peers with disagreeing cuckoo state can
            // forward the same packet back-and-forth forever.
            if traffic.watermark >= MAX_FORWARD_HOPS as u64 {
                debug!("forward dropped: ttl exceeded ({} hops)", traffic.watermark);
                // Tell upstream so it stops sending us packets that loop —
                // this is the cuckoo-FP / dead-end backtrack channel.
                self.send_path_negative(from, traffic.routing_tag, PATH_NEG_INITIAL_TTL);
                return;
            }

            // PRIMARY: greedy hyperbolic toward the stamped dest_coord —
            // loop-free (strictly decreasing distance), so it can't trigger the
            // micro-loop → TTL → PathNegative-poison cycle that cuckoo-only
            // transit suffered on a quiescent tree.
            // FALLBACK: cuckoo reachability on routing_tag (local minimum, or
            // the source didn't stamp a coord). Excluding `from` avoids the
            // trivial 2-cycle that bidirectional cuckoo gossip routinely makes.
            let next_hop = traffic.dest_coord
                .map(|c| HypCoord::decode(&c))
                .and_then(|dc| self.greedy_next_hop(dc, Some(from)))
                .or_else(|| self.lookup_by_tag_excluding(&traffic.routing_tag, Some(from)));

            if let Some(next_hop) = next_hop {
                let mut fwd = traffic;
                fwd.watermark = fwd.watermark.saturating_add(1);
                // Re-stamp the immediate-sender field so downstream peers see
                // *us* as the upstream hop, not the original source. Without
                // this the original source's pub_key leaks at every hop,
                // defeating the source-privacy that enc_header is supposed
                // to provide.
                fwd.from = self.pub_key;
                let encoded = fwd.encode();
                self.send_to_peer(&next_hop, encoded);
            } else {
                debug!("no route for routing_tag {:?}", &traffic.routing_tag[..4]);
                CUCKOO_NO_ROUTE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                // Backtrack: normally tell upstream we have no neighbour for this
                // tag so it caches (us, tag) and tries elsewhere. BUT during the
                // convergence grace window a "no route" is almost always a
                // transient aggregation hole while the tree re-settles, not a
                // genuine dead-end (B-step-3 §4.1). Poisoning it adds churn and,
                // on a no-alternative-path topology (chain/star), black-holes the
                // tag for PATH_NEG_TTL. So suppress the poison while convergence
                // is active and rely on the sender's natural retry (every 100 ms)
                // to catch the route once cuckoo fills in; after the window a
                // "no route" is treated as a real dead-end and poisoned as before.
                if !self.convergence_active() {
                    let tag = traffic.routing_tag;
                    self.send_path_negative(from, tag, PATH_NEG_INITIAL_TTL);
                }
            }
        }
    }

    /// Send a session-control payload (SessionInit / SessionAck) wrapped in a
    /// Traffic packet to `dst`.
    ///
    /// Control payloads are NOT session-encrypted (they carry ed25519 signatures).
    /// pkt_type = PKT_CONTROL (0x00). Payload is padded to normalise packet sizes.
    pub(crate) fn send_traffic_to(&mut self, dst: &PeerId, payload: Vec<u8>) {
        let src = self.pub_key;
        let (enc_header, tag) = encrypt_header(&src, dst);
        let padded = pad_payload(&payload);
        let traffic = Traffic {
            path: vec![],
            from: src,
            enc_header,
            routing_tag: tag,
            pkt_type: packet::PKT_CONTROL,
            dest_coord: self.coord_table.get(dst).map(|c| c.encode()),
            watermark: 0,
            payload: padded,
        };
        let encoded = traffic.encode();
        if let Some(next_hop) = self.lookup(dst) {
            self.send_to_peer(&next_hop, encoded);
        }
    }

    /// Greedy hyperbolic next-hop toward `dst_coord`: the neighbour strictly
    /// closer to it than we are, excluding `exclude` (the inbound peer, so we
    /// never bounce a packet straight back). `None` at a local minimum — no
    /// neighbour improves — so the caller can fall back to cuckoo reachability.
    ///
    /// Loop-free by construction: every hop it chooses strictly decreases the
    /// distance to `dst_coord`, so a packet cannot cycle through greedy hops.
    /// This is what lets TRANSIT nodes route by geometry (see `handle_traffic`)
    /// instead of leaning entirely on cuckoo freshness.
    pub(crate) fn greedy_next_hop(&self, dst_coord: HypCoord, exclude: Option<PeerId>) -> Option<PeerId> {
        let mut best_peer: Option<PeerId> = None;
        let mut best_dist = self.own_coord.distance(dst_coord); // must strictly improve
        for (peer_key, peer) in &self.peers {
            if exclude == Some(*peer_key) {
                continue;
            }
            if let Some(&peer_coord) = self.coord_table.get(&peer.pub_key) {
                let d = peer_coord.distance(dst_coord);
                if d < best_dist {
                    best_dist = d;
                    best_peer = Some(*peer_key);
                }
            }
        }
        best_peer
    }

    /// Greedy routing: find best next-hop for destination across all K trees.
    /// Hyperbolic greedy routing is tried first; falls back to cuckoo/XOR.
    pub fn lookup(&self, dst: &PeerId) -> Option<PeerId> {
        // ── Hyperbolic greedy routing (primary) ────────────────────────────
        // We know `dst`'s pub key, so we can read its coord directly.
        if let Some(&dst_coord) = self.coord_table.get(dst)
            && let Some(p) = self.greedy_next_hop(dst_coord, None) {
            return Some(p);
        }
        // No closer neighbour (local minimum / we ARE the destination / single
        // same-coord peer) — let the cuckoo fallback decide.

        // ── Cuckoo-filter lookup (fallback) ────────────────────────────────
        // Filters store routing_tags, not raw pub keys.
        let dst_tag = routing_tag(dst);
        let mut best: Option<(PeerId, u64)> = None;

        for (peer_key, peer) in &self.peers {
            for tree_id in 0..K {
                if peer.cuckoo[tree_id].contains(&dst_tag) {
                    let cost = peer.effective_cost();
                    let better = match &best {
                        None => true,
                        Some((_, bc)) => cost < *bc,
                    };
                    if better {
                        best = Some((*peer_key, cost));
                    }
                    break;
                }
            }
        }

        // ── XOR-distance last-resort ────────────────────────────────────────
        if best.is_none() {
            let mut best_dist: Option<([u8; 32], u64)> = None;
            for (peer_key, peer) in &self.peers {
                let mut dist = [0u8; 32];
                for i in 0..32 {
                    dist[i] = peer_key[i] ^ dst[i];
                }
                let cost = peer.effective_cost();
                let better = match &best_dist {
                    None => true,
                    Some((bd, bc)) => dist < *bd || (dist == *bd && cost < *bc),
                };
                if better {
                    best_dist = Some((dist, cost));
                    best = Some((*peer_key, cost));
                }
            }
        }

        best.map(|(k, _)| k)
    }
}
