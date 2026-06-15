//! `coords` methods of RouterState, split from router/mod.rs.
use super::*;

impl RouterState {
    /// Recompute our own hyperbolic coordinate from current depth.
    // Skip mutations: coordinates feed into hyperbolic routing which requires
    // a multi-hop test to verify greedy forwarding is affected.
    #[mutants::skip]
    pub(crate) fn update_own_coord(&mut self) {
        // v5 greedy embedding: θ derives from our PARENT's θ (a one-hop
        // neighbour, so its coord is in coord_table) — descendants cluster under
        // their ancestor, giving greedy a gradient. Root / not-yet-known parent
        // → parent_theta = 0 (and depth 0 → origin); θ converges as the parent's
        // CoordAnnounce arrives, exactly like depth converges.
        let parent_theta = self.trees[0].parent
            .and_then(|p| self.coord_table.get(&p))
            .map(|c| c.theta)
            .unwrap_or(0.0);
        self.own_coord =
            HypCoord::from_tree_position(self.own_depth, parent_theta, &self.pub_key);
        self.coord_table.insert(self.pub_key, self.own_coord);
        // Push the fresh coord into the session layer so outbound SessionInit/Ack
        // advertise our current position (Phase 2 coord dissemination).
        self.sessions.write_or_recover().set_own_coord(self.own_coord.encode());
    }

    /// Record a peer's hyperbolic coord learned from a session handshake
    /// (Phase 2). This is what makes greedy work multi-hop: once we know the
    /// destination's coord we stamp it as `dest_coord` on Traffic so transit
    /// nodes route greedily. Advisory — beyond the handshake's identity auth the
    /// coord is unverified (we don't know the peer's depth here), so a bogus
    /// coord only degrades greedy to the cuckoo fallback and is caught by the
    /// trust/probing defence. O(active sessions); respects the coord-table cap.
    pub(crate) fn note_peer_coord(&mut self, peer: [u8; 32], coord_bytes: [u8; 16]) {
        let coord = HypCoord::decode(&coord_bytes);
        if !coord.rho.is_finite() || !coord.theta.is_finite() {
            return;
        }
        if self.coord_table.len() >= MAX_COORD_TABLE_SIZE
            && !self.coord_table.contains_key(&peer)
        {
            let victim = self.coord_table.keys()
                .find(|k| !self.peers.contains_key(*k) && **k != self.pub_key)
                .copied();
            match victim {
                Some(v) => { self.coord_table.remove(&v); }
                None => return,
            }
        }
        self.coord_table.insert(peer, coord);
    }

    /// Broadcast our hyperbolic coordinate + onion ephemeral pub to all peers.
    #[mutants::skip]
    pub(crate) fn broadcast_coord(&mut self) {
        let coord_bytes = self.own_coord.encode();
        let onion_eph_pub = *self.onion_keys.pub_key().as_bytes();
        let unsigned = CoordAnnounce {
            version: COORD_FORMAT_V5,
            coord: coord_bytes,
            tree_depth: self.own_depth,
            onion_eph_pub,
            sig: [0u8; 64],
        };
        let sig = self.signing_key.sign(&unsigned.sign_bytes()).to_bytes();
        let ann = CoordAnnounce { sig, ..unsigned };
        let mut frame = vec![TYPE_COORD_ANNOUNCE];
        ann.encode_into(&mut frame);
        let peer_keys: Vec<PeerId> = self.peers.keys().copied().collect();
        for pk in peer_keys {
            self.send_to_peer(&pk, frame.clone());
        }
    }

    /// Handle an incoming CoordAnnounce from a peer.
    #[mutants::skip]
    pub fn handle_coord_announce(&mut self, from_key: [u8; 32], ann: CoordAnnounce) {
        let vk = match ed25519_dalek::VerifyingKey::from_bytes(&from_key) {
            Ok(v) => v,
            Err(_) => return,
        };
        let sig = ed25519_dalek::Signature::from_bytes(&ann.sig);
        if vk.verify_strict(&ann.sign_bytes(), &sig).is_err() {
            warn!("invalid coord announce signature from {:?}", &from_key[..4]);
            return;
        }
        let coord = HypCoord::decode(&ann.coord);
        if !coord.rho.is_finite() || !coord.theta.is_finite() {
            warn!("coord announce from {:?} has non-finite values, ignoring", &from_key[..4]);
            return;
        }

        // ── Consistency check #1: rho MUST match the depth-derived value.
        //
        // In the v5 greedy embedding θ is tree-position-derived (parent's θ + a
        // per-node offset), so a verifier cannot recompute the announcer's θ
        // without its parent context — θ is therefore accepted as advisory (a
        // greedy hint). rho stays strictly depth-bound and is verified here:
        // cheap, and it stops a peer claiming an artificially shallow/deep radial
        // position. A peer that lies about θ to attract greedy traffic and then
        // drops it is caught by the SAME per-peer trust-decay + active-probing
        // machinery that already defeats cuckoo-filter poisoning (measured ~30×
        // effective-cost increase against a planted attacker; see README).
        let expected_rho = HypCoord::from_tree_position(ann.tree_depth, 0.0, &from_key).rho;
        if (coord.rho - expected_rho).abs() > 1e-9 {
            warn!(
                "coord announce from {:?} rho {} inconsistent with depth {} (expected {}); rejecting",
                &from_key[..4], coord.rho, ann.tree_depth, expected_rho
            );
            // Treat as a soft-fail trust signal too.
            if let Some(peer) = self.peers.get_mut(&from_key) {
                peer.decay_trust();
            }
            return;
        }

        // ── Consistency check #2: tree_depth in the announce MUST agree with
        // the tree-0 Announce we have on file from the same peer (within a
        // small window to tolerate gossip lag). A peer claiming depth=0 in
        // CoordAnnounce but depth=5 in Announce is lying about its position.
        if let Some(peer) = self.peers.get(&from_key)
            && let Some(t0) = &peer.trees[0] {
            let announced = t0.depth as i64;
            let claimed = ann.tree_depth as i64;
            // Allow ±2 to accommodate transient mid-update races.
            if (announced - claimed).abs() > 2 {
                warn!(
                    "coord announce from {:?} claims tree-0 depth {}, but Announce says {}; rejecting",
                    &from_key[..4], claimed, announced
                );
                if let Some(peer) = self.peers.get_mut(&from_key) {
                    peer.decay_trust();
                }
                return;
            }
        }
        if self.coord_table.len() >= MAX_COORD_TABLE_SIZE
            && !self.coord_table.contains_key(&from_key) {
            let victim = self.coord_table.keys()
                .find(|k| !self.peers.contains_key(*k) && **k != self.pub_key)
                .copied();
            if let Some(v) = victim {
                self.coord_table.remove(&v);
            } else {
                return;
            }
        }
        self.coord_table.insert(from_key, coord);

        // Record the peer's *current* advertised onion ephemeral pub. Onion
        // packets built for this peer as a relay will encrypt to this key
        // rather than the long-term-identity-derived key, giving forward
        // secrecy once the peer rotates.
        if let Some(peer) = self.peers.get_mut(&from_key) {
            peer.onion_eph_pub = Some(ann.onion_eph_pub);
        }
    }
}
