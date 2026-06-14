//! `coords` methods of RouterState, split from router/mod.rs.
use super::*;

impl RouterState {
    /// Recompute our own hyperbolic coordinate from current depth.
    // Skip mutations: coordinates feed into hyperbolic routing which requires
    // a multi-hop test to verify greedy forwarding is affected.
    #[mutants::skip]
    pub(crate) fn update_own_coord(&mut self) {
        self.own_coord = HypCoord::from_tree_depth(self.own_depth, &self.pub_key);
        self.coord_table.insert(self.pub_key, self.own_coord);
    }

    /// Broadcast our hyperbolic coordinate + onion ephemeral pub to all peers.
    #[mutants::skip]
    pub(crate) fn broadcast_coord(&mut self) {
        let coord_bytes = self.own_coord.encode();
        let onion_eph_pub = *self.onion_keys.pub_key().as_bytes();
        let unsigned = CoordAnnounce {
            version: COORD_FORMAT_V4,
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

        // ── Consistency check #1: coord MUST equal from_tree_depth(depth, pub_key).
        //
        // Coords are a deterministic function of (tree_depth, pub_key), so the
        // sender cannot legitimately pick a coord independent of those two
        // inputs. Allowing arbitrary self-reported coords lets a malicious peer
        // place itself near any target, biasing greedy routing toward
        // themselves (sinkhole). We reject any mismatch.
        let expected = HypCoord::from_tree_depth(ann.tree_depth, &from_key);
        if !coords_approx_equal(&coord, &expected) {
            warn!(
                "coord announce from {:?} inconsistent with from_tree_depth(depth={}); rejecting",
                &from_key[..4], ann.tree_depth
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
