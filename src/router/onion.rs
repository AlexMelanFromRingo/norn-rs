//! Onion forwarding/peeling + routing-tag lookup methods of RouterState,
//! split from router/mod.rs.
use super::*;

impl RouterState {
    /// Handle an incoming OnionPacket addressed to this node.
    pub fn handle_onion(&mut self, from: PeerId, pkt: OnionPacket) {
        if let Some(peer) = self.peers.get_mut(&from) {
            peer.last_rx_time = Instant::now();
        }

        // Onion replay check: drop packets whose (epk, first AEAD bytes) hash
        // we've recently seen. Replays would let a tagging attacker confirm
        // path participation by re-injecting captured cells.
        if self.is_onion_replay(&pkt) {
            debug!("onion peel: replay detected, dropping");
            return;
        }

        match pkt.peel(&self.onion_keys) {
            Ok(PeeledOnion::Forward(inner_bytes)) => {
                // We are a relay: decode the next layer and forward it
                match OnionPacket::decode(&inner_bytes) {
                    Ok(inner) => {
                        let tag = inner.routing_tag;
                        let encoded = inner.encode();
                        if let Some(next) = self.lookup_by_tag_excluding(&tag, Some(from)) {
                            self.send_to_peer(&next, encoded);
                        } else {
                            debug!("onion: no route for next tag {:?}", &tag[..4]);
                            self.send_path_negative(from, tag, PATH_NEG_INITIAL_TTL);
                        }
                    }
                    Err(e) => debug!("onion: failed to decode inner layer: {}", e),
                }
            }
            Ok(PeeledOnion::Deliver(traffic_bytes)) => {
                // We are the exit relay: dispatch the inner Traffic packet
                if traffic_bytes.is_empty() {
                    return;
                }
                // traffic_bytes starts with TRAFFIC type byte; re-use dispatch
                let ptype = traffic_bytes[0];
                if ptype == TRAFFIC {
                    match Traffic::decode(&traffic_bytes[1..]) {
                        Ok(traffic) => self.handle_traffic(from, traffic),
                        Err(e) => debug!("onion: inner Traffic decode failed: {}", e),
                    }
                }
            }
            Err(e) => {
                debug!("onion peel failed from {:?}: {}", &from[..4], e);
            }
        }
    }

    /// Has this onion packet's tag been seen recently? If not, record it.
    /// We hash (epk || first 16 bytes of aead_payload) into a 32-byte BLAKE2b
    /// digest — collision-resistant and cheap. The cache is an LRU bounded by
    /// ONION_REPLAY_CACHE_SIZE.
    #[mutants::skip]
    pub(crate) fn is_onion_replay(&mut self, pkt: &OnionPacket) -> bool {
        use blake2::{Blake2b, Digest};
        use blake2::digest::consts::U32;
        let mut h: Blake2b<U32> = Blake2b::new();
        h.update(b"norn:onion-replay");
        h.update(pkt.epk);
        let prefix_len = pkt.aead_payload.len().min(16);
        h.update(&pkt.aead_payload[..prefix_len]);
        self.onion_digest_seen(h.finalize().into())
    }

    /// Record an onion replay digest; returns true if it was already seen.
    /// Shared by the legacy onion and the Sphinx-style cell. O(1) membership via
    /// the HashSet mirror; FIFO-evicted by `onion_seen` (bounded by
    /// ONION_REPLAY_CACHE_SIZE). `insert` returns false iff already present.
    pub(crate) fn onion_digest_seen(&mut self, digest: [u8; 32]) -> bool {
        if !self.onion_seen_set.insert(digest) {
            return true;
        }
        if self.onion_seen.len() >= ONION_REPLAY_CACHE_SIZE
            && let Some(evicted) = self.onion_seen.pop_front() {
            self.onion_seen_set.remove(&evicted);
        }
        self.onion_seen.push_back(digest);
        false
    }

    /// Handle an inbound Sphinx-style onion cell addressed to us (the dispatch
    /// already matched the cleartext routing tag). Mirrors [`Self::handle_onion`]:
    /// replay-check, MAC-authenticate + peel one layer, then forward the
    /// constant-size cell toward the next tag or deliver the inner Traffic packet.
    #[cfg(feature = "sphinx")]
    pub fn handle_sphinx(&mut self, from: PeerId, cell: Vec<u8>) {
        if let Some(peer) = self.peers.get_mut(&from) {
            peer.last_rx_time = Instant::now();
        }
        if let Some(digest) = crate::sphinx::replay_digest(&cell)
            && self.onion_digest_seen(digest) {
            debug!("sphinx: replay detected, dropping");
            return;
        }
        match crate::sphinx::process_sphinx(&cell, &self.onion_keys.sphinx_privs()) {
            Ok(crate::sphinx::SphinxPeeled::Forward { next_tag, cell }) => {
                if let Some(next) = self.lookup_by_tag_excluding(&next_tag, Some(from)) {
                    self.send_to_peer(&next, cell);
                } else {
                    debug!("sphinx: no route for next tag {:?}", &next_tag[..4]);
                    self.send_path_negative(from, next_tag, PATH_NEG_INITIAL_TTL);
                }
            }
            Ok(crate::sphinx::SphinxPeeled::Deliver(traffic_bytes)) => {
                if traffic_bytes.first() == Some(&TRAFFIC) {
                    match Traffic::decode(&traffic_bytes[1..]) {
                        Ok(traffic) => self.handle_traffic(from, traffic),
                        Err(e) => debug!("sphinx: inner Traffic decode failed: {}", e),
                    }
                }
            }
            Err(e) => debug!("sphinx process failed from {:?}: {}", &from[..4], e),
        }
    }

    /// Route lookup using only the 16-byte routing_tag (for forwarding Traffic
    /// where the full dest pub key is not known to intermediate nodes).
    #[cfg(test)]
    pub(crate) fn lookup_by_tag(&self, tag: &[u8; 16]) -> Option<PeerId> {
        self.lookup_by_tag_excluding(tag, None)
    }

    /// Same as `lookup_by_tag` but skips a specified peer. Used when forwarding
    /// to avoid bouncing a packet back to the peer it just came from — without
    /// this, cuckoo gossip (which naturally propagates each tag in both
    /// directions) creates trivial 2-cycles.
    ///
    /// Ranking uses *trust-adjusted* cost: peers that have failed past route
    /// probes get a higher effective cost and are pushed to the back of the
    /// queue. This mitigates cuckoo poisoning — a peer that lies about
    /// reachable tags will see its trust decay and stop being chosen.
    pub(crate) fn lookup_by_tag_excluding(&self, tag: &[u8; 16], exclude: Option<PeerId>) -> Option<PeerId> {
        let mut best: Option<(PeerId, u64)> = None;
        for (peer_key, peer) in &self.peers {
            if exclude == Some(*peer_key) {
                continue;
            }
            // Skip peers that recently sent us a PathNegative for this tag —
            // their cuckoo claim is a known false positive.
            if self.is_path_negative(peer_key, tag) {
                continue;
            }
            for tree_id in 0..K {
                if peer.cuckoo[tree_id].contains(tag) {
                    // Combine local trust with network-consensus trust if
                    // available; consensus = NULL → use local trust alone.
                    let local = peer.trust;
                    let combined = match self.consensus_trust(peer_key) {
                        Some(c) => (local + c) * 0.5,
                        None    => local,
                    };
                    let cost = peer.trust_adjusted_cost_with(combined);
                    let better = best.is_none_or(|(_, bc)| cost < bc);
                    if better {
                        best = Some((*peer_key, cost));
                    }
                    break;
                }
            }
        }
        best.map(|(k, _)| k)
    }
}
