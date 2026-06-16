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
        // Two candidate classes, both ranked by trust-adjusted cost:
        //   `best`     — peers that have NOT recently sent a PathNegative;
        //   `best_neg` — peers under a PathNegative (a *known recent* "can't
        //                reach this tag" — usually a cuckoo false positive, but
        //                during tree convergence it can be a transient gap).
        //
        // A PathNegative DEPRIORITISES a peer; it must not hard-exclude it.
        // Hard exclusion blackholes the only path in any topology without an
        // alternate (e.g. a linear chain: the upstream peer is the sole route
        // to everything beyond it), so one transient convergence gap could
        // wedge a destination for the full PATH_NEG_TTL. Preferring a
        // non-negative claimer keeps the cuckoo-poisoning defence (route around
        // a lying peer whenever an alternative exists); falling back to the
        // cheapest negative one only when there is NO alternative trades a
        // possibly-stale retry (self-heals, and trust-decay still punishes a
        // genuine liar) for never black-holing.
        let mut best: Option<(PeerId, u64)> = None;
        let mut best_neg: Option<(PeerId, u64)> = None;
        for (peer_key, peer) in &self.peers {
            if exclude == Some(*peer_key) {
                continue;
            }
            let claims = (0..K).any(|t| peer.cuckoo[t].contains(tag));
            if !claims {
                continue;
            }
            // Combine local trust with network-consensus trust if available;
            // consensus = NULL → use local trust alone (see `combined_trust`).
            let combined = self.combined_trust(peer_key, peer.trust);
            let cost = peer.trust_adjusted_cost_with(combined);
            let slot = if self.is_path_negative(peer_key, tag) { &mut best_neg } else { &mut best };
            if slot.is_none_or(|(_, bc)| cost < bc) {
                *slot = Some((*peer_key, cost));
            }
        }
        best.or(best_neg).map(|(k, _)| k)
    }
}
