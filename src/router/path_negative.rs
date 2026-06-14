//! `path_negative` methods of RouterState, split from router/mod.rs.
use super::*;

impl RouterState {
    /// Look up a peer's current entry in the cuckoo-FP negative cache. Returns
    /// true if the peer recently signalled "I can't reach this tag" — caller
    /// should skip this peer for this tag until the entry ages out. Also
    /// performs lazy eviction of stale entries.
    pub(crate) fn is_path_negative(&self, peer: &PeerId, tag: &[u8; 16]) -> bool {
        let now = Instant::now();
        match self.path_negative_cache.get(&(*peer, *tag)) {
            Some(t) => now.duration_since(*t) < PATH_NEG_TTL,
            None => false,
        }
    }

    /// Record an incoming PathNegative. Bounded by `MAX_PATH_NEG_CACHE`.
    pub(crate) fn record_path_negative(&mut self, peer: PeerId, tag: [u8; 16]) {
        let now = Instant::now();
        if self.path_negative_cache.len() >= MAX_PATH_NEG_CACHE {
            // Lazy eviction: drop the oldest expired entry, else any one.
            let cutoff = now.checked_sub(PATH_NEG_TTL).unwrap_or(now);
            let victim = self.path_negative_cache.iter()
                .find(|(_, t)| **t < cutoff)
                .map(|(k, _)| *k)
                .or_else(|| self.path_negative_cache.keys().next().copied());
            if let Some(v) = victim {
                self.path_negative_cache.remove(&v);
            }
        }
        self.path_negative_cache.insert((peer, tag), now);
    }

    /// Drop expired negative-cache entries — called from maintenance tick.
    pub(crate) fn cleanup_path_negative_cache(&mut self) {
        let now = Instant::now();
        self.path_negative_cache.retain(|_, t| now.duration_since(*t) < PATH_NEG_TTL);
    }

    /// Send a `PathNegative` UPSTREAM (back to the peer we received an
    /// undeliverable packet from). Called when we drop a Traffic/Onion forward
    /// because of no-route or TTL exhaustion. Caller decrements TTL appropriately.
    pub(crate) fn send_path_negative(&mut self, to: PeerId, tag: [u8; 16], ttl: u8) {
        if ttl == 0 {
            return;
        }
        let frame = crate::packet::PathNegative { routing_tag: tag, ttl };
        let encoded = frame.encode();
        self.send_to_peer(&to, encoded);
    }

    /// Handle an inbound `PathNegative`. Two effects:
    ///   1. Cache `(from, tag)` so we stop picking `from` for this tag.
    ///   2. If we ourselves are a forwarder for this tag (recently received
    ///      and propagated upstream), forward the PathNegative one more hop
    ///      upstream — bounded by the embedded TTL.
    ///
    /// We do NOT trust the routing_tag against any specific identity (the
    /// frame is unsigned) — the only effect is that the SENDER tells us not
    /// to pick THEM for this tag. They can already lie about their own
    /// connectivity anyway, so this is no worse than the existing cuckoo
    /// gossip authority model.
    pub fn handle_path_negative(&mut self, from: PeerId, neg: crate::packet::PathNegative) {
        if let Some(peer) = self.peers.get_mut(&from) {
            peer.last_rx_time = Instant::now();
        }
        self.record_path_negative(from, neg.routing_tag);
        debug!(
            "PathNegative: peer {:?} cannot route tag {:?} (ttl {})",
            &from[..4], &neg.routing_tag[..4], neg.ttl,
        );
        // TTL-bounded forward upstream: pick any non-`from` peer that
        // CURRENTLY claims the tag and propagate the negative hint. This
        // gives multi-hop convergence for FP-storms without flooding.
        if neg.ttl > 1
            && let Some(next) = self.lookup_by_tag_excluding(&neg.routing_tag, Some(from)) {
                self.send_path_negative(next, neg.routing_tag, neg.ttl - 1);
            }
    }
}
