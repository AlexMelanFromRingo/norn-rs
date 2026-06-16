//! `reputation` methods of RouterState, split from router/mod.rs.
use super::*;

impl RouterState {
    /// Periodic broadcast of signed reputation reports about each of our
    /// direct peers' local trust scores. Receivers aggregate into a
    /// "consensus trust" that biases their routing decisions.
    #[mutants::skip]
    pub(crate) fn broadcast_reputation(&mut self) {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let observer = self.pub_key;
        let observed_with_trust: Vec<([u8; 32], f32)> = self.peers.values()
            .map(|p| (p.pub_key, p.trust))
            .collect();
        for (observed, trust) in observed_with_trust {
            self.own_reputation_seq += 1;
            let seq = self.own_reputation_seq;
            // Quantise trust to u16 over the configured [TRUST_MIN, TRUST_MAX].
            // For wire compactness; receiver de-quantises.
            let frac = ((trust - TRUST_MIN) / (TRUST_MAX - TRUST_MIN)).clamp(0.0, 1.0);
            let score_q16 = (frac * u16::MAX as f32) as u16;
            let unsigned = ReputationReport {
                observer, observed, score_q16, seq, valid_from_ms: now_ms,
                sig: [0u8; 64],
            };
            let sig = self.signing_key.sign(&unsigned.sign_bytes()).to_bytes();
            let report = ReputationReport { sig, ..unsigned };
            // Record ourselves so consensus_trust sees our own view too.
            self.record_reputation(observer, observed, seq, report.score(), Instant::now());
            let encoded = report.encode();
            let peer_keys: Vec<PeerId> = self.peers.keys().copied().collect();
            for pk in peer_keys {
                self.send_to_peer(&pk, encoded.clone());
            }
        }
    }

    /// Handle an inbound reputation report from a peer (potentially originating
    /// far away). Verify, dedup, store, forward to non-sender peers.
    pub fn handle_reputation_report(&mut self, from: PeerId, r: ReputationReport) {
        // Reject if observer signed about themselves (no information).
        if r.observer == r.observed {
            return;
        }
        // Reject self-origin (we shouldn't accept claims about us as if we made them).
        if r.observer == self.pub_key {
            return;
        }
        let vk = match VerifyingKey::from_bytes(&r.observer) {
            Ok(v) => v,
            Err(_) => return,
        };
        if vk.verify_strict(&r.sign_bytes(), &ed25519_dalek::Signature::from_bytes(&r.sig)).is_err() {
            warn!("invalid reputation report sig from observer {:?}", &r.observer[..4]);
            return;
        }
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let age = now_ms.saturating_sub(r.valid_from_ms);
        if age > REPUTATION_VALIDITY_MS {
            return;
        }
        if r.valid_from_ms > now_ms.saturating_add(60_000) {
            return;
        }
        // Dedup: forward only if strictly newer seq from this (observer, observed).
        let is_newer = self.reputation.get(&r.observed)
            .and_then(|m| m.get(&r.observer))
            .map(|(prev_seq, _, _)| r.seq > *prev_seq)
            .unwrap_or(true);
        if !is_newer {
            return;
        }
        self.record_reputation(r.observer, r.observed, r.seq, r.score(), Instant::now());

        // Flood to other peers.
        let encoded = r.encode();
        let peer_keys: Vec<PeerId> = self.peers.keys().copied().collect();
        for pk in peer_keys {
            if pk != from {
                self.send_to_peer(&pk, encoded.clone());
            }
        }
    }

    /// Handle a HolePunch frame.
    ///
    /// Two cases:
    ///
    /// 1. `target == us` — we are the destination of the punch. Verify
    ///    the initiator's signature, log the observed endpoint so an
    ///    operator (or the on_hole_punch callback, if set) can act on it.
    /// 2. `target != us` AND we have a session with `target` — we are
    ///    the rendezvous. Verify and forward the same HolePunch frame
    ///    to `target` through the routed overlay.
    ///
    /// In all other cases the frame is dropped.
    pub fn handle_hole_punch(&mut self, _from: PeerId, hp: HolePunch) {
        // Sig binds initiator+target+endpoint+ts → rendezvous can't forge.
        let vk = match VerifyingKey::from_bytes(&hp.initiator) {
            Ok(v) => v,
            Err(_) => return,
        };
        if vk.verify_strict(&hp.sign_bytes(), &ed25519_dalek::Signature::from_bytes(&hp.sig)).is_err() {
            warn!("invalid HolePunch sig from {:?}", &hp.initiator[..4]);
            return;
        }
        // Freshness ±60s.
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64).unwrap_or(0);
        let skew = (now_ms as i64 - hp.valid_from_ms as i64).unsigned_abs();
        if skew > 60_000 {
            debug!("HolePunch outside freshness window, dropping");
            return;
        }

        if hp.target == self.pub_key {
            // We're the destination — dispatch the callback if registered.
            if let Some(cb) = &self.hole_punch_cb {
                let cb = cb.clone();
                let initiator = hp.initiator;
                let endpoint = hp.endpoint.clone();
                tokio::spawn(async move { cb(initiator, endpoint) });
            } else {
                debug!("HolePunch for us from {:?} at {}, but no on_hole_punch handler set",
                    &hp.initiator[..4], hp.endpoint);
            }
        } else {
            // Relay role: forward the *same* signed frame to target via
            // session-layer traffic if we have a session with target. We
            // wrap it in send_traffic_to which will route through whichever
            // next-hop currently knows target.
            let encoded = hp.encode();
            // send_traffic_to wraps as PKT_CONTROL with our identity as
            // source. The target's TRAFFIC handler unpads then sees the
            // HolePunch byte and re-dispatches. (Implemented as a
            // bypass: forward as a raw routing frame instead.)
            if let Some(next_hop) = self.lookup(&hp.target) {
                self.send_to_peer(&next_hop, encoded);
            } else {
                debug!("HolePunch: no route to target {:?}, dropping", &hp.target[..4]);
            }
        }
    }

    /// Insert/update one observation; bound the table size by per-peer.
    pub(crate) fn record_reputation(
        &mut self,
        observer: [u8; 32],
        observed: [u8; 32],
        seq: u64,
        score: f32,
        recorded_at: Instant,
    ) {
        // Cap total observations to avoid memory exhaustion. We evict a
        // whole per-observed bucket (least useful) when the total crosses
        // the limit and we're inserting into a new bucket.
        let total: usize = self.reputation.values().map(|m| m.len()).sum();
        if total >= MAX_REPUTATION_OBSERVATIONS && !self.reputation.contains_key(&observed) {
            // Evict an arbitrary non-peer observed entry.
            let victim = self.reputation.keys()
                .find(|k| !self.peers.contains_key(*k) && **k != self.pub_key)
                .copied();
            if let Some(v) = victim {
                self.reputation.remove(&v);
            } else {
                return;
            }
        }
        self.reputation
            .entry(observed)
            .or_default()
            .insert(observer, (seq, score, recorded_at));
    }

    /// Blend a peer's *local* trust with the Sybil-hardened network-consensus
    /// trust (from gossiped, PoW-weighted, trimmed-mean `ReputationReport`s).
    /// When no consensus is available (below quorum), falls back to local trust
    /// alone. This is the single trust signal every routing path should rank by,
    /// so a peer the wider network condemns is de-prioritised everywhere — not
    /// just on the tag-forwarding path.
    pub(crate) fn combined_trust(&self, peer_key: &PeerId, local: f32) -> f32 {
        match self.consensus_trust(peer_key) {
            Some(c) => (local + c) * 0.5,
            None => local,
        }
    }

    /// Compute consensus trust for `observed` with three Sybil/collusion hardenings:
    ///
    ///   1. **PoW-weighted observers.** Each observer's score is multiplied
    ///      by `min(1.0, observer_difficulty_bits / REPUTATION_WEIGHT_BITS)`.
    ///      A Sybil army of low-difficulty identities still counts, but each
    ///      vote is fractional — defeating cheap "1k Sybils trash one honest
    ///      peer" (bad-mouthing) and "1k Sybils inflate a peer they control"
    ///      (self-promotion).
    ///   2. **Trimmed mean.** Sort observed scores; discard top
    ///      `REPUTATION_TRIM_FRAC` and bottom `REPUTATION_TRIM_FRAC` before
    ///      averaging. A coalition has to control >25 % of voting weight to
    ///      shift the median; below that, their extreme votes get trimmed.
    ///   3. **Minimum quorum.** Below `REPUTATION_MIN_QUORUM` distinct
    ///      observers, return None (= "no consensus yet, fall back to local
    ///      trust"). Stops a lone attacker observation from dictating
    ///      consensus on a barely-known peer.
    ///
    /// Returns None when (a) no observations or (b) below quorum.
    pub fn consensus_trust(&self, observed: &[u8; 32]) -> Option<f32> {
        let bucket = self.reputation.get(observed)?;
        let cutoff = Instant::now().checked_sub(Duration::from_millis(REPUTATION_VALIDITY_MS))
            .unwrap_or(Instant::now());

        // Collect (weight, real_trust) pairs for fresh observations.
        let mut weighted: Vec<(f64, f64)> = Vec::with_capacity(bucket.len());
        for (observer_pub, (_, score, t)) in bucket {
            if *t < cutoff {
                continue;
            }
            let real_trust = TRUST_MIN + score * (TRUST_MAX - TRUST_MIN);
            let bits = crate::address::key_difficulty_bits(observer_pub);
            // Linear weight cap at REPUTATION_WEIGHT_BITS — Sybils with 0
            // bits contribute essentially nothing; the floor (1.0 / cap) is
            // kept so a small honest network with no PoW still operates.
            let w = ((bits as f64) / REPUTATION_WEIGHT_BITS as f64)
                .clamp(REPUTATION_WEIGHT_FLOOR, 1.0);
            weighted.push((w, real_trust as f64));
        }

        if weighted.len() < REPUTATION_MIN_QUORUM {
            return None;
        }

        // Trimmed-mean: sort by score, drop the top/bottom fraction.
        weighted.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));
        let n = weighted.len();
        let trim = ((n as f64) * REPUTATION_TRIM_FRAC).floor() as usize;
        let kept = &weighted[trim..n.saturating_sub(trim).max(trim + 1)];
        if kept.is_empty() {
            return None;
        }
        let total_w: f64 = kept.iter().map(|(w, _)| *w).sum();
        if total_w <= f64::EPSILON {
            return None;
        }
        let weighted_sum: f64 = kept.iter().map(|(w, s)| w * s).sum();
        Some((weighted_sum / total_w) as f32)
    }
}
