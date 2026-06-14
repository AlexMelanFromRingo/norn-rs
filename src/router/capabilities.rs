//! `capabilities` methods of RouterState, split from router/mod.rs.
use super::*;

impl RouterState {
    /// Periodic CapabilityAnnounce broadcast — mirrors broadcast_onion_key_announce:
    /// strictly increasing seq, signed, self-recorded, flooded to all peers.
    #[mutants::skip]
    pub(crate) fn broadcast_capabilities(&mut self) {
        self.own_caps_seq += 1;
        let seq = self.own_caps_seq;
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        // We always accept Sphinx cells inbound (the code is compiled in),
        // independent of our own *send* preference, so advertise unconditionally.
        let caps = crate::packet::CAP_ONION_SPHINX;
        let unsigned = crate::packet::CapabilityAnnounce {
            origin: self.pub_key,
            caps,
            seq,
            valid_from_ms: now_ms,
            sig: [0u8; 64],
        };
        let sig = self.signing_key.sign(&unsigned.sign_bytes()).to_bytes();
        let ann = crate::packet::CapabilityAnnounce { sig, ..unsigned };
        self.peer_capabilities.insert(self.pub_key, (caps, seq, Instant::now()));
        let encoded = ann.encode();
        let peer_keys: Vec<PeerId> = self.peers.keys().copied().collect();
        for pk in peer_keys {
            self.send_to_peer(&pk, encoded.clone());
        }
    }

    /// Handle an incoming CapabilityAnnounce: verify, dedup by (origin, seq),
    /// drop expired/future, record, then flood-forward to all peers but the sender.
    pub fn handle_capabilities(&mut self, from: PeerId, ann: crate::packet::CapabilityAnnounce) {
        if ann.origin == self.pub_key {
            return;
        }
        let vk = match VerifyingKey::from_bytes(&ann.origin) {
            Ok(v) => v,
            Err(_) => return,
        };
        if vk
            .verify_strict(&ann.sign_bytes(), &ed25519_dalek::Signature::from_bytes(&ann.sig))
            .is_err()
        {
            warn!("invalid CapabilityAnnounce sig from origin {:?}", &ann.origin[..4]);
            return;
        }
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        if now_ms.saturating_sub(ann.valid_from_ms) > CAPABILITY_VALIDITY_MS {
            debug!("CapabilityAnnounce too old, dropping");
            return;
        }
        if ann.valid_from_ms > now_ms.saturating_add(60_000) {
            debug!("CapabilityAnnounce from too far in future, dropping");
            return;
        }
        let is_newer = match self.peer_capabilities.get(&ann.origin) {
            Some((_, prev_seq, _)) => ann.seq > *prev_seq,
            None => true,
        };
        if !is_newer {
            return;
        }
        self.record_capability(ann.origin, ann.caps, ann.seq);
        let encoded = ann.encode();
        let peer_keys: Vec<PeerId> = self.peers.keys().copied().collect();
        for pk in peer_keys {
            if pk != from {
                self.send_to_peer(&pk, encoded.clone());
            }
        }
    }

    /// Record a peer's capabilities, bounded by MAX_CAPABILITY_ENTRIES (evicts a
    /// non-peer entry when full). Mirrors record_remote_onion_key.
    pub(crate) fn record_capability(&mut self, origin: [u8; 32], caps: u32, seq: u64) {
        if !self.peer_capabilities.contains_key(&origin)
            && self.peer_capabilities.len() >= MAX_CAPABILITY_ENTRIES
        {
            let victim = self
                .peer_capabilities
                .keys()
                .find(|k| !self.peers.contains_key(*k) && **k != self.pub_key)
                .copied();
            if let Some(v) = victim {
                self.peer_capabilities.remove(&v);
            } else {
                return;
            }
        }
        self.peer_capabilities.insert(origin, (caps, seq, Instant::now()));
    }

    /// Does every hop (relays + dst) advertise Sphinx support, recently enough,
    /// and does the path fit `sphinx::MAX_HOPS`? Used by the Auto onion selector
    /// so we never send a `TYPE_ONION_SPHINX` cell to a node that would drop it.
    pub(crate) fn path_supports_sphinx(&self, relays: &[crate::onion::OnionHop], dst: &[u8; 32]) -> bool {
        if relays.len() + 1 > crate::sphinx::MAX_HOPS {
            return false;
        }
        let supported = |id: &[u8; 32]| {
            matches!(
                self.peer_capabilities.get(id),
                Some((caps, _, recorded))
                    if caps & crate::packet::CAP_ONION_SPHINX != 0
                        && recorded.elapsed() < Duration::from_millis(CAPABILITY_VALIDITY_MS)
            )
        };
        relays.iter().all(|h| supported(&h.identity_ed_pub)) && supported(dst)
    }
}
