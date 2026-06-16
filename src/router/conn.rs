//! `PacketConn` — the public connection handle and the encrypt/send +
//! onion-send API, split from router/mod.rs.
use super::*;

pub struct PacketConn {
    inner: Arc<Mutex<RouterState>>,
    traffic_rx: tokio::sync::Mutex<mpsc::Receiver<InboundPacket>>,
    pub pub_key: [u8; 32],
    /// Clone of the signing key — needed by the transport layer to sign the
    /// per-connection authenticated handshake. Stored here so that transports
    /// don't need to be parameterised with the key separately.
    signing_key: SigningKey,
    /// Sybil-resistance threshold: an inbound peer's pub_key MUST have at
    /// least this many leading 1-bits in BLAKE2b(pub_key) (cf.
    /// `address::key_difficulty_bits`). 0 = no requirement. Stored as
    /// AtomicU32 so it can be raised at runtime without locking.
    min_peer_difficulty_bits: Arc<std::sync::atomic::AtomicU32>,
    shutdown_tx: watch::Sender<bool>,
    /// Roadmap #2: optional multi-core crypto worker pool. `None` until
    /// `enable_crypto_pool` installs one; once set, `write_to` offloads
    /// the encrypt+dispatch half onto it. `OnceLock` so the hot path
    /// reads it lock-free.
    crypto_pool: std::sync::OnceLock<CryptoPool>,
    /// Roadmap #7: optional transport-obfuscation key, derived from the
    /// configured PSK. `None` (unset) = obfuscation off. The transport
    /// layer reads it via `obfuscation_key()` to decide whether to wrap
    /// each TCP link in the keystream obfuscator.
    obfs_key: std::sync::OnceLock<[u8; 32]>,
}

/// Decoy-frame size in `PAD_BLOCK` units for a roll in `0..100`. Free fn so the
/// size-lattice property (decoys land on the same `PAD_BLOCK` lattice as real
/// frames, never the old distinguishable 64–256 B band) is unit-testable.
/// Distribution mimics the real send mix: mostly the smallest 1-payload-block
/// bucket, with a tail for multi-block sends. Always ≥ 2 blocks.
fn cover_frame_blocks(roll: u8) -> usize {
    match roll {
        0..=79 => 2,  // ≈512 B  (dominant — one payload block + frame overhead)
        80..=94 => 3, // ≈768 B
        _ => 4,       // ≈1024 B
    }
}

impl PacketConn {
    /// Borrow the signing key (used by the transport layer for handshake signing).
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    /// Current Sybil-resistance threshold in bits.
    pub fn min_peer_difficulty_bits(&self) -> u32 {
        self.min_peer_difficulty_bits.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Set the Sybil-resistance threshold. Inbound peers with fewer
    /// `key_difficulty_bits` are refused at the transport layer.
    pub fn set_min_peer_difficulty_bits(&self, bits: u32) {
        self.min_peer_difficulty_bits.store(bits, std::sync::atomic::Ordering::Relaxed);
    }

    /// Roadmap #7: install the transport-obfuscation PSK. An empty
    /// string leaves obfuscation off (the default). Idempotent and
    /// one-shot — call once at node startup, before transports spawn.
    pub fn set_obfuscation_psk(&self, psk: &str) {
        if let Some(key) = crate::obfs::derive_psk_key(psk) {
            let _ = self.obfs_key.set(key);
            tracing::info!("transport obfuscation enabled (roadmap #7)");
        }
    }

    /// Select which onion format `write_to_onion` builds (see
    /// [`crate::config::OnionFormat`]). Call once at node startup from config.
    #[cfg(feature = "sphinx")]
    pub fn set_onion_format(&self, fmt: crate::config::OnionFormat) {
        self.inner.lock_or_recover().onion_format = fmt;
    }

    /// Set the decoy/cover-traffic policy (see [`crate::config::CoverTraffic`]).
    /// The cover loop re-reads this each cycle, so it takes effect live. Call
    /// once at node startup from config.
    pub fn set_cover_traffic(&self, mode: crate::config::CoverTraffic) {
        self.inner.lock_or_recover().cover_mode = mode;
    }

    /// Install this node's long-term ML-DSA-65 signing identity (Option B
    /// PQ-hybrid handshake). Call once at node startup from the config seed;
    /// without it the SessionManager keeps the ephemeral key it was created
    /// with (the TOFU pin then resets on restart).
    pub fn set_pq_signer(&self, signer: crate::pq_sign::PqSigner) {
        self.inner
            .lock_or_recover()
            .sessions
            .write_or_recover()
            .set_pq_signer(signer);
    }

    /// Roadmap #7: the derived obfuscation key, or `None` when
    /// obfuscation is off. Read by the TCP transport per connection.
    pub fn obfuscation_key(&self) -> Option<[u8; 32]> {
        self.obfs_key.get().copied()
    }
}

impl PacketConn {
    pub fn new(signing_key: SigningKey) -> Self {
        let pub_key = signing_key.verifying_key().to_bytes();
        let signing_key_for_pc = signing_key.clone();
        let (traffic_tx, traffic_rx) = mpsc::channel(1024);
        let state = Arc::new(Mutex::new(RouterState::new(signing_key, traffic_tx)));
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        // Spawn maintenance background task
        {
            let state = state.clone();
            let mut shutdown = shutdown_rx.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(1));
                loop {
                    tokio::select! {
                        _ = interval.tick() => {
                            state.lock_or_recover().do_maintenance();
                        }
                        _ = shutdown.changed() => break,
                    }
                }
            });
        }

        // Cover traffic: send DUMMY packets to peers so a passive observer
        // cannot trivially correlate *when* / *how much* a node really sends.
        // Policy (off/light/constant) is read from RouterState each cycle, so
        // `set_cover_traffic` takes effect live. Decoys are dropped on receipt.
        //
        // Critical for it to be useful: a decoy's wire size must come from the
        // SAME lattice as real frames. A real Traffic frame is a fixed overhead
        // (~200 B) plus a `PAD_BLOCK`-multiple payload, i.e. it lands on ~256·m
        // for m ≥ 2. Decoys therefore use `blocks · PAD_BLOCK` with `blocks`
        // sampled to mimic the real mix, instead of the old 64–256 B band which
        // an observer could separate from real traffic by length alone.
        {
            let state = state.clone();
            let mut shutdown = shutdown_rx.clone();
            tokio::spawn(async move {
                use rand::Rng;
                let mut rng = rand::rngs::OsRng;
                // One decoy frame whose length matches the real-frame lattice.
                let cover_frame = |rng: &mut rand::rngs::OsRng| -> Vec<u8> {
                    let blocks = cover_frame_blocks(rng.gen_range(0u8..100));
                    let mut cover = vec![DUMMY];
                    cover.resize(blocks * PAD_BLOCK, 0u8);
                    cover
                };
                loop {
                    let mode = state.lock_or_recover().cover_mode;
                    use crate::config::CoverTraffic;
                    // Off → idle (still wake periodically to observe a live mode
                    // change). Light → randomised gaps. Constant → fixed 1 s tick.
                    let delay_ms = match mode {
                        CoverTraffic::Off => 5_000,
                        CoverTraffic::Light => rng.gen_range(8_000u64..30_000u64),
                        CoverTraffic::Constant => 1_000,
                    };
                    tokio::select! {
                        _ = tokio::time::sleep(Duration::from_millis(delay_ms)) => {}
                        _ = shutdown.changed() => break,
                    }
                    if matches!(mode, CoverTraffic::Off) {
                        continue;
                    }
                    let peers: Vec<PeerId> = {
                        state.lock_or_recover().peers.keys().copied().collect()
                    };
                    for peer in peers {
                        // Light: ~40 % of peers per cycle (variability). Constant:
                        // every peer, every tick (a continuous decoy floor).
                        let send = match mode {
                            CoverTraffic::Constant => true,
                            _ => rng.gen_bool(0.4),
                        };
                        if send {
                            let cover = cover_frame(&mut rng);
                            state.lock_or_recover().send_to_peer(&peer, cover);
                        }
                    }
                }
            });
        }

        PacketConn {
            inner: state,
            traffic_rx: tokio::sync::Mutex::new(traffic_rx),
            pub_key,
            signing_key: signing_key_for_pc,
            min_peer_difficulty_bits: Arc::new(std::sync::atomic::AtomicU32::new(0)),
            shutdown_tx,
            crypto_pool: std::sync::OnceLock::new(),
            obfs_key: std::sync::OnceLock::new(),
        }
    }

    /// Roadmap #2: spin up a pool of `workers` crypto worker tasks.
    /// Once installed, [`write_to`](Self::write_to) offloads the
    /// pad + encrypt + envelope + dispatch half of each send onto a
    /// worker (chosen by hashing the destination key), so the AEAD runs
    /// off the caller's task and across cores.
    ///
    /// Idempotent and one-shot: the first call with `workers > 0`
    /// installs the pool; `workers == 0` and any later call are no-ops.
    /// Call once at node startup, before traffic flows. A good value is
    /// the physical core count; see `NodeConfig.crypto_workers`.
    pub fn enable_crypto_pool(&self, workers: usize) {
        if workers == 0 || self.crypto_pool.get().is_some() {
            return;
        }
        let mut senders = Vec::with_capacity(workers);
        for _ in 0..workers {
            // Queue depth mirrors the per-peer write channel (8192):
            // deep enough to ride out a burst, bounded so a flooder
            // can't grow it without limit. Overflow falls back to
            // inline encryption — see CryptoPool::try_submit.
            let (tx, rx) = mpsc::channel::<CryptoJob>(8192);
            senders.push(tx);
            tokio::spawn(crypto_worker(
                rx,
                self.inner.clone(),
                self.pub_key,
                self.shutdown_tx.subscribe(),
            ));
        }
        let _ = self.crypto_pool.set(CryptoPool { senders });
        tracing::info!("crypto worker pool enabled: {workers} worker(s)");
    }

    /// Attach a new peer connection.
    ///
    /// This method **blocks** until the peer disconnects.  The caller (transport
    /// layer) should `tokio::spawn` this future and can rely on the return to
    /// know the connection lifetime has ended — no separate cleanup is needed.
    // Skip mutations: reads from network, spawns writer task, runs indefinite read loop —
    // mutation detection requires a live TCP connection.
    #[mutants::skip]
    pub async fn handle_conn(
        &self,
        remote_pub_key: [u8; 32],
        mut reader: impl AsyncRead + Unpin + Send + 'static,
        writer: impl AsyncWrite + Unpin + Send + 'static,
        priority: u8,
    ) {
        // Per-peer write channel. 256 was too small under sustained
        // load: a SOCKS5 download with N pipelined Data frames would
        // saturate the channel, `try_send` would silently drop frames,
        // our ARQ would retransmit, and TCP's CUBIC would interpret
        // the apparent burstiness as packet loss and halve cwnd —
        // collapsing single-stream throughput to ~37 Mbit/s on
        // long-fat WAN even after the bifrost-side reliability window
        // had been bumped to 4 MB. Sizing at 8192 lets ~512 MB of
        // pipelined Traffic frames queue before backpressure kicks in
        // (typical encrypted Traffic ≤ 64 KB).
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(8192);

        // Register peer (guarded against duplicates inside add_peer)
        self.inner.lock_or_recover().add_peer(remote_pub_key, tx, priority);

        let state = self.inner.clone();

        // Writer task — runs independently; terminates when channel closes or IO fails.
        //
        // sendmmsg-style coalescing: after the first frame arrives via
        // `recv().await`, drain any siblings that are already enqueued
        // with `try_recv()` and ship the whole batch with one
        // `write_frames_batched` call (= one `write_all`, = one
        // syscall). Bounds the batch at MAX_WRITE_BATCH so a flood
        // of telemetry doesn't grow our coalesce buffer without a
        // ceiling, and so the writer still yields back to tokio at
        // a sane cadence under heavy fan-in.
        const MAX_WRITE_BATCH: usize = 32;
        tokio::spawn(async move {
            let mut writer = writer;
            let mut batch: Vec<Vec<u8>> = Vec::with_capacity(MAX_WRITE_BATCH);
            while let Some(first) = rx.recv().await {
                batch.clear();
                batch.push(first);
                while batch.len() < MAX_WRITE_BATCH {
                    match rx.try_recv() {
                        Ok(more) => batch.push(more),
                        Err(_) => break, // empty or closed — flush what we have
                    }
                }
                if crate::packet::write_frames_batched(&mut writer, &batch).await.is_err() {
                    break;
                }
                // Flush so a buffered writer (the roadmap #7 obfuscation
                // layer) never strands a batch's tail when the peer goes
                // idle. A no-op for the bare TCP write half.
                if writer.flush().await.is_err() {
                    break;
                }
            }
        });

        // Initiate session exchange before entering the read loop.
        let init_bytes = {
            let s = state.lock_or_recover();
            s.sessions.write_or_recover().get_or_initiate_bytes(&remote_pub_key)
        };
        if let Some(init_data) = init_bytes {
            state.lock_or_recover().send_traffic_to(&remote_pub_key, init_data);
        }

        // Reader loop — runs inline so that handle_conn() only returns after the
        // peer disconnects.  This ensures the transport layer's `connected` dedup
        // set is not cleared too early (which would otherwise allow an immediate
        // reconnect that overwrites the peer entry and kills the writer task).
        loop {
            match read_frame(&mut reader).await {
                Ok(frame) => {
                    dispatch(&state, remote_pub_key, frame);
                }
                Err(e) => {
                    debug!("peer {:?} disconnected: {}", &remote_pub_key[..4], e);
                    state.lock_or_recover().remove_peer(&remote_pub_key);
                    break;
                }
            }
        }
    }

    // Skip mutations: awaits on the async traffic channel — requires a live sender.
    #[mutants::skip]
    pub async fn read_from(&self) -> Result<InboundPacket> {
        let mut rx = self.traffic_rx.lock().await;
        rx.recv().await.ok_or_else(|| anyhow::anyhow!("channel closed"))
    }

    // Skip mutations: session encrypt, pad, onion-wrap, and route lookup —
    // requires a two-node integration test with an established session.
    #[mutants::skip]
    pub async fn write_to(&self, payload: &[u8], dst: &[u8; 32]) -> Result<()> {
        // If no established session, send SessionInit (wrapped in Traffic) and bail.
        // Caller should retry; wait_for_session() in tests handles this.
        {
            let established = {
                let state = self.inner.lock_or_recover();
                let sm = state.sessions.read_or_recover();
                sm.is_established(dst)
            };
            if !established {
                let init_data = {
                    let state = self.inner.lock_or_recover();
                    let mut sm = state.sessions.write_or_recover();
                    sm.get_or_initiate_bytes(dst).unwrap_or_default()
                };
                if !init_data.is_empty() {
                    self.inner.lock_or_recover().send_traffic_to(dst, init_data);
                }
                bail!("session not established with {:?}", &dst[..4]);
            }
        }

        // Roadmap #2: with a crypto worker pool installed, hand the
        // expensive half (pad + ChaCha20-Poly1305 + envelope + route +
        // dispatch) to a worker so it runs on another core while this
        // task returns. `dst` is hashed to a fixed worker, so packets
        // for one peer keep submission order and never contend on that
        // peer's session mutex. A saturated pool falls through to
        // inline encryption below — never a drop.
        if let Some(pool) = self.crypto_pool.get()
            && pool.try_submit(payload, dst)
        {
            return Ok(());
        }
        encrypt_and_dispatch(&self.inner, &self.pub_key, payload, dst)
    }

    /// Batched analogue of `write_to`: encrypt + envelope + dispatch N
    /// payloads to the same destination under one round of session-
    /// manager mutex acquisitions.
    ///
    /// Why it exists: every `write_to` takes `state.sessions.lock`
    /// once for the encrypt and `state.inner.lock` twice for the
    /// route lookup + send_to_peer. For a 16-packet coalesced batch
    /// from `bifrost-vpnd::egress`, doing 16 independent `write_to`
    /// calls means 16 × 3 mutex acquires under load. Folding them
    /// into one call amortises the lock cost — important when the
    /// session manager's internal lock contention is on the perf-
    /// hot path (it's behind ChaCha20-Poly1305 today, but the perf
    /// trace flagged it as the next layer to surface once crypto
    /// stops being the dominant user-mode cost).
    ///
    /// Behaviour notes:
    /// * Returns `Ok(0)` if `payloads` is empty.
    /// * If the session isn't established, queues a SessionInit and
    ///   bails with the same error as `write_to`. None of the
    ///   payloads are sent.
    /// * If route lookup fails *after* encryption, bails — the
    ///   encrypted payloads are discarded (next call will retry).
    /// * Order is preserved: the writer task's
    ///   `write_frames_batched` keeps them in submission order on
    ///   the wire.
    ///
    /// Returns the number of payloads actually queued for the peer.
    #[mutants::skip]
    pub async fn write_to_batch(
        &self, payloads: &[Vec<u8>], dst: &[u8; 32],
    ) -> Result<usize> {
        if payloads.is_empty() {
            return Ok(0);
        }
        // Session establishment check — same shape as write_to.
        let established = {
            let state = self.inner.lock_or_recover();
            let sm = state.sessions.read_or_recover();
            sm.is_established(dst)
        };
        if !established {
            let init_data = {
                let state = self.inner.lock_or_recover();
                let mut sm = state.sessions.write_or_recover();
                sm.get_or_initiate_bytes(dst).unwrap_or_default()
            };
            if !init_data.is_empty() {
                self.inner.lock_or_recover().send_traffic_to(dst, init_data);
            }
            bail!("session not established with {:?}", &dst[..4]);
        }

        // Per-peer session lock: clone the SessionHandle once,
        // drop the SessionManager read lock, then encrypt all
        // payloads under one acquire of the per-peer mutex. Other
        // peers' encrypt/decrypt paths stay unblocked (Roadmap #2).
        let pub_key = self.pub_key;
        let (enc_header, tag) = encrypt_header(&pub_key, dst);
        let (handle, dest_coord) = {
            let state = self.inner.lock_or_recover();
            // Stamp the dst coord so transit nodes can route greedily.
            let dest_coord = state.coord_table.get(dst).map(|c| c.encode());
            let sm = state.sessions.read_or_recover();
            (sm.get_session(dst), dest_coord)
        };
        let Some(handle) = handle else {
            bail!("session not established with {:?}", &dst[..4]);
        };
        let encoded_frames: Vec<Vec<u8>> = {
            let mut info = handle.lock().unwrap();
            let mut out = Vec::with_capacity(payloads.len());
            for p in payloads {
                let padded = pad_payload(p);
                let ciphertext = info.encrypt(&padded)?;
                let traffic = Traffic {
                    path: vec![],
                    from: pub_key,
                    enc_header,
                    routing_tag: tag,
                    pkt_type: packet::PKT_DATA,
                    dest_coord,
                    watermark: 0,
                    payload: ciphertext,
                };
                out.push(traffic.encode());
            }
            out
        };

        // Route lookup once.
        let next_hop = self.inner.lock_or_recover().lookup(dst);
        let Some(next_hop) = next_hop else {
            bail!("no route to {:?}", &dst[..4]);
        };

        // Dispatch each encoded frame. send_to_peer round-robins
        // across the peer's multi-link tx vec, so consecutive frames
        // in this batch get spread across N TCP links naturally.
        let mut sent = 0usize;
        {
            let mut state = self.inner.lock_or_recover();
            for f in encoded_frames {
                state.send_to_peer(&next_hop, f);
                sent += 1;
            }
        }
        Ok(sent)
    }

    /// Select up to `n` random peers to use as onion relays.
    /// Returns fewer than `n` relays if insufficient peers are connected
    /// **with a known onion ephemeral pub** (learned via CoordAnnounce). Peers
    /// without one are skipped — we cannot give forward secrecy if we'd have
    /// to fall back to identity-derived keys.
    #[mutants::skip]
    pub fn select_relays(&self, n: usize) -> Vec<crate::onion::OnionHop> {
        use rand::seq::SliceRandom;
        let mut hops: Vec<crate::onion::OnionHop> = self.inner.lock_or_recover()
            .peers
            .values()
            .filter_map(|p| {
                p.onion_eph_pub.map(|eph| crate::onion::OnionHop {
                    identity_ed_pub: p.pub_key,
                    ephemeral_x_pub: eph,
                })
            })
            .collect();
        hops.shuffle(&mut rand::rngs::OsRng);
        hops.truncate(n);
        hops
    }

    /// Look up an OnionHop for the given identity.
    ///
    /// Returns `Some` with the peer's *current* announced ephemeral pub when
    /// known (full forward secrecy). When unknown — e.g. the identity is not
    /// a direct peer and we've never heard a CoordAnnounce from them — falls
    /// back to deriving an X25519 pub from the identity's Ed25519 key. The
    /// fallback works (Ed25519/X25519 share a curve so the derivation is
    /// well-defined) but provides NO forward secrecy for that hop: a future
    /// identity compromise lets the attacker decrypt past onion layers built
    /// against the derived key.
    ///
    /// A `warn!` is logged on fallback so operators can see which dests need
    /// out-of-band ephemeral-key propagation (a future PROTOCOL.md extension).
    pub fn onion_hop_for(&self, identity: &[u8; 32]) -> Option<crate::onion::OnionHop> {
        let state = self.inner.lock_or_recover();
        // Self-destination: use our own current onion pub.
        if identity == &state.pub_key {
            return Some(crate::onion::OnionHop {
                identity_ed_pub: *identity,
                ephemeral_x_pub: *state.onion_keys.pub_key().as_bytes(),
            });
        }
        // Direct peer with a known ephemeral (fast path, populated by either
        // CoordAnnounce or OnionKeyAnnounce).
        if let Some(p) = state.peers.get(identity)
            && let Some(eph) = p.onion_eph_pub {
            return Some(crate::onion::OnionHop {
                identity_ed_pub: *identity,
                ephemeral_x_pub: eph,
            });
        }
        // Network-wide table: OnionKeyAnnounce from anywhere in the mesh.
        if let Some((_, eph, _)) = state.remote_onion_keys.get(identity) {
            return Some(crate::onion::OnionHop {
                identity_ed_pub: *identity,
                ephemeral_x_pub: *eph,
            });
        }
        // Fallback: derive X25519 from the Ed25519 identity. Provides
        // confidentiality but not forward secrecy for this hop.
        match crate::session::ed25519_pub_to_x25519(identity) {
            Ok(x) => {
                warn!(
                    "onion hop {:?}: no advertised ephemeral pub, falling back to identity-derived key (no FS for this hop)",
                    &identity[..4]
                );
                Some(crate::onion::OnionHop {
                    identity_ed_pub: *identity,
                    ephemeral_x_pub: *x.as_bytes(),
                })
            }
            Err(_) => None,
        }
    }

    /// Send a payload to `dst` via the given `relays` using onion routing.
    ///
    /// The payload is encrypted with the session key for `dst`, then wrapped
    /// in an onion packet through each relay. Each relay sees only its
    /// predecessor and successor — not the full path or endpoints.
    ///
    /// If `relays` is empty this falls back to direct Traffic (same as `write_to`).
    // Skip mutations: onion-wrap + route to first relay — requires a multi-node
    // integration test to verify end-to-end encrypted delivery.
    #[mutants::skip]
    pub async fn write_to_onion(
        &self,
        payload: &[u8],
        dst: &[u8; 32],
        relays: &[crate::onion::OnionHop],
    ) -> Result<()> {
        if relays.is_empty() {
            return self.write_to(payload, dst).await;
        }

        // Onion format selection (OnionFormat). Sphinx removes the legacy
        // per-layer length leak; build it when forced, or under Auto when every
        // hop advertises support. Otherwise fall through to the legacy builder
        // below (also the Auto fallback for not-yet-capable paths).
        #[cfg(feature = "sphinx")]
        let use_sphinx = {
            let st = self.inner.lock_or_recover();
            match st.onion_format {
                crate::config::OnionFormat::Legacy => false,
                crate::config::OnionFormat::Sphinx => true,
                crate::config::OnionFormat::Auto => st.path_supports_sphinx(relays, dst),
            }
        };
        #[cfg(feature = "sphinx")]
        if use_sphinx {
            return self.write_to_onion_sphinx(payload, dst, relays).await;
        }

        // We need the destination's *current* onion ephemeral pub to build the
        // innermost layer. If we don't have one yet, abort — caller should
        // wait for a CoordAnnounce from the destination (or use write_to
        // which doesn't require it).
        let dest_hop = self.onion_hop_for(dst)
            .ok_or_else(|| anyhow::anyhow!(
                "no onion ephemeral pub known for dst {:?}; wait for CoordAnnounce or use write_to",
                &dst[..4]
            ))?;

        // Check session
        {
            let established = {
                let state = self.inner.lock_or_recover();
                state.sessions.read_or_recover().is_established(dst)
            };
            if !established {
                let init_data = {
                    let state = self.inner.lock_or_recover();
                    let mut sm = state.sessions.write_or_recover();
                    sm.get_or_initiate_bytes(dst).unwrap_or_default()
                };
                if !init_data.is_empty() {
                    self.inner.lock_or_recover().send_traffic_to(dst, init_data);
                }
                bail!("session not established with {:?}", &dst[..4]);
            }
        }

        let padded = pad_payload(payload);
        // `encrypt` is `&self` on SessionManager (it goes through the
        // per-peer Mutex<SessionInfo> internally), so a read guard is
        // sufficient — multiple concurrent encrypts to different
        // peers share this lock.
        let (ciphertext, dest_coord) = {
            let state = self.inner.lock_or_recover();
            let dest_coord = state.coord_table.get(dst).map(|c| c.encode());
            let ct = state.sessions.read_or_recover().encrypt(dst, &padded)?;
            (ct, dest_coord)
        };

        let pub_key = self.pub_key;
        let (enc_header, tag) = encrypt_header(&pub_key, dst);
        let traffic = Traffic {
            path: vec![],
            from: pub_key,
            enc_header,
            routing_tag: tag,
            pkt_type: packet::PKT_DATA,
            dest_coord,
            watermark: 0,
            payload: ciphertext,
        };
        let traffic_bytes = traffic.encode();

        let onion_pkt = match build_onion(relays, &dest_hop, traffic_bytes) {
            Ok(p) => p,
            Err(e) => bail!("failed to build onion: {}", e),
        };
        let encoded = onion_pkt.encode();

        let first_relay = relays[0].identity_ed_pub;
        let next_hop = self.inner.lock_or_recover().lookup(&first_relay);
        if let Some(next) = next_hop {
            self.inner.lock_or_recover().send_to_peer(&next, encoded);
        } else {
            bail!("no route to first relay {:?}", &first_relay[..4]);
        }
        Ok(())
    }

    /// Like [`Self::write_to_onion`] but builds a fixed-size Sphinx-style cell
    /// (`crate::sphinx`) — no per-layer cleartext length, so no onion-depth leak
    /// (REVIEW-FINDINGS #3). Additive and opt-in: every hop on the path (relays
    /// and `dst`) must understand `TYPE_ONION_SPHINX`, so callers must negotiate
    /// support before using this (a capability bit in CoordAnnounce is the planned
    /// signal). `relays.len() + 1` must be ≤ `sphinx::MAX_HOPS`, and the
    /// session-encrypted Traffic must fit `sphinx::MAX_TRAFFIC_LEN`.
    ///
    /// The session-setup + Traffic-build prefix mirrors `write_to_onion`
    /// deliberately (kept separate so the proven legacy path is untouched).
    #[mutants::skip]
    #[cfg(feature = "sphinx")]
    pub async fn write_to_onion_sphinx(
        &self,
        payload: &[u8],
        dst: &[u8; 32],
        relays: &[crate::onion::OnionHop],
    ) -> Result<()> {
        if relays.is_empty() {
            return self.write_to(payload, dst).await;
        }
        if relays.len() + 1 > crate::sphinx::MAX_HOPS {
            bail!(
                "sphinx onion: {} relays + dst exceeds MAX_HOPS {}",
                relays.len(), crate::sphinx::MAX_HOPS
            );
        }
        let dest_hop = self.onion_hop_for(dst).ok_or_else(|| {
            anyhow::anyhow!(
                "no onion ephemeral pub known for dst {:?}; wait for CoordAnnounce or use write_to",
                &dst[..4]
            )
        })?;

        // Session must be established (else kick off the handshake and bail).
        {
            let established = {
                let state = self.inner.lock_or_recover();
                state.sessions.read_or_recover().is_established(dst)
            };
            if !established {
                let init_data = {
                    let state = self.inner.lock_or_recover();
                    let mut sm = state.sessions.write_or_recover();
                    sm.get_or_initiate_bytes(dst).unwrap_or_default()
                };
                if !init_data.is_empty() {
                    self.inner.lock_or_recover().send_traffic_to(dst, init_data);
                }
                bail!("session not established with {:?}", &dst[..4]);
            }
        }

        let padded = pad_payload(payload);
        let (ciphertext, dest_coord) = {
            let state = self.inner.lock_or_recover();
            let dest_coord = state.coord_table.get(dst).map(|c| c.encode());
            let ct = state.sessions.read_or_recover().encrypt(dst, &padded)?;
            (ct, dest_coord)
        };
        let pub_key = self.pub_key;
        let (enc_header, tag) = encrypt_header(&pub_key, dst);
        let traffic = Traffic {
            path: vec![],
            from: pub_key,
            enc_header,
            routing_tag: tag,
            pkt_type: packet::PKT_DATA,
            dest_coord,
            watermark: 0,
            payload: ciphertext,
        };
        let traffic_bytes = traffic.encode();
        if traffic_bytes.len() > crate::sphinx::MAX_TRAFFIC_LEN {
            bail!(
                "sphinx onion: Traffic {} B exceeds payload budget {} B (use fewer hops or smaller payload)",
                traffic_bytes.len(), crate::sphinx::MAX_TRAFFIC_LEN
            );
        }

        // Map (relays.., dst) → Sphinx hops. Each hop's tag is BLAKE2b of its
        // identity; its onion_pub is the advertised ephemeral (FS) or the
        // identity-derived fallback (see onion_hop_for).
        let mut hops: Vec<crate::sphinx::SphinxHop> = relays
            .iter()
            .map(|h| crate::sphinx::SphinxHop {
                routing_tag: routing_tag(&h.identity_ed_pub),
                onion_pub: h.ephemeral_x_pub,
            })
            .collect();
        hops.push(crate::sphinx::SphinxHop {
            routing_tag: routing_tag(&dest_hop.identity_ed_pub),
            onion_pub: dest_hop.ephemeral_x_pub,
        });

        let cell = crate::sphinx::build_sphinx(&hops, &traffic_bytes)
            .map_err(|e| anyhow::anyhow!("build sphinx cell: {e}"))?;

        let first_relay = relays[0].identity_ed_pub;
        let next_hop = self.inner.lock_or_recover().lookup(&first_relay);
        if let Some(next) = next_hop {
            self.inner.lock_or_recover().send_to_peer(&next, cell);
        } else {
            bail!("no route to first relay {:?}", &first_relay[..4]);
        }
        Ok(())
    }

    pub fn mtu(&self) -> u64 {
        // u16::MAX - 2 (length header) - 16 (AEAD tag) - 128 (enc_header)
        // - small overhead; keep round number that's safely below u16::MAX.
        65000
    }

    // Skip mutations: sends shutdown signal and clears peers — no observable
    // side-effect accessible from a unit test after the call.
    #[mutants::skip]
    pub async fn close(&self) {
        // Signal all background tasks to exit
        let _ = self.shutdown_tx.send(true);
        // Drop all peer connections
        self.inner.lock_or_recover().peers.clear();
    }

    /// Inject ground-truth link statistics measured by the transport layer
    /// (e.g. Linux `SO_TCP_INFO`, or quinn's connection.rtt() / lost_packets).
    /// `rtt` overrides the EWMA `lag`; `loss_rate` is blended into the
    /// running EWMA. Both are far more accurate than the application-layer
    /// `SIG_REQ`/`SIG_RES` probe because they're not contaminated by
    /// head-of-line blocking or by ACK coalescing.
    ///
    /// Safe to call from any thread. No-op if `peer` is not currently in our
    /// peer table (concurrent disconnect race).
    pub fn record_kernel_link_stats(
        &self,
        peer: &[u8; 32],
        rtt: std::time::Duration,
        loss_rate: f32,
    ) {
        let mut state = self.inner.lock_or_recover();
        if let Some(p) = state.peers.get_mut(peer) {
            // Direct replace — kernel telemetry is authoritative for this
            // sample; the EWMA is only there to smooth one-shot jitter.
            p.lag = rtt;
            // Blend loss_rate with existing EWMA at α=0.25 to avoid a single
            // burst spiking the cost — same smoothing as the SIG_RES path.
            let clamped = loss_rate.clamp(0.0, 1.0);
            p.loss_rate = p.loss_rate * 0.75 + clamped * 0.25;
        }
    }

    /// Snapshot the per-tree state for all K spanning trees. Exposed via
    /// `/metrics` so a cluster-wide scraper can reconstruct the global
    /// shape of every tree (root, parent edges, depths) — basically
    /// "what would a graph viewer plot if it asked every node".
    ///
    /// `depth` is only tracked for tree 0 (`own_depth`); the other trees
    /// return 0 there. That's a known shortcoming of the current
    /// implementation, not a metric exposure issue.
    pub fn get_tree_state(&self) -> Vec<TreeStat> {
        let state = self.inner.lock_or_recover();
        let mut out = Vec::with_capacity(K);
        for (tree_id, tree) in state.trees.iter().enumerate() {
            let is_root = tree.parent.is_none();
            out.push(TreeStat {
                tree_id: tree_id as u8,
                root: tree.root,
                parent: tree.parent,
                depth: if tree_id == 0 { state.own_depth } else { 0 },
                parent_cost: tree.parent_cost,
                is_root,
            });
        }
        out
    }

    pub fn get_peer_stats(&self) -> Vec<PeerStats> {
        let state = self.inner.lock_or_recover();
        let now = Instant::now();
        state.peers.values().map(|p| PeerStats {
            key: p.pub_key,
            lag: p.lag,
            jitter: p.jitter,
            loss_rate: p.loss_rate,
            priority: p.priority,
            rx_bytes: p.rx_bytes,
            tx_bytes: p.tx_bytes,
            uptime: now.duration_since(p.connected_at),
            trust: p.trust,
        }).collect()
    }

    // Skip mutations: stores closure in mutex — verifying the callback fires requires
    // a live handle_path_notify invocation from a peer.
    #[mutants::skip]
    pub async fn set_path_notify<F: Fn([u8; 32]) + Send + Sync + 'static>(&self, f: F) {
        self.inner.lock_or_recover().path_notify = Some(Arc::new(f));
    }

    /// Install a callback fired when a HolePunch frame is received with us
    /// as the target. The transport layer wires this to issue a
    /// simultaneous outbound QUIC connect for symmetric-NAT traversal.
    #[mutants::skip]
    pub fn set_on_hole_punch<F: Fn([u8; 32], String) + Send + Sync + 'static>(&self, f: F) {
        self.inner.lock_or_recover().hole_punch_cb = Some(Arc::new(f));
    }

    /// Send a signed HolePunch frame to one of our peers, asking them to
    /// relay our endpoint to `target`. `endpoint` is the address we'd like
    /// `target` to dial back (usually our observed public IP:port from a
    /// STUN-like query or operator knowledge).
    #[mutants::skip]
    pub fn send_hole_punch(&self, rendezvous: &[u8; 32], target: [u8; 32], endpoint: String) {
        // The wire format length-prefixes the endpoint with a single byte, so
        // anything over 255 bytes would be silently truncated on encode (and a
        // truncated address is a wrong dial target). Refuse at the source — a
        // real socket address is never this long.
        if endpoint.len() > u8::MAX as usize {
            warn!("send_hole_punch: endpoint too long ({} bytes), refusing to send", endpoint.len());
            return;
        }
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64).unwrap_or(0);
        let initiator = self.pub_key;
        let unsigned = HolePunch {
            initiator, target, valid_from_ms: now_ms, endpoint,
            sig: [0u8; 64],
        };
        let sig = self.signing_key.sign(&unsigned.sign_bytes()).to_bytes();
        let hp = HolePunch { sig, ..unsigned };
        let encoded = hp.encode();
        self.inner.lock_or_recover().send_to_peer(rendezvous, encoded);
    }

    // Skip mutations: sends PathLookup to all peers — mutation detection requires
    // tracing lookup propagation through a live network.
    #[mutants::skip]
    pub async fn send_lookup(&self, partial: &[u8]) {
        let mut target = [0u8; 32];
        let len = partial.len().min(32);
        target[..len].copy_from_slice(&partial[..len]);

        let id = rand::random::<u64>();
        let pub_key = self.pub_key;
        let lookup = PathLookup {
            target,
            source: pub_key,
            id,
            path: vec![],
        };
        let encoded = lookup.encode();
        let peer_keys: Vec<PeerId> = self.inner.lock_or_recover().peers.keys().copied().collect();
        for pk in peer_keys {
            self.inner.lock_or_recover().send_to_peer(&pk, encoded.clone());
        }
    }
}

#[cfg(test)]
mod cover_tests {
    use super::cover_frame_blocks;
    use crate::router::header::PAD_BLOCK;

    #[test]
    fn decoy_frames_live_on_real_frame_lattice() {
        // Fix A: for every possible roll the decoy size must be a multiple of
        // PAD_BLOCK and at least one payload block above the minimum (≥512 B),
        // i.e. on the same lattice as real frames — never the old, trivially
        // distinguishable 64–256 B band.
        for roll in 0u8..100 {
            let blocks = cover_frame_blocks(roll);
            let size = blocks * PAD_BLOCK;
            assert!(blocks >= 2, "decoy must be ≥2 blocks (roll={roll})");
            assert_eq!(size % PAD_BLOCK, 0, "decoy must sit on the PAD_BLOCK lattice");
            assert!(size >= 512, "decoy must be ≥512 B, was {size} (roll={roll})");
            assert!(!(64..256).contains(&size), "must not fall in the old 64–256 B band");
        }
    }

    #[test]
    fn decoy_distribution_favours_smallest_bucket() {
        // The dominant bucket is the smallest real size (one payload block);
        // larger frames are a tail. Confirms the mix mimics real traffic.
        let counts = (0u8..100).map(cover_frame_blocks).fold([0; 5], |mut acc, b| {
            acc[b] += 1;
            acc
        });
        assert!(counts[2] > counts[3] && counts[3] >= counts[4],
            "smallest bucket must dominate: {counts:?}");
    }
}
