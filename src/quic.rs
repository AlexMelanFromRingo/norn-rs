//! QUIC transport (`quic://host:port` URIs).
//!
//! Parallel to `transport.rs` (TCP). Each QUIC connection is treated as a
//! single ordered byte stream (we open one bidirectional stream per session
//! and ignore QUIC's multiplexing — the existing framing in `packet.rs`
//! gives us all the framing we need).
//!
//! Cert model: each node generates a self-signed Ed25519 TLS certificate at
//! startup. The certificate is NOT used for authentication — the existing
//! NRN1 authenticated handshake binds the peer's identity to the connection
//! at the application layer. Both sides accept any cert so the TLS handshake
//! is essentially "opportunistic encryption" while NRN1 does identity.
//!
//! Benefits over TCP:
//!   - 0-RTT resumption (with session tickets, not yet wired)
//!   - Built-in encryption (defence in depth on top of NRN1's per-packet
//!     AEAD; underlay observers see encrypted bytes either way)
//!   - Independent flow control per stream (not exercised yet)
//!   - Better behaviour over lossy / mobile networks (no head-of-line blocking)

use anyhow::{anyhow, Context, Result};
use quinn::{ClientConfig, Endpoint, ServerConfig, TransportConfig};
use rcgen::{CertificateParams, KeyPair};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, SignatureScheme};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;
use tracing::{debug, info, warn};

use crate::router::PacketConn;
use crate::transport::{
    ConnectedPeers,
    // Reuse the NRN1 handshake helpers from the TCP transport so QUIC peers
    // authenticate identically.
};

/// Maximum time we allow for the QUIC handshake + our NRN1 handshake to
/// complete before giving up.
const QUIC_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

/// Parse a `quic://host:port` URI to its bare socket address string.
pub fn parse_quic_uri(uri: &str) -> Result<String> {
    uri.strip_prefix("quic://")
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow!("unsupported URI scheme (expected quic://): {}", uri))
}

/// Build a quinn ServerConfig with a self-signed Ed25519 cert and a
/// permissive client-cert verifier (we authenticate at the NRN1 layer).
fn make_server_config() -> Result<ServerConfig> {
    let (cert, key) = self_signed_cert()?;
    let mut crypto = rustls::ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .context("rustls protocol versions")?
        .with_client_cert_verifier(Arc::new(AcceptAnyClientCert))
        .with_single_cert(vec![cert], key)
        .context("rustls with_single_cert")?;
    crypto.alpn_protocols = vec![b"norn/0.4".to_vec()];

    let quic_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(crypto)
        .context("quic ServerConfig from rustls")?;
    let mut server_cfg = ServerConfig::with_crypto(Arc::new(quic_crypto));

    // Sane defaults: 30s idle timeout, allow up to 256 concurrent streams,
    // 1 MiB stream receive window (matches our 1 MiB frame cap).
    let mut transport = TransportConfig::default();
    transport.max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()));
    transport.max_concurrent_bidi_streams(quinn::VarInt::from_u32(256));
    server_cfg.transport_config(Arc::new(transport));
    Ok(server_cfg)
}

/// Build a quinn ClientConfig that accepts any server cert. NRN1 binds
/// identity at the application layer.
fn make_client_config() -> Result<ClientConfig> {
    let crypto = rustls::ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .context("rustls protocol versions")?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert))
        .with_no_client_auth();
    let mut crypto = crypto;
    crypto.alpn_protocols = vec![b"norn/0.4".to_vec()];

    let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
        .context("quic ClientConfig from rustls")?;
    let mut client_cfg = ClientConfig::new(Arc::new(quic_crypto));
    let mut transport = TransportConfig::default();
    transport.max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()));
    client_cfg.transport_config(Arc::new(transport));
    Ok(client_cfg)
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    // ring backend; identical to what quinn uses internally.
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Generate a self-signed Ed25519 cert for this process lifetime.
/// Valid for 365 days. CN/SAN: "norn.local".
fn self_signed_cert() -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>)> {
    let key = KeyPair::generate_for(&rcgen::PKCS_ED25519)
        .context("rcgen KeyPair::generate_for ED25519")?;
    let mut params = CertificateParams::new(vec!["norn.local".to_string()])
        .context("rcgen CertificateParams")?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    let cert = params.self_signed(&key).context("self-sign cert")?;
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_pem = key.serialize_pem();
    let key_der: PrivateKeyDer<'static> = {
        let mut reader = std::io::Cursor::new(key_pem.as_bytes());
        rustls_pemfile::private_key(&mut reader)
            .context("read PEM key")?
            .ok_or_else(|| anyhow!("no key in PEM"))?
    };
    Ok((cert_der, key_der))
}

/// Permissive ServerCertVerifier — accepts every server cert. NRN1 binds
/// identity at the application layer.
#[derive(Debug)]
struct AcceptAnyServerCert;

impl ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ED25519,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}

/// Permissive ClientCertVerifier — accepts any client cert (or none).
#[derive(Debug)]
struct AcceptAnyClientCert;

impl ClientCertVerifier for AcceptAnyClientCert {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] { &[] }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> std::result::Result<ClientCertVerified, rustls::Error> {
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519, SignatureScheme::ECDSA_NISTP256_SHA256]
    }

    fn offer_client_auth(&self) -> bool { false }
    fn client_auth_mandatory(&self) -> bool { false }
}

// ── Listener ──────────────────────────────────────────────────────────────

/// Start a QUIC listener. Accepts inbound connections, runs the NRN1
/// authenticated handshake on the first bidirectional stream, then hands
/// off to `PacketConn::handle_conn` exactly like the TCP transport.
#[mutants::skip]
pub async fn listen(
    uri: &str,
    conn: Arc<PacketConn>,
    connected: ConnectedPeers,
) -> Result<()> {
    let addr = parse_quic_uri(uri)?;
    let sock_addr: SocketAddr = addr.parse()
        .with_context(|| format!("parsing QUIC bind address {}", addr))?;
    let server_cfg = make_server_config()?;
    let endpoint = Endpoint::server(server_cfg, sock_addr)
        .with_context(|| format!("binding QUIC listener on {}", addr))?;
    info!("QUIC listener on {}", addr);

    while let Some(incoming) = endpoint.accept().await {
        let conn = conn.clone();
        let connected = connected.clone();
        tokio::spawn(async move {
            let new_conn = match incoming.await {
                Ok(c) => c,
                Err(e) => { warn!("QUIC accept: {}", e); return; }
            };
            let peer_addr = new_conn.remote_address();
            let (send, recv) = match timeout(QUIC_HANDSHAKE_TIMEOUT, new_conn.accept_bi()).await {
                Err(_) => { warn!("QUIC bi stream timeout from {}", peer_addr); return; }
                Ok(Err(e)) => { warn!("QUIC bi stream error from {}: {}", peer_addr, e); return; }
                Ok(Ok((s, r))) => (s, r),
            };
            handle_one(
                conn, connected,
                peer_addr.to_string(),
                Box::new(QuicReader(recv)),
                Box::new(QuicWriter(send)),
            ).await;
        });
    }
    Ok(())
}

/// Dial a QUIC peer. Symmetric to TCP::dial — runs NRN1 handshake then
/// hands off to PacketConn::handle_conn. Retries on failure with backoff.
#[mutants::skip]
pub async fn dial(uri: &str, conn: Arc<PacketConn>, connected: ConnectedPeers) {
    let addr = match parse_quic_uri(uri) {
        Ok(a) => a,
        Err(e) => { warn!("bad QUIC URI {}: {}", uri, e); return; }
    };
    let sock_addr: SocketAddr = match addr.parse() {
        Ok(a) => a,
        Err(e) => { warn!("bad QUIC addr {}: {}", addr, e); return; }
    };

    // One endpoint per dial loop, bound to a kernel-chosen UDP port.
    let local_bind: SocketAddr = if sock_addr.is_ipv6() {
        "[::]:0".parse().unwrap()
    } else {
        "0.0.0.0:0".parse().unwrap()
    };
    let mut endpoint = match Endpoint::client(local_bind) {
        Ok(e) => e,
        Err(e) => { warn!("QUIC endpoint bind: {}", e); return; }
    };
    match make_client_config() {
        Ok(cfg) => endpoint.set_default_client_config(cfg),
        Err(e) => { warn!("QUIC client config: {}", e); return; }
    }

    let mut delay = Duration::from_secs(1);
    loop {
        match endpoint.connect(sock_addr, "norn.local") {
            Ok(connecting) => {
                match timeout(QUIC_HANDSHAKE_TIMEOUT, connecting).await {
                    Err(_) => warn!("QUIC connect timeout to {}", addr),
                    Ok(Err(e)) => debug!("QUIC connect to {} failed: {}", addr, e),
                    Ok(Ok(new_conn)) => {
                        let (send, recv) = match timeout(QUIC_HANDSHAKE_TIMEOUT, new_conn.open_bi()).await {
                            Err(_) => { warn!("QUIC open_bi timeout to {}", addr); continue; }
                            Ok(Err(e)) => { warn!("QUIC open_bi to {} failed: {}", addr, e); continue; }
                            Ok(Ok((s, r))) => (s, r),
                        };
                        handle_one(
                            conn.clone(), connected.clone(),
                            addr.clone(),
                            Box::new(QuicReader(recv)),
                            Box::new(QuicWriter(send)),
                        ).await;
                        // Disconnect → reset backoff and reconnect.
                        delay = Duration::from_secs(5);
                    }
                }
            }
            Err(e) => debug!("QUIC connect to {} setup failed: {}", addr, e),
        }
        tokio::time::sleep(delay).await;
        let jitter = 0.8 + rand::random::<f64>() * 0.4;
        delay = Duration::from_millis((delay.as_millis() as f64 * 2.0 * jitter) as u64)
            .min(Duration::from_secs(60));
    }
}

/// Common per-connection plumbing for both accept and dial: run the NRN1
/// handshake over the QUIC bidi stream, then call `handle_conn`.
#[mutants::skip]
async fn handle_one(
    conn: Arc<PacketConn>,
    connected: ConnectedPeers,
    peer_label: String,
    mut reader: Box<dyn tokio::io::AsyncRead + Unpin + Send>,
    mut writer: Box<dyn tokio::io::AsyncWrite + Unpin + Send>,
) {
    // Reuse the *exact* NRN1 handshake messages defined in transport.rs by
    // simulating the same async exchange. We delegate to a thin shim because
    // transport::handshake is private and tied to TcpStream.

    let hs_result = timeout(
        QUIC_HANDSHAKE_TIMEOUT,
        crate::transport::handshake_over_stream(&mut reader, &mut writer, conn.signing_key()),
    ).await;
    let remote_pub = match hs_result {
        Err(_) => { warn!("QUIC handshake timed out from {}", peer_label); return; }
        Ok(Err(e)) => { warn!("QUIC handshake from {}: {:#}", peer_label, e); return; }
        Ok(Ok(p)) => p,
    };

    let min_bits = conn.min_peer_difficulty_bits();
    if min_bits > 0 {
        let got = crate::address::key_difficulty_bits(&remote_pub);
        if got < min_bits {
            warn!("QUIC: rejecting {} ({:?}): difficulty {} < {}",
                peer_label, &remote_pub[..4], got, min_bits);
            return;
        }
    }

    {
        let mut set = connected.lock().unwrap();
        if set.contains(&remote_pub) {
            debug!("QUIC duplicate inbound from {:?}", &remote_pub[..4]);
            return;
        }
        set.insert(remote_pub);
    }
    info!("QUIC peer {:?} from {}", &remote_pub[..4], peer_label);
    conn.handle_conn(remote_pub, reader, writer, 0).await;
    connected.lock().unwrap().remove(&remote_pub);
}

// ── AsyncRead / AsyncWrite adapters around quinn's typed streams ──────────

struct QuicReader(quinn::RecvStream);
struct QuicWriter(quinn::SendStream);

impl tokio::io::AsyncRead for QuicReader {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for QuicWriter {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        // quinn's SendStream uses its own WriteError; map to io::Error so we
        // can satisfy tokio::io::AsyncWrite which is io::Error-typed.
        match std::pin::Pin::new(&mut self.0).poll_write(cx, buf) {
            std::task::Poll::Pending => std::task::Poll::Pending,
            std::task::Poll::Ready(Ok(n)) => std::task::Poll::Ready(Ok(n)),
            std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Err(
                std::io::Error::other(format!("quic send: {e}"))
            )),
        }
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        // quinn streams have no flush concept (it's handled internally).
        // Returning Ready(Ok) is the documented behaviour.
        let _ = &mut self.0;
        std::task::Poll::Ready(Ok(()))
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        // Best-effort finish; ignore the error if the peer is already gone.
        let _ = self.0.finish();
        std::task::Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_quic_uri_valid() {
        assert_eq!(parse_quic_uri("quic://1.2.3.4:9001").unwrap(), "1.2.3.4:9001");
        assert_eq!(parse_quic_uri("quic://[::1]:9001").unwrap(), "[::1]:9001");
    }

    #[test]
    fn parse_quic_uri_wrong_scheme_fails() {
        assert!(parse_quic_uri("tcp://1.2.3.4:9001").is_err());
        assert!(parse_quic_uri("").is_err());
    }

    #[test]
    fn self_signed_cert_pair_generates() {
        let (cert, _key) = self_signed_cert().expect("cert generation must succeed");
        assert!(!cert.as_ref().is_empty(), "cert must be non-empty");
    }

    #[tokio::test]
    async fn end_to_end_quic_handshake() {
        // Spin up two PacketConns, one listening on a random UDP port, the
        // other dialling it via the QUIC transport. Confirm the NRN1
        // handshake completes — both sides see the other in get_peer_stats.
        use ed25519_dalek::SigningKey;
        use std::collections::HashSet;
        use std::sync::Mutex as StdMutex;

        let sk_a = SigningKey::generate(&mut rand::rngs::OsRng);
        let sk_b = SigningKey::generate(&mut rand::rngs::OsRng);
        let pub_b = sk_b.verifying_key().to_bytes();

        let conn_a = Arc::new(PacketConn::new(sk_a));
        let conn_b = Arc::new(PacketConn::new(sk_b));

        let connected_a: ConnectedPeers = Arc::new(StdMutex::new(HashSet::new()));
        let connected_b: ConnectedPeers = Arc::new(StdMutex::new(HashSet::new()));

        // B listens on a kernel-chosen port. Pick one and read it back via
        // a small probe: we use a fixed loopback port range.
        // For simplicity bind on port 0 and discover; but quinn's Endpoint
        // doesn't easily expose the bound port through our listen() wrapper.
        // Instead, pick a high random port and retry on collision.
        let port: u16 = 30000 + (rand::random::<u16>() % 5000);

        let listen_uri = format!("quic://127.0.0.1:{}", port);
        let dial_uri = format!("quic://127.0.0.1:{}", port);

        let conn_b_clone = conn_b.clone();
        let connected_b_clone = connected_b.clone();
        let lu = listen_uri.clone();
        let listener = tokio::spawn(async move {
            // Don't propagate the error if the port is already in use — the
            // test is best-effort.
            let _ = listen(&lu, conn_b_clone, connected_b_clone).await;
        });

        // Give the listener a moment to bind.
        tokio::time::sleep(Duration::from_millis(200)).await;

        let conn_a_clone = conn_a.clone();
        let connected_a_clone = connected_a.clone();
        let dial_uri_clone = dial_uri.clone();
        let dialer = tokio::spawn(async move {
            dial(&dial_uri_clone, conn_a_clone, connected_a_clone).await;
        });

        // Wait up to 5s for both sides to see each other.
        let mut both_connected = false;
        for _ in 0..50 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            let a_sees = conn_a.get_peer_stats().iter().any(|p| p.key == pub_b);
            let b_sees = !conn_b.get_peer_stats().is_empty();
            if a_sees && b_sees {
                both_connected = true;
                break;
            }
        }

        // Clean up.
        listener.abort();
        dialer.abort();

        assert!(both_connected,
            "both endpoints must complete the QUIC + NRN1 handshake within 5s");
    }
}
