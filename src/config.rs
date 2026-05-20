// Node configuration — loaded from TOML file.

use anyhow::{Context, Result};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::path::Path;
use zeroize::Zeroize;

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct NodeConfig {
    /// Hex-encoded ed25519 private key. Generated fresh if absent.
    pub private_key: Option<String>,

    /// TCP listen addresses, e.g. ["tcp://0.0.0.0:9001"]
    #[serde(default = "default_listen")]
    pub listen: Vec<String>,

    /// Static peer addresses, e.g. ["tcp://1.2.3.4:9001"]
    #[serde(default)]
    pub peers: Vec<String>,

    /// TUN interface name. Set to null/omit to disable TUN.
    #[serde(default = "default_tun_name")]
    pub tun_name: Option<String>,

    /// Admin UNIX socket path.
    #[serde(default = "default_admin_socket")]
    pub admin_socket: String,

    /// Enable multicast peer discovery (LAN).
    #[serde(default = "default_true")]
    pub multicast_enabled: bool,

    /// UDP port for multicast discovery beacons.
    #[serde(default = "default_multicast_port")]
    pub multicast_port: u16,

    /// Log level: "error" | "warn" | "info" | "debug" | "trace"
    #[serde(default = "default_log_level")]
    pub log_level: String,

    /// Path to the persistent known-peers cache. Each successfully-established
    /// peer is recorded here; on restart the cache is read back and every
    /// known URI is dialed alongside the static `peers` list. Set to an
    /// empty string to disable persistence.
    #[serde(default = "default_peer_cache_path")]
    pub peer_cache_path: String,

    /// Address for the Prometheus /metrics HTTP endpoint. Empty string =
    /// disabled. Default binds to loopback only — exposing it on a public
    /// interface leaks per-peer pub_keys and connection counts.
    #[serde(default = "default_metrics_addr")]
    pub metrics_addr: String,

    /// Sybil-resistance threshold: minimum `key_difficulty_bits` an inbound
    /// peer's pub_key must reach. Each extra bit doubles the expected cost
    /// of finding a valid pub_key, so 16 bits ≈ 65k hashes (~ms on modern
    /// CPU; one-time cost when generating an identity). Default 0 = off,
    /// since enabling this on an existing network locks out peers whose
    /// keys were generated without the requirement.
    #[serde(default)]
    pub min_peer_difficulty_bits: u32,

    /// Enable mDNS / DNS-SD peer discovery on the LAN. Standard
    /// `_norn._tcp.local` service type. Coexists with `multicast_enabled`;
    /// both can be on or off independently.
    #[serde(default = "default_true")]
    pub mdns_enabled: bool,

    /// Roadmap #2: number of dedicated crypto worker tasks. With `N > 0`,
    /// `PacketConn::write_to` offloads pad + ChaCha20-Poly1305 encrypt +
    /// envelope + dispatch onto a pool of N tasks, which a multi-thread
    /// runtime spreads across cores; each destination is pinned to one
    /// worker so per-peer wire order holds. Default 0 = encrypt inline on
    /// the caller's task. Only worth enabling on a fast (≥ ~500 Mbit/s),
    /// non-WAN-bottlenecked link where ChaCha20 is a real share of a
    /// core — on a slow WAN the extra queueing hop is pure overhead. A
    /// good value is the physical core count.
    #[serde(default)]
    pub crypto_workers: u8,

    /// Roadmap #7: transport-obfuscation pre-shared key. When non-empty,
    /// every TCP link is wrapped in a keystream obfuscator so the whole
    /// connection — NRN1 handshake included — looks like uniform random
    /// bytes to a deep-packet-inspection box, defeating signature-based
    /// blocking. Every node that should interoperate must share the
    /// exact same string. Empty (the default) = no obfuscation. Costs a
    /// little CPU and adds a 16-byte cleartext nonce per connection; it
    /// does not hide packet sizes or timing.
    #[serde(default)]
    pub obfuscation_psk: String,
}

fn default_listen() -> Vec<String> { vec!["tcp://0.0.0.0:9001".to_string()] }
fn default_tun_name() -> Option<String> { Some("norn0".to_string()) }
fn default_admin_socket() -> String { "/var/run/norn.sock".to_string() }
fn default_true() -> bool { true }
fn default_multicast_port() -> u16 { 9001 }
fn default_log_level() -> String { "info".to_string() }
fn default_peer_cache_path() -> String { "/var/lib/norn/peers.json".to_string() }
fn default_metrics_addr() -> String { String::new() } // disabled by default

impl Default for NodeConfig {
    fn default() -> Self {
        NodeConfig {
            private_key: None,
            listen: default_listen(),
            peers: vec![],
            tun_name: default_tun_name(),
            admin_socket: default_admin_socket(),
            multicast_enabled: true,
            multicast_port: default_multicast_port(),
            log_level: default_log_level(),
            peer_cache_path: default_peer_cache_path(),
            metrics_addr: default_metrics_addr(),
            min_peer_difficulty_bits: 0,
            mdns_enabled: true,
            crypto_workers: 0,
            obfuscation_psk: String::new(),
        }
    }
}

impl NodeConfig {
    /// Load config from a TOML file.
    ///
    /// Enforces 0o600 / no-group / no-other permissions on Unix because the file
    /// contains the node's ed25519 private key. A world-readable config is a
    /// configuration error, not a degraded mode — we refuse rather than warn.
    pub fn load(path: &Path) -> Result<Self> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let meta = std::fs::metadata(path)
                .with_context(|| format!("stat'ing config {:?}", path))?;
            // mode & 0o077 picks up the group + other bits. Any non-zero
            // means readable/writable by someone other than the owner.
            let mode = meta.mode() & 0o777;
            if mode & 0o077 != 0 {
                anyhow::bail!(
                    "refusing to load config {path:?} with mode {mode:o}: \
                     it contains the private key. Run: chmod 600 {path:?}"
                );
            }
        }
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading config {:?}", path))?;
        toml::from_str(&text).context("parsing TOML config")
    }

    /// Generate a default config TOML string with a fresh private key.
    pub fn generate_toml() -> String {
        let sk = SigningKey::generate(&mut OsRng);
        let key_hex = hex::encode(sk.to_bytes());
        format!(
            r#"# norn-rs configuration

# Your node's private key (ed25519, 32 bytes hex).
# KEEP THIS SECRET. Regenerate to get a new identity and address.
private_key = "{key_hex}"

# TCP addresses to listen on for incoming peer connections.
listen = ["tcp://0.0.0.0:9001"]

# Static peers to dial on startup.
# peers = ["tcp://peer.example.com:9001"]
peers = []

# TUN interface name. Comment out or set to null to disable.
tun_name = "norn0"

# Admin socket (UNIX). Use with nornctl.
admin_socket = "/var/run/norn.sock"

# Enable multicast peer discovery on the local network.
multicast_enabled = true
multicast_port = 9001

# Logging verbosity: error | warn | info | debug | trace
log_level = "info"
"#
        )
    }

    /// Parse the private key from config, or generate a fresh ephemeral one.
    ///
    /// Private-key bytes are zeroized after the SigningKey is constructed —
    /// SigningKey itself zeroizes on drop (via `zeroize` in ed25519-dalek 2.x).
    pub fn signing_key(&self) -> Result<SigningKey> {
        match &self.private_key {
            Some(hex_key) => {
                let mut bytes = hex::decode(hex_key).context("decoding private_key hex")?;
                if bytes.len() != 32 {
                    bytes.zeroize();
                    anyhow::bail!("private_key must be 32 bytes (64 hex chars), got {}", bytes.len());
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                bytes.zeroize();
                let sk = SigningKey::from_bytes(&arr);
                arr.zeroize();
                Ok(sk)
            }
            None => {
                // Ephemeral keys are useful for testing but actively dangerous in
                // production: the node's address changes every restart, peers
                // re-pin nothing, and any operator-side audit log of "node X did Y"
                // becomes worthless. Refuse unless an env var explicitly opts in.
                if std::env::var("NORN_ALLOW_EPHEMERAL_KEY").is_err() {
                    anyhow::bail!(
                        "no private_key in config and NORN_ALLOW_EPHEMERAL_KEY is not set. \
                         Run `nornd genconfig > norn.toml && chmod 600 norn.toml` for a stable identity."
                    );
                }
                tracing::warn!("using ephemeral key (NORN_ALLOW_EPHEMERAL_KEY set) — identity will change on restart");
                Ok(SigningKey::generate(&mut OsRng))
            }
        }
    }

    /// Extract the TCP port from the first listen address, for multicast beacons.
    pub fn tcp_listen_port(&self) -> Option<u16> {
        self.listen.first().and_then(|uri| {
            let addr = uri.strip_prefix("tcp://")?;
            let port_str = addr.rsplit(':').next()?;
            port_str.parse().ok()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── default values ────────────────────────────────────────────────────────

    #[test]
    fn default_listen_is_nonempty() {
        let v = default_listen();
        assert!(!v.is_empty(), "default_listen must return at least one address");
        assert!(v[0].starts_with("tcp://"), "default listen must be a tcp URI");
    }

    #[test]
    fn default_tun_name_is_some() {
        let t = default_tun_name();
        assert_eq!(t, Some("norn0".to_string()),
            "default_tun_name must be Some(\"norn0\")");
    }

    #[test]
    fn default_admin_socket_is_nonempty() {
        let s = default_admin_socket();
        assert_eq!(s, "/var/run/norn.sock",
            "default_admin_socket must be /var/run/norn.sock");
    }

    #[test]
    fn default_true_returns_true() {
        assert!(default_true(), "default_true must return true, not false");
    }

    #[test]
    fn default_multicast_port_nonzero() {
        let p = default_multicast_port();
        assert_ne!(p, 0, "multicast port must not be 0");
        assert_eq!(p, 9001);
    }

    #[test]
    fn default_log_level_is_nonempty() {
        let l = default_log_level();
        assert_eq!(l, "info", "default_log_level must be \"info\"");
    }

    // ── signing_key ───────────────────────────────────────────────────────────

    #[test]
    fn signing_key_from_valid_hex() {
        let sk = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let hex = hex::encode(sk.to_bytes());
        let cfg = NodeConfig { private_key: Some(hex), ..Default::default() };
        let loaded = cfg.signing_key().unwrap();
        assert_eq!(loaded.to_bytes(), sk.to_bytes(), "signing key must round-trip via hex");
    }

    #[test]
    fn signing_key_invalid_hex_fails() {
        let cfg = NodeConfig { private_key: Some("not_hex!".into()), ..Default::default() };
        assert!(cfg.signing_key().is_err(), "invalid hex must fail");
    }

    #[test]
    fn signing_key_wrong_length_fails() {
        // 16 bytes (32 hex chars) — too short
        let cfg = NodeConfig { private_key: Some("aabbccdd".repeat(4)), ..Default::default() };
        assert!(cfg.signing_key().is_err(), "wrong-length key must fail");
    }

    // Both ephemeral-key checks live in one test because they manipulate a
    // process-global env var; running them in parallel would race.
    #[test]
    fn signing_key_none_requires_explicit_opt_in() {
        let cfg = NodeConfig { private_key: None, ..Default::default() };

        // Phase 1: without the env var, must refuse.
        unsafe { std::env::remove_var("NORN_ALLOW_EPHEMERAL_KEY"); }
        assert!(cfg.signing_key().is_err(),
            "ephemeral key must require explicit opt-in via NORN_ALLOW_EPHEMERAL_KEY");

        // Phase 2: with the env var, must succeed.
        unsafe { std::env::set_var("NORN_ALLOW_EPHEMERAL_KEY", "1"); }
        let result = cfg.signing_key();
        unsafe { std::env::remove_var("NORN_ALLOW_EPHEMERAL_KEY"); }
        assert!(result.is_ok(), "explicit opt-in must allow ephemeral key");
    }

    // ── tcp_listen_port ───────────────────────────────────────────────────────

    #[test]
    fn tcp_listen_port_extracts_correctly() {
        let cfg = NodeConfig {
            listen: vec!["tcp://0.0.0.0:9001".into()],
            ..Default::default()
        };
        assert_eq!(cfg.tcp_listen_port(), Some(9001));
    }

    #[test]
    fn tcp_listen_port_empty_listen_returns_none() {
        let cfg = NodeConfig { listen: vec![], ..Default::default() };
        assert_eq!(cfg.tcp_listen_port(), None);
    }

    #[test]
    fn tcp_listen_port_non_tcp_returns_none() {
        let cfg = NodeConfig { listen: vec!["invalid".into()], ..Default::default() };
        assert_eq!(cfg.tcp_listen_port(), None);
    }

    // ── generate_toml ─────────────────────────────────────────────────────────

    #[test]
    fn generate_toml_contains_private_key() {
        let toml = NodeConfig::generate_toml();
        assert!(toml.contains("private_key"), "generate_toml must include private_key field");
        assert!(!toml.is_empty(), "generate_toml must not be empty");
    }

    #[test]
    fn generate_toml_is_valid_toml() {
        let toml_str = NodeConfig::generate_toml();
        let parsed: Result<NodeConfig, _> = toml::from_str(&toml_str);
        assert!(parsed.is_ok(), "generate_toml must produce valid TOML: {:?}", parsed);
    }

    // ── load from file ────────────────────────────────────────────────────────

    #[test]
    fn load_valid_config() {
        use std::io::Write;
        let toml_str = NodeConfig::generate_toml();
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(toml_str.as_bytes()).unwrap();
        // Lock down permissions before load() — load() refuses world-readable configs.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let cfg = NodeConfig::load(tmp.path()).unwrap();
        assert!(cfg.private_key.is_some(), "loaded config must have private_key");
    }

    #[test]
    fn load_nonexistent_file_fails() {
        let result = NodeConfig::load(Path::new("/nonexistent/path/norn.toml"));
        assert!(result.is_err(), "loading nonexistent file must fail");
    }

    #[cfg(unix)]
    #[test]
    fn load_refuses_world_readable_config() {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;
        let toml_str = NodeConfig::generate_toml();
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(toml_str.as_bytes()).unwrap();
        // Deliberately permissive.
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = NodeConfig::load(tmp.path()).unwrap_err().to_string();
        assert!(err.contains("mode") || err.contains("600"),
            "must reject world-readable config; got: {err}");
    }
}
