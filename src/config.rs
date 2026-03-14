// Node configuration — loaded from TOML file.

use anyhow::{Context, Result};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::path::Path;

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
}

fn default_listen() -> Vec<String> { vec!["tcp://0.0.0.0:9001".to_string()] }
fn default_tun_name() -> Option<String> { Some("norn0".to_string()) }
fn default_admin_socket() -> String { "/var/run/norn.sock".to_string() }
fn default_true() -> bool { true }
fn default_multicast_port() -> u16 { 9001 }
fn default_log_level() -> String { "info".to_string() }

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
        }
    }
}

impl NodeConfig {
    /// Load config from a TOML file.
    pub fn load(path: &Path) -> Result<Self> {
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
    pub fn signing_key(&self) -> Result<SigningKey> {
        match &self.private_key {
            Some(hex_key) => {
                let bytes = hex::decode(hex_key).context("decoding private_key hex")?;
                if bytes.len() != 32 {
                    anyhow::bail!("private_key must be 32 bytes (64 hex chars), got {}", bytes.len());
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                Ok(SigningKey::from_bytes(&arr))
            }
            None => {
                tracing::warn!("no private_key in config, using ephemeral key (identity will change on restart)");
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
