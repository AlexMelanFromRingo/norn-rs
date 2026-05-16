// nornctl — admin client for nornd
//
// Wraps the JSON UNIX-socket protocol exposed by `nornd` so operators don't
// have to remember the JSON shape. Defaults to the system socket; --socket
// switches it. Exits non-zero on transport errors or daemon-reported errors.

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

const DEFAULT_SOCKET: &str = "/var/run/norn.sock";

#[derive(Parser)]
#[command(
    name = "nornctl",
    version = env!("CARGO_PKG_VERSION"),
    about = "Administer a running nornd daemon",
    long_about = "Talks to the nornd admin UNIX socket. Default path: /var/run/norn.sock.\n\
                  Use --socket to override (e.g. when running nornd as a non-root user)."
)]
struct Cli {
    /// Path to the admin UNIX socket.
    #[arg(short = 's', long, default_value = DEFAULT_SOCKET)]
    socket: PathBuf,

    /// Output raw JSON instead of a human-readable table.
    #[arg(long)]
    json: bool,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Show this node's identity, address, and peer count.
    Status,
    /// List currently-connected peers with link metrics.
    Peers,
    /// Dial a new peer at the given URI (tcp://host:port).
    Addpeer { uri: String },
    /// Show derived address for the node behind a given hex pubkey.
    Showaddr {
        /// 64-char hex Ed25519 public key.
        pub_key_hex: String,
    },
}

// ── JSON wire structs (mirror src/admin.rs) ──────────────────────────────

#[derive(Serialize)]
struct Req<'a> {
    method: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    uri: Option<String>,
}

#[derive(Deserialize, Debug)]
struct SelfInfo {
    pub_key: String,
    address: String,
    peer_count: usize,
}

#[derive(Deserialize, Debug)]
#[allow(dead_code)] // Used reflectively via serde_json::from_value; fields are read indirectly.
struct PeerInfo {
    pub_key: String,
    address: String,
    lag_ms: f64,
    jitter_ms: f64,
    loss_rate: f32,
    rx_bytes: u64,
    tx_bytes: u64,
    uptime_secs: f64,
    priority: u8,
    trust: f32,
}

#[derive(Deserialize, Debug)]
struct AddPeerResult {
    status: String,
    uri: String,
}

// The admin socket returns `untagged` unions; we parse with serde_json::Value
// first and dispatch on the field shape.

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.cmd {
        Cmd::Status => {
            let v = call(&cli.socket, "getSelf", None).await?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&v)?);
            } else {
                let s: SelfInfo = serde_json::from_value(v).context("parsing getSelf reply")?;
                println!("pub_key:    {}", s.pub_key);
                println!("address:    {}", s.address);
                println!("peer_count: {}", s.peer_count);
            }
        }
        Cmd::Peers => {
            let v = call(&cli.socket, "getPeers", None).await?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&v)?);
            } else {
                let peers: Vec<PeerInfo> = serde_json::from_value(v).context("parsing getPeers reply")?;
                if peers.is_empty() {
                    println!("(no peers connected)");
                } else {
                    println!("{:<10}  {:<40}  {:>8}  {:>8}  {:>6}  {:>5}  {:>10}  {:>10}  {:>10}",
                        "ID", "ADDRESS", "LAG_MS", "JITTER", "LOSS", "TRUST", "RX", "TX", "UPTIME_S");
                    for p in peers {
                        let id_short = &p.pub_key[..p.pub_key.len().min(8)];
                        println!("{:<10}  {:<40}  {:>8.1}  {:>8.1}  {:>6.3}  {:>5.2}  {:>10}  {:>10}  {:>10.0}",
                            id_short, p.address, p.lag_ms, p.jitter_ms,
                            p.loss_rate, p.trust, p.rx_bytes, p.tx_bytes, p.uptime_secs);
                    }
                }
            }
        }
        Cmd::Addpeer { uri } => {
            let v = call(&cli.socket, "addPeer", Some(uri.clone())).await?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&v)?);
            } else {
                let r: AddPeerResult = serde_json::from_value(v).context("parsing addPeer reply")?;
                println!("{}: {}", r.status, r.uri);
            }
        }
        Cmd::Showaddr { pub_key_hex } => {
            // Local computation — no socket call needed.
            let bytes = hex::decode(&pub_key_hex).context("pub_key_hex must be hex")?;
            if bytes.len() != 32 {
                bail!("pub_key_hex must decode to 32 bytes, got {}", bytes.len());
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            let addr = norn_rs::address::address_from_key(&arr);
            use std::net::Ipv6Addr;
            let v6 = Ipv6Addr::from(addr);
            println!("{}", v6);
        }
    }

    Ok(())
}

/// Send one JSON request, read one JSON reply, return as serde Value.
/// Aborts on transport error or daemon-reported `{"error": ...}`.
async fn call(socket: &PathBuf, method: &str, uri: Option<String>) -> Result<serde_json::Value> {
    let stream = UnixStream::connect(socket)
        .await
        .with_context(|| format!("connecting admin socket {:?}", socket))?;
    let (reader, mut writer) = stream.into_split();

    let req = serde_json::to_string(&Req { method, uri })?;
    writer.write_all(req.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    writer.shutdown().await.ok(); // half-close so server flushes its reply

    let mut lines = BufReader::new(reader).lines();
    let line = lines.next_line().await?
        .ok_or_else(|| anyhow::anyhow!("admin socket closed without reply"))?;
    let v: serde_json::Value = serde_json::from_str(&line)
        .with_context(|| format!("parsing reply JSON: {line}"))?;

    // The admin server uses untagged unions; an error variant returns
    // {"error": "..."}.
    if let Some(err) = v.get("error").and_then(|s| s.as_str()) {
        bail!("daemon error: {err}");
    }
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_parses_status() {
        let cli = Cli::try_parse_from(["nornctl", "status"]).unwrap();
        assert!(matches!(cli.cmd, Cmd::Status));
    }

    #[test]
    fn cli_parses_peers() {
        let cli = Cli::try_parse_from(["nornctl", "peers"]).unwrap();
        assert!(matches!(cli.cmd, Cmd::Peers));
    }

    #[test]
    fn cli_parses_addpeer_with_uri() {
        let cli = Cli::try_parse_from(["nornctl", "addpeer", "tcp://1.2.3.4:9001"]).unwrap();
        match cli.cmd {
            Cmd::Addpeer { uri } => assert_eq!(uri, "tcp://1.2.3.4:9001"),
            _ => panic!("expected Addpeer"),
        }
    }

    #[test]
    fn cli_parses_showaddr() {
        let cli = Cli::try_parse_from(["nornctl", "showaddr", &"00".repeat(32)]).unwrap();
        match cli.cmd {
            Cmd::Showaddr { pub_key_hex } => assert_eq!(pub_key_hex.len(), 64),
            _ => panic!("expected Showaddr"),
        }
    }

    #[test]
    fn cli_socket_override() {
        let cli = Cli::try_parse_from(["nornctl", "-s", "/tmp/x.sock", "status"]).unwrap();
        assert_eq!(cli.socket.to_str().unwrap(), "/tmp/x.sock");
    }

    #[test]
    fn cli_default_socket() {
        let cli = Cli::try_parse_from(["nornctl", "status"]).unwrap();
        assert_eq!(cli.socket.to_str().unwrap(), DEFAULT_SOCKET);
    }
}
