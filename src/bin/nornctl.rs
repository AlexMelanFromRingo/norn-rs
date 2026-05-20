// nornctl — admin client for nornd
//
// Wraps the JSON UNIX-socket protocol exposed by `nornd` so operators don't
// have to remember the JSON shape. Defaults to the system socket; --socket
// switches it. Exits non-zero on transport errors or daemon-reported errors.

use anyhow::{bail, Context, Result};
use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::{generate, Shell};
use serde::{Deserialize, Serialize};
use std::io;
use std::path::PathBuf;
#[cfg(unix)]
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
#[cfg(unix)]
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
    /// Show this node's identity as a shareable QR code + word mnemonic.
    ///
    /// Hand the 24-word phrase to someone over the phone, or let them
    /// scan the QR — both decode back to the exact 64-hex public key.
    Share,
    /// Decode a 24-word key mnemonic back into a hex public key + address.
    ///
    /// Example: nornctl resolve abandon abandon ... art
    Resolve {
        /// The 24 words of the mnemonic, space-separated.
        #[arg(required = true, num_args = 1..)]
        mnemonic: Vec<String>,
    },
    /// Emit shell-completion script to stdout.
    ///
    /// Examples:
    ///   nornctl completions bash > /usr/share/bash-completion/completions/nornctl
    ///   nornctl completions zsh  > ~/.zsh/completions/_nornctl
    ///   nornctl completions fish > ~/.config/fish/completions/nornctl.fish
    Completions {
        /// Target shell: bash | zsh | fish | elvish | powershell
        #[arg(value_enum)]
        shell: Shell,
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
        Cmd::Completions { shell } => {
            // Generate the script to stdout — does not touch the admin socket.
            let mut cmd = Cli::command();
            let name = cmd.get_name().to_string();
            generate(shell, &mut cmd, name, &mut io::stdout());
            return Ok(());
        }
        Cmd::Showaddr { pub_key_hex } => {
            // Local computation — no socket call needed.
            let arr = parse_hex_key(&pub_key_hex)?;
            let addr = norn_rs::address::address_from_key(&arr);
            println!("{}", std::net::Ipv6Addr::from(addr));
        }
        Cmd::Share => {
            // getSelf gives us our own pub_key; the rest is local rendering.
            let v = call(&cli.socket, "getSelf", None).await?;
            let s: SelfInfo = serde_json::from_value(v).context("parsing getSelf reply")?;
            let key = parse_hex_key(&s.pub_key)?;
            let mnemonic = norn_rs::keyshare::to_mnemonic(&key);
            if cli.json {
                let out = serde_json::json!({
                    "pub_key": s.pub_key,
                    "address": s.address,
                    "mnemonic": mnemonic,
                });
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else {
                println!("pub_key:  {}", s.pub_key);
                println!("address:  {}", s.address);
                println!();
                println!("mnemonic (24 words — read aloud or paste; `nornctl resolve` decodes it):");
                println!("  {mnemonic}");
                println!();
                println!("QR (scan with a phone camera):");
                println!("{}", norn_rs::keyshare::qr_terminal(&s.pub_key)?);
            }
        }
        Cmd::Resolve { mnemonic } => {
            // Local computation — no socket call needed.
            let key = norn_rs::keyshare::from_mnemonic(&mnemonic.join(" "))?;
            let hex_key = hex::encode(key);
            let v6 = std::net::Ipv6Addr::from(norn_rs::address::address_from_key(&key));
            if cli.json {
                let out = serde_json::json!({ "pub_key": hex_key, "address": v6.to_string() });
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else {
                println!("pub_key:  {hex_key}");
                println!("address:  {v6}");
            }
        }
    }

    Ok(())
}

/// Decode a 64-char hex string into a 32-byte key array.
fn parse_hex_key(hex_str: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(hex_str.trim()).context("public key must be hex")?;
    if bytes.len() != 32 {
        bail!("public key must decode to 32 bytes, got {}", bytes.len());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

/// Send one JSON request, read one JSON reply, return as serde Value.
/// Aborts on transport error or daemon-reported `{"error": ...}`.
#[cfg(unix)]
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

/// Windows stub: admin socket protocol is UNIX-only. status/peers/addpeer
/// all need this; only `showaddr` (local computation) and `completions`
/// work without a daemon.
#[cfg(not(unix))]
async fn call(_socket: &PathBuf, _method: &str, _uri: Option<String>) -> Result<serde_json::Value> {
    bail!("admin socket commands (status/peers/addpeer) are not supported on Windows; \
           use showaddr or completions, or run nornctl on a Unix host")
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
    fn cli_parses_share() {
        let cli = Cli::try_parse_from(["nornctl", "share"]).unwrap();
        assert!(matches!(cli.cmd, Cmd::Share));
    }

    #[test]
    fn cli_parses_resolve_collects_all_words() {
        let words = "abandon abandon abandon abandon abandon abandon abandon abandon \
                     abandon abandon abandon abandon abandon abandon abandon abandon \
                     abandon abandon abandon abandon abandon abandon abandon art";
        let mut argv = vec!["nornctl", "resolve"];
        argv.extend(words.split_whitespace());
        let cli = Cli::try_parse_from(argv).unwrap();
        match cli.cmd {
            Cmd::Resolve { mnemonic } => {
                assert_eq!(mnemonic.len(), 24, "all 24 words must be collected");
                // Round-trips through the keyshare decoder to the zero key.
                assert_eq!(
                    norn_rs::keyshare::from_mnemonic(&mnemonic.join(" ")).unwrap(),
                    [0u8; 32]
                );
            }
            _ => panic!("expected Resolve"),
        }
    }

    #[test]
    fn cli_resolve_requires_at_least_one_word() {
        assert!(Cli::try_parse_from(["nornctl", "resolve"]).is_err());
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

    #[test]
    fn cli_completions_accepts_known_shells() {
        for s in &["bash", "zsh", "fish", "elvish", "powershell"] {
            let cli = Cli::try_parse_from(["nornctl", "completions", s]).unwrap();
            assert!(matches!(cli.cmd, Cmd::Completions { .. }));
        }
    }

    #[test]
    fn cli_completions_rejects_unknown_shell() {
        let result = Cli::try_parse_from(["nornctl", "completions", "tcsh"]);
        assert!(result.is_err());
    }

    #[test]
    fn completions_bash_writes_nonempty() {
        // Smoke test: generate a bash completion script into a Vec<u8> and
        // verify it's a plausible shell script (mentions our binary name).
        let mut buf = Vec::new();
        let mut cmd = Cli::command();
        let name = cmd.get_name().to_string();
        generate(Shell::Bash, &mut cmd, name, &mut buf);
        let s = String::from_utf8(buf).expect("completion output must be UTF-8");
        assert!(!s.is_empty(), "bash completion script must not be empty");
        assert!(s.contains("nornctl"),
            "bash completion script must mention 'nornctl'");
    }
}
