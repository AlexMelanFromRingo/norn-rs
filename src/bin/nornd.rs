// nornd — norn-rs mesh routing daemon

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;

use norn_rs::config::NodeConfig;
use norn_rs::node::Node;

#[derive(Parser)]
#[command(
    name = "nornd",
    version = env!("CARGO_PKG_VERSION"),
    about = "norn-rs mesh routing daemon",
    long_about = "A next-generation mesh routing daemon with hyperbolic geometric routing,\n\
                  K=3 spanning trees, cuckoo filter gossip, and ChaCha20-Poly1305 sessions."
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    /// Config file path
    #[arg(short, long, value_name = "FILE", default_value = "/etc/norn/norn.toml")]
    config: PathBuf,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a new config file with a random private key
    Genconfig {
        /// Output file path [default: stdout]
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Show this node's public key and IPv6 address from a config file
    Showaddr,
}

// Skip mutations of main: it is an integration entry point that calls tokio::signal::ctrl_c()
// and network I/O that cannot be unit-tested. Any mutation here (e.g. replace with Ok(()))
// would require a full end-to-end integration test to catch.
#[mutants::skip]
#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Some(Command::Genconfig { output }) => {
            let toml = NodeConfig::generate_toml();
            match output {
                Some(path) => {
                    // Write with 0o600 atomically: open with O_CREAT|O_EXCL|O_WRONLY
                    // and a restrictive mode so the secret never exists with looser perms.
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::OpenOptionsExt;
                        use std::io::Write;
                        let mut f = std::fs::OpenOptions::new()
                            .create_new(true)
                            .write(true)
                            .mode(0o600)
                            .open(path)
                            .with_context(|| format!("creating {:?} (refusing to overwrite)", path))?;
                        f.write_all(toml.as_bytes())
                            .with_context(|| format!("writing config to {:?}", path))?;
                    }
                    #[cfg(not(unix))]
                    {
                        std::fs::write(path, &toml)
                            .with_context(|| format!("writing config to {:?}", path))?;
                    }
                    eprintln!("config written to {:?} (mode 0600)", path);
                }
                None => print!("{}", toml),
            }
            return Ok(());
        }

        Some(Command::Showaddr) => {
            let config = NodeConfig::load(&cli.config)
                .with_context(|| format!("loading {:?}", cli.config))?;
            let sk = config.signing_key()?;
            let pub_key = sk.verifying_key().to_bytes();
            let addr = norn_rs::address::address_from_key(&pub_key);
            let addr_str = format_ipv6(&addr);
            println!("pub_key: {}", hex::encode(pub_key));
            println!("address: {}", addr_str);
            return Ok(());
        }

        None => {} // fall through to daemon start
    }

    // Load config
    let config = if cli.config.exists() {
        NodeConfig::load(&cli.config)
            .with_context(|| format!("loading config {:?}", cli.config))?
    } else {
        eprintln!(
            "config not found at {:?} — using defaults with ephemeral key.\n\
             Run `nornd genconfig` to create a persistent config.",
            cli.config
        );
        NodeConfig::default()
    };

    // Init logging
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(&config.log_level));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();

    // Start node
    let node = Node::new(config).await?;
    node.start().await?;

    // Run forever (Ctrl-C to exit)
    tracing::info!("nornd running — Ctrl-C to stop");
    tokio::signal::ctrl_c().await.context("waiting for Ctrl-C")?;
    tracing::info!("shutting down");
    node.conn.close().await;

    Ok(())
}

fn format_ipv6(bytes: &[u8; 16]) -> String {
    use std::net::Ipv6Addr;
    let mut groups = [0u16; 8];
    for (i, chunk) in bytes.chunks(2).enumerate() {
        groups[i] = u16::from_be_bytes([chunk[0], chunk[1]]);
    }
    Ipv6Addr::new(
        groups[0], groups[1], groups[2], groups[3],
        groups[4], groups[5], groups[6], groups[7],
    ).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_ipv6_loopback() {
        let mut bytes = [0u8; 16];
        bytes[15] = 1;
        assert_eq!(format_ipv6(&bytes), "::1",
            "loopback address must format as ::1");
    }

    #[test]
    fn format_ipv6_all_bytes_set() {
        // 2001:0db8:85a3:0000:0000:8a2e:0370:7334
        let bytes: [u8; 16] = [
            0x20, 0x01, 0x0d, 0xb8,
            0x85, 0xa3, 0x00, 0x00,
            0x00, 0x00, 0x8a, 0x2e,
            0x03, 0x70, 0x73, 0x34,
        ];
        let s = format_ipv6(&bytes);
        // Rust formats this with consecutive-zero compression
        assert!(s.contains("2001") && s.contains("db8") && s.contains("7334"),
            "format_ipv6 must return a non-empty IPv6 string, got {:?}", s);
        assert!(!s.is_empty());
        assert_ne!(s, "xyzzy", "must not return placeholder string");
        assert_ne!(s, "", "must not return empty string");
    }

    #[test]
    fn format_ipv6_known_address() {
        // 0200:0000:0000:0000:0000:0000:0000:0001 = 200::1
        let bytes: [u8; 16] = [
            0x02, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01,
        ];
        assert_eq!(format_ipv6(&bytes), "200::1",
            "known address must format to 200::1");
    }
}
