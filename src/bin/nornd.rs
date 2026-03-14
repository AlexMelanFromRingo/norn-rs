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

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Some(Command::Genconfig { output }) => {
            let toml = NodeConfig::generate_toml();
            match output {
                Some(path) => {
                    std::fs::write(path, &toml)
                        .with_context(|| format!("writing config to {:?}", path))?;
                    eprintln!("config written to {:?}", path);
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
