// Multicast peer discovery for norn-rs.
//
// Sends UDP beacons to ff02::1:9 (link-local multicast) every 30 seconds.
// On receipt of a foreign beacon, dials the announced TCP address.
//
// Beacon wire format: [magic: 4]["NORN"][pub_key: 32][tcp_port: 2]

use anyhow::Result;
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{Ipv6Addr, SocketAddrV6};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tracing::{debug, info, warn};

use crate::router::PacketConn;
use crate::transport::{dial, ConnectedPeers};

/// Link-local multicast group for norn discovery.
const MULTICAST_GROUP: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0x01, 0x09);
const BEACON_MAGIC: &[u8; 4] = b"NORN";
const BEACON_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);

/// Start multicast peer discovery.
/// `tcp_port`: our TCP listen port to announce (None = listen-only mode).
// Skip mutations: binds real multicast UDP sockets and loops indefinitely —
// all mutations require a live multicast-capable network interface.
#[mutants::skip]
pub async fn start(
    conn: Arc<PacketConn>,
    multicast_port: u16,
    tcp_port: Option<u16>,
    connected: ConnectedPeers,
) -> Result<()> {
    let sock = build_socket(multicast_port)?;
    let sock = Arc::new(sock);

    // Sender: broadcast our beacon periodically
    if let Some(port) = tcp_port {
        let sock_tx = sock.clone();
        let our_pub = conn.pub_key;
        let target = std::net::SocketAddr::V6(
            SocketAddrV6::new(MULTICAST_GROUP, multicast_port, 0, 0)
        );
        tokio::spawn(async move {
            // Small initial delay so the listener loop is ready
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            loop {
                let mut beacon = BEACON_MAGIC.to_vec();
                beacon.extend_from_slice(&our_pub);
                beacon.extend_from_slice(&port.to_le_bytes());
                if let Err(e) = sock_tx.send_to(&beacon, target).await {
                    warn!("multicast send: {}", e);
                }
                tokio::time::sleep(BEACON_INTERVAL).await;
            }
        });
    }

    // Receiver: handle incoming beacons
    let our_pub = conn.pub_key;
    let mut buf = [0u8; 256];
    loop {
        let (len, src) = match sock.recv_from(&mut buf).await {
            Ok(r) => r,
            Err(e) => { warn!("multicast recv: {}", e); continue; }
        };

        let data = &buf[..len];
        if data.len() < 4 + 32 + 2 || &data[..4] != BEACON_MAGIC {
            continue;
        }

        let mut remote_pub = [0u8; 32];
        remote_pub.copy_from_slice(&data[4..36]);
        let port = u16::from_le_bytes([data[36], data[37]]);

        if remote_pub == our_pub {
            continue; // our own beacon
        }

        // Skip already-connected peers
        if conn.get_peer_stats().iter().any(|p| p.key == remote_pub) {
            continue;
        }

        let src_ip = match src.ip() {
            std::net::IpAddr::V6(ip) => ip,
            std::net::IpAddr::V4(ip) => ip.to_ipv6_mapped(),
        };
        // Strip IPv6 zone id / link-local scope from address
        let src_ip_str = if src_ip.is_loopback() {
            "127.0.0.1".to_string()
        } else {
            src_ip.to_string()
        };
        let dial_uri = format!("tcp://[{}]:{}", src_ip_str, port);
        info!("discovered peer {:?} via multicast at {}", &remote_pub[..4], dial_uri);

        let conn_clone = conn.clone();
        let connected_clone = connected.clone();
        tokio::spawn(async move {
            dial(&dial_uri, conn_clone, connected_clone).await;
        });

        debug!("multicast beacon from {:?}", &remote_pub[..4]);
    }
}

fn build_socket(port: u16) -> Result<UdpSocket> {
    let sock = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_reuse_address(true)?;
    #[cfg(unix)]
    sock.set_reuse_port(true)?;
    sock.set_nonblocking(true)?;
    sock.bind(&SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0).into())?;
    // Join multicast on all interfaces (interface index 0 = all)
    sock.join_multicast_v6(&MULTICAST_GROUP, 0)?;
    sock.set_multicast_loop_v6(false)?;
    let std_sock: std::net::UdpSocket = sock.into();
    Ok(UdpSocket::from_std(std_sock)?)
}
