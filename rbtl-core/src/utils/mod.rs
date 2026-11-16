//! Helpers for implementors

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};

mod ping_tracker;

pub use ping_tracker::PingTracker;

/// Helper for implementors: turns the local address of a bound socket into an address other machines can use.
///
/// A socket bound to 0.0.0.0 (or ::) listens on every interface, but that address can't be connected to.
/// In that case, the IP of the interface used to reach the internet is used instead (usually the LAN IP),
/// or localhost if there is no network.
pub fn shareable_local_addr(local_addr: SocketAddr) -> SocketAddr {
    if !local_addr.ip().is_unspecified() {
        return local_addr;
    }
    let (bind_addr, probe_addr, localhost): (SocketAddr, SocketAddr, IpAddr) = if local_addr.is_ipv4() {
        (
            (Ipv4Addr::UNSPECIFIED, 0).into(),
            (Ipv4Addr::new(8, 8, 8, 8), 53).into(),
            Ipv4Addr::LOCALHOST.into(),
        )
    } else {
        (
            (Ipv6Addr::UNSPECIFIED, 0).into(),
            (Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888), 53).into(),
            Ipv6Addr::LOCALHOST.into(),
        )
    };
    // "connecting" a udp socket sends nothing, it only asks the OS which interface it would use
    // so we're using a completely irrelevant probe_addr to just get the socket's local_addr
    let ip = UdpSocket::bind(bind_addr)
        .and_then(|probe| probe.connect(probe_addr).and_then(|()| probe.local_addr()))
        .map(|addr| addr.ip())
        .ok()
        .filter(|ip| !ip.is_unspecified())
        .unwrap_or(localhost);
    SocketAddr::new(ip, local_addr.port())
}

#[test]
fn shareable_local_addr_keeps_specific_ip() {
    let addr: SocketAddr = "192.168.1.20:4000".parse().unwrap();
    assert_eq!(shareable_local_addr(addr), addr);
    let shared = shareable_local_addr("0.0.0.0:4000".parse().unwrap());
    assert_eq!(shared.port(), 4000);
    assert!(!shared.ip().is_unspecified());
}
