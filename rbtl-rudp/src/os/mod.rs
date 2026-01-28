
#[cfg(target_os = "windows")]
pub mod windows;

/// Prepare the socket with OS-specific stuff
#[allow(unused)]
pub (crate) fn prepare_socket(udp_socket: &std::net::UdpSocket) {
    #[cfg(target_os = "windows")]
    windows::disable_virtual_udp_circuit(udp_socket);
}