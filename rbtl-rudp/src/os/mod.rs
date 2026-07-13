
#[cfg(target_os = "windows")]
pub mod windows;

/// Prepare the socket with OS-specific stuff
///
/// This is useful to make it behavethe same through all platforms
#[allow(unused)]
pub fn prepare_socket(udp_socket: &std::net::UdpSocket) {
    #[cfg(target_os = "windows")]
    windows::disable_virtual_udp_circuit(udp_socket);
}