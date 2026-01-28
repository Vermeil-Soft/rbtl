use std::os::windows::io::AsRawSocket;

/// Disable the "ConnectionReset" errors that might spawn on windows because of virtual udp circuit
pub fn disable_virtual_udp_circuit(udp_socket: &std::net::UdpSocket) {
    use windows::Win32::Networking::WinSock::{WSAIoctl, SOCKET};
    use windows::Win32::Foundation::{BOOL};
    let socket = udp_socket.as_raw_socket();
    let mut bytes_returned = 0;
    let enable = BOOL::from(&false);
    unsafe {
        let _r = WSAIoctl(
            SOCKET(socket as usize),
            windows::Win32::Networking::WinSock::SIO_UDP_CONNRESET,
            Some(&enable as *const _ as *const core::ffi::c_void),
            std::mem::size_of_val(&enable) as u32,
            None,
            0,
            &mut bytes_returned,
            None,
            None
        );
    }
}