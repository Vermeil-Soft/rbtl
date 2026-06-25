use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6, Ipv4Addr, Ipv6Addr};

#[derive(Clone, Debug)]
pub struct ConnectInfo {
    pub addr: SocketAddr
}

impl<'a> TryFrom<&'a [u8]> for ConnectInfo {
    type Error = ();

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        if value.len() == 18 {
            // ipv6
            let ip_bytes = <[u8; 16]>::try_from(&value[0..16]).unwrap();
            let port_bytes = <[u8; 2]>::try_from(&value[16..18]).unwrap();
            let v6 = SocketAddrV6::new(
                Ipv6Addr::from_octets(ip_bytes),
                u16::from_be_bytes(port_bytes),
                0,
                0
            );
            Ok(ConnectInfo { addr: SocketAddr::V6(v6) })
        } else if value.len() == 6 {
            // ipv4
            let ip_bytes = <[u8; 4]>::try_from(&value[0..4]).unwrap();
            let port_bytes = <[u8; 2]>::try_from(&value[4..6]).unwrap();
            let v4 = SocketAddrV4::new(
                Ipv4Addr::from_octets(ip_bytes),
                u16::from_be_bytes(port_bytes),
            );
            Ok(ConnectInfo { addr: SocketAddr::V4(v4) })
        } else {
            Err(())
        }
    }
}

impl TryInto<Vec<u8>> for ConnectInfo {
    type Error = ();

    fn try_into(self) -> Result<Vec<u8>, ()> {
        match self.addr {
            SocketAddr::V6(v6) => {
                let mut v = vec![0; 18];
                let ip_bytes = v6.ip().octets();
                let port_bytes = v6.port().to_be_bytes();
                (v[0..16]).copy_from_slice(&ip_bytes);
                (v[16..18]).copy_from_slice(&port_bytes);
                Ok(v)
            },
            SocketAddr::V4(v4) => {
                let mut v = vec![0; 6];
                let ip_bytes = v4.ip().octets();
                let port_bytes = v4.port().to_be_bytes();
                (v[0..4]).copy_from_slice(&ip_bytes);
                (v[4..6]).copy_from_slice(&port_bytes);
                Ok(v)
            }
        }
    }
}