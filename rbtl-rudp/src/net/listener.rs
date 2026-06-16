use std::net::{SocketAddr, UdpSocket, ToSocketAddrs};
use std::io::{ErrorKind as IoErrorKind, Result as IoResult};
use std::sync::Arc;
use std::time::Duration;
use std::fmt::Display;

use byteorder::{ByteOrder, LittleEndian};
use hashbrown::{HashMap, hash_map::Entry};
use std::ops::{Index, IndexMut};

use crate::net::socket::{SocketCreateError};
use crate::{PacketSendOptions, SeqId, SocketEvent, SocketShared, Error};
use crate::net::common::{ListenerConfig, SocketConfig, PacketSendError};
use crate::net::protocol::packet::{UdpBytes};

/// Represents the identity of a socket of a Listener.
///
/// To ease use with potential STUN servers, connections are not obtained with a SocketAddr, but instead a custom
/// SocketIdentity, holding the first 4 bytes of the public key of the remote
#[derive(Hash, Clone, Copy, Eq, PartialEq)]
pub struct SocketIdentity {
    /// first 4 bytes of a remote's public key.
    pub (crate) public_key: [u8; 4],
}

impl std::fmt::Debug for SocketIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SocketIdentity({})", self)
    }
}

impl SocketIdentity {
    pub fn as_bytes(&self) -> &[u8; 4] {
        &self.public_key
    }

    pub fn as_u32(&self) -> u32 {
        LittleEndian::read_u32(&self.public_key[0..4])
    }
}

impl std::fmt::Display for SocketIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:08x}", self.as_u32())
    }
}

/// A Server that holds multiple remotes
///
/// It handles incoming connections automatically, expired connections (timeouts),
/// and obviously the ability to send/receive data and events to all remotes, either by handpicking
/// or all at the same time.
///
/// The `get_mut` method allows you to get mutably a socket to send a specific remote some data.
/// However, if you choose to not send everyone the same data, you **will** have to
/// keep track of the socket identities in one way or another.
#[derive(Debug)]
pub struct Listener {
    pub (crate) remotes: HashMap<SocketIdentity, SocketShared>,
    pub (crate) udp_socket: Arc<UdpSocket>,
    pub (crate) unknown_messages: std::collections::VecDeque<(Box<[u8]>, SocketAddr)>,
    pub (crate) socket_config: SocketConfig,
    
    pub (crate) listener_config: ListenerConfig,
}

impl Listener {
    /// Tries to create a new server with the binding address.
    ///
    /// It's often a good idea to have a value like "0.0.0.0:YOUR_PORT",
    /// to bind your address to the internet.
    pub fn new<A: ToSocketAddrs + Display>(local_addr: A) -> Result<Listener, Error> {
        let udp_socket = Arc::new(UdpSocket::bind(&local_addr)
            .map_err(|e| Error::from_cause(format!("failed to bind {}", local_addr), e))?);

        crate::os::prepare_socket(&udp_socket);
        udp_socket.set_nonblocking(true)
            .map_err(|e| Error::from_cause(format!("failed to set socket as non blocking"), e))?;
        Ok(Listener {
            remotes: HashMap::default(),
            udp_socket,
            socket_config: SocketConfig::new(),
            listener_config: ListenerConfig::new(),
            unknown_messages: Default::default(),
        })
    }

    pub (crate) fn update_config_for_remotes(&mut self) {
        for socket in self.remotes.values_mut() {
            socket.config.clone_from(&self.socket_config);
        }
    }

    /// Set the time required before a remote is set as "dead" for all past and all new remotes.
    pub fn set_timeout_delay(&mut self, timeout_delay: Duration) {
        self.socket_config.timeout_delay = timeout_delay;
        self.update_config_for_remotes();
    }

    /// Set the time required before we send a "heartbeat" message to the clients, to avoid seeing us as timeout-ed.
    pub fn set_heartbeat(&mut self, delay: Duration) {
        self.socket_config.heartbeat_delay = delay;
        self.update_config_for_remotes();
    }

    fn process_one_incoming(&mut self, udp_packet: UdpBytes<Box<[u8]>>, remote_addr: SocketAddr) -> IoResult<()> {
        let packet = match udp_packet.compute_packet() {
            Ok(packet) => packet,
            Err((error, udp_bytes)) => {
                if self.listener_config.transfer_unknown_raw {
                    self.unknown_messages.push_back((udp_bytes.buffer, remote_addr));
                } else {
                    log::trace!("invalid packet coming from {}: {:?}", remote_addr, error);
                }
                return Ok(())
            },
        };
        let identity = SocketIdentity { public_key: packet.pub_identity };
        match self.remotes.entry(identity) {
            Entry::Occupied(mut o) => {
                let socket = o.get_mut();
                if remote_addr == socket.socket.remote_addr {
                    // ensure that the address we know from this pub_id is the same we just got the message from
                    socket.add_packet(packet);
                }
            },
            Entry::Vacant(vacant) => {
                // buffer len is used for debug/log purposes
                match SocketShared::new_incoming(self.udp_socket.clone(), packet, remote_addr) {
                    Err(SocketCreateError::IoError(io_error)) => return Err(io_error),
                    Err(SocketCreateError::NotSyn) => {
                        log::trace!("received unexpected message from unknown remote {}", remote_addr);
                        /* ignore */
                    },
                    Ok(mut socket) => {
                        socket.config = self.socket_config.clone();
                        vacant.insert(socket);
                    },
                };
            }
        };
        Ok(())
    }

    pub fn raw(&self) -> &UdpSocket {
        &self.udp_socket
    }

    pub (crate) fn process_all_incoming(&mut self) -> IoResult<()> {
        let mut done = false;

        while !done {
            match UdpBytes::<Box<[u8]>>::from_udp_socket(&self.udp_socket) {
                Ok((packet, socket_addr)) => {
                    self.process_one_incoming(packet, socket_addr)?;
                },
                Err(err) => {
                    match err.kind() {
                        IoErrorKind::WouldBlock => { done = true },
                        // Windows may send ConnectionReset errors, even for UDP:
                        // On a UDP-datagram socket this error indicates a previous
                        // send operation resulted in an ICMP Port Unreachable message.
                        // https://stackoverflow.com/questions/15228272/what-would-cause-a-connectionreset-on-an-udp-socket
                        IoErrorKind::ConnectionReset => { continue; },
                        err_kind => {
                            panic!("received other unexpected net error {:?}", err_kind)
                        }
                    }
                },
            };
        };
        Ok(())
    }

    /// Send some data to a single remote
    pub fn send_data_to<I: Into<Arc<[u8]>> + AsRef<[u8]> + Clone>(&mut self, data: I, identity: SocketIdentity, options: PacketSendOptions) -> Result<SeqId, PacketSendError> {
        match self.remotes.get_mut(&identity) {
            Some(r) => r.send_data(data, options),
            None => Err(PacketSendError::RemoteNotConnected)
        }
    }

    /// Send some data to ALL remotes
    pub fn send_data<I: Into<Arc<[u8]>> + AsRef<[u8]> + Clone>(&mut self, data: I, options: PacketSendOptions)
        -> Result<(), PacketSendError>{
        let mut err: Option<PacketSendError> = None;
        let mut has_success = false;
        for socket in self.remotes.values_mut() {
            match socket.send_data(data.clone(), options.clone()) {
                Ok(_) => has_success = true,
                Err(e) => err = Some(e),
            }
        }
        if let Some(err) = err {
            if !has_success {
                return Err(err);
            }
        }
        Ok(())
    }

    /// Send a "end" message to ALL remotes
    pub fn send_end(&mut self) {
        for socket in self.remotes.values_mut() {
            let _r = socket.end();
        }
    }

    #[inline]
    /// Return the amount of remotes we hold
    pub fn remotes_len(&self) -> usize {
        self.remotes.len()
    }

    /// Does internal processing for all remotes. Must be done before receiving events.
    pub fn process(&mut self) -> IoResult<()> {
        self.remotes.retain(|_, v| {
            ! v.should_clear()
        });
        let now = std::time::Instant::now();
        for socket in self.remotes.values_mut() {
            socket.update_cached_now(Some(now));
        }
        self.process_all_incoming()?;
        for socket in self.remotes.values_mut() {
            socket.inner_tick()?;
        }
        Ok(())
    }

    pub fn iter(&self) -> impl Iterator<Item=(&SocketIdentity, &SocketShared)> {
        self.remotes.iter()
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item=(&SocketIdentity, &mut SocketShared)> {
        self.remotes.iter_mut()
    }

    /// Get the socket stored for given the address
    pub fn get(&self, identity: SocketIdentity) -> Option<&SocketShared> {
        self.remotes.get(&identity)
    }
    
    /// Get the mutable socket stored for given the address
    pub fn get_mut(&mut self, identity: SocketIdentity) -> Option<&mut SocketShared> {
        self.remotes.get_mut(&identity)
    }

    /// Returns an iterator that drain events for all known remotes
    ///
    /// You must call `process` before hand to ensure all the messages are correctly processed internally
    pub fn drain_events<'a>(&'a mut self) -> impl 'a + Iterator<Item=(SocketIdentity, SocketEvent)> {
        self.remotes.iter_mut().flat_map(|(addr, socket)| {
            socket.drain_events().map(move |event| (*addr, event) )
        })
    }

    /// Returns an iterator that drains events for all unknown remotes.
    ///
    /// If you have the config "accept_unknown" enabled, you **must** drain unknown events once in a while,
    /// otherwise the buffer will keep filling up and keep consuming heap as unknown messages accumulate
    pub fn drain_unknown_events<'a>(&'a mut self) -> impl 'a + Iterator<Item=(SocketAddr, Box<[u8]>)> {
        self.unknown_messages.drain(..).map(|(data, addr)| (addr, data))
    }
}

impl Index<SocketIdentity> for Listener {
    type Output = SocketShared;

    fn index<'a>(&'a self, index: SocketIdentity) -> &'a SocketShared {
        self.get(index).expect("identity does not exist for this listener")
    }
}

impl IndexMut<SocketIdentity> for Listener {
    fn index_mut<'a>(&'a mut self, index: SocketIdentity) -> &'a mut SocketShared {
        self.get_mut(index).expect("identity does not exist for this listener")
    }
}