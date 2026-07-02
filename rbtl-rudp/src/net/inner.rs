
use std::{
    sync::Arc,
    net::{UdpSocket, SocketAddr},
    io::{Result as IoResult},
    time::{Instant, Duration},
};

use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, aead::Aead};
use x25519_dalek::{PublicKey, EphemeralSecret, SharedSecret};

use crate::{
    SocketEvent,
    net::protocol::{fragment::{Fragment, ack::Ack}, packet::{Packet, PacketVariant}},
    net::common::SeqId,
};

use super::{
    protocol::packet::UdpBytes,
};

pub (crate) enum SocketSecret {
    Ours(EphemeralSecret),
    Shared(SharedSecret),
}

impl SocketSecret {
    pub (self) fn new(our_secret: EphemeralSecret) -> Self {
        Self::Ours(our_secret)
    }

    pub (self) fn new_shared(our_secret: EphemeralSecret, other_pub: &PublicKey) -> Self {
        Self::Shared(our_secret.diffie_hellman(other_pub))
    }

    /// Return the shared secret if available
    pub (crate) fn shared(&self) -> Option<&SharedSecret> {
        if let Self::Shared(shared) = self {
            Some(shared)
        } else {
            None
        }
    }

    pub (crate) fn apply(&mut self, other_pub: &PublicKey) {
        match self {
            Self::Ours(secret) => {
                *self = Self::Shared(std::mem::replace(secret, unsafe { std::mem::zeroed() }).diffie_hellman(other_pub))
            }
            Self::Shared(_) => {
                // nothing to do, we already have a shared secret
            }
        }
    }
}

/// Represents the internal connection status of the Socket
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketStatus {
    SynSent(Instant),
    SynReceived,

    TimeoutError { error_since: Instant, duration: Duration },

    Connected,

    TerminateSent(Instant),
    TerminateReceived(Instant),
}

impl SocketStatus {
    pub fn is_connected(self) -> bool {
        self == SocketStatus::Connected
    }

    pub (crate) fn event(self) -> Option<SocketEvent> {
        match self {
            SocketStatus::TimeoutError { .. } => Some(SocketEvent::Timeout),
            SocketStatus::TerminateSent(_) => Some(SocketEvent::Ended),
            // // this is actually commented to tell you that you should NOT uncomment this,
            // // when we receive a packet, we automatically send the right event (ended or aborted)
            // // so there is no need to have a similar event sent here as well
            // SocketStatus::TerminateReceived => Some(SocketEvent::Ended),
            SocketStatus::TerminateReceived(_) => None,
            SocketStatus::Connected => Some(SocketEvent::Connected),
            _ => None
        }
    }

    pub fn is_finished(self) -> bool {
        use SocketStatus::*;
        match self {
            TimeoutError { .. } | TerminateSent(_) | TerminateReceived(_) => true,
            _ => false
        }
    }

    pub fn is_disconnected(self) -> bool {
        use SocketStatus::*;
        match self {
            TimeoutError { .. } | TerminateReceived(_) => true,
            _ => false
        }
    }

    /// Returns true if the connection is finished and old enough to be deleted permanently.
    pub fn is_finished_and_old(self, now: Instant) -> bool {
        use SocketStatus::*;
        match self {
            TimeoutError { error_since: t, .. } | TerminateSent(t) | TerminateReceived(t) => (now - t).as_secs() >= 2,
            _ => false
        }
    }
}

impl std::fmt::Debug for SocketSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SocketSecret").finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub (crate) struct SocketInner {
    pub (crate) udp_socket: Arc<UdpSocket>,
    pub (crate) remote_addr: SocketAddr,
    pub (crate) status: SocketStatus,

    pub (crate) last_sent_message: Instant,
    pub (crate) self_pub_key: PublicKey,
    pub (crate) secret: SocketSecret,
    pub (crate) other_pub_key: PublicKey,
}


impl SocketInner {
    pub (crate) fn new_connecting(udp_socket: Arc<UdpSocket>, remote_addr: SocketAddr, keys: Option<(PublicKey, EphemeralSecret)>) -> Self {
        let (pub_key, priv_key) = keys.unwrap_or_else(|| {
            let priv_key = EphemeralSecret::random();
            let pub_key = PublicKey::from(&priv_key);
            (pub_key, priv_key)
        });
        let now = Instant::now();
        SocketInner {
            udp_socket,
            status: SocketStatus::SynSent(now),
            remote_addr,
            last_sent_message: now,
            secret: SocketSecret::new(priv_key),
            self_pub_key: pub_key,
            other_pub_key: unsafe { std::mem::zeroed() },
        }
    }

    pub (crate) fn new_connected(udp_socket: Arc<UdpSocket>, remote_addr: SocketAddr, other_pub: [u8; 32]) -> Self {
        Self::new_connected_with_keys(udp_socket, remote_addr, other_pub, None)
    }

    pub (crate) fn new_connected_with_keys(udp_socket: Arc<UdpSocket>, remote_addr: SocketAddr, other_pub: [u8; 32], keys: Option<(PublicKey, EphemeralSecret)>) -> Self {
        let (pub_key, priv_key) = keys.unwrap_or_else(|| {
            let priv_key = EphemeralSecret::random();
            let pub_key = PublicKey::from(&priv_key);
            (pub_key, priv_key)
        });
        let other_pub_key = PublicKey::from(other_pub);
        SocketInner {
            udp_socket,
            remote_addr,
            status: SocketStatus::SynReceived,
            last_sent_message: Instant::now(),
            secret: SocketSecret::new_shared(priv_key, &other_pub_key),
            self_pub_key: pub_key,
            other_pub_key,
        }
    }

    /// Send some bytes without splitting in any way
    #[inline]
    pub fn send_raw_bytes(&self, bytes: &[u8]) -> IoResult<()> {
        let sent_size = self.udp_socket.send_to(bytes, self.remote_addr)?;
        debug_assert_eq!(sent_size, bytes.len(), "udp packet did not contain whole packet");
        Ok(())
    }

    pub fn check_self_key(&self, id: &[u8; 4]) -> bool {
        &self.self_pub_key.as_bytes()[0..4] == id
    }

    pub fn check_other_key(&self, id: &[u8; 4]) -> bool {
        &self.other_pub_key.as_bytes()[0..4] == id
    }

    pub (crate) fn send_ack<D: AsRef<[u8]> + 'static>(&mut self, seq_id: SeqId, ack: Ack<D>, now: Instant) -> std::io::Result<()> {
        let packet: Packet<D> = Packet::build(
            self.self_pub_key.as_bytes(),
            self.other_pub_key.as_bytes(),
            PacketVariant::Ack { seq_id, slice: ack.into_inner() }
        );
        self.send_packet(packet, now)
    }

    /// Same as `terminate`, but leave the Socket alive.
    ///
    /// This is mostly useful if you want to still receive the data the other remote is currently
    /// sending at this time.
    pub (crate) fn send_end(&mut self, last_seq_id: SeqId, now: Instant) -> std::io::Result<()> {
        let packet: Packet<Box<[u8]>> = Packet::build(
            self.self_pub_key.as_bytes(),
            self.other_pub_key.as_bytes(),
            PacketVariant::End { last_seq_id }
        );
        self.send_packet(packet, now)
    }

    pub (crate) fn send_abort(&mut self, last_seq_id: SeqId, now: Instant) -> std::io::Result<()> {
        let packet: Packet<Box<[u8]>> = Packet::build(
            self.self_pub_key.as_bytes(),
            self.other_pub_key.as_bytes(),
            PacketVariant::Abort { last_seq_id }
        );
        self.send_packet(packet, now)
    }

    pub (crate) fn send_synack(&mut self, now: Instant) -> std::io::Result<()> {
        let packet: Packet<Box<[u8]>> = Packet::build(
            self.self_pub_key.as_bytes(),
            self.other_pub_key.as_bytes(),
            PacketVariant::SynAck { pub_key: self.self_pub_key.to_bytes() }
        );
        self.send_packet(packet, now)
    }

    pub (crate) fn send_syn(&mut self, now: Instant) -> std::io::Result<()> {
        let packet: Packet<Box<[u8]>> = Packet::build(
            self.self_pub_key.as_bytes(),
            self.other_pub_key.as_bytes(),
            PacketVariant::Syn { pub_key: self.self_pub_key.to_bytes() }
        );
        self.send_packet(packet, now)
    }

    pub (crate) fn send_heartbeat(&mut self, now: Instant) -> std::io::Result<()> {
        let packet: Packet<Box<[u8]>> = Packet::build(
            self.self_pub_key.as_bytes(),
            self.other_pub_key.as_bytes(),
            PacketVariant::Heartbeat
        );
        self.send_packet(packet, now)
    }

    pub (crate) fn send_fragment<D: AsRef<[u8]>>(&mut self, fragment: Fragment<D>, now: Instant) -> std::io::Result<()> {
        let packet: Packet<D> = Packet::build(
            self.self_pub_key.as_bytes(),
            self.other_pub_key.as_bytes(),
            PacketVariant::Fragment(fragment),
        );
        self.send_packet(packet, now)
    }

    pub (crate) fn send_fragment_ref<'a, D: AsRef<[u8]> + 'a>(&mut self, fragment: &'a Fragment<D>, now: Instant) -> std::io::Result<()> {
        self.send_fragment(fragment.as_borrowed_frag(), now)
    }

    pub (crate) fn send_packet<P: AsRef<[u8]>>(&mut self, packet: Packet<P>, now: Instant) -> IoResult<()> {
        self.last_sent_message = now;
        let udp_bytes = UdpBytes::from(&packet);
        self.send_udp_bytes(&udp_bytes)
    }

    #[inline]
    pub (crate) fn send_udp_bytes<P: AsRef<[u8]>>(&self, udp_bytes: &UdpBytes<P>) -> IoResult<()> {
        if !self.status.is_disconnected() {
            self.send_raw_bytes(udp_bytes.as_bytes())
        } else {
            Ok(())
        }
    }
}