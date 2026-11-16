
use std::{
    sync::Arc,
    net::{UdpSocket, SocketAddr},
    io::{Error as IoError, Result as IoResult},
    time::{Instant, Duration},
};

use chacha20poly1305::{ChaCha20Poly1305, KeyInit, aead::{Aead, Payload}};
use x25519_dalek::{PublicKey, EphemeralSecret, SharedSecret};

use rbtl_core::Status;

use crate::{
    SocketEvent,
    consts::CONTROL_MAC_TAG_SIZE,
    net::protocol::{fragment::{Fragment, ack::{Ack, AckTiming}}, packet::{ControlMac, Packet, PacketVariant}},
    net::common::SeqId,
};

use super::{
    protocol::packet::UdpBytes,
};

pub (crate) enum SocketSecret {
    Ours(EphemeralSecret),
    Shared {
        secret: SharedSecret,
        /// Used to authenticate control packets, with a key derived from `secret`
        control_cipher: ChaCha20Poly1305,
    },
    /// Only while `apply` replaces `Ours` by `Shared`
    Empty,
}

/// Nonce used to derive the control packets key from the shared secret.
///
/// Encrypted messages use the shared secret directly with the nonce [seq_id (LE)][first 8 bytes of sender's pub key],
/// this is the same as seq_id=0x6c746272 for a sender whose public key starts with "-ctrlkey", which will never happen.
const CONTROL_KEY_DERIVATION_NONCE: [u8; 12] = *b"rbtl-ctrlkey";

impl SocketSecret {
    pub (self) fn new(our_secret: EphemeralSecret) -> Self {
        Self::Ours(our_secret)
    }

    pub (self) fn new_shared(our_secret: EphemeralSecret, other_pub: &PublicKey) -> Self {
        let secret = our_secret.diffie_hellman(other_pub);
        // Derives the key used to authenticate control packets (see `control_tag`).
        //
        // This stands in for a standard key derivation (HKDF, or `blake3::derive_key("rbtl-rudp control", secret)`),
        // because the only crypto crate we depend on is chacha20poly1305:
        // encrypting zeros gives the ChaCha20 keystream for (secret, nonce): random-looking bytes that can't be linked
        // back to the secret, which makes a good separate key. The tag after it is ignored.
        let cipher = ChaCha20Poly1305::new_from_slice(secret.as_bytes()).unwrap();
        let keystream = cipher.encrypt(&CONTROL_KEY_DERIVATION_NONCE.into(), [0u8; 32].as_ref())
            .expect("chacha20 encryption of 32 bytes can't fail");
        let control_cipher = ChaCha20Poly1305::new_from_slice(&keystream[0..32]).unwrap();
        Self::Shared { secret, control_cipher }
    }

    /// Return the shared secret if available
    pub (crate) fn shared(&self) -> Option<&SharedSecret> {
        if let Self::Shared { secret, .. } = self {
            Some(secret)
        } else {
            None
        }
    }

    /// Return the cipher to authenticate control packets, if the shared secret is available
    pub (crate) fn control_cipher(&self) -> Option<&ChaCha20Poly1305> {
        if let Self::Shared { control_cipher, .. } = self {
            Some(control_cipher)
        } else {
            None
        }
    }

    pub (crate) fn apply(&mut self, other_pub: &PublicKey) {
        *self = match std::mem::replace(self, Self::Empty) {
            Self::Ours(secret) => Self::new_shared(secret, other_pub),
            // nothing to do, we already have a shared secret
            already_shared => already_shared,
        };
    }
}

/// Computes the (truncated) tag of a control packet
///
/// This stands in for a keyed hash such as `blake3::keyed_hash(control_key, mac_input)` or HMAC-SHA256,
/// because the only crypto crate we depend on is chacha20poly1305. It is ChaCha20Poly1305 authenticating
/// `mac_input` without encrypting anything, which is a sound MAC with one extra rule a keyed hash doesn't have:
/// the nonce (so the counter) must never be used twice with the same key, or tags can be forged.
/// That's why `send_packet` refuses to send rather than wrap the counter, and keys change on every connection.
fn control_tag(cipher: &ChaCha20Poly1305, counter: u32, sender_pub_key: &[u8; 32], mac_input: &[u8]) -> [u8; CONTROL_MAC_TAG_SIZE] {
    let mut nonce = [0u8; 12];
    nonce[0..4].copy_from_slice(&counter.to_le_bytes());
    nonce[4..12].copy_from_slice(&sender_pub_key[0..8]);
    // nothing to encrypt: the output is only the 16 bytes tag of the "additional data"
    let tag = cipher.encrypt(&nonce.into(), Payload { msg: &[], aad: mac_input })
        .expect("chacha20poly1305 of an empty message can't fail");
    tag[0..CONTROL_MAC_TAG_SIZE].try_into().unwrap()
}

/// Remembers which control packet counters were received, to refuse replayed packets.
///
/// Packets may arrive out of order, so counters slightly lower than the highest one are still accepted once.
#[derive(Debug, Default)]
pub (crate) struct ReplayWindow {
    highest: Option<u32>,
    /// bit n is set if `highest - n` was received
    received: u64,
}

impl ReplayWindow {
    /// Returns whether `counter` has never been received, and is recent enough to be checked
    pub (crate) fn is_new(&self, counter: u32) -> bool {
        let Some(highest) = self.highest else { return true };
        if counter > highest {
            return true;
        }
        let age = highest - counter;
        age < u64::BITS && self.received & (1 << age) == 0
    }

    pub (crate) fn mark_received(&mut self, counter: u32) {
        match self.highest {
            Some(highest) if counter <= highest => {
                self.received |= 1 << (highest - counter);
            },
            Some(highest) => {
                let shift = counter - highest;
                self.received = if shift >= u64::BITS { 0 } else { self.received << shift };
                self.received |= 1;
                self.highest = Some(counter);
            },
            None => {
                self.received = 1;
                self.highest = Some(counter);
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

    pub fn to_rbtl_status(self) -> Status {
        match self {
            SocketStatus::Connected => Status::Ok,
            SocketStatus::SynReceived => Status::Connecting,
            SocketStatus::SynSent(_) => Status::Connecting,
            SocketStatus::TerminateReceived(_) => Status::Ended { by_remote: true },
            SocketStatus::TerminateSent(_) => Status::Ended { by_remote: false },
            SocketStatus::TimeoutError { .. } => Status::Timeout,
        }
    }

    pub (crate) fn event(self) -> Option<SocketEvent> {
        match self {
            SocketStatus::TimeoutError { .. } => Some(SocketEvent::Timeout),
            SocketStatus::TerminateSent(_) => Some(SocketEvent::Ended { by_remote: false }),
            // // this is actually commented to tell you that you should NOT uncomment this,
            // // when we receive a packet, we automatically send the right event (ended or aborted)
            // // so there is no need to have a similar event sent here as well
            // SocketStatus::TerminateReceived => Some(SocketEvent::Ended { by_remote: true }),
            SocketStatus::TerminateReceived(_) => None,
            SocketStatus::Connected => Some(SocketEvent::Connected),
            _ => None
        }
    }

    /// Normal connection is finished, but some leftover "ack" messages may still be sent
    pub fn is_finished(self) -> bool {
        use SocketStatus::*;
        match self {
            TimeoutError { .. } | TerminateSent(_) | TerminateReceived(_) => true,
            _ => false
        }
    }

    /// Completely disconnected, stop sending messages
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

    /// Counter of the next authenticated control packet we send. u64 so that running out of u32 can be detected.
    pub (crate) next_control_counter: u64,
    /// Counters of the authenticated control packets received
    pub (crate) control_received: ReplayWindow,
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
            // unknown until we receive the SynAck: all 0s is what the protocol expects for an unknown destination
            other_pub_key: PublicKey::from([0u8; 32]),
            next_control_counter: 0,
            control_received: ReplayWindow::default(),
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
            next_control_counter: 0,
            control_received: ReplayWindow::default(),
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

    /// Checks the mac of a received control packet. Other packets are always accepted.
    ///
    /// Once we have the shared secret, control packets without a valid mac are refused, as are
    /// replayed ones. Before that, there is nothing to check them with, so they are accepted.
    pub (crate) fn verify_control_mac<P: AsRef<[u8]>>(&mut self, packet: &Packet<P>) -> bool {
        if !packet.packet_variant.is_control() {
            return true;
        }
        let Some(cipher) = self.secret.control_cipher() else {
            return true;
        };
        let Some(mac) = packet.mac else {
            return false;
        };
        if !self.control_received.is_new(mac.counter) {
            return false;
        }
        let expected = control_tag(cipher, mac.counter, self.other_pub_key.as_bytes(), &packet.mac_input());
        // constant time comparison
        let diff = expected.iter().zip(mac.tag.iter()).fold(0u8, |acc, (a, b)| acc | (a ^ b));
        if diff != 0 {
            return false;
        }
        self.control_received.mark_received(mac.counter);
        true
    }

    pub (crate) fn send_ack<D: AsRef<[u8]> + 'static>(&mut self, seq_id: SeqId, timing: AckTiming, ack: Ack<D>, now: Instant) -> std::io::Result<()> {
        let packet: Packet<D> = Packet::build(
            self.self_pub_key.as_bytes(),
            self.other_pub_key.as_bytes(),
            PacketVariant::Ack { seq_id, timing, slice: ack.into_inner() }
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

    /// Sends the packet, authenticating it first if it is a control packet and we have the shared secret
    pub (crate) fn send_packet<P: AsRef<[u8]>>(&mut self, mut packet: Packet<P>, now: Instant) -> IoResult<()> {
        if packet.packet_variant.is_control() {
            if let Some(cipher) = self.secret.control_cipher() {
                // a counter must never be used twice: ~4 billion control packets is years of connection,
                // but stop rather than reusing a nonce.
                let Ok(counter) = u32::try_from(self.next_control_counter) else {
                    return Err(IoError::other("too many control packets sent on this connection"));
                };
                self.next_control_counter += 1;
                let tag = control_tag(cipher, counter, self.self_pub_key.as_bytes(), &packet.mac_input());
                packet.mac = Some(ControlMac { counter, tag });
            }
        }
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

#[test]
fn replay_window() {
    let mut w = ReplayWindow::default();
    assert!(w.is_new(5));
    w.mark_received(5);
    assert!(!w.is_new(5));
    // out of order, but recent: accepted once
    assert!(w.is_new(3));
    w.mark_received(3);
    assert!(!w.is_new(3));
    w.mark_received(100);
    assert!(w.is_new(99));
    assert!(!w.is_new(100));
    // too old to be tracked: refused
    assert!(!w.is_new(30));
    w.mark_received(u32::MAX);
    assert!(!w.is_new(100));
}

#[test]
fn control_mac_roundtrip() {
    let udp = Arc::new(UdpSocket::bind("127.0.0.1:0").unwrap());
    let addr = udp.local_addr().unwrap();
    let client_secret = EphemeralSecret::random();
    let client_pub = PublicKey::from(&client_secret);
    let server_secret = EphemeralSecret::random();
    let server_pub = PublicKey::from(&server_secret);
    let mut client = SocketInner::new_connecting(udp.clone(), addr, Some((client_pub, client_secret)));
    client.other_pub_key = server_pub;
    client.secret.apply(&server_pub);
    let mut server = SocketInner::new_connected_with_keys(udp, addr, client_pub.to_bytes(), Some((server_pub, server_secret)));

    let build_heartbeat = |from: &SocketInner| -> Packet<Box<[u8]>> {
        Packet::build(from.self_pub_key.as_bytes(), from.other_pub_key.as_bytes(), PacketVariant::Heartbeat)
    };
    // what `send_packet` does, without sending
    let sign = |from: &mut SocketInner, mut packet: Packet<Box<[u8]>>| {
        let counter = from.next_control_counter as u32;
        from.next_control_counter += 1;
        let tag = control_tag(from.secret.control_cipher().unwrap(), counter, from.self_pub_key.as_bytes(), &packet.mac_input());
        packet.mac = Some(ControlMac { counter, tag });
        packet
    };

    let heartbeat = build_heartbeat(&client);
    let packet = sign(&mut client, heartbeat);
    assert!(server.verify_control_mac(&packet));
    // replayed
    assert!(!server.verify_control_mac(&packet));
    // forged tag
    let heartbeat = build_heartbeat(&client);
    let mut forged = sign(&mut client, heartbeat);
    forged.mac.as_mut().unwrap().tag[0] ^= 1;
    assert!(!server.verify_control_mac(&forged));
    // no mac at all
    assert!(!server.verify_control_mac(&build_heartbeat(&client)));
    // a packet authenticated by the server can't be reflected back to it as if the client sent it
    let heartbeat = build_heartbeat(&server);
    let reflected = sign(&mut server, heartbeat);
    assert!(!server.verify_control_mac(&reflected));
    assert!(client.verify_control_mac(&reflected));
}
