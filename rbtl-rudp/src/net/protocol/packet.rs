use byteorder::{BigEndian, ByteOrder};
use crate::{net::common::SeqId, utils::crc32_hash};

use crate::{
    utils::{BoxedSlice, OwnedSlice},
    consts::*,
    net::protocol::{
        fragment::{Fragment, FragmentSetFlags, ack::AckTiming},
    }
};

/// Authentication of a control packet (Ack, End, Abort, Heartbeat), see `UdpBytes` for the layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub (crate) struct ControlMac {
    /// Number of control packets sent before this one by the sender: never the same twice,
    /// so the tag can be computed with a unique nonce, and replayed packets can be detected.
    pub (crate) counter: u32,
    /// Poly1305 tag of the packet, truncated
    pub (crate) tag: [u8; CONTROL_MAC_TAG_SIZE],
}

#[derive(Debug)]
pub (crate) struct Packet<P: AsRef<[u8]>> {
    pub (crate) src_identity: [u8; 4],
    pub (crate) dst_identity: [u8; 4],
    pub (crate) packet_variant: PacketVariant<P>,
    /// Only for control packets, and only when both sides have the shared secret
    pub (crate) mac: Option<ControlMac>,
}

#[derive(Debug, PartialEq)]
pub (crate) enum PacketVariant<P: AsRef<[u8]>> {
    Fragment(Fragment<P>),
    Ack { seq_id: SeqId, timing: AckTiming, slice: P },
    Syn { pub_key: [u8; 32] },
    SynAck { pub_key: [u8; 32] },
    Heartbeat,
    End { last_seq_id: SeqId },
    Abort { last_seq_id: SeqId }
}

impl<P: AsRef<[u8]>> PacketVariant<P> {
    /// Control packets can be authenticated with a `ControlMac`
    pub (crate) fn is_control(&self) -> bool {
        matches!(self, Self::Ack { .. } | Self::Heartbeat | Self::End { .. } | Self::Abort { .. })
    }
}

/// Flag of control packets: the packet ends with a `ControlMac`
const CONTROL_FLAG_HAS_MAC: u16 = 0b1;

impl<P: AsRef<[u8]>> Packet<P> {
    pub (crate) fn new(src_identity: [u8; 4], dst_identity: [u8; 4], packet_variant: PacketVariant<P>) -> Self {
        Self {
            src_identity,
            dst_identity,
            packet_variant,
            mac: None,
        }
    }

    pub (crate) fn build(src_id: &[u8; 32], dst_id: &[u8; 32], packet_variant: PacketVariant<P>) -> Self {
        let src_id: [u8; 4] = src_id[0..4].try_into().unwrap();
        let dst_id: [u8; 4] = dst_id[0..4].try_into().unwrap();
        Self::new(src_id, dst_id, packet_variant)
    }

    fn udp_packet_size(&self) -> usize {
        let after_common: usize = match &self.packet_variant {
            // seq_id + data.len()
            PacketVariant::Fragment(f) => std::mem::size_of::<u32>() + f.data.as_ref().len(),
            // seq_id + timing + ack_slice.len()
            PacketVariant::Ack { slice, .. } => std::mem::size_of::<u32>() + std::mem::size_of::<u16>() + slice.as_ref().len(),
            // public key of 32 bytes, + payload
            PacketVariant::Syn { .. } => std::mem::size_of::<[u8; 32]>(),
            // public key of 32 bytes
            PacketVariant::SynAck { .. } => std::mem::size_of::<[u8; 32]>(),
            PacketVariant::Heartbeat { .. } => 0,
            // seq_id
            PacketVariant::End { .. } => std::mem::size_of::<u32>(),
            // seq_id
            PacketVariant::Abort { .. } => std::mem::size_of::<u32>(),
        };
        PACKET_CRC32_SIZE + PACKET_COMMON_HEADER_SIZE + after_common
    }

    #[inline]
    fn write_frags(frag_id: u8, frag_tot: u8, output: &mut Vec<u8>) {
        output[13] = frag_tot;
        output[12] = frag_id;
    }

    #[inline]
    fn write_flags(flags: u16, output: &mut Vec<u8>) {
        BigEndian::write_u16(&mut output[14..16], flags);
    }

    #[inline]
    fn write_seq_id(seq_id: SeqId, output: &mut Vec<u8>) {
        BigEndian::write_u32(&mut output[16..20], seq_id);
    }

    fn write_pub_key(key: &[u8; 32], output: &mut Vec<u8>) {
        output[16..48].copy_from_slice(key);
    }

    /// Writes everything except the CRC32 (left as 0s) and the mac
    fn to_bytes_without_mac(&self, has_mac: bool) -> Vec<u8> {
        let mut bytes = vec![0; self.udp_packet_size()];
        let control_flags = if has_mac { CONTROL_FLAG_HAS_MAC } else { 0 };

        match &self.packet_variant {
            PacketVariant::Fragment(f) => {
                bytes[20..].copy_from_slice(f.data.as_ref());
                Self::write_seq_id(f.seq_id, &mut bytes);
                Self::write_flags(f.frag_set_flags.0, &mut bytes);
                Self::write_frags(f.frag_id, f.frag_total, &mut bytes);
            },
            PacketVariant::Ack { seq_id, timing, slice } => {
                bytes[22..].copy_from_slice(slice.as_ref());
                BigEndian::write_u16(&mut bytes[20..22], timing.to_u16());
                Self::write_seq_id(*seq_id, &mut bytes);
                Self::write_flags(control_flags, &mut bytes);
                Self::write_frags(255, 0, &mut bytes);
            },
            PacketVariant::Syn { pub_key } => {
                Self::write_pub_key(&pub_key, &mut bytes);
                Self::write_flags(0, &mut bytes);
                Self::write_frags(255, 1, &mut bytes);
            },
            PacketVariant::SynAck { pub_key } => {
                Self::write_pub_key(&pub_key, &mut bytes);
                Self::write_flags(0, &mut bytes);
                Self::write_frags(255, 2, &mut bytes);
            },
            PacketVariant::End { last_seq_id } => {
                Self::write_seq_id(*last_seq_id, &mut bytes);
                Self::write_flags(control_flags, &mut bytes);
                Self::write_frags(255, 3, &mut bytes);
            },
            PacketVariant::Abort { last_seq_id } => {
                Self::write_seq_id(*last_seq_id, &mut bytes);
                Self::write_flags(control_flags, &mut bytes);
                Self::write_frags(255, 4, &mut bytes);
            },
            PacketVariant::Heartbeat => {
                Self::write_flags(control_flags, &mut bytes);
                Self::write_frags(255, 10, &mut bytes);
            },
        }
        bytes[4..8].copy_from_slice(&self.src_identity);
        bytes[8..12].copy_from_slice(&self.dst_identity);
        bytes
    }

    /// The bytes covered by the mac of a control packet: everything except the CRC32 and the mac itself.
    ///
    /// Serialization is deterministic, so the sender and the receiver compute the same bytes.
    pub (crate) fn mac_input(&self) -> Vec<u8> {
        let mut bytes = self.to_bytes_without_mac(true);
        bytes.drain(0..PACKET_CRC32_SIZE);
        bytes
    }

    pub (crate) fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = self.to_bytes_without_mac(self.mac.is_some());
        if let Some(mac) = &self.mac {
            bytes.extend_from_slice(&mac.counter.to_be_bytes());
            bytes.extend_from_slice(&mac.tag);
        }
        let generated_crc: u32 = crc32_hash(&bytes[4..]);
        BigEndian::write_u32(&mut bytes[0..4], generated_crc);
        bytes
    }

    fn read_common_header(bytes: &[u8; 16]) -> (u32, [u8; 4], [u8; 4], u8, u8, u16) {
        let crc32 = BigEndian::read_u32(&bytes[0..4]);
        let src_id = <[u8; 4]>::try_from(&bytes[4..8]).unwrap();
        let dst_id = <[u8; 4]>::try_from(&bytes[8..12]).unwrap();
        let frag_id = bytes[12];
        let frag_tot = bytes[13];
        let frag_flags = BigEndian::read_u16(&bytes[14..16]);
        (crc32, src_id, dst_id, frag_id, frag_tot, frag_flags)
    }

    pub fn attempt_from_bytes(bytes: P) -> Result<Packet<OwnedSlice<u8, P>>, (UdpDataError, P)> {
        let bytes_ref = bytes.as_ref();
        let Some((header_slice, data_slice)) = bytes_ref.split_at_checked(PACKET_VAR_START_BYTE) else {
            return Err((UdpDataError::NotBigEnough, bytes));
        };
        let header_slice = header_slice.as_array().unwrap();
        let (crc32, src_id, dst_id, frag_id, frag_tot, frag_flags) = Self::read_common_header(header_slice);

        let computed_crc32 = crc32_hash(&bytes_ref[4..]);
        if computed_crc32 != crc32 {
            return Err((UdpDataError::InvalidCrc, bytes));
        }

        // control packets may end with a mac, cut it from the data
        let is_control = frag_id == 255 && matches!(frag_tot, 0 | 3 | 4 | 10);
        let (data_slice, mac) = if is_control && frag_flags & CONTROL_FLAG_HAS_MAC != 0 {
            let Some((data_slice, mac_slice)) = data_slice.split_at_checked(data_slice.len().wrapping_sub(CONTROL_MAC_SIZE)) else {
                return Err((UdpDataError::NotBigEnough, bytes));
            };
            let mac = ControlMac {
                counter: BigEndian::read_u32(&mac_slice[0..4]),
                tag: mac_slice[4..].try_into().unwrap(),
            };
            (data_slice, Some(mac))
        } else {
            (data_slice, None)
        };
        let mac_len = if mac.is_some() { CONTROL_MAC_SIZE } else { 0 };

        let variant = match (frag_id, frag_tot) {
            (255, 0) => {
                if data_slice.len() < 6 {
                    return Err((UdpDataError::NotBigEnough, bytes));
                }
                let seq_id = BigEndian::read_u32(&data_slice[0..4]);
                let timing = AckTiming::from_u16(BigEndian::read_u16(&data_slice[4..6]));
                PacketVariant::Ack { seq_id, timing, slice: OwnedSlice::new_stripped(bytes, PACKET_VAR_START_BYTE + 6, mac_len) }
            },
            (255, 1) => {
                if data_slice.len() < 32 {
                    return Err((UdpDataError::NotBigEnough, bytes));
                }
                let pub_key = <[u8; 32]>::try_from(&data_slice[0..32]).unwrap();
                PacketVariant::Syn { pub_key }
            },
            (255, 2) => {
                if data_slice.len() < 32 {
                    return Err((UdpDataError::NotBigEnough, bytes));
                }
                let pub_key = <[u8; 32]>::try_from(&data_slice[0..32]).unwrap();
                PacketVariant::SynAck { pub_key }
            },
            (255, 3) => {
                if data_slice.len() < 4 {
                    return Err((UdpDataError::NotBigEnough, bytes));
                }
                let seq_id = BigEndian::read_u32(&data_slice[0..4]);
                PacketVariant::End { last_seq_id: seq_id }
            },
            (255, 4) => {
                if data_slice.len() < 4 {
                    return Err((UdpDataError::NotBigEnough, bytes));
                }
                let seq_id = BigEndian::read_u32(&data_slice[0..4]);
                PacketVariant::Abort { last_seq_id: seq_id }
            },
            (255, 10) => PacketVariant::Heartbeat,
            (frag_id, frag_total) if frag_id <= frag_total => {
                if data_slice.len() < 4 {
                    return Err((UdpDataError::NotBigEnough, bytes));
                }
                let seq_id = BigEndian::read_u32(&data_slice[0..4]);
                PacketVariant::Fragment(Fragment {
                    data: OwnedSlice::new(bytes, PACKET_VAR_START_BYTE + 4),
                    seq_id,
                    frag_id,
                    frag_total,
                    frag_set_flags: FragmentSetFlags(frag_flags)
                })
            }
            (frag_id, frag_total) => return Err((UdpDataError::InvalidFragLayout(frag_id, frag_total), bytes)),
        };
        let mut packet = Packet::new(src_id, dst_id, variant);
        packet.mac = mac;
        Ok(packet)
    }

    #[cfg(test)]
    pub (crate) fn cmp_with<T2: AsRef<[u8]>>(&self, other: &Packet<T2>) -> bool {
        self.src_identity == other.src_identity &&
        self.dst_identity == other.dst_identity &&
        self.mac == other.mac &&
        self.packet_variant.cmp_with(&other.packet_variant)
    }
}

impl<P: AsRef<[u8]>> PacketVariant<P> {
    /// For testing purposes
    #[inline]
    #[cfg(test)]
    pub (crate) fn cmp_with<T2: AsRef<[u8]>>(&self, other: &PacketVariant<T2>) -> bool {
        use self::PacketVariant::*;
        match (self, other) {
            (Fragment(f1), Fragment(f2)) =>
                f1.seq_id == f2.seq_id && f1.frag_id == f2.frag_id && f1.frag_total == f2.frag_total
                && f1.data.as_ref() == f2.data.as_ref(),
            (Ack { seq_id: s1, timing: t1, slice: d1 }, Ack { seq_id: s2, timing: t2, slice: d2 }) =>
                s1 == s2 && t1 == t2 && d1.as_ref() == d2.as_ref(),
            (Syn { pub_key: p1 }, Syn { pub_key: p2 }) => p1.as_ref() == p2.as_ref(),
            (SynAck { pub_key: p1 }, SynAck { pub_key: p2 }) => p1.as_ref() == p2.as_ref(),
            (End { last_seq_id: s1 }, End { last_seq_id: s2 }) => s1 == s2,
            (Abort { last_seq_id: s1 }, Abort { last_seq_id: s2 }) => s1 == s2,
            (Heartbeat, Heartbeat) => true,
            _ => false,
        }
    }
}

/// UdpBytes represents the raw bytes that we get from a UdpSocket.
///
/// It must contain a buffer that is AT LEAST
/// 10 bytes long. The structure for the udp message is as follow:
///
/// [0-3]: CRC32 check of [4-] as BigEndian u32
/// [4-7]: first 4 bytes of DH pub key working as "identity" of sender (for NAT traversal and other things)
/// [8-11]: first 4 bytes of DH pub key, but for the destination instead. If unknown, send all 0s
/// [12]: "Frag Id"
/// [13] "Frag total"
/// [14-15]: frag set flags; such as "IS_EXPIRE", "IS_KEY", ... For control packets, "HAS_MAC"
/// [16-19]: sequence id (if applicable).
/// [rest..]: data (if applicable)
/// [last 12 bytes]: only for control packets with the "HAS_MAC" flag: the mac (see "Control packets mac")
///
/// For now, there are 6 types of messages:
/// `Fragment`s, `Ack`s, `Syn`, `SynAck`, `End`, `Abort` and `Heartbeat`.
///
/// # Determine the type of the packet:
///
/// Note that FragTotal+1 represents the number of frags there may be, so it IS possible
/// to have 0 as a frag_total (1 fragment) and 255 as well (255 fragments).
///
/// However, it does not make sense if frag_id is greater than frag_total, so some of those
/// couples are reserved to determine the type of the received (or sent!) packet:
///
/// * If Frag ID <= Frag Total, type = Fragment, (including Frag ID <= Frag Total == 255)
/// * If Frag ID == 255, Frag Total == 0: type = Ack. Ack packet for a fragment/sequence element.
/// * If Frag ID == 255, Frag Total == 1: type = Syn. This type is sent when trying to initiate
/// a connection with a remote.
/// * If Frag ID == 255, Frag Total == 2: type = SynAck: confirm that a connection has been created.
/// * If Frag ID == 255, Frag Total == 3: type = End. The other end has nothing else to send,
/// and the connection is immediatly closed.
/// * If Frag ID == 255, Frag Total == 4: type = Abort: Other program has been terminated
/// unexpectedly and will not receive nor send packets anymore.
/// * If Frag ID == 255, Frag Total == 10: type = Heartbeat: Message sent every few iterations
/// to make sure the remote does not disconnect unexpectedly.
/// * Other uses for Frag ID == 255 and Frag Total != 255 are reserved for other packets like these.
/// Note that Frag ID == 255 and Frag Total == 255 means
///
/// A Fragment is a chunk of a message, represented with the structure above.
///
/// Rather than a length explanation, let's start with a simply message: [1, 2, 3, 4, 5].
///
/// Let's say the the maximum payload size (TOTAL_SIZE - HEADER_SIZE) is 2 bytes. That
/// means we have to split our message in 3 fragments: one containing [1, 2], the other [3, 4]
/// and the last [5]. Let's say this is the second message we were to send, the seq_id would be 1.
///
/// Frag total would be 2, because we have 3 packets total, and frag_total is always frags.len()-1.
///
/// As for the respective frag_id, they are 0 for [1, 2], 1 for [3, 4] and so on.
///
/// Finally, based on that, for every fragment the CRC32 is generated: it is based on the slice that
/// starts at the end of the CRC32 and ends at the end of the UDP Packet. Meaning,
/// for TOTAL_SIZE=12, the CRC32 would be based on frag[4..12] of the packet.
///
/// # Ack
///
/// [20-21] are the "ack timing", a BigEndian u16: the highest bit is set if the last fragment received
/// for this seq_id was a resend, and the 15 other bits are how long the receiver waited between receiving that
/// fragment and sending this ack, in units of 200µs (all 1s means too long). The sender of the message uses it to
/// compute the ping without the receiver's delay.
///
/// [22..] is additional data, not defined by the user.
/// This additional data will be at most the size of (Type<FragId>::Max + 1) / 8, meaning
/// (255 + 1) / 8 = 32 bytes.
///
/// Hence for a Ack packet, the maximum length will be of 16bytes (header) + 4 + 2 + 32bytes = 54 bytes (+ 12 for the mac).
///
/// Those 32 bytes are filled with binaries (1 or 0), and are used to send which of the frag IDs
/// have been received.
///
/// If the maximum a sequence can be is 64 packets, the first 64 bits
/// (so 1 x u64, or 8 x u8) represent whether or not each corresponding packet has been
/// acknowledged. For instance, if a sender sends a packet with frag total of 3 (so, truly 4 fragments total),
/// and the bits are like so: 0101; then it means the packets 0 and 2 have *not* been received and
/// must be sent again by the client receiving the ACK.
///
/// The receiver will send 1 of these packets per iteration at *most*, unless the packet is totally received
/// (all 1s to send), then the packet is sent once per iteration,
/// for multiple iterations (to make sure the ack goes through).
///
/// # Control packets mac
///
/// Acks, End, Abort and Heartbeat are "control packets". Once the shared secret is known, they are authenticated,
/// otherwise anyone knowing the 4 bytes identities (sent in clear) could fake them, to end a connection for instance.
///
/// When the flag "HAS_MAC" (0b1) is set, the packet ends with:
///
/// [0-3]: a counter, BigEndian u32: number of control packets sent before by this sender
/// [4-11]: a Poly1305 tag truncated to 8 bytes, of everything in the packet after the CRC32 and before the mac.
///
/// The tag is computed with ChaCha20Poly1305, using a key derived from the shared secret (different from the
/// key of the encrypted messages) and the nonce [counter (LE, 4 bytes)][first 8 bytes of the sender's public key].
/// (ChaCha20Poly1305 is used in place of a keyed hash like BLAKE3 or HMAC, see `control_tag` in inner.rs.)
///
/// Note that everything is Big Endian encoded (as is the standard for most network protocols)
pub struct UdpBytes<B: AsRef<[u8]>> {
   pub (crate) buffer: B
}

impl<B: AsRef<[u8]>> std::fmt::Debug for UdpBytes<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        write!(f, "UdpData [{} bytes]", self.buffer.as_ref().len())
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub (crate) enum UdpDataError {
    /// Received data was not big enough to be a message readable by this crate.
    NotBigEnough, // (That's what she said)
    /// The Crc inside the message was not valid
    InvalidCrc,
    /// Frag Layout is incorrect (frag_id, frag_total)
    InvalidFragLayout(u8, u8),
}

impl<'a, T: AsRef<[u8]>> From<&'a Packet<T>> for UdpBytes<Box<[u8]>> {
    fn from(p: &'a Packet<T>) -> UdpBytes<Box<[u8]>> {
        UdpBytes {buffer: p.to_bytes().into_boxed_slice()}
    }
}

impl<B: AsRef<[u8]>> UdpBytes<B> {
    #[cfg(test)]
    pub fn new(b: B) -> UdpBytes<B>{
        UdpBytes {buffer: b}
    }

    /// Reads one message from a udp socket and returns its content as a UdpData
    ///
    /// Proper parameters that you see fit must have been set on UdpSocket. For instance,
    /// it may be wise to set this udp socket as non-blocking  if you don't want to block
    /// your thread forever trying to read one message.
    pub fn from_udp_socket(udp_socket: &std::net::UdpSocket) -> std::io::Result<(UdpBytes<Box<[u8]>>, std::net::SocketAddr)> {
        let mut buffer = vec!(0; MAX_RCV_UDP_DATA_SIZE);
        let (message_size, socket_addr) = udp_socket.recv_from(buffer.as_mut_slice())?;
        buffer.truncate(message_size);
        let udp_message = UdpBytes {buffer: buffer.into_boxed_slice()};
        Ok((udp_message, socket_addr))
    }

    #[inline]
    pub (crate) fn as_bytes(&self) -> &[u8] {
        self.buffer.as_ref()
    }
}

impl<D: AsRef<[u8]> + 'static> UdpBytes<D> {
    pub (crate) fn compute_packet(self) -> Result<Packet<OwnedSlice<u8, D>>, (UdpDataError, Self)> {
        Packet::attempt_from_bytes(self.buffer)
            .map_err(|(e, b)| (e, Self { buffer: b }))
    }
}

#[test]
#[cfg(test)]
fn udp_unrecognized_passthrough() {
    let received_message: &'static [u8] = b"HELLOWORLD";
    let received_fragment = UdpBytes::new(received_message);
    let e = received_fragment.compute_packet().expect_err("compute packet error");
    assert_eq!(e.1.as_bytes(), received_message);
}

#[test]
#[cfg(test)]
fn udp_fail_not_big_enough() {
    let received_message: &'static [u8] = &[0u8, 0u8, 0u8, 0u8, 1u8, 2u8, 5u8];
    let received_fragment = UdpBytes::new(received_message);
    let e = received_fragment.compute_packet().expect_err("compute packet error");
    assert_eq!(e.0, UdpDataError::NotBigEnough);
}

#[test]
#[cfg(test)]
fn udp_fail_invalid_crc() {
    let received_message: &'static [u8] = &[0; 20];
    let received_udp_message = UdpBytes::new(received_message);
    let e = received_udp_message.compute_packet().expect_err("compute packet error");
    assert_eq!(e.0, UdpDataError::InvalidCrc);
}

#[test]
#[cfg(test)]
fn udp_success_fragment_parse() {
    let received_message_bytes: &'static [u8] = &[
        0xBE, 0xE8, 0xC1, 0x2B, // crc32
        0x00, 0x00, 0x00, 0x00, // pub src key
        0x00, 0x00, 0x00, 0x00, // pub dst key
        0x00, 0x00, 0x00, 0x00, // frag id / frag tot / frag flags
        0x00, 0x00, 0x00, 0x00, // seq id
        1 // data
    ];
    let udp_message = UdpBytes::new(received_message_bytes);
    let packet = udp_message.compute_packet().expect("compute packet");
    if let PacketVariant::Fragment(f) = &packet.packet_variant {
        assert_eq!(f.seq_id, 0);
        assert_eq!(f.frag_id, 0);
        assert_eq!(f.frag_total, 0);
        assert_eq!(f.frag_set_flags, FragmentSetFlags::new());
        assert_eq!(f.data.as_ref(), &[1]);
    } else {
        panic!("Received packet was not a fragment");
    }
}

#[test]
#[cfg(test)]
fn udp_fail_fragment_invalid_layout() {
    let received_message_bytes: &'static [u8] = &[
        0xA0, 0x70, 0x47, 0x78,
        0x00, 0x00, 0x00, 0x00, // pub src key
        0x00, 0x00, 0x00, 0x00, // pub dst key
        0xFE, 0xFD, 0x00, 0x00, // frag id / frag tot / frag flags
    ];
    let udp_message = UdpBytes::new(received_message_bytes);
    let err = udp_message.compute_packet().expect_err("compute packet error");
    assert_eq!(err.0, UdpDataError::InvalidFragLayout(0xFE, 0xFD));
}

#[test]
#[cfg(test)]
fn udp_success_ack_parse() {
    let received_message_bytes: &'static [u8] = &[
        0xA0, 0x41, 0xB6, 0xCD, // crc32
        0x00, 0x00, 0x00, 0x00, // pub src key
        0x00, 0x00, 0x00, 0x00, // pub dst key
        0xFF, 0x00, 0x00, 0x00, // frag id / frag tot / frag flags
        0x00, 0x00, 0x00, 0x05, // seq id
        0xFF, 0xFF, // ack timing: delay too long, after a resend
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF // data
    ];
    let udp_message = UdpBytes::new(received_message_bytes);
    let packet = udp_message.compute_packet().expect("compute packet");
    if let PacketVariant::Ack { seq_id, timing, slice } = &packet.packet_variant {
        assert_eq!(*timing, AckTiming { delay: None, after_resend: true });
        assert_eq!(*seq_id, 5);
        assert_eq!(slice.as_ref().len(), 6);
    } else {
        panic!("Received packet was not a fragment ACK");
    }
}

#[test]
#[cfg(test)]
fn udp_success_syn_parse() {
    let received_message_bytes: &'static [u8] = &[
        0x7C, 0x51, 0x6C, 0xF3,
        0x00, 0xFF, 0x00, 0xFF, // pub src key
        0x00, 0xDD, 0x00, 0xDD, // pub dst key
        0xFF, 0x01, 0x00, 0x00, // frag id / frag tot / frag flags
        0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, // pub key: 32 bytes
        0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF,
        0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF,
        0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF,
    ];
    let udp_message = UdpBytes::new(received_message_bytes);
    let packet = udp_message.compute_packet().expect("compute packet");
    if let PacketVariant::Syn { pub_key } = &packet.packet_variant {
        assert_eq!(pub_key[0], 0);
        assert_eq!(pub_key[1], 255);
    } else {
        panic!("Received packet was not a fragment SYN");
    }
}

#[test]
#[cfg(test)]
fn udp_success_synack_parse() {
    let received_message_bytes: &'static [u8] = &[
        0xF7, 0x82, 0x52, 0xEA,
        0x00, 0xFF, 0x00, 0xFF, // pub src key
        0x00, 0xDD, 0x00, 0xDD, // pub dst key
        0xFF, 0x02, 0x00, 0x00, // frag id / frag tot / frag flags
        0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, // pub key: 32 bytes
        0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF,
        0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF,
        0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF,
    ];
    let udp_message = UdpBytes::new(received_message_bytes);
    let packet = udp_message.compute_packet().expect("compute packet");
    if let PacketVariant::SynAck { pub_key } = &packet.packet_variant {
        assert_eq!(pub_key[0], 0);
        assert_eq!(pub_key[1], 255);
    } else {
        panic!("Received packet was not a fragment SYNACK");
    }
}

#[test]
#[cfg(test)]
fn udp_success_heartbeat_parse() {
    let received_message_bytes: &'static [u8] = &[
        0x40, 0x42, 0x03, 0xC4,
        0x00, 0xFF, 0x00, 0xFF, // pub src key
        0x00, 0xDD, 0x00, 0xDD, // pub dst key
        0xFF, 0x0A, 0x00, 0x00, // frag id / frag tot / frag flags
    ];
    let udp_message = UdpBytes::new(received_message_bytes);
    let packet = udp_message.compute_packet().expect("compute packet");
    if let PacketVariant::Heartbeat = packet.packet_variant {
    } else {
        panic!("Received packet was not a fragment SYNACK");
    }
}

#[test]
#[cfg(test)]
fn udp_ser_de_ack() {
    let timing = AckTiming { delay: Some(std::time::Duration::from_millis(3)), after_resend: false };
    let ack = PacketVariant::Ack { seq_id: 9, timing, slice: vec![0xAA, 0xAA].into_boxed_slice() };
    let packet = Packet::new([0xEE; 4], [0xDD; 4], ack);
    let udp_packet = UdpBytes::from(&packet);
    let parsed = udp_packet.compute_packet().expect("compute packet");
    if !packet.cmp_with(&parsed) {
        panic!("{:?} != {:?}, ack serialized is different from deserialized", packet, parsed);
    }
}

#[test]
#[cfg(test)]
fn udp_ser_de_syn_synack_others() {
    let pub_key = [
        0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF,
        0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF,
        0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF,
        0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF
    ];
    let src_id = [0x00, 0xFF, 0x00, 0xFF];
    let dst_id = [0x00, 0xDD, 0x00, 0xDD];
    let seq_id = 7;
    let syn1: Packet<Box<[u8]>> = Packet::new(src_id, dst_id, PacketVariant::Syn { pub_key });
    let synack1: Packet<Box<[u8]>> = Packet::new(src_id, dst_id, PacketVariant::SynAck { pub_key });
    let end1: Packet<Box<[u8]>> = Packet::new(src_id, dst_id, PacketVariant::End { last_seq_id: seq_id });
    let abort1: Packet<Box<[u8]>> = Packet::new(src_id, dst_id, PacketVariant::Abort { last_seq_id: seq_id });
    let heartbeat1: Packet<Box<[u8]>> = Packet::new(src_id, dst_id, PacketVariant::Heartbeat);
    let syn_packet = UdpBytes::from(&syn1);
    let synack_packet = UdpBytes::from(&synack1);
    let end_packet = UdpBytes::from(&end1);
    let abort_packet = UdpBytes::from(&abort1);
    let heartbeat_packet = UdpBytes::from(&heartbeat1);

    let syn2 = syn_packet.compute_packet().expect("compute packet syn2");
    let synack2 = synack_packet.compute_packet().expect("compute packet synack2");
    let end2 = end_packet.compute_packet().expect("compute packet end2");
    let abort2 = abort_packet.compute_packet().expect("compute packet abort2");
    let heartbeat2 = heartbeat_packet.compute_packet().expect("compute packet heartbeat2");
    if !syn1.cmp_with(&syn2) {
        panic!("{:?} != {:?}, syn serialized is different from deserialized", syn1, syn2);
    }
    if !synack1.cmp_with(&synack2) {
        panic!("{:?} != {:?}, synack serialized is different from deserialized", synack1, synack2);
    }
    if !end1.cmp_with(&end2) {
        panic!("{:?} != {:?}, end serialized is different from deserialized", end1, end2);
    }
    if !abort1.cmp_with(&abort2) {
        panic!("{:?} != {:?}, abort serialized is different from deserialized", abort1, abort2);
    }
    if !heartbeat1.cmp_with(&heartbeat2) {
        panic!("{:?} != {:?}, heartbeat serialized is different from deserialized", heartbeat1, heartbeat2);
    }
}

#[test]
#[cfg(test)]
fn udp_success_frag_conversions() {
    let sent_fragment = Fragment {
        seq_id: 12,
        frag_id: 0,
        frag_total: 0,
        frag_set_flags: FragmentSetFlags(1),
        data: vec![1u8, 2, 3, 4].into_boxed_slice()
    };
    let packet = Packet::new(
        [0x00, 0xFF, 0x00, 0xFF],
        [0x00, 0xDD, 0x00, 0xDD],
        PacketVariant::Fragment(sent_fragment.clone())
    );
    let udp_message: UdpBytes<_> = UdpBytes::from(&packet);

    let received_packet = udp_message.compute_packet().expect("compute packet");

    if let PacketVariant::Fragment(f) = &received_packet.packet_variant {
        assert_eq!(f.seq_id, sent_fragment.seq_id);
        assert_eq!(f.frag_id, sent_fragment.frag_id);
        assert_eq!(f.frag_total, sent_fragment.frag_total);
        assert_eq!(f.frag_set_flags, FragmentSetFlags(1));
        assert_eq!(f.data.as_ref(), &*sent_fragment.data);
    } else {
        panic!("Received message is not of fragment type!")
    }
}
#[test]
#[cfg(test)]
fn udp_ser_de_control_mac() {
    let mac = ControlMac { counter: 0xDEADBEEF, tag: [7; CONTROL_MAC_TAG_SIZE] };
    let timing = AckTiming { delay: Some(std::time::Duration::ZERO), after_resend: false };
    let variants: Vec<PacketVariant<Box<[u8]>>> = vec![
        PacketVariant::Ack { seq_id: 9, timing, slice: vec![0xAA, 0xAA].into_boxed_slice() },
        PacketVariant::Ack { seq_id: 9, timing, slice: vec![].into_boxed_slice() },
        PacketVariant::End { last_seq_id: 3 },
        PacketVariant::Abort { last_seq_id: 3 },
        PacketVariant::Heartbeat,
    ];
    for variant in variants {
        let mut packet = Packet::new([0xEE; 4], [0xDD; 4], variant);
        packet.mac = Some(mac);
        let bytes = packet.to_bytes();
        // the mac input is the packet without its crc and mac
        assert_eq!(packet.mac_input(), &bytes[PACKET_CRC32_SIZE..bytes.len() - CONTROL_MAC_SIZE]);
        let parsed = UdpBytes::new(bytes.into_boxed_slice()).compute_packet().expect("compute packet");
        assert!(packet.cmp_with(&parsed), "{:?} != {:?}", packet, parsed);
        assert_eq!(parsed.mac_input(), packet.mac_input());
    }
}

#[test]
#[cfg(test)]
fn udp_control_mac_too_short() {
    // HAS_MAC flag set on a heartbeat, but no room for the mac
    let mut bytes = vec![0u8; 16 + CONTROL_MAC_SIZE - 1];
    bytes[12] = 0xFF;
    bytes[13] = 10;
    bytes[15] = 1;
    let crc = crc32_hash(&bytes[4..]);
    BigEndian::write_u32(&mut bytes[0..4], crc);
    let e = UdpBytes::new(bytes.into_boxed_slice()).compute_packet().expect_err("compute packet error");
    assert_eq!(e.0, UdpDataError::NotBigEnough);
}
