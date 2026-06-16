use byteorder::{BigEndian, ByteOrder};
use crate::{net::common::SeqId, utils::crc32_hash};

use crate::{
    utils::{BoxedSlice, OwnedSlice},
    consts::*,
    net::protocol::{
        fragment::{Fragment, FragmentSetFlags, ack::Acks},
    }
};

#[derive(Debug)]
pub (crate) struct Packet<P: AsRef<[u8]>> {
    pub (crate) pub_identity: [u8; 4],
    pub (crate) packet_variant: PacketVariant<P>,
}

#[derive(Debug, PartialEq)]
pub (crate) enum PacketVariant<P: AsRef<[u8]>> {
    Fragment(Fragment<P>),
    Ack { seq_id: SeqId, slice: P },
    Syn { pub_key: [u8; 32] },
    SynAck { pub_key: [u8; 32] },
    Heartbeat,
    End { last_seq_id: SeqId },
    Abort { last_seq_id: SeqId }
}

impl<P: AsRef<[u8]>> Packet<P> {
    pub (crate) fn new(pub_identity: [u8; 4], packet_variant: PacketVariant<P>) -> Self {
        Self {
            pub_identity,
            packet_variant
        }
    }

    pub (crate) fn build(pub_identity: &[u8; 32], packet_variant: PacketVariant<P>) -> Self {
        let pub_identity: [u8; 4] = pub_identity[0..4].try_into().unwrap();
        Self::new(pub_identity, packet_variant)
    }

    fn udp_packet_size(&self) -> usize {
        let after_common: usize = match &self.packet_variant {
            // seq_id + data.len()
            PacketVariant::Fragment(f) => std::mem::size_of::<u32>() + f.data.as_ref().len(),
            // seq_id + ack_slice.len()
            PacketVariant::Ack { slice, .. } => std::mem::size_of::<u32>() + slice.as_ref().len(),
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
        output[9] = frag_tot;
        output[8] = frag_id;
    }

    #[inline]
    fn write_flags(flags: u16, output: &mut Vec<u8>) {
        BigEndian::write_u16(&mut output[10..12], flags);
    }

    #[inline]
    fn write_seq_id(seq_id: SeqId, output: &mut Vec<u8>) {
        BigEndian::write_u32(&mut output[12..16], seq_id);
    }

    fn write_pub_key(key: &[u8; 32], output: &mut Vec<u8>) {
        output[12..44].copy_from_slice(key);
    }

    pub (crate) fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![0; self.udp_packet_size()];

        match &self.packet_variant {
            PacketVariant::Fragment(f) => {
                bytes[16..].copy_from_slice(f.data.as_ref());
                Self::write_seq_id(f.seq_id, &mut bytes);
                Self::write_flags(f.frag_set_flags.0, &mut bytes);
                Self::write_frags(f.frag_id, f.frag_total, &mut bytes);
            },
            PacketVariant::Ack { seq_id, slice } => {
                bytes[16..].copy_from_slice(slice.as_ref());
                Self::write_seq_id(*seq_id, &mut bytes);
                Self::write_flags(0, &mut bytes);
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
                Self::write_flags(0, &mut bytes);
                Self::write_frags(255, 3, &mut bytes);
            },
            PacketVariant::Abort { last_seq_id } => {
                Self::write_seq_id(*last_seq_id, &mut bytes);
                Self::write_flags(0, &mut bytes);
                Self::write_frags(255, 4, &mut bytes);
            },
            PacketVariant::Heartbeat => {
                Self::write_flags(0, &mut bytes);
                Self::write_frags(255, 10, &mut bytes);
            },
        }
        bytes[4..8].copy_from_slice(&self.pub_identity);
        let generated_crc: u32 = crc32_hash(&bytes[4..]);
        BigEndian::write_u32(&mut bytes[0..4], generated_crc);
        bytes
    }

    fn read_common_header(bytes: &[u8; 12]) -> (u32, [u8; 4], u8, u8, u16) {
        let crc32 = BigEndian::read_u32(&bytes[0..4]);
        let pub_id = <[u8; 4]>::try_from(&bytes[4..8]).unwrap();
        let frag_id = bytes[8]; 
        let frag_tot = bytes[9]; 
        let frag_flags = BigEndian::read_u16(&bytes[10..12]);
        (crc32, pub_id, frag_id, frag_tot, frag_flags)
    }

    pub fn attempt_from_bytes(bytes: P) -> Result<Packet<OwnedSlice<u8, P>>, (UdpDataError, P)> {
        let bytes_ref = bytes.as_ref();
        let Some((header_slice, data_slice)) = bytes_ref.split_at_checked(PACKET_VAR_START_BYTE) else {
            return Err((UdpDataError::NotBigEnough, bytes));
        };
        let header_slice = <&[u8; 12]>::try_from(header_slice).unwrap();
        let (crc32, pub_id, frag_id, frag_tot, frag_flags) = Self::read_common_header(header_slice);

        let computed_crc32 = crc32_hash(&bytes_ref[4..]);
        if computed_crc32 != crc32 {
            return Err((UdpDataError::InvalidCrc, bytes));
        }

        let variant = match (frag_id, frag_tot) {
            (255, 0) => {
                if data_slice.len() < 4 {
                    return Err((UdpDataError::NotBigEnough, bytes));
                }
                let seq_id = BigEndian::read_u32(&data_slice[0..4]);
                PacketVariant::Ack { seq_id , slice: OwnedSlice::new(bytes, PACKET_VAR_START_BYTE + 4) }
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
        let packet = Packet::new(pub_id, variant);
        Ok(packet)
    }

    #[cfg(test)]
    pub (crate) fn cmp_with<T2: AsRef<[u8]>>(&self, other: &Packet<T2>) -> bool {
        self.pub_identity == other.pub_identity && self.packet_variant.cmp_with(&other.packet_variant)
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
            (Ack { seq_id: s1, slice: d1 }, Ack { seq_id: s2, slice: d2 }) => s1 == s2 && d1.as_ref() == d2.as_ref(),
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
/// [4-7]: first 4 bytes of DH pub key working as "identity" of sender
/// [8-11]:
///     * if type == Fragment, the sequence id
///     * if type == Ack, the sequence id of the acknowledged sequence
///     * if type == Syn, type == SynAck, nothing (0s)
///     * if type == End or type == Abort, the last SeqId sent
/// [8]: "Frag Id"
/// [9] "Frag total"
/// [10-11]: frag set flags; such as "IS_EXPIRE", "IS_KEY", ...
/// [12-15]: sequence id, if applicable.
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
/// * If Frag ID <= Frag Total, type = Fragment.
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
///
/// # Fragment
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
/// Payload will contain additional data on top of the header, not defined by the user.
/// This additional data will be at most the size of (Type<FragId>::Max + 1) / 8, meaning
/// (255 + 1) / 8 = 32 bytes.
/// 
/// Hence for a Ack packet, the maximum length will be of 16bytes (header) + 32bytes = 48 bytes.
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
    ///
    /// (It must be at least 10 bytes, 11 bytes for frags)
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
        0x78, 0x73, 0x76, 0x14, // crc32
        0x00, 0x00, 0x00, 0x00, // pub key
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
        0xbe, 0x87, 0x5e, 0x7e,
        0x00, 0x00, 0x00, 0x00, // pub key
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
        0x0c, 0x55, 0xe7, 0x60, // crc32
        0x00, 0x00, 0x00, 0x00, // pub key
        0xFF, 0x00, 0x00, 0x00, // frag id / frag tot / frag flags
        0x00, 0x00, 0x00, 0x05, // seq id
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF // data
    ];
    let udp_message = UdpBytes::new(received_message_bytes);
    let packet = udp_message.compute_packet().expect("compute packet");
    if let PacketVariant::Ack { seq_id, slice } = &packet.packet_variant {
        assert_eq!(*seq_id, 5);
        assert_eq!(slice.as_ref().len(), 8);
    } else {
        panic!("Received packet was not a fragment ACK");
    }
}

#[test]
#[cfg(test)]
fn udp_success_syn_parse() {
    let received_message_bytes: &'static [u8] = &[
        0x24, 0x08, 0x3d, 0x4b,
        0x00, 0xFF, 0x00, 0xFF, // pub key
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
        0xaf, 0xdb, 0x03, 0x52,
        0x00, 0xFF, 0x00, 0xFF, // pub key
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
        0xee, 0xe2, 0xd1, 0xf2,
        0x00, 0xFF, 0x00, 0xFF, // pub key
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
    let ack = PacketVariant::Ack { seq_id: 9, slice: vec![0xAA, 0xAA].into_boxed_slice() };
    let packet = Packet::new([0xEE; 4], ack);
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
    let pub_id = [0x00, 0xFF, 0x00, 0xFF];
    let seq_id = 7;
    let syn1: Packet<Box<[u8]>> = Packet::new(pub_id, PacketVariant::Syn { pub_key });
    let synack1: Packet<Box<[u8]>> = Packet::new(pub_id, PacketVariant::SynAck { pub_key });
    let end1: Packet<Box<[u8]>> = Packet::new(pub_id, PacketVariant::End { last_seq_id: seq_id });
    let abort1: Packet<Box<[u8]>> = Packet::new(pub_id, PacketVariant::Abort { last_seq_id: seq_id });
    let heartbeat1: Packet<Box<[u8]>> = Packet::new(pub_id, PacketVariant::Heartbeat);
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
    let packet = Packet::new([0x00, 0xFF, 0x00, 0xFF], PacketVariant::Fragment(sent_fragment.clone()));
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