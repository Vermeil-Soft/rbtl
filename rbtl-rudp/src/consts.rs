use std::time::Duration;

// CRC32 = u32 = 4bytes
pub (crate) const PACKET_CRC32_SIZE: usize = std::mem::size_of::<u32>();

// 4 for the src identity key, 4 for the dst identity key,
// 1 for the frag_id, 1 for the frag_total, 2 for flags or reserved stuff
pub (crate) const PACKET_COMMON_HEADER_SIZE: usize = 12;

pub (crate) const PACKET_VAR_START_BYTE: usize = PACKET_CRC32_SIZE + PACKET_COMMON_HEADER_SIZE;

pub (crate) const MAX_RCV_UDP_DATA_SIZE: usize = 1400;

pub (crate) const SEQ_DATA_CLEANUP_DELAY: std::time::Duration = std::time::Duration::from_millis(5000);

// Since the frag_id max is 255, we can have at most 256 frags in a message.
pub (crate) const MAX_FRAGMENTS_IN_MESSAGE: usize = 256;

// 1024 + 128 = 1152 is an arbitrary value below most common MTU values
//
// note that this is the "inner" part of the message, MTU also include ipv4/ipv6 packet size (40 bytes),
// and udp packet size (8 bytes). The total is 1200, which is slightly below the minimum value of ipv6, 1280.
//
// "most" routers have a MTU of 1500, but do you really want to come across a router that just deletes your
// messages entirely?
pub (crate) const MAX_FRAGMENT_INNER_SIZE: usize = 1024 + 128;

/// The maximum size of a message that can be sent before it needs to be split into smaller ones, in bytes.
///
/// For encrypted messages, this is the size WITH the encryption data, which is typically 16 bytes for chacha20
pub const MAX_MESSAGE_SIZE: usize = MAX_FRAGMENT_INNER_SIZE * MAX_FRAGMENTS_IN_MESSAGE;

/// Number of iterations we must wait to send the next ack since the last one.
pub (crate) const ACK_SEND_INTERVAL: Duration = Duration::from_millis(50);

/// Maximum number of messages being re-assembled at the same time, per remote.
///
/// Each one can hold up to `MAX_MESSAGE_SIZE` bytes, so this bounds the memory a remote can make us use.
pub (crate) const MAX_INCOMPLETE_FRAGMENT_SETS: usize = 32;

/// Maximum number of messages (complete or not) remembered per remote.
///
/// Complete messages are remembered for a while so that resent fragments are not delivered twice.
/// They are small, but a remote sending lots of messages could still fill the memory without a limit.
pub (crate) const MAX_FRAGMENT_SETS: usize = 16384;

/// Delay before re-sending the first Syn if there is no answer. It doubles after each try, up to `SYN_RESEND_MAX_DELAY`.
pub (crate) const SYN_RESEND_FIRST_DELAY: Duration = Duration::from_millis(250);

pub (crate) const SYN_RESEND_MAX_DELAY: Duration = Duration::from_secs(1);

/// Size of the truncated Poly1305 tag of control packets
pub (crate) const CONTROL_MAC_TAG_SIZE: usize = 8;

/// Size of the mac at the end of control packets: a u32 counter, then the tag
pub (crate) const CONTROL_MAC_SIZE: usize = 4 + CONTROL_MAC_TAG_SIZE;
