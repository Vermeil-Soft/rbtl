use std::time::Duration;

use crate::consts;

#[derive(Debug)]
pub enum PacketSendError {
    SentMsgTooBig { attempt_size: usize },
    SentMsgEmpty,
    /// When you want to send a message before obtaining a shared secret
    NoEncryptionKey,
    /// Some unknown encryption error happened. Basically should never happen.
    EncryptionError,
    /// The remote doesn't exist or has disconnected
    RemoteNotConnected,
}

impl std::error::Error for PacketSendError {
}

pub type SeqId = u32;

impl std::fmt::Display for PacketSendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SentMsgTooBig { attempt_size } =>
                write!(f, "Sent msg is {} bytes, above the limit of {} bytes in a single message:", attempt_size, consts::MAX_MESSAGE_SIZE),
            Self::SentMsgEmpty => {
                write!(f, "Sent msg is empty, which is illegal")
            },
            Self::NoEncryptionKey => {
                write!(f, "The message was supposed to be encrypted, but we haven't got a shared secret yet")
            },
            Self::RemoteNotConnected => {
                write!(f, "Remote not connected")
            },
            Self::EncryptionError => {
                write!(f, "encryption error")
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SocketConfig {
    /// delay without an answer from the remote to consider a timeout
    pub timeout_delay: Duration,
    /// delay of which to send a heartbeat if no messages has been sent recently
    pub heartbeat_delay: Duration,
    /// if we receive a message from a known remote but with an unknown message, should we transfer it or ignore?
    pub transfer_raw: bool,
    /// if we receive a message from a unknown remote but with an unknown message, should we transfer it or ignore?
    pub transfer_unknown_raw: bool,
}

impl SocketConfig {
    pub const DEFAULT_TIMEOUT_DELAY: Duration = Duration::from_secs(5);
    pub const DEFAULT_HEARTBEAT_DELAY: Duration = Duration::from_secs(1);
    pub const DEFAULT_TRANSFER_RAW: bool = false;
    pub const DEFAULT_TRANSFER_UNKNOWN_RAW: bool = false;

    pub fn new() -> Self {
        Self {
            timeout_delay: Self::DEFAULT_TIMEOUT_DELAY,
            heartbeat_delay: Self::DEFAULT_HEARTBEAT_DELAY,
            transfer_raw: Self::DEFAULT_TRANSFER_RAW,
            transfer_unknown_raw: Self::DEFAULT_TRANSFER_UNKNOWN_RAW,
        }
    }

    pub fn with_timeout(mut self, timeout_ms: u64) -> Self {
        self.timeout_delay = Duration::from_millis(timeout_ms);
        self
    }
}

impl Default for SocketConfig {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ListenerConfig {
    /// if we receive an unknown message from a unknown remote, should we transfer it or ignore?
    pub transfer_unknown_raw: bool,
}

impl ListenerConfig {
    pub const DEFAULT_TRANSFER_UNKNOWN_RAW: bool = false;

    pub fn new() -> Self {
        Self {
            transfer_unknown_raw: Self::DEFAULT_TRANSFER_UNKNOWN_RAW,
        }
    }
}

impl Default for ListenerConfig {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug)]
pub struct PacketSendOptions {
    pub resend_delay: Duration,
    pub encryption: bool,
    /// Expiration = None means the message never expires
    pub expiration: Option<Duration>,
    /// Can the sent message be forgotten and ignored by the sender or receiver if needed?
    pub key: bool,
}

impl Default for PacketSendOptions {
    fn default() -> Self {
        Self::new()
    }
}

impl PacketSendOptions {
    pub const DEFAULT_RESEND_DELAY: Duration = Duration::from_millis(160);
    pub const DEFAULT_ENCRYPTION: bool = true;
    pub const DEFAULT_EXPIRATION: Option<Duration> = None;
    pub const DEFAULT_KEY: bool = true;

    pub fn new() -> Self {
        Self {
            encryption: Self::DEFAULT_ENCRYPTION,
            expiration: Self::DEFAULT_EXPIRATION,
            key: Self::DEFAULT_KEY,
            resend_delay: Self::DEFAULT_RESEND_DELAY
        }
    }

    pub fn encryption(mut self, b: bool) -> Self {
        self.encryption = b;
        self
    }

    pub fn expiration(mut self, exp: impl Into<Option<Duration>>) -> Self {
        self.expiration = exp.into();
        self
    }

    pub fn key(mut self, key: bool) -> Self {
        self.key = key;
        self
    }

    pub fn resend_delay(mut self, delay: Duration) -> Self {
        self.resend_delay = delay;
        self
    }

    pub fn resend_delay_ms(self, delay_ms: u64) -> Self {
        self.resend_delay(Duration::from_millis(delay_ms))
    }
}

pub (crate) fn nonce_from_seq_id(seq_id: SeqId) -> [u8; 12] {
    let mut a = [0; 12];
    a[0..4].copy_from_slice(&seq_id.to_le_bytes());
    a[4..8].copy_from_slice(&seq_id.to_le_bytes());
    a[8..12].copy_from_slice(&seq_id.to_le_bytes());
    a
}