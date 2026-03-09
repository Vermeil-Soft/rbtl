//! RBTL with TCP
//! 
//! Should be used as a fallback only when all udp alternatives are impossible, because TCP completely destroys RBTL's
//! message based approach with its streaming model.
//!
//! The stream is a continuous loop of submessages that look like this:
//! 
//! [ msg_type: u8 ][submessage: ...]
//! 
//! with submessage being either:
//! 
//! * Status update: [ last_recv_seq_id: u32 ]
//! * Data: [ seq_id: u32 ][ msg_len: u32 ][ data: "msg_len" bytes ]
//! 
//! Status update is a way for us to estimate ping with TCP, since there is no consistent cross platform way to do
//! this via syscalls without administrator access.
//! 
//! You do not have to remember this as a library user, it is just a quick overview of how it works under the hood.

mod ping_tracker;

use byteorder::{BigEndian, ByteOrder};

use std::{
    io::{Read, Write, Error as IoError, ErrorKind as IoErrorKind},
    net::{TcpStream, SocketAddr}
};

use ping_tracker::PingTracker;

pub type SeqId = u32;

struct IncompleteData {
    waiting_bytes: Vec<u8>,
    expected_len: u32,
    seq_id: u32,
}

impl IncompleteData {
    /// bytes MUST have a length of 8
    ///
    /// Returns an error if the expected len is higher than max length
    pub fn new(bytes: &[u8], max_len: u32) -> Result<Self, u32> {
        assert_eq!(bytes.len(), 8);
        let seq_id = BigEndian::read_u32(&bytes[0..4]);
        let expected_len = BigEndian::read_u32(&bytes[4..8]);
        if expected_len > max_len {
            return Err(expected_len);
        }
        Ok(Self {
            waiting_bytes: Vec::with_capacity(expected_len as usize),
            seq_id,
            expected_len
        })
    }
}

enum IncomingIncomplete {
    Bytes(Vec<u8>),
    Data(IncompleteData),
}

struct InTracker {
    incomplete: Option<IncomingIncomplete>,
    msgs: Vec<Vec<u8>>,
}

impl InTracker {
    pub (crate) fn new() -> Self {
        Self {
            incomplete: None,
            msgs: Vec::new(),
        }
    }
}

struct SocketConfig {
    max_msg_len: u32
}

impl SocketConfig {
    pub const MAX_MSG_LEN: u32 = 1024 * 1024;

    pub fn new() -> Self {
        Self {
            max_msg_len: Self::MAX_MSG_LEN
        }
    }
}

pub enum SocketStatus {
    Normal,
    Error(String),
    Ended,
}

impl SocketStatus {
    fn is_error(&self) -> bool {
        matches!(self, SocketStatus::Error(_))
    }
}

pub struct Socket {
    stream: TcpStream,
    in_tracker: InTracker,
    out_seq_id: SeqId,
    ping_tracker: PingTracker,
    config: SocketConfig,
    status: SocketStatus,
}

impl Socket {
    const MSG_TYPE_DATA_ID: u8 = 0;
    const MSG_TYPE_STATUS_ID: u8 = 1;

    const MSG_TYPE_DATA_HEAD_LEN: usize = 8;
    const MSG_TYPE_STATUS_HEAD_LEN: usize = 4;

    pub fn new(remote_addr: SocketAddr) -> Result<Self, IoError> {
        let socket = TcpStream::connect(remote_addr)?;
        socket.set_nodelay(true);
        socket.set_nonblocking(true);
        Ok(Self {
            stream: socket,
            out_seq_id: 0,
            ping_tracker: PingTracker::new(),
            config: SocketConfig::new(),
            in_tracker: InTracker::new(),
            status: SocketStatus::Normal,
        })
    }

    fn take_bytes(&mut self, bytes: &[u8]) {
        if bytes.len() == 0 {
            return;
        }
        // that's not very DRY..., but I don't know how to simplify it better than that.
        match &mut self.in_tracker.incomplete {
            None => {
                let id = bytes[0];
                let bytes = &bytes[1..];
                if id == Self::MSG_TYPE_DATA_ID {
                    match bytes.split_at_checked(Self::MSG_TYPE_DATA_HEAD_LEN) {
                        None => {
                            self.in_tracker.incomplete = Some(IncomingIncomplete::Bytes(Vec::from(bytes)));
                        },
                        Some((head, tail)) => {
                            let d = IncompleteData::new(head, self.config.max_msg_len);
                            match d {
                                Ok(d) => {
                                    self.in_tracker.incomplete = Some(IncomingIncomplete::Data(d));
                                    self.take_bytes(tail);
                                },
                                Err(expected_len) => {
                                    self.status = SocketStatus::Error(format!("sent message from remote was too big: {} bytes", expected_len));
                                }
                            }
                        },
                    };
                } else if id == Self::MSG_TYPE_STATUS_ID {
                    match bytes.split_at_checked(Self::MSG_TYPE_STATUS_HEAD_LEN) {
                        None => {
                            self.in_tracker.incomplete = Some(IncomingIncomplete::Bytes(Vec::from(bytes)));
                        },
                        Some((head, tail)) => {
                            let seq_id = BigEndian::read_u32(head);
                            self.ping_tracker.pong(seq_id);
                            self.take_bytes(tail);
                        },
                    };
                } else {
                    self.status = SocketStatus::Error(format!("wrong rbtl-tcp msg id {}", id));
                }
            }
            Some(IncomingIncomplete::Bytes(incomplete_bytes)) => {
                let id = incomplete_bytes[0];
                if id == Self::MSG_TYPE_DATA_ID {
                    match bytes.split_at_checked(Self::MSG_TYPE_DATA_HEAD_LEN - incomplete_bytes.len() + 1) {
                        None => {
                            let mut v = std::mem::take(incomplete_bytes);
                            v.extend_from_slice(bytes);
                            self.in_tracker.incomplete = Some(IncomingIncomplete::Bytes(Vec::from(v)));
                        },
                        Some((head, tail)) => {
                            incomplete_bytes.extend_from_slice(head);
                            match IncompleteData::new(&incomplete_bytes, self.config.max_msg_len) {
                                Ok(d) => {
                                    self.in_tracker.incomplete = Some(IncomingIncomplete::Data(d));
                                    self.take_bytes(tail);
                                },
                                Err(expected_len) => {
                                    self.status = SocketStatus::Error(format!("sent message from remote was too big: {} bytes", expected_len));
                                }
                            }
                        },
                    };
                } else if id == Self::MSG_TYPE_STATUS_ID {
                    match bytes.split_at_checked(Self::MSG_TYPE_STATUS_HEAD_LEN - incomplete_bytes.len() + 1) {
                        None => {
                            let mut v = std::mem::take(incomplete_bytes);
                            v.extend_from_slice(bytes);
                            self.in_tracker.incomplete = Some(IncomingIncomplete::Bytes(Vec::from(bytes)));
                        },
                        Some((head, tail)) => {
                            incomplete_bytes.extend_from_slice(head);
                            let seq_id = BigEndian::read_u32(&incomplete_bytes);
                            self.ping_tracker.pong(seq_id);
                            self.take_bytes(tail);
                        },
                    };
                } else {
                    self.status = SocketStatus::Error(format!("wrong rbtl-tcp msg id {}", id));
                }
            },
            Some(IncomingIncomplete::Data(d)) => {
                let taken = std::cmp::min(d.expected_len as usize - d.waiting_bytes.len(), bytes.len());
                d.waiting_bytes.extend_from_slice(&bytes[0..taken]);
                if d.expected_len as usize == d.waiting_bytes.len() {
                    // the message is complete, transform it
                    self.in_tracker.msgs.push(std::mem::take(&mut d.waiting_bytes));
                    self.in_tracker.incomplete = None;
                    if taken < bytes.len() {
                        self.take_bytes(&bytes[taken..]);
                    }
                } else {
                    // the message is still incomplete, but there are no more bytes to take
                }
            },
        }
    }

    fn recv_single(&mut self) -> Result<(), IoError> {
        if self.status.is_error() {
            return Ok(());
        }
        let mut buf = [0; 2048];
        let size = self.stream.read(&mut buf)?;
        self.take_bytes(&buf[0..size]);
        Ok(())
    }

    fn recv_all(&mut self) -> Result<(), std::io::Error> {
        loop {
            match self.recv_single() {
                Ok(()) => { continue },
                Err(e) => {
                    match e.kind() {
                        IoErrorKind::WouldBlock => { return Ok(()) },
                        _ => return Err(e),
                    }
                }
            }
        }
    }

    fn internal_send_data(&mut self, seq_id: u32, bytes: &[u8]) {
        let mut header = [0u8; 9];
        header[0] = Self::MSG_TYPE_DATA_ID;
        BigEndian::write_u32(&mut header[1..5], seq_id);
        BigEndian::write_u32(&mut header[5..9], bytes.len() as u32);
        let _r = self.stream.write(&header);
        let _r = self.stream.write(bytes);
    }
}