
use byteorder::{BigEndian, ByteOrder};

use std::{
    io::{Error as IoError, ErrorKind as IoErrorKind, Read, Write},
    net::{SocketAddr, TcpStream, ToSocketAddrs}, time::Instant
};

use crate::{SeqId, ingester::{Ingester, IngesterResult}, ping_tracker::PingTracker};

#[derive(Clone)]
pub struct SocketConfig {
    pub max_msg_len: u32
}

impl SocketConfig {
    pub const MAX_MSG_LEN: u32 = 1024 * 1024;

    pub fn new() -> Self {
        Self {
            max_msg_len: Self::MAX_MSG_LEN
        }
    }
}

pub enum SocketEvent {
    Data(Box<[u8]>),
    Status(SocketStatus),
}

impl std::fmt::Debug for SocketEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            SocketEvent::Data(d) => write!(f, "Data({:?} bytes)", d.len()),
            SocketEvent::Status(s) => write!(f, "NewStatus({:?})", s),
        }
    }
}

#[derive(Clone, Debug)]
pub enum SocketStatus {
    Connected,
    Error(String),
    Timeout,
    LocalEnded,
    RemoteEnded,
}

impl SocketStatus {
    pub fn is_error(&self) -> bool {
        matches!(self, SocketStatus::Error(_))
    }

    pub fn is_connected(&self) -> bool {
        matches!(self, SocketStatus::Connected)
    }
}

pub struct Socket {
    pub (crate) tcp_stream: TcpStream,
    ingester: Ingester,
    out_seq_id: SeqId,
    last_ok_seq_id: Option<SeqId>,
    ping_tracker: PingTracker,
    pub (crate) config: SocketConfig,
    status: SocketStatus,

    events: Vec<SocketEvent>,
}

pub (crate) const MSG_TYPE_DATA_ID: u8 = 0;
pub (crate) const MSG_TYPE_STATUS_ID: u8 = 1;
pub (crate) const MSG_TYPE_DATA_HEAD_LEN: usize = 8;
pub (crate) const MSG_TYPE_STATUS_HEAD_LEN: usize = 4;

impl Socket {
    pub (crate) fn prepare_tcp_stream(tcp_stream: &TcpStream) {
        let _r = tcp_stream.set_nodelay(true);
        let _r = tcp_stream.set_nonblocking(true);
    }

    pub fn new_from_tcp_stream(tcp_stream: TcpStream) -> Self {
        Self::prepare_tcp_stream(&tcp_stream);
        Self {
            tcp_stream,
            out_seq_id: 0,
            last_ok_seq_id: None,
            ping_tracker: PingTracker::new(),
            config: SocketConfig::new(),
            ingester: Ingester::new(),
            status: SocketStatus::Connected,

            events: Vec::new(),
        }
    }

    pub fn raw(&self) -> &TcpStream {
        &self.tcp_stream
    }

    /// Connect to the remote. This call will block until the connection is made or dropped.
    pub fn new<A: ToSocketAddrs>(remote_addr: A) -> Result<Self, IoError> {
        let tcp_stream = TcpStream::connect(remote_addr)?;
        Ok(Self::new_from_tcp_stream(tcp_stream))
    }

    /// Receives a single call of tcp socket read and stores it in the ingester
    fn recv_single(&mut self) -> Result<(), IoError> {
        if !self.status.is_connected() {
            return Ok(());
        }
        let mut buf = [0; 2048];
        let size = self.tcp_stream.read(&mut buf)?;
        if size == 0 {
            return Err(IoError::new(IoErrorKind::ConnectionReset, "end of stream"));
        }
        self.ingester.take_bytes(&buf[0..size], self.config.max_msg_len);
        Ok(())
    }

    /// Processes tcp read calls until the receiving tcp queue is empty
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

    /// Omit of &mut self is needed for borrow checker purposes
    fn stream_send_status(stream: &mut TcpStream, seq_id: u32) {
        let mut out_bytes = vec![0u8; 5];
        out_bytes[0] = MSG_TYPE_STATUS_ID;
        BigEndian::write_u32(&mut out_bytes[1..5], seq_id);
        let _r = stream.write(&out_bytes);
    }

    fn internal_send_data(&mut self, seq_id: u32, bytes: &[u8]) {
        let mut out_bytes = vec![0u8; 9 + bytes.len()];
        out_bytes[0] = MSG_TYPE_DATA_ID;
        BigEndian::write_u32(&mut out_bytes[1..5], seq_id);
        BigEndian::write_u32(&mut out_bytes[5..9], bytes.len() as u32);
        out_bytes[9..].copy_from_slice(bytes);
        let _r = self.tcp_stream.write(&out_bytes);
        self.ping_tracker.ping(seq_id);
    }

    fn set_status(&mut self, status: SocketStatus) {
        self.events.push(SocketEvent::Status(status.clone()));
        self.status = status;
    }

    pub (crate) fn insert_event(&mut self, socket_event: SocketEvent) {
        self.events.push(socket_event);
    }

    pub (crate) fn has_events(&self) -> bool {
        !self.events.is_empty()
    }

    fn process_ingester_results(&mut self) {
        for ingester_result in self.ingester.results.drain(..) {
            match ingester_result {
                IngesterResult::Data(seq_id, data) => {
                    self.events.push(SocketEvent::Data(data.into_boxed_slice()));
                    Self::stream_send_status(&mut self.tcp_stream, seq_id);
                },
                IngesterResult::Error(err_msg) => {
                    let new_status = SocketStatus::Error(err_msg);
                    self.events.push(SocketEvent::Status(new_status.clone()));
                    self.status = new_status;
                },
                IngesterResult::SeqIdOk(seq_id) => {
                    self.ping_tracker.pong(seq_id);
                }
            }
        }
    }

    pub fn process(&mut self) {
        let r = self.recv_all();
        self.process_ingester_results();
        match r {
            Ok(()) => {},
            Err(io_error) => {
                match io_error.kind() {
                    IoErrorKind::TimedOut => {
                        self.set_status(SocketStatus::Timeout);
                    },
                    IoErrorKind::ConnectionAborted | IoErrorKind::ConnectionReset => {
                        self.set_status(SocketStatus::RemoteEnded);
                    },
                    IoErrorKind::UnexpectedEof => {
                        self.set_status(SocketStatus::RemoteEnded);
                    },
                    _ => {
                        self.set_status(SocketStatus::Error(format!("unexpected IO error {}", io_error.to_string())));
                    }
                }
            }
        }
    }

    /// Returns the ping to the remote as ms
    /// 
    /// `seconds` is the duration over which to compute the average, 1.0 means compute the avg ping over the last second
    ///
    /// Returns None if the ping has not been computed yet
    ///
    /// If seconds is zero or negative or not enoguh to have a ping recorded,
    /// it will simply retrun the latest ping if there is one
    pub fn avg_ping(&self, seconds: f32) -> Option<f32> {
        self.ping_tracker.avg_ping(seconds)
    }

    /// Returns the last ping available, and when it was received in time.
    pub fn last_ping_info(&self) -> Option<(u32, Instant)> {
        self.ping_tracker.last_ping_info()
    }

    pub fn end(&mut self) {
        self.set_status(SocketStatus::LocalEnded);
    }

    pub fn send_data<B>(&mut self, bytes: B) -> SeqId where B: AsRef<[u8]> {
        let seq_id = self.out_seq_id;
        self.out_seq_id = self.out_seq_id.wrapping_add(1);
        self.internal_send_data(seq_id, bytes.as_ref());
        seq_id
    }

    pub fn status(&self) -> SocketStatus {
        self.status.clone()
    }

    pub fn drain_events<'a>(&'a mut self) -> impl 'a + Iterator<Item=SocketEvent> {
        self.events.drain(..)
    }

    pub fn is_seq_id_received(&self, seq_id: SeqId) -> bool {
        match self.last_ok_seq_id {
            None => false,
            Some(ok_seq_id) => {
                // we can't use simple comparisons here just in case we wrap around SeqId::max
                // a simple alternative is just taking the diff between ok_seq_id and seq_id, 2 cases:
                // * ok_seq_id = 4_000_000_000; seq_id = 1 => diff = 4billion
                // * ok_seq_id = 0; seq_id = 1 => diff = -1, but wrapped ~4billion
                // in both cases 4billion would be above u32::MAX / 2, so the check would not pass
                let diff = ok_seq_id.wrapping_sub(seq_id);
                diff < SeqId::MAX / 2
            }
        }
    }
}