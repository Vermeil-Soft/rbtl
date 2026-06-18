use byteorder::{BigEndian, ByteOrder};

use std::{
    io::{Error as IoError, ErrorKind as IoErrorKind, Read, Write},
    sync::{Arc, OnceLock},
    cell::UnsafeCell,
    time::Duration,
    net::{SocketAddr, TcpStream, ToSocketAddrs}, time::Instant
};

use crate::{SeqId, ingester::{Ingester, IngesterResult}, Error, ping_tracker::PingTracker};

#[derive(Clone, Debug)]
pub struct SocketConfig {
    pub max_msg_len: u32,
    pub timeout_ms: u64,
}

impl SocketConfig {
    pub const MAX_MSG_LEN: u32 = 1024 * 1024;

    pub fn new() -> Self {
        Self {
            max_msg_len: Self::MAX_MSG_LEN,
            timeout_ms: Socket::TIMEOUT_DURATION_DEFAULT_MS,
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
    Connecting,
    Connected,
    Error(Error),
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
    pub (crate) tcp_stream: Arc<UnsafeCell<OnceLock<TcpStream>>>,
    ingester: Ingester,
    out_seq_id: SeqId,
    last_ok_seq_id: Option<SeqId>,
    ping_tracker: PingTracker,
    pub (crate) config: SocketConfig,
    peer_addr: SocketAddr,
    status: SocketStatus,
    last_recv_heartbeat: Instant,
    last_sent_heartbeat: Instant,

    events: Vec<SocketEvent>,
}

pub (crate) const MSG_TYPE_DATA_ID: u8 = 0;
pub (crate) const MSG_TYPE_STATUS_ID: u8 = 1;
pub (crate) const MSG_TYPE_HEARTBEAT_ID: u8 = 2;
pub (crate) const MSG_TYPE_DATA_HEAD_LEN: usize = 8;
pub (crate) const MSG_TYPE_STATUS_HEAD_LEN: usize = 4;

impl Socket {
    pub const TIMEOUT_DURATION_DEFAULT_MS: u64 = 5000;
    pub const TIMEOUT_DURATION_DEFAULT: Duration = Duration::from_millis(Self::TIMEOUT_DURATION_DEFAULT_MS);

    pub (crate) fn prepare_tcp_stream(tcp_stream: &TcpStream) {
        let _r = tcp_stream.set_nodelay(true);
        let _r = tcp_stream.set_nonblocking(true);
        let _r = tcp_stream.set_read_timeout(Some(Self::TIMEOUT_DURATION_DEFAULT));
        let _r = tcp_stream.set_write_timeout(Some(Self::TIMEOUT_DURATION_DEFAULT));
    }

    pub fn new_from_tcp_stream(tcp_stream: TcpStream) -> Self {
        Self::prepare_tcp_stream(&tcp_stream);
        let peer_addr = tcp_stream.peer_addr().unwrap();
        let lock = OnceLock::new();
        let _r = lock.set(tcp_stream);
        let tcp_stream = Arc::new(UnsafeCell::new(lock));
        let now = Instant::now();
        Self {
            peer_addr,
            tcp_stream,
            out_seq_id: 0,
            last_ok_seq_id: None,
            ping_tracker: PingTracker::new(),
            config: SocketConfig::new(),
            ingester: Ingester::new(),
            last_recv_heartbeat: now,
            last_sent_heartbeat: now,
            status: SocketStatus::Connected,
            events: Vec::new(),
        }
    }

    /// Create a connection connecting the remote.
    /// 
    /// Unlike `TcpStream`, this wil lreturn immediatly, you must listen to SocketEvent to know whether or not
    /// this socket is connected.
    pub fn new_blocking<A: ToSocketAddrs>(remote_addr: A) -> Result<Self, Error> {
        let remote_addr = remote_addr.to_socket_addrs()
            .map_err(|e| Error::from_cause(format!("unable to get socket addr"), e))?
            .next()
            .ok_or_else(|| Error::new(format!("unable to get socket addr")))?;
        let tcp_stream = TcpStream::connect_timeout(&remote_addr, Self::TIMEOUT_DURATION_DEFAULT)
            .map_err(|e| Error::from_cause(format!("unable to connect to {}", remote_addr), e))?;
        Ok(Self::new_from_tcp_stream(tcp_stream))
    }

    pub fn raw(&self) -> Option<&TcpStream> {
        let ptr = self.tcp_stream.get();
        if let Some(tcp_stream) = unsafe { (*ptr).get() } {
            Some(&tcp_stream)
        } else {
            None
        }
    }

    /// borrow checker purposes
    fn stream_raw_mut(lock: &mut Arc<UnsafeCell<OnceLock<TcpStream>>>) -> Option<&mut TcpStream> {
        let ptr = lock.get();
        // safety: this is safe as long as we never `take` the value from the lock
        if let Some(tcp_stream) = unsafe { (*ptr).get_mut() } {
            Some(unsafe { &mut *(tcp_stream as *mut TcpStream) })
        } else {
            None
        }
    }

    pub fn raw_mut(&mut self) -> Option<&mut TcpStream> {
        Self::stream_raw_mut(&mut self.tcp_stream)
    }

    /// Receives a single call of tcp socket read and stores it in the ingester
    fn recv_single(&mut self) -> Result<(), IoError> {
        let mut buf = [0; 2048];
        let Some(tcp_stream) = self.raw_mut() else {
            return Ok(())
        };
        let size = tcp_stream.read(&mut buf)?;
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

    fn internal_send_data(&mut self, seq_id: u32, bytes: &[u8]) -> Result<(), Error> {
        let Some(tcp_stream) = self.raw_mut() else {
            return Err(Error::new(format!("not connected yet")))
        };
        let mut out_bytes = vec![0u8; 9 + bytes.len()];
        out_bytes[0] = MSG_TYPE_DATA_ID;
        BigEndian::write_u32(&mut out_bytes[1..5], seq_id);
        BigEndian::write_u32(&mut out_bytes[5..9], bytes.len() as u32);
        out_bytes[9..].copy_from_slice(bytes);
        tcp_stream.write(&out_bytes)
            .map_err(|e| Error::from_cause(format!("tcp write err"), e))?;
        self.ping_tracker.ping(seq_id);
        Ok(())
    }

    fn set_status(&mut self, new_status: SocketStatus) {
        if !new_status.is_connected() {
            if let SocketStatus::Error(err) = &new_status {
                log::error!("conn with peer {} error: {}", self.peer_addr, err)
            } else {
                log::info!("disconnected from {}: {:?}", self.peer_addr, new_status);
            }
        }
        if new_status.is_connected() || self.status.is_connected() {
            // if either the new or old status is connected, update the events. Otherwise do nothing.
            // this prevents Timeout from being overwritten by RemoteEnded, or LocalEnded overwritten by RemoteEnded...
            self.events.push(SocketEvent::Status(new_status.clone()));
            self.status = new_status;
        }
    }

    pub (crate) fn insert_event(&mut self, socket_event: SocketEvent) {
        self.events.push(socket_event);
    }

    pub (crate) fn has_events(&self) -> bool {
        !self.events.is_empty()
    }

    fn process_ingester_results(&mut self, now: Instant) {
        for ingester_result in self.ingester.results.drain(..) {
            match ingester_result {
                IngesterResult::Data(seq_id, data) => {
                    self.events.push(SocketEvent::Data(data.into_boxed_slice()));
                    if let Some(tcp_stream) = Self::stream_raw_mut(&mut self.tcp_stream) {
                        Self::stream_send_status(tcp_stream, seq_id);
                    }
                },
                IngesterResult::Heartbeat => {
                    self.last_recv_heartbeat = now;
                },
                IngesterResult::Error(err_msg) => {
                    let new_status = SocketStatus::Error(Error::new(err_msg));
                    self.events.push(SocketEvent::Status(new_status.clone()));
                    self.status = new_status;
                },
                IngesterResult::SeqIdOk(seq_id) => {
                    self.ping_tracker.pong(seq_id);
                }
            }
        }
    }

    fn maybe_send_heartbeat(&mut self, now: Instant) {
        if !self.status.is_connected() {
            return;
        }
        const HEARTBEAT_INTERVAL: Duration = Duration::from_millis(1000);
        let sent_diff = now.saturating_duration_since(self.last_sent_heartbeat);
        if sent_diff >= HEARTBEAT_INTERVAL {
            if let Some(tcp_stream) = Self::stream_raw_mut(&mut self.tcp_stream) {
                let _r = tcp_stream.write(&[MSG_TYPE_HEARTBEAT_ID]);
            }
            self.last_sent_heartbeat = now;
        }
    }

    pub fn process(&mut self) {
        let r = self.recv_all();
        let now = Instant::now();
        self.process_ingester_results(now);
        let heartbeat_diff = now.saturating_duration_since(self.last_recv_heartbeat);
        if heartbeat_diff >= Duration::from_millis(self.config.timeout_ms) {
            self.set_status(SocketStatus::Timeout);
        }
        self.maybe_send_heartbeat(now);
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
                        self.set_status(SocketStatus::Error(
                            Error::from_cause(format!("ingester unexpected IO"), io_error)
                        ))
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
        if let Some(tcp_stream) = self.raw_mut() {
            let _r = tcp_stream.shutdown(std::net::Shutdown::Write);
        }
        self.set_status(SocketStatus::LocalEnded);
    }

    pub fn send_data<B>(&mut self, bytes: B) -> Result<SeqId, Error> where B: AsRef<[u8]> {
        let seq_id = self.out_seq_id;
        self.out_seq_id = self.out_seq_id.wrapping_add(1);
        self.internal_send_data(seq_id, bytes.as_ref())?;
        Ok(seq_id)
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