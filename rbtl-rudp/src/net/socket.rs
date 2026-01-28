use std::{
    marker::PhantomData,
    net::{SocketAddr, UdpSocket, ToSocketAddrs},
    io::{Error as IoError, ErrorKind as IoErrorKind, Result as IoResult},
    sync::Arc,
    collections::VecDeque,
    time::{Duration, Instant},
};

use x25519_dalek::{PublicKey, EphemeralSecret, SharedSecret};

use crate::{
    PacketSendOptions, SocketIdentity,
    net::{
        common::{PacketSendError, SocketConfig, SeqId},
        inner::{SocketInner, SocketStatus},
        ping_tracker::PingTracker,
        protocol::{
            fragment::{ack::Ack, frag_assembly::FragmentAssembler},
            packet::{Packet, PacketVariant, UdpBytes},
        },
        sent_data_tracker::SentDataTracker
    },
    utils::{BoxedSlice, OwnedSlice}
};

pub trait SocketKind {}

#[derive(Debug)]
pub enum SocketKindUnique {}
#[derive(Debug)]
pub enum SocketKindShared {}

impl SocketKind for SocketKindUnique {}
impl SocketKind for SocketKindShared {}

// Used for client sockets.
pub type Socket = SocketCommon<SocketKindUnique>;
/// Used for server sockets for each client link.
pub type SocketShared = SocketCommon<SocketKindShared>;

/// Represents an event of the Socket.
///
/// They fall in mostly 2 categories: meta events, and data events.
pub enum SocketEvent {
    /// Data sent by the remote, re-assembled in order
    Data(Box<[u8]>),
    /// Represents when the handshake with the other side was done successfully
    Connected,
    /// Connection was aborted unexpectedly by the other end (not the same as Timeout or Ended)
    Aborted,
    /// Connection was ended peacefully by the other end
    Ended,
    /// We haven't got any packet coming from the other for a certain amount of time
    Timeout,
    /// A raw udp packet that the socket failed to parse, not decoded by anything else
    Raw(Box<[u8]>),
}

impl std::fmt::Debug for SocketEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            SocketEvent::Data(d) => write!(f, "Data({:?} bytes)", d.len()),
            SocketEvent::Connected => write!(f, "Connected"),
            SocketEvent::Aborted => write!(f, "Aborted"),
            SocketEvent::Ended => write!(f, "Ended"),
            SocketEvent::Timeout => write!(f, "Timeout"),
            SocketEvent::Raw(d) => write!(f, "Raw({:?} bytes)", d.len()),
        }
    }
}

/// A Client Socket
///
/// Represents a connection between you and the remote. You
/// can send messages, receive messages and poll it for various events.
///
/// Once dropped, the socket will send a "terminate" message to the remote before shutting down.
///
/// This is the common implementation, you will mostly use `Socket` or `SocketShared`.
#[derive(Debug)]
pub struct SocketCommon<K: SocketKind> {
    pub (crate) local_addr: SocketAddr,
    pub (crate) socket: SocketInner,

    pub (crate) fragment_assembler: FragmentAssembler<BoxedSlice<u8>>,
    pub (crate) sent_data_tracker: SentDataTracker<Arc<[u8]>>,
    pub (crate) ping_handler: PingTracker,

    /// events of this remote. Messages not from this remote are in `unknown_messages`
    pub (crate) events: VecDeque<SocketEvent>,

    pub (self) next_local_seq_id: SeqId,

    /// store a "now()" to avoid calling the system super often using `std::time::Instant::now()`
    pub (self) cached_now: Instant,
    pub (self) last_received_message: Instant,

    pub (crate) config: SocketConfig,

    // unused when in server mode
    pub (crate) unknown_messages: VecDeque<(SocketAddr, Box<[u8]>)>,

    _phantom: PhantomData<K>,
}

#[derive(Debug)]
pub (crate) enum SocketCreateError {
    IoError(IoError),
    /// data that is understood by this crate, but wasn't epxected at this time
    NotSyn,
}

impl From<IoError> for SocketCreateError {
    fn from(io_error: IoError) -> SocketCreateError {
        SocketCreateError::IoError(io_error)
    }
}


impl<K: SocketKind> SocketCommon<K> {

    #[inline]
    /// Drains socket events for this Socket.
    ///
    /// This is one of the 2 ways to loop over all incoming events. See the examples
    /// for how to use it.
    pub fn drain_events<'a>(&'a mut self) -> impl Iterator<Item=SocketEvent> + 'a {
        self.events.drain(..)
    }

    /// Drain raw messages from unknown remotes
    pub fn drain_unknown<'a>(&'a mut self) -> impl Iterator<Item=(SocketAddr, Box<[u8]>)> + use<'a, K> {
        self.unknown_messages.drain(..)
    }

    #[inline]
    /// Gets the next socket event for this socket.
    pub fn next_event(&mut self) -> Option<SocketEvent> {
        self.events.pop_front()
    }

    #[inline]
    pub (self) fn set_status(&mut self, status: SocketStatus) {
        log::debug!("socket {}: new status {:?}", self.remote_addr(), status);
        self.socket.status = status;
        if let Some(event) = status.event() {
            // We should notify this event
            self.events.push_back(event);
        }
    }

    /// Gets the underlying raw UDP socket
    pub fn raw(&self) -> &UdpSocket {
        &self.socket.udp_socket
    }

    /// Returns whether or not the seq_id has been received by the remote.
    ///
    /// Ok(true) = has been received
    /// Ok(false) = has not been received yet
    /// Err(()) = invalid u32 OR message was sent a long time ago
    pub fn is_seq_id_received(&self, seq_id: SeqId) -> Result<bool, ()> {
        self.sent_data_tracker.is_seq_id_received(seq_id)
    }
    
    #[inline]
    /// Send data to the remote.
    ///
    /// Returns the sequence_id of the message sent. This may be useful to track whether or not the message has been received.
    pub fn send_data<I: Into<Arc<[u8]>> + AsRef<[u8]>>(&mut self, data: I, send_options: PacketSendOptions) -> Result<u32, PacketSendError> {
        if send_options.key {
            self.ping_handler.ping(self.next_local_seq_id);
        }
        let seq_id = self.next_local_seq_id;
        self.next_local_seq_id += 1;
        match self.sent_data_tracker.send_data(seq_id, data, self.cached_now, send_options, &mut self.socket) {
            Ok(()) => Ok(seq_id),
            Err(e) => Err(e)
        }
    }

    /// Send a "end" message, meaning this socket has ended peacefully
    pub fn end(&mut self) -> IoResult<()> {
        self.socket.send_end(self.next_local_seq_id.saturating_sub(1), self.cached_now)?;
        self.set_status(SocketStatus::TerminateSent(self.cached_now));
        Ok(())
    }

    /// Send a "abort" message, meaning this socket has ended abruptly
    ///
    /// This is automatically called on Drop
    pub fn abort(&mut self) -> IoResult<()> {
        self.socket.send_abort(self.next_local_seq_id.saturating_sub(1), self.cached_now)?;
        self.set_status(SocketStatus::TerminateSent(self.cached_now));
        Ok(())
    }

    pub (crate) fn add_packet(&mut self, packet: Packet<OwnedSlice<u8, Box<[u8]>>>) {
        self.last_received_message = self.cached_now;
        log::trace!("received packet {:?} from remote {}", packet, self.remote_identity());
        match packet.packet_variant {
            PacketVariant::Fragment(f) => {
                log::trace!("received fragment {:?}", f);
                self.fragment_assembler.push(f, self.cached_now, self.socket.secret.shared());
                if let Some((_seq_id, data)) = self.fragment_assembler.next_out_message() {
                    self.events.push_back(SocketEvent::Data(data));
                }
            },
            PacketVariant::Ack { seq_id, slice } => {
                log::trace!("received ack({}) {:?}", seq_id, slice);
                self.ping_handler.pong(seq_id);
                self.sent_data_tracker.receive_ack(seq_id, slice, self.cached_now);
            },
            PacketVariant::Heartbeat => {
                log::trace!("received heartbeat");
                // heartbeat is only meant for us to update hte "last received message", which we already have done
            },
            PacketVariant::Syn { .. } => {
                log::trace!("received a syn message while already connected {}, resending a synack", self.remote_addr());
                let _r = self.socket.send_synack(self.cached_now);
                /* do nothing for special now, but we may want to handle "syn" later to
                have a 'reconnect' feature or something? */
            },
            PacketVariant::SynAck { pub_key } => {
                if let SocketStatus::SynSent(_) = self.socket.status {
                    log::info!("connected to remote {}, ids: (ours) {} <-> {} (theirs)",
                        self.remote_addr(), self.self_identity(), self.remote_identity()
                    );
                    self.socket.other_pub_key = PublicKey::from(pub_key);
                    self.socket.secret.apply(&self.socket.other_pub_key);
                    self.set_status(SocketStatus::Connected);
                } else {
                    log::warn!("received synack while the status isn't synsent for {}", self.remote_identity());
                    /* received synack when the status isn't even SynSent? Mmmh... */
                }
            },
            PacketVariant::End { last_seq_id } => {
                log::trace!("received End({})", last_seq_id);
                self.set_status(SocketStatus::TerminateReceived(self.cached_now));
                self.events.push_back(SocketEvent::Ended);
            },
            PacketVariant::Abort { last_seq_id } => {
                log::trace!("received Abort({})", last_seq_id);
                self.set_status(SocketStatus::TerminateReceived(self.cached_now));
                self.events.push_back(SocketEvent::Aborted);
            }
        }
    }

    /// Get the next socket event from the queue.
    ///
    /// Call `process` before this to ensure events are correctly processed
    pub fn next_socket_event(&mut self) -> Option<SocketEvent> {
        self.events.pop_front()
    }

    /// Returns the ping to the remote as ms
    ///
    /// Returns None if the ping has not been computed yet
    ///
    /// If seconds is zero or negative, it will simply retrun the latest ping if there is one
    pub fn avg_ping(&self, seconds: f32) -> Option<f32> {
        self.ping_handler.avg_ping(seconds)
    }

    /// Returns the last ping available, and when it was received in time.
    pub fn last_ping_info(&self) -> Option<(u32, Instant)> {
        self.ping_handler.last_ping_info()
    }

    /// Simply update the internal "now" to "Instant::now()"
    pub (crate) fn update_cached_now(&mut self) {
        self.cached_now = Instant::now();
    }

    pub (crate) fn inner_tick(&mut self) -> IoResult<()> {
        let acks_to_send = self.fragment_assembler.tick(self.cached_now);
        let last_received_ago: Duration = self.cached_now.saturating_duration_since(self.last_received_message);
        if last_received_ago >= self.config.timeout_delay && !self.socket.status.is_finished() {
            log::warn!("socket {} timed out: last_received_message was {:.01}s ago",
                self.remote_addr(), last_received_ago.as_secs_f32());
            self.set_status(SocketStatus::TimeoutError { error_since: self.cached_now, duration: last_received_ago });
        }
        for (seq_id, ack) in acks_to_send {
            self.socket.send_ack(seq_id, ack, self.cached_now)?;
        }
        if self.status().is_connected() {
            if self.cached_now - self.socket.last_sent_message > self.config.heartbeat_delay {
                self.socket.send_heartbeat(self.cached_now)?;
            }
        } else { 
            if let SocketStatus::SynSent(last_sent) = self.status() {
                // we're attempting to connect..
                // but if we haven't received an answer for 3 seconds, the message might have been missed and we'll resend it.
                if self.cached_now > last_sent + Duration::from_secs(3) {
                    // every 3 seconds (we incremented tick once before this call so 0 is out)
                    // resend a "syn" to attempt to connect.
                    self.socket.send_syn(self.cached_now)?;
                    self.set_status(SocketStatus::SynSent(self.cached_now))
                }
            }
        }
        self.sent_data_tracker.next_tick(self.cached_now, &mut self.socket);
        Ok(())
    }

    /// Terminates and consumes the socket, by sending a "Ended" event to the remote.
    pub fn terminate(mut self) -> IoResult<()> {
        self.end()
    }

    #[inline]
    pub fn status(&self) -> SocketStatus {
        self.socket.status
    }

    pub fn remote_identity(&self) -> SocketIdentity {
        let p = self.socket.other_pub_key.to_bytes();
        SocketIdentity {
            public_key: [p[0], p[1], p[2], p[3]]
        }
    }

    pub fn self_identity(&self) -> SocketIdentity {
        let p = self.socket.self_pub_key.to_bytes();
        SocketIdentity {
            public_key: [p[0], p[1], p[2], p[3]]
        }
    }

    /// Returns whether or not you should clear this socket.
    pub (crate) fn should_clear(&self) -> bool {
        self.socket.status.is_finished_and_old(self.cached_now)
    }

    #[inline]
    /// Returns the local addr this socket uses to receive messages.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Returns the remote addr messages will be sent do
    pub fn remote_addr(&self) -> SocketAddr {
        self.socket.remote_addr
    }
}

impl SocketCommon<SocketKindShared> {
    pub (crate) fn new_incoming(udp_socket: Arc<UdpSocket>, incoming_packet: Packet<OwnedSlice<u8, Box<[u8]>>>, incoming_address: SocketAddr) -> Result<SocketShared, SocketCreateError> {
        let PacketVariant::Syn { pub_key: their_pub_key } = incoming_packet.packet_variant else {
            /* understood the message, but it was not a syn packet */
            return Err(SocketCreateError::NotSyn);
        };
        let local_addr = udp_socket.local_addr()?;
        let now = Instant::now();
        let mut socket = SocketCommon {
            socket: SocketInner::new_connected(udp_socket, incoming_address, their_pub_key),
            local_addr,
            fragment_assembler: FragmentAssembler::new(),
            sent_data_tracker: SentDataTracker::new(),
            events: Default::default(),
            next_local_seq_id: 0,
            ping_handler: PingTracker::new(),
            cached_now: now,
            last_received_message: now,

            _phantom: PhantomData,
            config: SocketConfig::new(),
            unknown_messages: Default::default(),
        };
        socket.socket.send_synack(now)?;
        socket.set_status(SocketStatus::Connected);
        log::info!("received incoming connection from {}, ids (ours) {} <-> {} (theirs)",
            socket.remote_addr(), socket.self_identity(), socket.remote_identity()
        );

        Ok(socket)
    }
}

impl SocketCommon<SocketKindUnique> {
    /// See `connect`, but provide the UDP socket instead of creating it
    pub fn connect_with_socket<A: ToSocketAddrs>(udp_socket: UdpSocket, remote_addr: A) -> IoResult<Socket> {
        let remote_addr = remote_addr.to_socket_addrs()?.next().unwrap();

        let udp_socket = Arc::new(udp_socket);
        crate::os::prepare_socket(&udp_socket);
        udp_socket.set_nonblocking(true)?;
        let local_addr = udp_socket.local_addr()?;

        let now = Instant::now();

        let mut socket = SocketCommon {
            socket: SocketInner::new_connecting(udp_socket, remote_addr),
            local_addr,
            sent_data_tracker: SentDataTracker::new(),
            fragment_assembler: FragmentAssembler::new(),
            events: Default::default(),
            ping_handler: PingTracker::new(),
            next_local_seq_id: 0,
            cached_now: now,
            last_received_message: now,

            config: SocketConfig::new(),
            _phantom: PhantomData,
            unknown_messages: Default::default(),
        };
        log::info!("trying to connect to remote {} with our identity {}...", socket.remote_addr(), socket.self_identity());
        socket.socket.send_syn(now)?;

        Ok(socket)
    }

    /// Creates a Socket and connects to the remote instantly.
    ///
    /// This will fail ONLY if there is something wrong with the network,
    /// preventing it to create a UDP Socket. This is NOT blocking,
    /// so any timeout event or things or the like will arrive as `SocketEvent`s.
    ///
    /// The socket will be created with the status SynSent, after which there will be 2 outcomes:
    ///
    /// * The remote answered SynAck, and we set the status as "Connected"
    /// * The remote did not answer, and we will get a timeout
    // If you want to accept a new connection, use `new_incoming` instead.
    pub fn connect<A: ToSocketAddrs>(remote_addr: A) -> IoResult<Socket> {
        Self::connect_with_socket(UdpSocket::bind("0.0.0.0:0")?, remote_addr)
    }

    /// Internal processing for this single source
    ///
    /// Must be done before draining events. Even if there are no events,
    /// you will want to re-send acks, keep track of sent data, etc. `next_tick` does that for you.
    pub fn process(&mut self) -> IoResult<()> {
        self.update_cached_now();
        let mut done = false;

        // receive incoming packets and put them in a queue for processing
        while !done {
            match UdpBytes::<Box<[u8]>>::from_udp_socket(&self.socket.udp_socket) {
                Ok((packet, remote_addr)) => {
                    if remote_addr == self.socket.remote_addr {
                        self.add_received_bytes(packet);
                    } else if self.config.transfer_unknown_raw {
                        /* received packet from unknown source */
                        self.unknown_messages.push_back((remote_addr, packet.buffer));
                    }
                },
                Err(err) => {
                    match err.kind() {
                        IoErrorKind::WouldBlock => { done = true },
                        err_kind => {
                            log::error!("SingleSocket: Received other unexpected net error {:?}", err_kind)
                        }
                    }
                },
            };
        };
        // process everything we have received
        self.inner_tick()?;
        Ok(())
    }

    pub (crate) fn add_received_bytes(&mut self, udp_bytes: UdpBytes<Box<[u8]>>) {
        match udp_bytes.compute_packet() {
            Ok(packet) => self.add_packet(packet),
            Err((_e, data)) => {
                if self.config.transfer_raw {
                    // errors are not ignored, but simply transferred as raw packets to the user
                    self.events.push_back(SocketEvent::Raw(data.buffer));
                }
            }
        };
    }
}

impl<K: SocketKind> Drop for SocketCommon<K> {
    fn drop(&mut self) {
        match self.socket.status {
            SocketStatus::Connected | SocketStatus::SynSent(_) | SocketStatus::SynReceived => {
                // TODO: At least log the error
                let _r = self.abort();
            },
            _ => {},
        }
    }
}