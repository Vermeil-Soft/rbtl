use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket}, sync::Arc, vec::IntoIter
};

use crate::{
    Listener, SocketEvent, Socket, SocketCommon, SocketStatus, SocketShared, SocketIdentity, Error,
    net::{
        socket::SocketKind,
        connect_info::ConnectInfo,
        common::{PacketSendError, PacketSendOptions, SocketConfig, ListenerConfig, SeqId},
    }
};

use rbtl_core::{Client, Event, ServClient, Server, Status};

fn status_common<T: SocketKind>(s: &SocketCommon<T>) -> Status {
    match s.status() {
        SocketStatus::Connected => Status::Ok,
        SocketStatus::SynReceived => Status::Connecting,
        SocketStatus::SynSent(_) => Status::Connecting,
        SocketStatus::TerminateReceived(_) => Status::Ended { by_remote: true },
        SocketStatus::TerminateSent(_) => Status::Ended { by_remote: false },
        SocketStatus::TimeoutError { .. } => Status::Timeout,
    }
}

fn map_event(socket_event: SocketEvent) -> Option<Event> {
    match socket_event {
        SocketEvent::Data(b) => Some(Event::Data(b)),
        SocketEvent::Aborted => Some(Event::StatusChanged(Status::Ended { by_remote: true })),
        SocketEvent::Timeout => Some(Event::StatusChanged(Status::Timeout)),
        SocketEvent::Connected => Some(Event::StatusChanged(Status::Ok)),
        SocketEvent::Ended => Some(Event::StatusChanged(Status::Ended { by_remote: true })),
        SocketEvent::Raw(_) => None,
    }
}

impl Client for Socket {
    type Server = Listener;
    type ClientConfig = SocketConfig;
    type ConnectOptions = SocketConfig;
    type StateError = Error;
    type SendError = PacketSendError;
    type Init = (Option<SocketAddr>, Option<UdpSocket>);
    type SendOptions = PacketSendOptions;

    fn status(&self) -> Status {
        status_common(self)
    }

    fn get_config(&self) -> Self::ClientConfig {
        self.config
    }

    fn set_config(&mut self, config: Self::ClientConfig) {
        self.config = config;
    }

    /// Drain events aside from the "raw" ones.
    fn drain_events<'a>(&'a mut self) -> impl Iterator<Item=Event> + 'a {
        self.drain_events().filter_map(map_event)
    }

    fn new<I: Into<Self::Init>>(init: I, options: SocketConfig) -> Result<Self, Self::StateError> where Self: Sized {

        let (socket_addr, udp_socket) = init.into();
        let socket_addr = socket_addr.unwrap_or(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0));
        if let Some(socket) = udp_socket {
            Socket::connect_with_socket(socket, socket_addr, options)
        } else {
            Socket::connect(socket_addr, options)
        }
    }

    fn from_connect_info(connect_info: ConnectInfo, options: Self::ConnectOptions) ->
        Result<Self, Self::StateError> where Self: Sized {
        Socket::connect(connect_info.addr, options)
    }

    fn process(&mut self) {
        let _r = self.process();
    }

    fn ping(&self, seconds: f32) -> Option<f32> {
        self.avg_ping(seconds)
    }

    fn is_msg_received(&self, msg_id: &u32) -> Result<bool, ()> {
        self.is_seq_id_received(*msg_id)
    }

    fn send<B>(&mut self, bytes: B, send_opts: Self::SendOptions) -> Result<u32, Self::SendError>
            where B: Into<Arc<[u8]>> + AsRef<[u8]> + Clone {
        self.send_data(bytes, send_opts)
    }

    fn end(&mut self) {
        let _r = self.send_end();
    }
}

impl ServClient for SocketShared {
    type Server = Listener;

    fn send<B: Into<Arc<[u8]>> + AsRef<[u8]> + Clone>(&mut self, bytes: B, send_opts: <Self::Server as Server>::SendOptions)
            -> Result<<Self::Server as Server>::MessageId, <Self::Server as Server>::SendError> {
        self.send_data(bytes, send_opts)
    }

    fn is_msg_received(&self, msg_id: &u32) -> Result<bool, ()> {
        self.is_seq_id_received(*msg_id)
    }

    fn ping(&self, seconds: f32) -> Option<f32> {
        self.avg_ping(seconds)
    }

    fn status(&self) -> Status {
        status_common(self)
    }
}

impl Server for Listener {
    const RBTL_PROTOCOL_ID: u8 = 1;
    const RBTL_PROTOCOL_NAME: &str = "rudp";

    type ServClient = SocketShared;
    type ConnectingClient = Socket;
    type Init = SocketAddr;
    type Key = SocketIdentity;
    type SendOptions = PacketSendOptions;
    type SendError = PacketSendError;
    type MessageId = u32;
    type ConnectInfo = ConnectInfo;
    type ServerConfig = (SocketConfig, ListenerConfig);
    type StateError = Error;

    fn drain_events<'a>(&'a mut self) -> impl Iterator<Item=(Self::Key, Event)> + 'a {
        self.drain_events()
            .filter_map(|(id, ev)| map_event(ev).map(|ev| (id, ev)))
    }

    fn get(&self, k: &Self::Key) -> Option<&Self::ServClient> {
        self.get(*k)
    }

    fn get_mut(&mut self, k: &Self::Key) -> Option<&mut Self::ServClient> {
        self.get_mut(*k)
    }

    fn get_config(&self) -> Self::ServerConfig {
        (self.socket_config, self.listener_config)
    }

    fn set_config(&mut self, (socket_config, listener_config): Self::ServerConfig) {
        self.listener_config = listener_config;
        self.socket_config = socket_config;
        self.update_config_for_remotes();
    }

    fn iter(&self) -> impl Iterator<Item=(&Self::Key, &Self::ServClient)> {
        self.iter()
    }

    fn iter_mut(&mut self) -> impl Iterator<Item=(&Self::Key, &mut Self::ServClient)> {
        self.iter_mut()
    }

    fn connected_len(&self) -> usize {
        self.connected_remotes_len()
    }

    fn len(&self) -> usize {
        self.remotes_len()
    }

    fn connect_info(&self) -> Result<Self::ConnectInfo, ()> {
        let mut local_addr = self.udp_socket.local_addr().map_err(|_| ())?;
        if local_addr.is_ipv4() {
            local_addr.set_ip(IpAddr::V4(Ipv4Addr::LOCALHOST))
        } else {
            local_addr.set_ip(IpAddr::V6(Ipv6Addr::LOCALHOST))
        }
        Ok(ConnectInfo { addr: local_addr })
    }

    fn new<I: Into<Self::Init>>(local_addr: I) -> Result<Self, Self::StateError> where Self: Sized {
        let local_addr = local_addr.into();
        Self::new(local_addr)
    }

    fn new_defaults() -> Result<Self, Self::StateError> where Self: Sized {
        Self::new("0.0.0.0:0")
    }

    fn new_with<I: Into<Self::Init>>(local_addr: I, config: Self::ServerConfig) -> Result<Self, Self::StateError> where Self: Sized {
        let local_addr = local_addr.into();
        Self::new_with(local_addr, config)
    }

    fn process(&mut self) {
        let _r = self.process();
    }

    fn end(&mut self) {
        self.send_end();
    }

    fn send_all<B>(&mut self, bytes: B, send_opts: Self::SendOptions) -> Result<(), Self::SendError>
            where B: Into<Arc<[u8]>> + AsRef<[u8]> + Clone {
        self.send_data(bytes, send_opts)
    }
}