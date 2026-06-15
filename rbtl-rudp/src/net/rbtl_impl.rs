use std::{
    net::{SocketAddr, ToSocketAddrs, UdpSocket},
    sync::Arc,
    vec::IntoIter
};

use crate::{
    Listener, SocketEvent, Socket, SocketCommon, SocketStatus, SocketShared, SocketIdentity,
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
    type ClientConfig = SocketConfig;
    type StateError = std::io::Error;
    type SendError = PacketSendError;
    type Init = (Box<dyn ToSocketAddrs<Iter = IntoIter<SocketAddr>>>, Option<UdpSocket>);
    type MessageId = u32;
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

    fn new<I: Into<Self::Init>>(init: I) -> Result<Self, Self::StateError> where Self: Sized {
        let (socket_addr, udp_socket) = init.into();
        let socket_addr = socket_addr.to_socket_addrs()?.next().unwrap();
        if let Some(socket) = udp_socket {
            Socket::connect_with_socket(socket, socket_addr)
        } else {
            Socket::connect(socket_addr)
        }
    }

    fn process(&mut self) {
        let _r = self.process();
    }

    fn ping(&self, seconds: f32) -> Option<f32> {
        self.avg_ping(seconds)
    }

    fn send<B>(&mut self, bytes: B, send_opts: Self::SendOptions) -> Result<Self::MessageId, Self::SendError>
            where B: Into<Arc<[u8]>> + AsRef<[u8]> + Clone {
        self.send_data(bytes, send_opts)
    }
}

impl ServClient for SocketShared {
    type Server = Listener;

    fn send<B: Into<Arc<[u8]>> + AsRef<[u8]> + Clone>(&mut self, bytes: B, send_opts: <Self::Server as Server>::SendOptions)
            -> Result<<Self::Server as Server>::MessageId, <Self::Server as Server>::SendError> {
        self.send_data(bytes, send_opts)
    }

    fn ping(&self, seconds: f32) -> Option<f32> {
        self.avg_ping(seconds)
    }

    fn status(&self) -> Status {
        status_common(self)
    }
}

impl Server for Listener {
    const RBTL_ID: u8 = 1;

    type ServClient = SocketShared;
    type ConnectingClient = Socket;
    type Init = Box<dyn ToSocketAddrs<Iter = IntoIter<SocketAddr>>>;
    type Key = SocketIdentity;
    type SendOptions = PacketSendOptions;
    type SendError = PacketSendError;
    type MessageId = u32;
    type ConnectInfo = ConnectInfo;
    type ServerConfig = (SocketConfig, ListenerConfig);
    type StateError = std::io::Error;

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

    fn len(&self) -> usize {
        self.remotes_len()
    }

    fn connect_info(&self) -> Result<Self::ConnectInfo, ()> {
        let local_addr = self.udp_socket.local_addr().expect("unable to get local addr");
        Ok(ConnectInfo {
            addr: local_addr
        })
    }

    fn new_with<I: Into<Self::Init>>(local_addr: I) -> Result<Self, Self::StateError> where Self: Sized {
        let local_addr = local_addr.into();
        Self::new(&*local_addr)
    }

    fn new() -> Result<Self, Self::StateError> where Self: Sized {
        Self::new("0.0.0.0:0")
    }

    fn process(&mut self) {
        let _r = self.process();
    }

    fn send_all<B>(&mut self, bytes: B, send_opts: Self::SendOptions) -> Result<(), Self::SendError>
            where B: Into<Arc<[u8]>> + AsRef<[u8]> + Clone {
        self.send_data(bytes, send_opts)
    }
}