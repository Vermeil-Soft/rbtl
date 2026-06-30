use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs}, sync::Arc, vec::IntoIter
};

use crate::{
    Listener, Socket, SocketEvent, SocketStatus, ConnectInfo, Error,
    listener::ListenerConfig, socket::SocketConfig
};

use rbtl_core::{Client, Event, ServClient, Server, Status};

fn convert_status(socket_status: SocketStatus) -> Status {
    match socket_status {
        SocketStatus::Connecting => Status::Connecting,
        SocketStatus::Connected => Status::Ok,
        SocketStatus::RemoteEnded => Status::Ended { by_remote: true },
        SocketStatus::LocalEnded => Status::Ended { by_remote: false },
        SocketStatus::Error(e) => Status::Error(Arc::new(e)),
        SocketStatus::Timeout => Status::Timeout,
    }
}

fn map_event(socket_event: SocketEvent) -> Option<Event> {
    match socket_event {
        SocketEvent::Data(b) => Some(Event::Data(b)),
        SocketEvent::Status(s) => Some(Event::StatusChanged(convert_status(s))),
    }
}

pub enum SocketInit {
    Addr(Box<dyn ToSocketAddrs<Iter = IntoIter<SocketAddr>>>),
    Stream(TcpStream)
}

impl From<&'static str> for SocketInit {
    fn from(value: &'static str) -> Self {
        SocketInit::Addr(Box::new(value))
    }
}

impl From<TcpStream> for SocketInit {
    fn from(value: TcpStream) -> Self {
        SocketInit::Stream(value)
    }
}

impl Client for Socket {
    type Server = Listener;
    type ClientConfig = SocketConfig;
    type StateError = Error;
    type ConnectOptions = SocketConfig;
    type SendError = Error;
    type Init = SocketInit;
    type SendOptions = ();

    fn status(&self) -> Status {
        convert_status(self.status())
    }

    fn get_config(&self) -> Self::ClientConfig {
        self.config.clone()
    }

    fn set_config(&mut self, config: Self::ClientConfig) {
        self.config = config;
    }

    /// Drain events aside from the "raw" ones.
    fn drain_events<'a>(&'a mut self) -> impl Iterator<Item=Event> + 'a {
        self.drain_events().filter_map(map_event)
    }

    fn new<I: Into<Self::Init>>(init: I, options: SocketConfig) -> Result<Self, Self::StateError> where Self: Sized {
        match init.into() {
            SocketInit::Addr(addr) => Socket::new(&*addr, options),
            SocketInit::Stream(stream) => Ok(Socket::new_from_tcp_stream(stream, options)),
        }
    }

    fn from_connect_info(connect_info: ConnectInfo, options: Self::ConnectOptions) ->
        Result<Self, Self::StateError> where Self: Sized {
        Socket::new(connect_info.addr, options)
    }

    fn process(&mut self) {
        let _r = self.process();
    }

    fn ping(&self, seconds: f32) -> Option<f32> {
        self.avg_ping(seconds)
    }

    fn is_msg_received(&self, msg_id: &u32) -> Result<bool, ()> {
        Ok(self.is_seq_id_received(*msg_id))
    }

    fn send<B>(&mut self, bytes: B, _send_opts: Self::SendOptions) -> Result<u32, Self::SendError>
            where B: Into<Arc<[u8]>> + AsRef<[u8]> + Clone {
        self.send_data(bytes)
    }

    fn end(&mut self) {
        let _r = self.send_end();
    }
}

impl ServClient for Socket {
    type Server = Listener;

    fn send<B: Into<Arc<[u8]>> + AsRef<[u8]> + Clone>(&mut self, bytes: B, _send_opts: ()) 
            -> Result<<Self::Server as Server>::MessageId, <Self::Server as Server>::SendError> {
        self.send_data(bytes)
    }

    fn is_msg_received(&self, msg_id: &u32) -> Result<bool, ()> {
        Ok(self.is_seq_id_received(*msg_id))
    }

    fn ping(&self, seconds: f32) -> Option<f32> {
        self.avg_ping(seconds)
    }

    fn status(&self) -> Status {
        convert_status(self.status())
    }
}

impl Server for Listener {
    const RBTL_PROTOCOL_ID: u8 = 2;
    const RBTL_PROTOCOL_NAME: &str = "tcp";

    type ServClient = Socket;
    type Init = Box<dyn ToSocketAddrs<Iter = IntoIter<SocketAddr>>>;
    type Key = SocketAddr;
    type ConnectingClient = Socket;
    type SendOptions = ();
    type SendError = Error;
    type MessageId = u32;
    type ServerConfig = (SocketConfig, ListenerConfig);
    type ConnectInfo = ConnectInfo;
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
        (self.socket_config.clone(), self.listener_config.clone())
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
        let mut local_addr = self.tcp_listener.local_addr().map_err(|_| ())?;
        if local_addr.is_ipv4() {
            local_addr.set_ip(IpAddr::V4(Ipv4Addr::LOCALHOST))
        } else {
            local_addr.set_ip(IpAddr::V6(Ipv6Addr::LOCALHOST))
        }
        Ok(ConnectInfo {
            addr: local_addr
        })
    }

    fn new<I: Into<Self::Init>>(init: I) -> Result<Self, Self::StateError> where Self: Sized {
        let local_addr = init.into();
        Self::bind(&*local_addr)
    }

    fn new_with<I: Into<Self::Init>>(init: I, config: Self::ServerConfig) -> Result<Self, Self::StateError> where Self: Sized {
        let local_addr = init.into();
        Self::bind_with(&*local_addr, config)
    }

    fn new_defaults() -> Result<Self, Self::StateError> where Self: Sized {
        Self::bind("0.0.0.0:0")
    }

    fn process(&mut self) {
        let _r = self.process();
    }

    fn send_all<B>(&mut self, bytes: B, _send_opts: Self::SendOptions) -> Result<(), Self::SendError>
            where B: Into<Arc<[u8]>> + AsRef<[u8]> + Clone {
        Ok(self.send_data(bytes))
    }

    fn end(&mut self) {
        self.send_end();
    }
}