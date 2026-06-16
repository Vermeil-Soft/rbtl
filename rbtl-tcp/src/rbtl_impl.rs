use std::{
    net::{SocketAddr, ToSocketAddrs, TcpStream},
    sync::Arc,
    vec::IntoIter
};

use crate::{
    Listener, Socket, SocketEvent, SocketStatus, ConnectInfo, Error,
    listener::ListenerConfig, socket::SocketConfig
};

use rbtl_core::{Client, Event, ServClient, Server, Status};

fn convert_status(socket_status: SocketStatus) -> Status {
    match socket_status {
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
    type ClientConfig = ();
    type StateError = Error;
    type SendError = Error;
    type Init = SocketInit;
    type MessageId = u32;
    type SendOptions = ();

    fn status(&self) -> Status {
        convert_status(self.status())
    }

    fn get_config(&self) -> Self::ClientConfig {
        ()
    }

    fn set_config(&mut self, _config: Self::ClientConfig) {
    }

    /// Drain events aside from the "raw" ones.
    fn drain_events<'a>(&'a mut self) -> impl Iterator<Item=Event> + 'a {
        self.drain_events().filter_map(map_event)
    }

    fn new<I: Into<Self::Init>>(init: I) -> Result<Self, Self::StateError> where Self: Sized {
        match init.into() {
            SocketInit::Addr(addr) => Socket::new(&*addr),
            SocketInit::Stream(stream) => Ok(Socket::new_from_tcp_stream(stream)),
        }
    }

    fn process(&mut self) {
        let _r = self.process();
    }

    fn ping(&self, seconds: f32) -> Option<f32> {
        self.avg_ping(seconds)
    }

    fn send<B>(&mut self, bytes: B, _send_opts: Self::SendOptions) -> Result<Self::MessageId, Self::SendError>
            where B: Into<Arc<[u8]>> + AsRef<[u8]> + Clone {
        Ok(self.send_data(bytes))
    }
}

impl ServClient for Socket {
    type Server = Listener;

    fn send<B: Into<Arc<[u8]>> + AsRef<[u8]> + Clone>(&mut self, bytes: B, _send_opts: ()) 
            -> Result<<Self::Server as Server>::MessageId, <Self::Server as Server>::SendError> {
        Ok(self.send_data(bytes))
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

    fn len(&self) -> usize {
        self.remotes_len()
    }

    fn connect_info(&self) -> Result<Self::ConnectInfo, ()> {
        let local_addr = self.tcp_listener.local_addr().expect("unable to get local addr");
        Ok(ConnectInfo {
            addr: local_addr
        })
    }

    fn new_with<I: Into<Self::Init>>(init: I) -> Result<Self, Self::StateError> where Self: Sized {
        let local_addr = init.into();
        Self::bind(&*local_addr)
    }

    fn new() -> Result<Self, Self::StateError> where Self: Sized {
        Self::bind("0.0.0.0:0")
    }

    fn process(&mut self) {
        let _r = self.process();
    }

    fn send_all<B>(&mut self, bytes: B, _send_opts: Self::SendOptions) -> Result<(), Self::SendError>
            where B: Into<Arc<[u8]>> + AsRef<[u8]> + Clone {
        Ok(self.send_data(bytes))
    }
}