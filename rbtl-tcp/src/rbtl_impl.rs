use std::{
    net::{SocketAddr, ToSocketAddrs, TcpStream},
    sync::Arc,
    vec::IntoIter
};

use crate::{Listener, Socket, SocketEvent, SocketStatus, listener::ListenerConfig, socket::SocketConfig};

use rbtl_core::{Client, Event, SClient, Server, Status};

fn convert_status(socket_status: SocketStatus) -> Status {
    match socket_status {
        SocketStatus::Connected => Status::Ok,
        SocketStatus::RemoteEnded => Status::Ended { by_remote: true },
        SocketStatus::LocalEnded => Status::Ended { by_remote: false },
        SocketStatus::Error(_e) => Status::Error,
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
    type StateError = std::io::Error;
    type SendError = ();
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

    fn send<B>(&mut self, bytes: B, _send_opts: Self::SendOptions) -> Result<Self::MessageId, Self::SendError>
            where B: Into<Arc<[u8]>> + AsRef<[u8]> + Clone {
        Ok(self.send_data(bytes))
    }
}

impl SClient for Socket {
    type Server = Listener;

    fn send<B: Into<Arc<[u8]>> + AsRef<[u8]> + Clone>(&mut self, bytes: B, _send_opts: ()) 
            -> Result<<Self::Server as Server>::MessageId, <Self::Server as Server>::SendError> {
        Ok(self.send_data(bytes))
    }

    fn status(&self) -> Status {
        convert_status(self.status())
    }
}

impl Server for Listener {
    type Client = Socket;
    type Init = Box<dyn ToSocketAddrs<Iter = IntoIter<SocketAddr>>>;
    type Key = SocketAddr;
    type SendOptions = ();
    type SendError = ();
    type MessageId = u32;
    type ServerConfig = (SocketConfig, ListenerConfig);
    type StateError = std::io::Error;

    fn drain_events<'a>(&'a mut self) -> impl Iterator<Item=(Self::Key, Event)> + 'a {
        self.drain_events()
            .filter_map(|(id, ev)| map_event(ev).map(|ev| (id, ev)))
    }

    fn get(&self, k: &Self::Key) -> Option<&Self::Client> {
        self.get(*k)
    }

    fn get_mut(&mut self, k: &Self::Key) -> Option<&mut Self::Client> {
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

    fn iter(&self) -> impl Iterator<Item=(&Self::Key, &Self::Client)> {
        self.iter()
    }

    fn iter_mut(&mut self) -> impl Iterator<Item=(&Self::Key, &mut Self::Client)> {
        self.iter_mut()
    }

    fn new<I: Into<Self::Init>>(init: I) -> Result<Self, Self::StateError> where Self: Sized {
        let local_addr = init.into();
        Self::bind(&*local_addr)
    }

    fn process(&mut self) {
        let _r = self.process();
    }

    fn send_all<B>(&mut self, bytes: B, _send_opts: Self::SendOptions) -> Result<(), Self::SendError>
            where B: Into<Arc<[u8]>> + AsRef<[u8]> + Clone {
        Ok(self.send_data(bytes))
    }
}