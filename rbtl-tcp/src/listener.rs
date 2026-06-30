use std::{
    io::Error as IoError,
    net::{SocketAddr, TcpListener, ToSocketAddrs},
    ops::{Index, IndexMut}
};

use hashbrown::{HashMap};

use crate::{SeqId, Error, Socket, SocketStatus, socket::{SocketConfig, SocketEvent}};

#[derive(Default, Clone, Debug)]
pub struct ListenerConfig {
}

pub struct Listener {
    pub (crate) listener_config: ListenerConfig,
    pub (crate) socket_config: SocketConfig,
    pub (crate) tcp_listener: TcpListener,
    remotes: HashMap<SocketAddr, Socket>,
}

impl Listener {
    pub fn bind<A: ToSocketAddrs>(addr: A) -> Result<Self, Error> {
        Self::bind_with(addr, Default::default())
    }

    pub fn bind_with<A: ToSocketAddrs>(addr: A, config: (SocketConfig, ListenerConfig)) -> Result<Self, Error> {
        let remote_addr = addr.to_socket_addrs()
            .map_err(|e| Error::from_cause(format!("no target addr found"), e))?
            .next()
            .ok_or_else(|| Error::new(format!("no target addr found")))?;
        let tcp_listener = TcpListener::bind(remote_addr)
            .map_err(|e| Error::from_cause(format!("could not bind {}", remote_addr), e))?;
        let _r = tcp_listener.set_nonblocking(true);
        Ok(Listener {
            tcp_listener,
            listener_config: config.1,
            socket_config: config.0,
            remotes: HashMap::default()
        })
    }

    pub fn remotes_len(&self) -> usize {
        self.remotes.len()
    }

    pub fn connected_remotes_len(&self) -> usize {
        self.remotes.iter().filter(|r| r.1.status().is_connected()).count()
    }

    pub (crate) fn update_config_for_remotes(&mut self) {
        for socket in self.remotes.values_mut() {
            socket.config.clone_from(&self.socket_config);
        }
    }

    /// Send some data to a single remote
    pub fn send_data_to<I: AsRef<[u8]>>(&mut self, data: I, identity: SocketAddr) -> Result<SeqId, Error> {
        match self.remotes.get_mut(&identity) {
            Some(s) => s.send_data(data.as_ref()),
            None => Err(Error::new(format!("remote {} not found", identity))),
        }
    }

    /// Send some data to ALL remotes
    pub fn send_data<I: AsRef<[u8]>>(&mut self, data: I) {
        for socket in self.remotes.values_mut() {
            let _r = socket.send_data(data.as_ref());
        }
    }

    fn process_all_incoming(&mut self) {
        while let Ok((stream, peer_addr)) = self.tcp_listener.accept() {
            let mut socket = Socket::new_from_tcp_stream(stream, self.socket_config.clone());
            socket.config = self.socket_config.clone();
            log::info!("received incoming connection from {:?}", peer_addr);
            socket.insert_event(SocketEvent::Status(SocketStatus::Connected));
            self.remotes.insert(peer_addr, socket);
        }
    }

    pub fn process(&mut self) -> Result<(), IoError> {
        // if it's still connected, or if it's disconnected but still has events to process, retain the remote
        self.remotes.retain(|_, v| v.status().is_connected() || v.has_events());
        self.process_all_incoming();
        for socket in self.remotes.values_mut() {
            socket.process();
        }
        Ok(())
    }

    pub fn iter(&self) -> impl Iterator<Item=(&SocketAddr, &Socket)> {
        self.remotes.iter()
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item=(&SocketAddr, &mut Socket)> {
        self.remotes.iter_mut()
    }

    /// Get the socket stored for given the address
    pub fn get(&self, addr: SocketAddr) -> Option<&Socket> {
        self.remotes.get(&addr)
    }

    pub fn raw(&self) -> &TcpListener {
        &self.tcp_listener
    }
    
    /// Get the mutable socket stored for given the address
    pub fn get_mut(&mut self, addr: SocketAddr) -> Option<&mut Socket> {
        self.remotes.get_mut(&addr)
    }

    /// Returns an iterator that drain events for all known remotes
    ///
    /// You must call `process` before hand to ensure all the messages are correctly processed internally
    pub fn drain_events<'a>(&'a mut self) -> impl 'a + Iterator<Item=(SocketAddr, SocketEvent)> {
        self.remotes.iter_mut().flat_map(|(addr, socket)| {
            socket.drain_events().map(move |event| (*addr, event) )
        })
    }

    /// Send a "end" message to ALL remotes
    pub fn send_end(&mut self) {
        for socket in self.remotes.values_mut() {
            let _r = socket.send_end();
        }
    }
}

impl Index<SocketAddr> for Listener {
    type Output = Socket;

    fn index<'a>(&'a self, index: SocketAddr) -> &'a Socket {
        self.get(index).expect("addr does not exist for this listener")
    }
}

impl IndexMut<SocketAddr> for Listener {
    fn index_mut<'a>(&'a mut self, index: SocketAddr) -> &'a mut Socket {
        self.get_mut(index).expect("addr does not exist for this listener")
    }
}