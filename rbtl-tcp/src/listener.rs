use std::{
    io::Error as IoError,
    net::{SocketAddr, TcpListener, ToSocketAddrs},
    ops::{Index, IndexMut}
};

use hashbrown::{HashMap};

use crate::{Socket, socket::SocketEvent};

#[derive(Default)]
struct ListenerConfig {
}

pub struct Listener {
    config: ListenerConfig,
    tcp_listener: TcpListener,
    remotes: HashMap<SocketAddr, Socket>,
}

impl Listener {
    pub fn bind<A: ToSocketAddrs>(addr: A) -> Result<Self, IoError> {
        let tcp_listener = TcpListener::bind(addr)?;
        let _r = tcp_listener.set_nonblocking(true);
        Ok(Listener {
            tcp_listener,
            config: Default::default(),
            remotes: HashMap::default()
        })
    }

    pub fn remotes_len(&self) -> usize {
        self.remotes.len()
    }

    fn process_all_incoming(&mut self) {
        for stream in self.tcp_listener.incoming() {
            if let Ok(stream) = stream {
                if let Ok(peer_addr) = stream.peer_addr() {
                    let socket = Socket::new_from_tcp_stream(stream);
                    self.remotes.insert(peer_addr, socket);
                }
            } else {
                // .incoming is a loop that never ends, instead we expect a WouldBlock to end the loop
                break;
            }
        }
    }

    pub fn process(&mut self) -> Result<(), IoError> {
        self.remotes.retain(|_, v| { v.status().is_normal() });
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