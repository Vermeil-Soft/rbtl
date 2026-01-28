//! Trait used by the RBTL implementors

use std::sync::Arc;

pub enum Event {
    Data(Box<[u8]>),
    StatusChanged(Status),
}

pub enum Status {
    /// Trying to connect to the other party, cannot send data yet
    Connecting,
    /// Connected and everything is in order
    Ok,
    /// A timeout error
    ///
    /// You can check `error()` to see the details of the error, but realistically you probably will not need it
    Timeout,
    /// The connection was ended, by us or the remote.
    Ended { by_remote: bool },
    // /// An error not related to the local, e.g. could not create a socket, could not access the network, ...
    // /// 
    // /// You must check `error()` to see the details of the error
    // LocalError,
    // /// An error related to the remote, but not a timeout: typically a crash
    // /// 
    // /// You must check `error()` to see the details of the error
    // RemoteError,
}

pub trait Client {
    type ClientConfig;
    type Init;
    type SendOptions;
    type SendError;
    type StateError;
    type MessageId;

    fn new(init: Self::Init) -> Result<Self, Self::StateError> where Self: Sized;

    fn set_config(&mut self, config: Self::ClientConfig);

    fn get_config(&self) -> Self::ClientConfig;

    fn status(&self) -> Status;

    fn send<B>(&mut self, bytes: B, send_opts: Self::SendOptions) -> Result<Self::MessageId, Self::SendError>
        where B: Into<Arc<[u8]>> + AsRef<[u8]> + Clone;

    // fn error(&self) -> Option<Self::StateError>;

    fn process(&mut self);

    fn drain_events<'a>(&'a mut self) -> impl Iterator<Item=Event> + 'a;
}

pub trait SClient {
    type Server: Server;

    fn send<B: Into<Arc<[u8]>> + AsRef<[u8]> + Clone>(&mut self, bytes: B, send_options: <Self::Server as Server>::SendOptions)
        -> Result<<Self::Server as Server>::MessageId, <Self::Server as Server>::SendError>;

    fn status(&self) -> Status;
}

pub trait Server {
    type Key;
    type Init;
    type ServerConfig;
    type Client: SClient;
    type SendOptions;
    type SendError;
    type StateError;
    type MessageId;

    fn new(init: Self::Init) -> Result<Self, Self::StateError> where Self: Sized;

    fn set_config(&mut self, config: Self::ServerConfig);

    fn get_config(&self) -> Self::ServerConfig;

    fn send_all<B>(&mut self, bytes: B, send_opts: Self::SendOptions) -> Result<(), Self::SendError>
        where B: Into<Arc<[u8]>> + AsRef<[u8]> + Clone;

    fn get_mut(&mut self, k: &Self::Key) -> Option<&mut Self::Client>;

    fn get(&self, k: &Self::Key) -> Option<&Self::Client>;

    fn iter(&self) -> impl Iterator<Item=(&Self::Key, &Self::Client)>;

    fn iter_mut(&mut self) -> impl Iterator<Item=(&Self::Key, &mut Self::Client)>;

    fn process(&mut self);

    fn drain_events<'a>(&'a mut self) -> impl Iterator<Item=(Self::Key, Event)> + 'a;
}