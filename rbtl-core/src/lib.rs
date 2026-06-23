//! Trait used by the RBTL implementors

use std::{error::Error, sync::Arc, fmt::Debug};

pub enum Event {
    Data(Box<[u8]>),
    StatusChanged(Status),
}

#[derive(Clone)]
pub enum Status {
    /// Trying to connect to the other party, cannot send data yet
    Connecting,
    /// Connected and everything is in order
    Ok,
    /// A timeout error, either while connecting or being already connected
    Timeout,
    /// The connection was ended, by us or the remote.
    Ended { by_remote: bool },
    /// An error that can be a protocol error, a network error, coming from us, the remote, ...
    Error(Arc<dyn std::error::Error>),
}

pub trait Client {
    type ClientConfig: Clone + Debug;
    type Init;
    type ConnectOptions: Default + Clone + Debug;
    type SendOptions;
    type SendError;
    type StateError: Error;
    type MessageId;

    /// Create a new client for this connection type.
    fn new<I: Into<Self::Init>>(init: I, options: Self::ConnectOptions) -> Result<Self, Self::StateError> where Self: Sized;

    fn set_config(&mut self, config: Self::ClientConfig);

    fn get_config(&self) -> Self::ClientConfig;

    fn status(&self) -> Status;

    fn send<B>(&mut self, bytes: B, send_opts: Self::SendOptions) -> Result<Self::MessageId, Self::SendError>
        where B: Into<Arc<[u8]>> + AsRef<[u8]> + Clone;

    // fn error(&self) -> Option<Self::StateError>;

    /// Returns the average ping over the duration in milliseconds
    fn ping(&self, seconds: f32) -> Option<f32>;

    fn process(&mut self);

    fn drain_events<'a>(&'a mut self) -> impl Iterator<Item=Event> + 'a;
}

pub trait ServClient {
    type Server: Server;

    fn send<B: Into<Arc<[u8]>> + AsRef<[u8]> + Clone>(&mut self, bytes: B, send_options: <Self::Server as Server>::SendOptions)
        -> Result<<Self::Server as Server>::MessageId, <Self::Server as Server>::SendError>;

    /// Returns the average ping over the duration in milliseconds
    fn ping(&self, seconds: f32) -> Option<f32>;

    fn status(&self) -> Status;
}

pub trait Server {
    /// RBTL_PROTOCOL_ID: must be unique for each implementation. As a guideline, "public" implementations start from 0,
    /// while "private" ones go from 255 descending.
    ///
    /// Its purpose is to serialize/parse connection info, having an identifier that we know belongs to this impl
    /// helps
    const RBTL_PROTOCOL_ID: u8;
    const RBTL_PROTOCOL_NAME: &str;

    type Key: Clone;
    type Init;
    type ServerConfig: Clone + Debug;
    type ServClient: ServClient;
    type ConnectingClient;
    type SendOptions: Default;
    type SendError;
    type StateError: Error;
    // struct to indicate how to connect to this listener
    type ConnectInfo: Clone + for <'a> TryFrom<&'a [u8]> + TryInto<Vec<u8>>;
    type MessageId;

    /// Create a server/listener with a custom init payload, such as the port to choose, etc
    fn new_with<I: Into<Self::Init>>(init: I) -> Result<Self, Self::StateError> where Self: Sized;

    /// Create a server/listener with sensible defaults
    fn new() -> Result<Self, Self::StateError> where Self: Sized;

    fn set_config(&mut self, config: Self::ServerConfig);

    fn get_config(&self) -> Self::ServerConfig;

    fn send_all<B>(&mut self, bytes: B, send_opts: Self::SendOptions) -> Result<(), Self::SendError>
        where B: Into<Arc<[u8]>> + AsRef<[u8]> + Clone;

    fn get_mut(&mut self, k: &Self::Key) -> Option<&mut Self::ServClient>;

    fn get(&self, k: &Self::Key) -> Option<&Self::ServClient>;

    fn iter(&self) -> impl Iterator<Item=(&Self::Key, &Self::ServClient)>;

    fn iter_mut(&mut self) -> impl Iterator<Item=(&Self::Key, &mut Self::ServClient)>;

    /// Returns the info of how to connect to this listener, or an error if the info is not available (yet or forever)
    fn connect_info(&self) -> Result<Self::ConnectInfo, ()>;

    fn len(&self) -> usize;

    fn process(&mut self);

    fn drain_events<'a>(&'a mut self) -> impl Iterator<Item=(Self::Key, Event)> + 'a;
}