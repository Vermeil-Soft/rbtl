//! Trait used by the RBTL implementors

use std::{error::Error, fmt::Debug, hash::Hash, sync::Arc};

#[derive(Debug)]
pub enum Event {
    Data(Box<[u8]>),
    StatusChanged(Status),
}

#[derive(Clone, Debug)]
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
    Error(Arc<dyn std::error::Error + Sync + Send + 'static>),
}

impl Status {
    pub fn is_ok(&self) -> bool {
        matches!(self, Self::Ok)
    }

    /// Is the connection over, as in are we not "connecting" nor "connected"
    pub fn is_conn_over(&self) -> bool {
        matches!(self, Self::Timeout | Self::Ended { .. } | Self::Error(_))
    }
}

pub trait Client {
    type Server: Server;
    type ClientConfig: Clone + Debug + Default;
    type Init;
    type ConnectOptions: Debug + Default;
    type SendOptions: Debug + Default + Clone;
    type SendError;
    type StateError: Error;

    /// Create a new client for this connection type.
    fn new<I: Into<Self::Init>>(init: I, options: Self::ConnectOptions) -> Result<Self, Self::StateError> where Self: Sized;

    fn from_connect_info(connect_info: <Self::Server as Server>::ConnectInfo, options: Self::ConnectOptions) ->
        Result<Self, Self::StateError> where Self: Sized;

    fn set_config(&mut self, config: Self::ClientConfig);

    fn get_config(&self) -> Self::ClientConfig;

    fn status(&self) -> Status;

    fn send<B>(&mut self, bytes: B, send_opts: Self::SendOptions) -> Result<<Self::Server as Server>::MessageId, Self::SendError>
        where B: Into<Arc<[u8]>> + AsRef<[u8]> + Clone;

    /// Fetches whether a sent message has been received by the remote
    /// 
    /// Returns either true or false for if the message has been received, or an error (if the operation
    /// is not supported, if the given msg_id is invalid, etc)
    fn is_msg_received(&self, msg_id: &<Self::Server as Server>::MessageId) -> Result<bool, ()>;

    /// Returns the average ping over the duration in milliseconds
    fn ping(&self, seconds: f32) -> Option<f32>;

    fn process(&mut self);

    /// End this remote, ending connection wit the server
    /// 
    /// The same is done when this is dropped, but here there is time to make sure the server has received it
    fn end(&mut self);

    fn drain_events<'a>(&'a mut self) -> impl Iterator<Item=Event> + 'a;
}

pub trait ServClient {
    type Server: Server;

    fn send<B: Into<Arc<[u8]>> + AsRef<[u8]> + Clone>(&mut self, bytes: B, send_options: <Self::Server as Server>::SendOptions)
        -> Result<<Self::Server as Server>::MessageId, <Self::Server as Server>::SendError>;

    fn is_msg_received(&self, msg_id: &<Self::Server as Server>::MessageId) -> Result<bool, ()>;

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

    type Key: Debug + Clone + Hash + PartialEq + Eq;
    type Init;
    type ServerConfig: Clone + Debug + Default;
    type ServClient: ServClient;
    type ConnectingClient;
    type SendOptions: Default;
    type SendError;
    type StateError: Error;
    // struct to indicate how to connect to this listener
    type ConnectInfo: Clone + for <'a> TryFrom<&'a [u8]> + TryInto<Vec<u8>> + Debug;
    type MessageId: Debug + Clone + PartialOrd + PartialEq + Eq;

    /// Create a server/listener with sensible defaults
    fn new_defaults() -> Result<Self, Self::StateError> where Self: Sized;

    /// Create a server/listener with a custom init payload, such as the port to choose, etc
    fn new<I: Into<Self::Init>>(init: I) -> Result<Self, Self::StateError> where Self: Sized;

    fn new_with<I: Into<Self::Init>>(init: I, server_config: Self::ServerConfig) -> Result<Self, Self::StateError> where Self: Sized;

    fn set_config(&mut self, config: Self::ServerConfig);

    fn get_config(&self) -> Self::ServerConfig;

    fn send_all<B>(&mut self, bytes: B, send_opts: Self::SendOptions) -> Result<(), Self::SendError>
        where B: Into<Arc<[u8]>> + AsRef<[u8]> + Clone;

    fn get_mut(&mut self, k: &Self::Key) -> Option<&mut Self::ServClient>;

    fn get(&self, k: &Self::Key) -> Option<&Self::ServClient>;

    fn iter(&self) -> impl Iterator<Item=(&Self::Key, &Self::ServClient)>;

    fn iter_mut(&mut self) -> impl Iterator<Item=(&Self::Key, &mut Self::ServClient)>;

    /// Returns the info of how to connect to this listener.
    /// 
    /// * None => not yet available
    /// * Some(Err(_)) => an error happened and we are unable to generate a connect_info
    /// * Some(Ok(_)) => we can use the connect info
    fn connect_info(&self) -> Option<Result<Self::ConnectInfo, ()>>;

    /// End all the remotes
    /// 
    /// the same is done when this is dropped, but here there is time to make sure the remotes receive it
    fn end(&mut self);

    /// Returns the amount of *registered* remotes. They do not have to be connected to be registered.
    fn len(&self) -> usize;

    /// Returns the amount of *connected* remotes. They do not have to be connected to be registered.
    fn connected_len(&self) -> usize;

    fn process(&mut self);

    fn drain_events<'a>(&'a mut self) -> impl Iterator<Item=(Self::Key, Event)> + 'a;
}