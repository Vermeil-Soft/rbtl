
// #[derive(Clone, Copy)]
// pub struct SendDataOptions {
//     /// Also used as the opposite of `nagle`.
//     /// 
//     /// * Immediate = true means the message is sent immediatly
//     /// * Immediate = false means that the message can wait for other data to be sent in a bigger chunk, but increasing
//     /// latency
//     pub immediate: bool,
//     pub resend_delay_ms: u32,
//     /// The time in ms where this message is expired and does not need to be sent anymore
//     /// 
//     /// 0 means that this message instantly expires, u32::MAX means that this message never expires and must arrive.
//     pub expiration_ms: u32,
//     /// Always try to make sure this arrives at dest within `expiration_ms`
//     pub key: bool,
// }

// impl SendDataOptions {
//     pub const DEFAULT_RESEND_DELAY_MS: u32 = 160;
//     pub fn new() -> Self {
//         Self {
//             immediate: true,
//             resend_delay_ms: Self::DEFAULT_RESEND_DELAY_MS,
//             expiration_ms: u32::MAX,
//             key: true,
//         }
//     }

//     pub fn set_unexpire(&mut self) {
//         self.expiration_ms = u32::MAX;
//     }

//     pub fn set_forgettable(&mut self) {
//         self.key = false;
//     }

//     pub fn set_key(&mut self) {
//         self.key = true;
//     }

//     pub fn set_expiration(&mut self, ms: u32) {
//         self.expiration_ms = ms;
//     }

//     pub fn set_instant_expire(&mut self) {
//         self.expiration_ms = 0;
//     }
// }

// impl Default for SendDataOptions {
//     fn default() -> Self {
//         Self::new()
//     }
// }

// pub enum SocketEvent<T> {
//     Data(T),
//     StatusChanged(SocketStatus),
// }

// pub enum SocketStatus {
//     /// The socket is connecting, sending data is not available yet
//     Connecting,
//     /// The socket is connected and can transmit data
//     Connected,
//     /// An error not related to the remote, e.g. could not create a socket, could not access the network, ...
//     /// 
//     /// You must check `error()` to see the details of the error
//     LocalError,
//     /// A timeout error
//     ///
//     /// You can check `error()` to see the details of the error, but realistically you probably will not need it
//     Timeout,
//     /// An error related to the remote, but not a timeout: typically a crash
//     /// 
//     /// You must check `error()` to see the details of the error
//     RemoteError,
//     /// The connection was ended, by us or the remote.
//     Ended { by_remote: bool },
// }