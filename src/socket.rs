use std::sync::Arc;
// use crate::common::{SendDataOptions, SocketStatus, SocketEvent};

// pub enum Socket<I, O> {
// }

// impl<I, O> Socket<I, O> {
//     pub fn new<T: Into<Self>>(stem: T) -> Self {
//         stem.into()
//     }

//     /// Send data to the remote.
//     ///
//     /// Returns an id called `sequence_id`, to track whether or not the message has arrived. Not all backends
//     /// support this, those which don't will always return 0.
//     pub fn send_data(&mut self, data: &T, options: SendDataOptions) -> u32 {
//         todo!()
//     }

//     /// Gracefully asks the remote to end the connection. You may still receive some inbound messages in the meantime.
//     ///
//     /// THis step is automatically done on drop.
//     pub fn send_end(&mut self) {
//         todo!()
//     }

//     /// Returns the last ping we have for this socket
//     pub fn last_ping_ms(&self) -> Option<u32> {
//         todo!()
//     }

//     /// Returns the average ping over the given last seconds
//     pub fn avg_ping_ms(&self, window_seconds: u32) -> Option<u32> {
//         todo!()
//     }

//     pub fn status(&self) -> SocketStatus {
//         todo!()
//     }

//     /// Returns whether or not the sequence id has been *fully* received by the remote
//     /// 
//     /// Returns `Err` if the remote does not support this
//     pub fn is_seq_id_received(&self, seq_id: SeqId) -> Result<bool, ()> {
//         Err(())
//     }

//     pub fn next_event(&mut self) -> Option<SocketEvent<T>> {
//         None
//     }

//     pub fn set_timeout_delay(&mut self, time_ms: u32) {
//         todo!()
//     }

//     pub fn process_all(&mut self) {

//     }
// }