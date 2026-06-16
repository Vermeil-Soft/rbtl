//! RBTL with TCP
//! 
//! Should be used as a fallback only when all udp alternatives are impossible, because TCP completely destroys RBTL's
//! message based approach with its streaming model.
//!
//! The stream is a continuous loop of submessages that look like this:
//! 
//! [ msg_type: u8 ][submessage: ...]
//! 
//! with submessage being either:
//! 
//! * Status update: [ last_recv_seq_id: u32 ]
//! * Data: [ seq_id: u32 ][ msg_len: u32 ][ data: "msg_len" bytes ]
//! 
//! Status update is a way for us to estimate ping with TCP, since there is no consistent cross platform way to do
//! this via syscalls without administrator access.
//! 
//! You do not have to remember this as a library user, it is just a quick overview of how it works under the hood.

mod ping_tracker;
mod ingester;
mod socket;
mod listener;
mod rbtl_impl;
mod connect_info;
mod error;

pub type SeqId = u32;

pub use crate::{
    socket::{Socket, SocketEvent, SocketStatus},
    connect_info::ConnectInfo,
    error::Error,
    listener::Listener
};