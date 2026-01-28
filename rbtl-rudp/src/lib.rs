//! Reliable Bridge Transport Layer: Reliable UDP

mod utils;
pub mod consts;
mod os;
mod net;

pub use crate::net::{
    socket::{
        Socket, SocketShared, SocketCommon, SocketEvent,
    },
    common::{PacketSendOptions, SeqId},
    inner::SocketStatus,
    listener::{Listener, SocketIdentity},
};

pub use rbtl_core;