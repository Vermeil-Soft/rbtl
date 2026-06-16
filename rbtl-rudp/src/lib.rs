//! Reliable Bridge Transport Layer: Reliable UDP

mod utils;
pub mod consts;
mod os;
mod net;
mod error;

pub use crate::{
    error::Error,
    net::{
        socket::{
            Socket, SocketShared, SocketCommon, SocketEvent,
        },
        common::{PacketSendOptions, SeqId},
        connect_info::ConnectInfo,
        inner::SocketStatus,
        listener::{Listener, SocketIdentity},
    }
};

pub use rbtl_core;