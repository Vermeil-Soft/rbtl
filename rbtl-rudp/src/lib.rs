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
            Socket, SocketShared, SocketCommon, SocketEvent, SocketCreateConfig,
        },
        common::{PacketSendOptions, SeqId},
        connect_info::ConnectInfo,
        inner::SocketStatus,
        listener::{Listener, SocketIdentity},
    }
};

pub use x25519_dalek;
pub use rbtl_core;