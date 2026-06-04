
pub use rbtl_rudp;
pub use rbtl_tcp;
pub use rbtl_core;

pub mod prelude;
mod socket;
mod common;
mod macr;
mod macr_default;

pub use rbtl_core::{Client, Server, ServClient, Event, Status};
pub use macr_default::{RBTLListener, RBTLKey, RBTLServClient, RBTLServClientMut, RBTLClient};