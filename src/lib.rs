
pub use rbtl_rudp;
pub use rbtl_tcp;

pub mod prelude;
mod socket;
mod listener;
mod common;

pub enum RemoteId {

}

pub enum RemoteKind {
    Rudp,
    Tcp,
}