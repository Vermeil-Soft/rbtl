
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