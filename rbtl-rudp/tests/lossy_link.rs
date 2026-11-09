//! End to end tests between a client and a listener on loopback, with a relay in the middle
//! that can drop packets.

use std::{net::{SocketAddr, UdpSocket}, time::{Duration, Instant}};
use rbtl_rudp::{Listener, Socket, SocketCreateConfig, PacketSendOptions, SocketEvent};

const PACKET_HEADER_LEN: usize = 20;

fn is_fragment(b: &[u8]) -> bool {
    b.len() >= PACKET_HEADER_LEN && b[12] <= b[13]
}

fn is_ack(b: &[u8]) -> bool {
    b.len() >= PACKET_HEADER_LEN && b[12] == 255 && b[13] == 0
}

/// What the relay should drop
#[derive(Default)]
struct DropRules {
    /// number of client -> server fragments to drop
    c2s_frags: usize,
    /// number of server -> client acks to drop
    s2c_acks: usize,
}

struct Harness {
    listener: Listener,
    client: Socket,
    relay: UdpSocket,
    server_addr: SocketAddr,
    client_addr: Option<SocketAddr>,
    drop: DropRules,
    /// every client -> server fragment seen by the relay, dropped or not
    c2s_frags: Vec<Vec<u8>>,
    s2c_frags: Vec<Vec<u8>>,
    server_data: Vec<Box<[u8]>>,
}

impl Harness {
    fn new() -> Self {
        let listener = Listener::new("127.0.0.1:0").unwrap();
        let server_addr = listener.raw().local_addr().unwrap();
        let relay = UdpSocket::bind("127.0.0.1:0").unwrap();
        relay.set_nonblocking(true).unwrap();
        let client = Socket::connect(relay.local_addr().unwrap(), SocketCreateConfig::default()).unwrap();
        let mut h = Self {
            listener, client, relay, server_addr,
            client_addr: None,
            drop: DropRules::default(),
            c2s_frags: vec![], s2c_frags: vec![], server_data: vec![],
        };
        h.run_until(Duration::from_secs(2), |h| h.client.status().is_connected() && h.listener.connected_remotes_len() == 1);
        assert!(h.client.status().is_connected(), "client did not connect");
        h
    }

    fn step(&mut self) {
        let mut buf = [0u8; 2048];
        while let Ok((n, from)) = self.relay.recv_from(&mut buf) {
            let pkt = &buf[..n];
            if from == self.server_addr {
                if is_fragment(pkt) { self.s2c_frags.push(pkt.to_vec()); }
                if is_ack(pkt) && self.drop.s2c_acks > 0 { self.drop.s2c_acks -= 1; continue; }
                if let Some(c) = self.client_addr { let _ = self.relay.send_to(pkt, c); }
            } else {
                self.client_addr = Some(from);
                if is_fragment(pkt) {
                    self.c2s_frags.push(pkt.to_vec());
                    if self.drop.c2s_frags > 0 { self.drop.c2s_frags -= 1; continue; }
                }
                let _ = self.relay.send_to(pkt, self.server_addr);
            }
        }
        let _ = self.client.process();
        let _ = self.listener.process();
        for (_id, ev) in self.listener.drain_events() {
            if let SocketEvent::Data(d) = ev { self.server_data.push(d); }
        }
        for _ in self.client.drain_events() {}
    }

    fn run_until(&mut self, max: Duration, mut done: impl FnMut(&Self) -> bool) {
        let start = Instant::now();
        while start.elapsed() < max && !done(self) {
            self.step();
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    fn run_for(&mut self, d: Duration) {
        self.run_until(d, |_| false);
    }

    fn delivered(&self, payload: &[u8]) -> usize {
        self.server_data.iter().filter(|d| &d[..] == payload).count()
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn resent_encrypted_message_stays_encrypted_and_is_acked() {
    let mut h = Harness::new();
    let payload = b"TOP_SECRET_RESENT_PAYLOAD";
    h.drop.c2s_frags = 1;
    let seq_id = h.client.send_data(&payload[..], PacketSendOptions::new()).unwrap();

    h.run_until(Duration::from_secs(3), |h| h.client.is_seq_id_received(seq_id) == Ok(true));

    assert!(h.c2s_frags.len() >= 2, "the dropped fragment was never resent");
    for frag in &h.c2s_frags {
        assert!(!contains(frag, payload), "plaintext visible on the wire");
        assert_eq!(frag[14..16], h.c2s_frags[0][14..16], "resent fragment flags differ from the original");
    }
    assert_eq!(h.client.is_seq_id_received(seq_id), Ok(true));
    assert_eq!(h.delivered(payload), 1);
}

#[test]
fn lost_complete_acks_are_sent_again() {
    let mut h = Harness::new();
    let payload = b"payload whose acks get lost";
    // the receiver sends the complete ack twice, drop more than that
    h.drop.s2c_acks = 4;
    let seq_id = h.client.send_data(&payload[..], PacketSendOptions::new().encryption(false)).unwrap();

    h.run_until(Duration::from_secs(4), |h| h.client.is_seq_id_received(seq_id) == Ok(true));

    assert_eq!(h.client.is_seq_id_received(seq_id), Ok(true), "sender never learned the message was received");
    h.run_for(Duration::from_millis(500));
    assert_eq!(h.delivered(payload), 1);
}

#[test]
fn both_directions_use_different_nonces() {
    let mut h = Harness::new();
    // same length plaintexts, both seq_id 0
    let client_pt = b"CLIENT_PLAINTEXT_0";
    let server_pt = b"SERVER_PLAINTEXT_0";
    h.client.send_data(&client_pt[..], PacketSendOptions::new()).unwrap();
    let id = *h.listener.iter().next().unwrap().0;
    h.listener.send_data_to(&server_pt[..], id, PacketSendOptions::new()).unwrap();

    h.run_until(Duration::from_secs(2), |h| !h.c2s_frags.is_empty() && !h.s2c_frags.is_empty());

    let c = &h.c2s_frags[0][PACKET_HEADER_LEN..];
    let s = &h.s2c_frags[0][PACKET_HEADER_LEN..];
    let ct_xor: Vec<u8> = c.iter().zip(s).take(client_pt.len()).map(|(a, b)| a ^ b).collect();
    let pt_xor: Vec<u8> = client_pt.iter().zip(server_pt).map(|(a, b)| a ^ b).collect();
    assert_ne!(ct_xor, pt_xor, "same keystream used in both directions");

    h.run_until(Duration::from_secs(1), |h| h.delivered(client_pt) == 1);
    assert_eq!(h.delivered(client_pt), 1);
}

#[test]
fn nine_fragments_lost_first_fragment() {
    let mut h = Harness::new();
    // 9 fragments: frag_total = 8, the ack bitmap edge case
    let payload: Vec<u8> = (0..(8 * 1152 + 100)).map(|i| i as u8).collect();
    h.drop.c2s_frags = 1;
    let seq_id = h.client.send_data(payload.clone(), PacketSendOptions::new()).unwrap();

    h.run_until(Duration::from_secs(3), |h| h.client.is_seq_id_received(seq_id) == Ok(true));

    assert_eq!(h.client.is_seq_id_received(seq_id), Ok(true));
    assert_eq!(h.delivered(&payload), 1);
}
