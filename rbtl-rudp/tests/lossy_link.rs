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
    /// every non-data event of the server, as Debug strings
    server_events: Vec<String>,
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
            c2s_frags: vec![], s2c_frags: vec![], server_data: vec![], server_events: vec![],
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
            match ev {
                SocketEvent::Data(d) => self.server_data.push(d),
                ev => self.server_events.push(format!("{:?}", ev)),
            }
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
    // 0b1000 is the "resend" flag, the only one that may differ between sends
    let set_flags = |frag: &Vec<u8>| u16::from_be_bytes([frag[14], frag[15]]) & !0b1000;
    for frag in &h.c2s_frags {
        assert!(!contains(frag, payload), "plaintext visible on the wire");
        assert_eq!(set_flags(frag), set_flags(&h.c2s_frags[0]), "resent fragment flags differ from the original");
    }
    assert_eq!(h.c2s_frags[0][15] & 0b1000, 0, "the first send is not a resend");
    assert!(h.c2s_frags[1..].iter().all(|frag| frag[15] & 0b1000 != 0), "resends are flagged as such");
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

/// Builds a control packet from the server to the client, as an attacker knowing the 4 bytes identities would
fn forge_s2c_control(h: &Harness, frag_tot: u8, mac: Option<[u8; 12]>) -> Vec<u8> {
    let client_id = h.client.self_identity();
    let server_id = h.client.remote_identity();
    let mut pkt = vec![0u8; 20];
    pkt[4..8].copy_from_slice(server_id.as_bytes());
    pkt[8..12].copy_from_slice(client_id.as_bytes());
    pkt[12] = 255;
    pkt[13] = frag_tot;
    if let Some(mac) = mac {
        pkt[15] = 1;
        pkt.extend_from_slice(&mac);
    }
    let crc = crc32fast::hash(&pkt[4..]);
    pkt[0..4].copy_from_slice(&crc.to_be_bytes());
    pkt
}

#[test]
fn forged_end_is_ignored() {
    let mut h = Harness::new();
    let client_addr = h.client_addr.unwrap();
    // End without a mac, then with a made up one, sent from the address the client expects
    for mac in [None, Some([0xAB; 12])] {
        h.relay.send_to(&forge_s2c_control(&h, 3, mac), client_addr).unwrap();
        h.run_for(Duration::from_millis(50));
        assert!(h.client.status().is_connected(), "forged End (mac={:?}) disconnected the client", mac);
    }
}

#[test]
fn replayed_control_packet_is_ignored() {
    let mut h = Harness::new();
    let client_addr = h.client_addr.unwrap();
    // capture a real (authenticated) heartbeat from the server by sending nothing for a while
    let mut captured = None;
    let start = Instant::now();
    let mut buf = [0u8; 2048];
    while captured.is_none() && start.elapsed() < Duration::from_secs(3) {
        if let Ok((n, from)) = h.relay.recv_from(&mut buf) {
            if from == h.server_addr && buf[12] == 255 && buf[13] == 10 {
                captured = Some(buf[..n].to_vec());
            }
            let _ = h.relay.send_to(&buf[..n], if from == h.server_addr { client_addr } else { h.server_addr });
        }
        let _ = h.client.process();
        let _ = h.listener.process();
        std::thread::sleep(Duration::from_millis(2));
    }
    let heartbeat = captured.expect("no heartbeat from the server");
    assert_eq!(heartbeat[15] & 1, 1, "heartbeat is authenticated");
    assert_eq!(heartbeat.len(), 16 + 12);
    // the server stops talking: replaying its heartbeat must not keep the client alive
    let mut client = h.client;
    drop(h.listener);
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(7) && !matches!(client.status(), rbtl_rudp::SocketStatus::TimeoutError { .. }) {
        h.relay.send_to(&heartbeat, client_addr).unwrap();
        let _ = client.process();
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(matches!(client.status(), rbtl_rudp::SocketStatus::TimeoutError { .. }), "replayed heartbeats kept the client alive");
}

#[test]
fn local_end_is_reported_as_local() {
    use rbtl_rudp::rbtl_core::{Client, Event, Status};
    let mut h = Harness::new();
    h.client.send_end().unwrap();
    let events: Vec<Event> = Client::drain_events(&mut h.client).collect();
    assert!(
        events.iter().any(|e| matches!(e, Event::StatusChanged(Status::Ended { by_remote: false }))),
        "{:?}", events
    );
    assert!(matches!(Client::status(&h.client), Status::Ended { by_remote: false }));
    // the server sees it as ended by the remote: the End is authenticated and accepted
    h.run_until(Duration::from_secs(1), |h| h.server_events.iter().any(|e| e == "Ended { by_remote: true }"));
    assert!(h.server_events.iter().any(|e| e == "Ended { by_remote: true }"), "{:?}", h.server_events);
}

#[test]
fn ping_ignores_receiver_ack_delay() {
    let mut h = Harness::new();
    // the first ack is lost: the next one is sent by the receiver ~50ms later, it must not count in the ping
    h.drop.s2c_acks = 1;
    let seq_id = h.client.send_data(&b"ping me"[..], PacketSendOptions::new()).unwrap();
    h.run_until(Duration::from_secs(2), |h| h.client.is_seq_id_received(seq_id) == Ok(true));
    let (ping_ms, _) = h.client.last_ping_info().expect("no ping recorded");
    assert!(ping_ms < 30, "ping includes the receiver's ack delay: {}ms", ping_ms);
}

#[test]
fn resent_message_is_not_used_for_ping() {
    let mut h = Harness::new();
    h.drop.c2s_frags = 1;
    let seq_id = h.client.send_data(&b"resent"[..], PacketSendOptions::new()).unwrap();
    h.run_until(Duration::from_secs(2), |h| h.client.is_seq_id_received(seq_id) == Ok(true));
    assert_eq!(h.client.is_seq_id_received(seq_id), Ok(true));
    // the ack answers the resend, which we can't tell apart from the original send: no sample (Karn's algorithm)
    assert_eq!(h.client.last_ping_info(), None);
    // the next message can be timed
    let seq_id = h.client.send_data(&b"not resent"[..], PacketSendOptions::new()).unwrap();
    h.run_until(Duration::from_secs(2), |h| h.client.is_seq_id_received(seq_id) == Ok(true));
    assert!(h.client.last_ping_info().is_some());
}

#[test]
fn syn_is_resent_quickly_then_backs_off() {
    // a "server" that never answers
    let silent = UdpSocket::bind("127.0.0.1:0").unwrap();
    silent.set_read_timeout(Some(Duration::from_millis(5))).unwrap();
    let mut client = Socket::connect(silent.local_addr().unwrap(), SocketCreateConfig::default()).unwrap();
    let start = Instant::now();
    let mut syns = 0;
    let mut buf = [0u8; 2048];
    // sent at 0, 250ms and 750ms, then 1750ms
    while start.elapsed() < Duration::from_millis(1400) {
        let _ = client.process();
        if let Ok((n, _)) = silent.recv_from(&mut buf) {
            if n >= 16 && buf[12] == 255 && buf[13] == 1 { syns += 1; }
        }
    }
    assert_eq!(syns, 3);
}
