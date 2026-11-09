use rbtl_tcp::{Listener, Socket, SocketConfig, SocketEvent};
use std::time::{Duration, Instant};

#[test]
fn large_messages_survive_partial_writes() {
    let mut listener = Listener::bind("127.0.0.1:0").unwrap();
    let addr = listener.raw().local_addr().unwrap();
    let mut client = Socket::new_blocking(addr, SocketConfig::new()).unwrap();
    std::thread::sleep(Duration::from_millis(50));
    listener.process().unwrap();

    // big enough to fill the kernel socket buffers, so writes are partial
    let messages: Vec<Vec<u8>> = (0..4u8).map(|i| vec![i; 900_000]).collect();
    for m in &messages {
        client.send_data(m).unwrap();
    }

    let mut received = vec![];
    let start = Instant::now();
    while received.len() < messages.len() && start.elapsed() < Duration::from_secs(5) {
        client.process();
        listener.process().unwrap();
        for (_addr, ev) in listener.drain_events() {
            match ev {
                SocketEvent::Data(d) => received.push(d),
                SocketEvent::Status(s) => assert!(!s.is_error(), "server error: {:?}", s),
            }
        }
        std::thread::sleep(Duration::from_millis(2));
    }

    assert_eq!(received.len(), messages.len());
    for (r, m) in received.iter().zip(&messages) {
        assert_eq!(&r[..], &m[..]);
    }
}
