use std::time::{Duration, Instant};

use rbtl::{
    Event, Status, RBTLAsyncClient, RBTLClientConnectInfo, RBTLServStem, RBTLClientStem,
    RBTLServCreateParams, RBTLConnector, RBTLListener,
};

fn listener() -> RBTLListener {
    let serv_stem = RBTLServStem { rudp: Some(()), tcp: None };
    let create_params = RBTLServCreateParams {
        rudp: Some("127.0.0.1:0".parse().unwrap()),
        tcp: None,
    };
    RBTLListener::new(&serv_stem, create_params).unwrap()
}

/// Connects an async client (graceful end of 300ms) to a listener, then stops it with `stop`.
///
/// Returns how long `stop` took, and whether the server saw the client end.
fn connect_then_stop(stop: fn(RBTLAsyncClient)) -> (Duration, bool) {
    let mut listener = listener();
    let connect_info = loop {
        listener.process();
        if let Some(info) = listener.connect_info() { break info; }
        std::thread::sleep(Duration::from_millis(5));
    };
    let client_connect_info = RBTLClientConnectInfo::from(&connect_info);

    let client_thread = std::thread::spawn(move || {
        let client_stem = RBTLClientStem { rudp: Some(()), tcp: None };
        let mut connector = RBTLConnector::new(&client_stem, client_connect_info, Default::default()).unwrap();
        let client = loop {
            match connector.attempt_connect(&client_stem) {
                None => std::thread::sleep(Duration::from_millis(5)),
                Some(r) => break r.unwrap(),
            }
        };
        let client = RBTLAsyncClient::new_with_graceful_end(client, Duration::from_millis(300));
        let start = Instant::now();
        while !client.status().is_ok() && start.elapsed() < Duration::from_secs(2) {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(client.status().is_ok(), "client did not connect");
        std::thread::sleep(Duration::from_millis(50));
        let start = Instant::now();
        stop(client);
        start.elapsed()
    });

    let mut ended = false;
    let start = Instant::now();
    while !ended && start.elapsed() < Duration::from_secs(5) {
        listener.process();
        for (_key, ev) in listener.drain_events() {
            if let Event::StatusChanged(Status::Ended { by_remote: true }) = ev {
                ended = true;
            }
        }
        listener.post_process();
        std::thread::sleep(Duration::from_millis(2));
    }
    (client_thread.join().unwrap(), ended)
}

#[test]
fn async_client_stop_and_wait_blocks_for_graceful_end() {
    let (stop_duration, ended) = connect_then_stop(|client| client.stop_and_wait());
    assert!(ended, "the server never saw the client end");
    assert!(stop_duration >= Duration::from_millis(300), "stopped after {:?}", stop_duration);
    assert!(stop_duration < Duration::from_secs(1), "stopped after {:?}", stop_duration);
}

#[test]
fn async_client_drop_does_not_block() {
    let (drop_duration, ended) = connect_then_stop(|client| drop(client));
    assert!(drop_duration < Duration::from_millis(20), "drop took {:?}", drop_duration);
    // the thread ends the connection in the background
    assert!(ended, "the server never saw the client end");
}
