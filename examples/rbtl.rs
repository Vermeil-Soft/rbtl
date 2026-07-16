use rbtl::{RBTLClientConnectInfo, RBTLConnector, RBTLConnectInfo, RBTLListener, RBTLMessageId};

fn spawn_client(client_connect_info: RBTLClientConnectInfo) {
    let mut connector = RBTLConnector::new(client_connect_info, Default::default()).unwrap();
    println!("(client) created");
    let mut client = None;
    for _i in 0..100 {
        match connector.attempt_connect() {
            None => { std::thread::sleep(std::time::Duration::from_millis(16)); },
            Some(Ok(new_client)) => {
                client = Some(new_client);
                break;
            },
            Some(Err(e)) => {
                panic!("could not connect: {}", e);
            }
        }
    }
    let mut client = client.unwrap();

    println!("(client) successfully connected with {:?} ({})", client.kind(), client.kind().rbtl_protocol_name());

    const BYTES: &[u8] = &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
    let mut last_msg_id: Option<RBTLMessageId> = None;
    for i in 0..500 {
        client.process();

        for ev in client.drain_events() {
            println!("(client) >> new event {:?}", ev);
        }
        if let Some(msg_id) = last_msg_id.as_ref() {
            if let Ok(true) = client.is_msg_received(&msg_id) {
                println!("(client) message {:?} has arrived", last_msg_id.as_ref().cloned().unwrap());
                last_msg_id = None;
            }
        } else {
            if i % 10 == 0 {
                last_msg_id = client.send(BYTES, Default::default()).ok();
                if last_msg_id.is_some() {
                    println!("(client) sending message {:?}", last_msg_id.as_ref().cloned().unwrap());
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(16));
    }
    println!("(client) shutting down");
}

fn wait_for_connect_info(listener: &mut RBTLListener) -> RBTLConnectInfo {
    for _i in 0..100 {
        listener.process();
        if let Some(info) = listener.connect_info() {
            return info;
        }
        std::thread::sleep(std::time::Duration::from_millis(16));
    }
    panic!("(serv) did not get server conn info in time")
}

fn main() {
    let mut listener = RBTLListener::new_defaults().unwrap();

    #[allow(unused_mut)]
    let mut connect_info = wait_for_connect_info(&mut listener);
    // connect_info.rudp = Err(()); // don't send rudp conn data
    // connect_info.tcp = Err(()); // don't send tcp conn data
    let client_connect_info = RBTLClientConnectInfo::from(&connect_info);
    println!("(serv) created");

    let r = std::thread::spawn(move || spawn_client(client_connect_info));

    const BYTES: &[u8] = &[9, 8, 7, 6, 5, 4, 3, 2, 1, 0];

    for i in 0..1000 {
        listener.process();

        for (key, ev) in listener.drain_events() {
            println!("(serv) >> new event {:?} from {:?}", ev, key);
        }

        if i % 10 == 0 {
            let _r = listener.send_all(BYTES, Default::default());
            println!("(server) sending message to {} remotes...", listener.connected_len());
        }

        std::thread::sleep(std::time::Duration::from_millis(16));
    }
    drop(listener);
    println!("(serv) shutting down");

    r.join().unwrap();
    println!("Done");
}