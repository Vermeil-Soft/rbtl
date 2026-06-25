use rbtl::{RBTLClient, RBTLConnector, RBTLMessageId, RBTLClientConnectInfo, RBTLListener};

fn spawn_client(client_connect_info: RBTLClientConnectInfo) {
    let mut connector = RBTLConnector::new(client_connect_info, Default::default()).unwrap();

    let mut client = None;
    for _i in 0..1000 {
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
    println!("(client) successfully connected with {}", client.kind().rbtl_protocol_name());

    const BYTES: &[u8] = &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
    let mut last_msg_id: Option<RBTLMessageId> = None;
    for i in 0..100 {
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
                last_msg_id = Some(client.send(BYTES, Default::default()).unwrap());
                println!("(client) sending message {:?}", last_msg_id.as_ref().cloned().unwrap());
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(16));
    }
    println!("(client) shutting down");
}

fn main() {
    let mut listener = RBTLListener::new().unwrap();

    let connect_info = listener.connect_info();
    let client_connect_info = RBTLClientConnectInfo::from(&connect_info);
    println!("(serv) created");

    std::thread::spawn(move || spawn_client(client_connect_info));

    for _i in 0..1000 {
        listener.process();

        for (key, ev) in listener.drain_events() {
            println!("(serv) >> new event {:?} from {:?}", ev, key);
        }

        std::thread::sleep(std::time::Duration::from_millis(16));
    }
    println!("(serv) shutting down");
}