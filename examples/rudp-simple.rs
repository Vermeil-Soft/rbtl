use rbtl::rbtl_rudp::{Listener, Socket};
use rbtl_rudp::{SocketEvent, SocketIdentity};
use std::sync::Arc;

// for the example, you need to start the server, then the client
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arg1 = std::env::args().skip(1).next();
    if arg1.as_ref().map_or(false, |s| s == "server") {
        main_server()
    } else {
        main_client(arg1)
    }
}

fn main_server() -> Result<(), Box<dyn std::error::Error>> {
    let mut server = Listener::new("0.0.0.0:50000").expect("Failed to create server");
    let mut remote_id: Option<SocketIdentity> = None;
    println!("Starting server");

    let really_big_message: Vec<u8> = (0..65536).map(|v| (v % 256) as u8).collect();
    let really_big_message: Arc<[u8]> = Arc::from(really_big_message.into_boxed_slice());

    for _frame in 0..5000 {
        server.process()?;

        if let Some(remote_id) = remote_id {
            if _frame % 100 == 0 {
                let _r = server.send_data_to(Arc::clone(&really_big_message), remote_id, Default::default());
            }
        }

        for (identity, event) in server.drain_events() {
            println!("Server: Incoming event {:?} from {:?}", event, identity);
            match event {
                SocketEvent::Connected => {
                    remote_id = Some(identity);
                },
                _ => {}
            }
        }
        std::thread::sleep(std::time::Duration::from_micros(16666));
    }
    println!("Done.");
    Ok(())
}

fn main_client(arg1: Option<String>) -> Result<(), Box<dyn std::error::Error>> {
    let mut client = if let Some(addr) = arg1 {
        Socket::connect(&format!("{}:50000", addr), Default::default()).unwrap()
    } else {
        Socket::connect("127.0.0.1:50000", Default::default()).unwrap()
    };
    println!("Starting client");

    let mut connected = false;

    let really_big_message: Vec<u8> = (0..65536).map(|v| (v % 256) as u8).collect();
    let really_big_message: Arc<[u8]> = Arc::from(really_big_message.into_boxed_slice());

    for _frame in 0..5000 {
        client.process()?;
        if _frame % 50 == 0 {
            println!("(Status: {:?})", client.status());
        }

        if connected && _frame % 100 == 0 {
            let _r = client.send_data(Arc::clone(&really_big_message), Default::default());
        }

        for event in client.drain_events() {
            println!("Client: Incoming event {:?}", event);
            match event {
                SocketEvent::Connected => {
                    connected = true;
                },
                _ => {}
            }
        }
        std::thread::sleep(std::time::Duration::from_micros(16666));
    }
    println!("Done.");
    Ok(())
}