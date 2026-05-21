use rbtl::rbtl_rudp::{Listener, Socket};
use rbtl_rudp::{SocketEvent, SocketIdentity};
use std::sync::Arc;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let really_big_message: Vec<u8> = (0..65536).map(|v| (v % 256) as u8).collect();
    let really_big_message: Arc<[u8]> = Arc::from(really_big_message.into_boxed_slice());

    let mut server = Listener::new("0.0.0.0:50000").expect("Failed to create server");

    let mut client = Socket::connect("127.0.0.1:50000").expect("Failed to create client");

    let mut sent_message: bool = false;

    let mut remote_id: Option<SocketIdentity> = None;

    println!("Created server & client. Starting main loop");
    for _frame in 0..300 {
        server.process()?;
        client.process()?;

        for client_event in client.drain_events() {
            println!("Client: Incoming event {:?}", client_event);
        }

        for server_event in server.drain_events() {
            println!("Server: Incoming event {:?}", server_event);
            match server_event.1 {
                SocketEvent::Connected => {
                    remote_id = Some(server_event.0);
                },
                _ => {}
            }
        }
        
        if let Some(remote_id) = &remote_id {
            if !sent_message {
                println!("Sending message from client to server");
                let _r = client.send_data(Arc::clone(&really_big_message), Default::default());
                let _r = server.send_data_to(Arc::clone(&really_big_message), *remote_id, Default::default());
                sent_message = true;
            }
        }

        ::std::thread::sleep(::std::time::Duration::from_micros(16666));
    }

    println!("Stopping server...");
    server.send_end();
    drop(server);
    
    for _frame in 0..10 {
        client.process()?;

        for client_event in client.drain_events() {
            println!("Client: Incoming event {:?}", client_event);
        }
        ::std::thread::sleep(::std::time::Duration::from_micros(16666));
    }

    println!("Done.");
    Ok(())
}