use rbtl_tcp::{Listener, Socket};

// for the example, you need to start the server, then the client
fn main() {
    let arg1 = std::env::args().skip(1).next();
    if arg1.as_ref().map_or(false, |s| s == "server") {
        main_server();
    } else {
        main_client(arg1);
    }
}

fn main_server() {
    let mut listener = Listener::bind("0.0.0.0:1234").unwrap();

    for i in 0..5000 {
        let _r = listener.process();
        if i % 100 == 0 {
            listener.send_data(b"HELLOFROMSERVER");
        } else if i % 100 == 50 {
            println!("#server remotes: {}", listener.remotes_len());
            let first_ping = listener.iter().next().map(|r| r.1.avg_ping(10.0).unwrap_or(999.0));
            if let Some(first_ping) = first_ping {
                println!("#ping: {}ms", first_ping );
            }
        }
        for (addr, event) in listener.drain_events() {
            println!("<SERVER: FROM {:?}, EVENT {:?}", addr, event);
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

fn main_client(arg1: Option<String>) {
    let mut socket = if let Some(addr) = arg1 {
        Socket::new(&format!("{}:1234", addr)).unwrap()
    } else {
        Socket::new("127.0.0.1:1234").unwrap()
    };

    for i in 0..500 {
        socket.process();
        if i == 10 {
            socket.send_data(b"HELLOFROMCLIENT1");
        } else if i == 450 {
            socket.end();
        }

        for event in socket.drain_events() {
            println!(">CLIENT: EVENT {:?}", event);
        }

        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}