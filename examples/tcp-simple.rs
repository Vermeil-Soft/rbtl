use rbtl_tcp::{Listener, Socket};

fn main() {

    let mut listener = Listener::bind("0.0.0.0:1234").unwrap();
    let mut socket = Socket::new("127.0.0.1:1234").unwrap();

    for i in 0..100 {
        socket.process();
        listener.process().unwrap();

        if i == 10 {
            socket.send_data(b"HELLOFROMCLIENT1");
        } else if i == 20 {
            listener.send_data(b"HELLOFROMSERVER");
        }

        for event in socket.drain_events() {
            println!(">CLIENT: EVENT {:?}", event);
        }

        for (addr, event) in listener.drain_events() {
            println!("<SERVER: FROM {:?}, EVENT {:?}", addr, event);
        }

        std::thread::sleep(std::time::Duration::from_millis(16));
    }

    let server_ping = listener.iter().next().unwrap().1.avg_ping(10.0).unwrap();
    let client_ping = socket.avg_ping(10.0).unwrap();
    println!("pings: server {}ms, client {}ms", server_ping, client_ping);

    println!("server remotes: {}", listener.remotes_len());
    drop(socket);
    for _i in 0..10 {
        listener.process().unwrap();
        for (addr, event) in listener.drain_events() {
            println!("<SERVER: FROM {:?}, EVENT {:?}", addr, event);
        }
        std::thread::sleep(std::time::Duration::from_millis(16));
    }
    println!("server remotes: {}", listener.remotes_len());
}