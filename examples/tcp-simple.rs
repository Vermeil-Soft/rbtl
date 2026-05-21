use rbtl_tcp::Socket;

fn main() {
    let mut socket = Socket::new("127.0.0.1:1234").unwrap();

    for _ in 0..100 {
        socket.process();
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}