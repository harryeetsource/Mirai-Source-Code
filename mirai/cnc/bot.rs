use std::net::TcpStream;
use std::io::{Read, Write};
use std::sync::Arc;
use std::time::Duration;
use std::sync::Mutex;

struct Bot {
    uid: i32,
    conn: Arc<Mutex<TcpStream>>,
    version: u8,
    source: String,
}

impl Bot {
    fn new(conn: TcpStream, version: u8, source: String) -> Self {
        Bot {
            uid: -1,
            conn: Arc::new(Mutex::new(conn)),
            version,
            source,
        }
    }

    fn handle(&self) {
        // Assuming `client_list` is accessible here, e.g., via Arc<Mutex<ClientList>>
        let client_list = client_list.clone(); // Clone the Arc to use in the closure
        
        client_list.add_client(self.clone()); // Add client to the list
        let client_list = client_list.clone(); // Clone the Arc to use in the closure

        let conn = self.conn.clone();
        std::thread::spawn(move || {
            let mut buf = [0u8; 2];
            loop {
                let mut stream = conn.lock().unwrap();
                if let Err(_) = stream.set_read_timeout(Some(Duration::new(180, 0))) {
                    break;
                }
                let n = match stream.read(&mut buf) {
                    Ok(n) if n == buf.len() => n,
                    _ => break,
                };
                if let Err(_) = stream.write_all(&buf) {
                    break;
                }
            }
            client_list.del_client(self.clone()); // Remove client from the list
        });
    }

    fn queue_buf(&self, buf: &[u8]) {
        let mut stream = self.conn.lock().unwrap();
        let _ = stream.write_all(buf);
    }
}
