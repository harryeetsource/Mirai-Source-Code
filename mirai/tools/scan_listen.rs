use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;
use std::thread;

fn main() -> io::Result<()> {
    let listener = TcpListener::bind("0.0.0.0:48101")?;
    println!("Server listening on port 48101");

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                thread::spawn(move || {
                    handle_connection(stream).unwrap_or_else(|err| eprintln!("Error handling connection: {}", err));
                });
            }
            Err(e) => {
                eprintln!("Connection failed: {}", e);
            }
        }
    }
    Ok(())
}

fn handle_connection(mut stream: TcpStream) -> io::Result<()> {
    stream.set_read_timeout(Some(Duration::new(10, 0)))?;

    let buf_chk = read_x_bytes(&mut stream, 1)?;
    let mut ip_int: u32;
    let mut port_int: u16;

    if buf_chk[0] == 0 {
        let ip_buf = read_x_bytes(&mut stream, 4)?;
        ip_int = u32::from_be_bytes([ip_buf[0], ip_buf[1], ip_buf[2], ip_buf[3]]);

        let port_buf = read_x_bytes(&mut stream, 2)?;
        port_int = u16::from_be_bytes([port_buf[0], port_buf[1]]);
    } else {
        let ip_buf = read_x_bytes(&mut stream, 3)?;
        let mut full_ip_buf = [0u8; 4];
        full_ip_buf[..1].copy_from_slice(&buf_chk);
        full_ip_buf[1..].copy_from_slice(&ip_buf);
        ip_int = u32::from_be_bytes(full_ip_buf);

        port_int = 23;
    }

    let u_len_buf = read_x_bytes(&mut stream, 1)?;
    let username_buf = read_x_bytes(&mut stream, u_len_buf[0] as usize)?;

    let p_len_buf = read_x_bytes(&mut stream, 1)?;
    let password_buf = read_x_bytes(&mut stream, p_len_buf[0] as usize)?;

    println!(
        "{}.{}.{}.{}:{} {}:{}",
        (ip_int >> 24) & 0xff,
        (ip_int >> 16) & 0xff,
        (ip_int >> 8) & 0xff,
        ip_int & 0xff,
        port_int,
        String::from_utf8_lossy(&username_buf),
        String::from_utf8_lossy(&password_buf)
    );

    Ok(())
}

fn read_x_bytes(stream: &mut TcpStream, amount: usize) -> io::Result<Vec<u8>> {
    let mut buf = vec![0; amount];
    let mut total_read = 0;

    while total_read < amount {
        match stream.read(&mut buf[total_read..]) {
            Ok(0) => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "unexpected EOF")),
            Ok(n) => total_read += n,
            Err(e) => return Err(e),
        }
    }

    Ok(buf)
}
