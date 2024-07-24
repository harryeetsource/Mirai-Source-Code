use std::io::{self, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpStream};
use std::os::unix::io::AsRawFd;
use std::str;

const BUFFER_SIZE: usize = 1024;

fn hex_dump(desc: Option<&str>, addr: &[u8]) {
    let len = addr.len();
    if let Some(d) = desc {
        println!("{}:", d);
    }

    if len == 0 {
        println!("  ZERO LENGTH");
        return;
    }

    if len < 0 {
        println!("  NEGATIVE LENGTH: {}", len);
        return;
    }

    let mut buff = [0; 17];
    for i in 0..len {
        if i % 16 == 0 {
            if i != 0 {
                println!("  {}", unsafe { std::ffi::CStr::from_ptr(buff.as_ptr()) }.to_string_lossy());
            }
            print!("  {:04x} ", i);
        }

        print!(" {:02x}", addr[i]);

        buff[i % 16] = if addr[i] < 0x20 || addr[i] > 0x7e {
            b'.'
        } else {
            addr[i]
        };
        buff[(i % 16) + 1] = 0;
    }

    while (len % 16) != 0 {
        print!("   ");
        len += 1;
    }

    println!("  {}", unsafe { std::ffi::CStr::from_ptr(buff.as_ptr()) }.to_string_lossy());
}

fn util_socket_and_bind(bind_addrs: &[Ipv4Addr]) -> io::Result<TcpStream> {
    let mut bound = false;
    let mut bind_addr = SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0);

    let fd = TcpStream::bind(bind_addr)?;
    let start_addr = rand::random::<usize>() % bind_addrs.len();

    for i in 0..bind_addrs.len() {
        bind_addr.set_ip(bind_addrs[(start_addr + i) % bind_addrs.len()]);
        if fd.bind(bind_addr).is_ok() {
            bound = true;
            break;
        }
    }

    if !bound {
        return Err(io::Error::new(io::ErrorKind::Other, "Failed to bind on any address"));
    }

    fd.set_nonblocking(true)?;
    Ok(fd)
}

fn util_memsearch(buf: &[u8], mem: &[u8]) -> Option<usize> {
    buf.windows(mem.len()).position(|window| window == mem)
}

fn util_sockprintf(fd: &TcpStream, fmt: &str, args: std::fmt::Arguments) -> io::Result<()> {
    let mut buffer = vec![0; BUFFER_SIZE + 2];
    let len = std::fmt::write(&mut buffer, args)?;

    if len > 0 {
        let len = len.min(BUFFER_SIZE);

        #[cfg(debug_assertions)]
        hex_dump(Some("TELOUT"), &buffer[..len]);

        fd.write_all(&buffer[..len])?;
    }

    Ok(())
}

fn util_trim(s: &str) -> &str {
    s.trim()
}
