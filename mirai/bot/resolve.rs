use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::io::{self, Write};
use std::ptr;
use std::os::unix::io::AsRawFd;
use libc::{fcntl, F_GETFL, F_SETFL, O_NONBLOCK};
use rand::Rng;

#[repr(C)]
struct DnsHeader {
    id: u16,
    flags: u16,
    qdcount: u16,
    ancount: u16,
    nscount: u16,
    arcount: u16,
}

#[repr(C)]
struct DnsQuestion {
    qtype: u16,
    qclass: u16,
}

#[repr(C)]
struct DnsResource {
    name: u16,
    _type: u16,
    _class: u16,
    ttl: u32,
    data_len: u16,
}

struct ResolvEntries {
    addrs_len: u8,
    addrs: Vec<Ipv4Addr>,
}

fn resolv_domain_to_hostname(dst_hostname: &mut [u8], src_domain: &str) {
    let mut lbl = 0;
    let mut curr_len = 0;

    for (i, &c) in src_domain.as_bytes().iter().enumerate() {
        if c == b'.' || c == b'\0' {
            dst_hostname[lbl] = curr_len;
            lbl = i + 1;
            curr_len = 0;
        } else {
            curr_len += 1;
            dst_hostname[i + 1] = c;
        }
    }
    dst_hostname[lbl] = curr_len;
}

fn resolv_skip_name(reader: &mut &[u8], buffer: &[u8], count: &mut usize) {
    let mut jumped = false;
    *count = 1;
    while reader[0] != 0 {
        if reader[0] >= 192 {
            let offset = ((reader[0] as usize) << 8 | reader[1] as usize) - 49152;
            *reader = &buffer[offset..];
            jumped = true;
        }
        *reader = &reader[1..];
        if !jumped {
            *count += 1;
        }
    }

    if jumped {
        *count += 1;
    }
}

fn resolv_lookup(domain: &str) -> Option<ResolvEntries> {
    let mut entries = ResolvEntries {
        addrs_len: 0,
        addrs: Vec::new(),
    };

    let mut query = [0u8; 2048];
    let mut response = [0u8; 2048];
    let dnsh = unsafe { &mut *(query.as_mut_ptr() as *mut DnsHeader) };
    let qname = &mut query[std::mem::size_of::<DnsHeader>()..];

    resolv_domain_to_hostname(qname, domain);

    let dnst = unsafe { &mut *(qname[qname.iter().position(|&c| c == 0).unwrap() + 1..].as_mut_ptr() as *mut DnsQuestion) };
    let addr = SocketAddr::new(Ipv4Addr::new(8, 8, 8, 8), 53);

    dnsh.id = rand::thread_rng().gen();
    dnsh.flags = 1 << 8;
    dnsh.qdcount = 1;
    dnst.qtype = 1;  // A record
    dnst.qclass = 1; // IN class

    for _ in 0..5 {
        let socket = UdpSocket::bind("0.0.0.0:0").expect("Failed to create socket");
        socket.set_nonblocking(true).expect("Failed to set non-blocking");

        let fd = socket.as_raw_fd();
        unsafe {
            fcntl(fd, F_SETFL, O_NONBLOCK | fcntl(fd, F_GETFL, 0));
        }

        socket.connect(addr).expect("Failed to connect socket");
        socket.send(&query).expect("Failed to send query");

        let mut fds = libc::fd_set {
            __fds_bits: [0; libc::FD_SETSIZE / (8 * std::mem::size_of::<libc::c_long>())],
        };
        unsafe { libc::FD_SET(fd, &mut fds) };

        let mut timeout = libc::timeval {
            tv_sec: 5,
            tv_usec: 0,
        };

        let ret = unsafe { libc::select(fd + 1, &mut fds, ptr::null_mut(), ptr::null_mut(), &mut timeout) };

        if ret > 0 && unsafe { libc::FD_ISSET(fd, &mut fds) } {
            let ret = socket.recv(&mut response).expect("Failed to receive response");
            let dnsh = unsafe { &*(response.as_ptr() as *const DnsHeader) };
            let qname = &response[std::mem::size_of::<DnsHeader>()..];
            let dnst = unsafe { &*(qname[qname.iter().position(|&c| c == 0).unwrap() + 1..].as_ptr() as *const DnsQuestion) };

            if dnsh.id != dnsh.id {
                continue;
            }

            let mut name = &response[std::mem::size_of::<DnsHeader>() + qname.len() + 1 + std::mem::size_of::<DnsQuestion>()..];
            let mut ancount = dnsh.ancount;

            while ancount > 0 {
                let mut stop = 0;
                resolv_skip_name(&mut name, &response, &mut stop);
                name = &name[stop..];

                let r_data = unsafe { &*(name.as_ptr() as *const DnsResource) };
                name = &name[std::mem::size_of::<DnsResource>()..];

                if r_data._type == 1 && r_data._class == 1 && r_data.data_len == 4 {
                    let addr = Ipv4Addr::new(name[0], name[1], name[2], name[3]);
                    entries.addrs.push(addr);
                    entries.addrs_len += 1;
                }

                name = &name[r_data.data_len as usize..];
                ancount -= 1;
            }

            break;
        }
    }

    if entries.addrs_len > 0 {
        Some(entries)
    } else {
        None
    }
}

fn resolv_entries_free(entries: Option<ResolvEntries>) {
    if let Some(_) = entries {
        // Entries are automatically cleaned up when the Vec goes out of scope
    }
}


