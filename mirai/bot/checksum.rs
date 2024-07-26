use std::net::Ipv4Addr;
use std::convert::TryInto;

fn checksum_generic(addr: &[u16]) -> u16 {
    let mut sum: u32 = 0;

    for &val in addr {
        sum += u32::from(val);
    }

    if addr.len() % 2 == 1 {
        sum += u32::from(addr[addr.len() - 1] & 0xFF00);
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
}

fn checksum_tcpudp(iph: &iphdr, buff: &[u8], data_len: u16, len: usize) -> u16 {
    let mut sum: u32 = 0;
    let buf: &[u16] = &buff.chunks(2).map(|chunk| {
        if chunk.len() == 2 {
            u16::from_ne_bytes(chunk.try_into().unwrap())
        } else {
            u16::from(chunk[0]) << 8
        }
    }).collect::<Vec<u16>>();

    for &val in buf {
        sum += u32::from(val);
    }

    if len % 2 == 1 {
        sum += u32::from(buf[len / 2] & 0xFF00);
    }

    let ip_src = u32::from_ne_bytes(iph.saddr.octets());
    let ip_dst = u32::from_ne_bytes(iph.daddr.octets());

    sum += (ip_src >> 16) & 0xFFFF;
    sum += ip_src & 0xFFFF;
    sum += (ip_dst >> 16) & 0xFFFF;
    sum += ip_dst & 0xFFFF;
    sum += u32::from(iph.protocol) << 8;
    sum += u32::from(data_len);

    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
}

#[derive(Debug)]
struct iphdr {
    saddr: Ipv4Addr,
    daddr: Ipv4Addr,
    protocol: u8,
}
