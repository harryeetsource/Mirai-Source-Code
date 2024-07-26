use std::convert::TryInto;

// Equivalent to struct dnshdr in Rust
#[repr(C, packed)]
pub struct DnsHdr {
    pub id: u16,
    pub opts: u16,
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}

// Equivalent to struct dns_question in Rust
#[repr(C)]
pub struct DnsQuestion {
    pub qtype: u16,
    pub qclass: u16,
}

// Equivalent to struct dns_resource in Rust
#[repr(C, packed)]
pub struct DnsResource {
    pub type_: u16,
    pub class: u16,
    pub ttl: u32,
    pub data_len: u16,
}

// Equivalent to struct grehdr in Rust
#[repr(C)]
pub struct GreHdr {
    pub opts: u16,
    pub protocol: u16,
}

// Constants for DNS query types and classes
pub const PROTO_DNS_QTYPE_A: u16 = 1;
pub const PROTO_DNS_QCLASS_IP: u16 = 1;

// Constants for TCP options
pub const PROTO_TCP_OPT_NOP: u8 = 1;
pub const PROTO_TCP_OPT_MSS: u8 = 2;
pub const PROTO_TCP_OPT_WSS: u8 = 3;
pub const PROTO_TCP_OPT_SACK: u8 = 4;
pub const PROTO_TCP_OPT_TSVAL: u8 = 8;

// Constants for GRE protocol types
pub const PROTO_GRE_TRANS_ETH: u16 = 0x6558;
