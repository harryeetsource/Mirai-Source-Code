use std::net::{Ipv4Addr, SocketAddrV4};
use std::str::FromStr;
use std::convert::TryInto;

#[derive(Debug, Default)]
struct TelnetInfo {
    user: String,
    pass: String,
    arch: String,
    addr: Ipv4Addr,
    port: u16,
    has_auth: bool,
    has_arch: bool,
}

impl TelnetInfo {
    fn new(user: Option<&str>, pass: Option<&str>, arch: Option<&str>, addr: Ipv4Addr, port: u16) -> Self {
        let has_auth = user.is_some() || pass.is_some();
        let has_arch = arch.is_some();
        
        TelnetInfo {
            user: user.unwrap_or("").to_string(),
            pass: pass.unwrap_or("").to_string(),
            arch: arch.unwrap_or("").to_string(),
            addr,
            port,
            has_auth,
            has_arch,
        }
    }

    fn parse(input: &str) -> Option<Self> {
        let parts: Vec<&str> = input.split_whitespace().collect();
        if parts.len() < 2 {
            return None;
        }

        let conn = parts[0];
        let auth = parts[1];
        let arch = parts.get(2).map(|&s| s);

        let conn_parts: Vec<&str> = conn.split(':').collect();
        if conn_parts.len() != 2 {
            return None;
        }
        let addr_str = conn_parts[0];
        let port_str = conn_parts[1];

        let addr = Ipv4Addr::from_str(addr_str).ok()?;
        let port: u16 = port_str.parse().ok()?;

        let (user, pass) = if auth.len() == 1 {
            if auth == ":" {
                ("", "")
            } else if auth != "?" {
                return None;
            } else {
                (auth, "")
            }
        } else {
            let auth_parts: Vec<&str> = auth.split(':').collect();
            if auth_parts.len() != 2 {
                return None;
            }
            (auth_parts[0], auth_parts[1])
        };

        Some(TelnetInfo::new(Some(user), Some(pass), arch, addr, port))
    }
}
