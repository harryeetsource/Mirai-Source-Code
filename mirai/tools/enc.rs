use std::env;
use std::net::Ipv4Addr;
use std::num::ParseIntError;

static TABLE_KEY: u32 = 0xdeadbeef;

fn x(data: &mut [u8]) {
    let k1 = (TABLE_KEY & 0xff) as u8;
    let k2 = ((TABLE_KEY >> 8) & 0xff) as u8;
    let k3 = ((TABLE_KEY >> 16) & 0xff) as u8;
    let k4 = ((TABLE_KEY >> 24) & 0xff) as u8;

    for byte in data.iter_mut() {
        *byte ^= k1;
        *byte ^= k2;
        *byte ^= k3;
        *byte ^= k4;
    }
}

fn main() -> Result<(), ParseIntError> {
    let args: Vec<String> = env::args().collect();

    if args.len() != 3 {
        println!("Usage: {} <string | ip | uint32 | uint16 | uint8 | bool> <data>", args[0]);
        return Ok(());
    }

    let data_type = &args[1];
    let data_value = &args[2];
    let mut data: Vec<u8>;

    match data_type.as_str() {
        "string" => {
            data = data_value.as_bytes().to_vec();
        }
        "ip" => {
            let ip: Ipv4Addr = data_value.parse().unwrap_or(Ipv4Addr::UNSPECIFIED);
            data = ip.octets().to_vec();
        }
        "uint32" => {
            let value: u32 = data_value.parse()?;
            data = value.to_be_bytes().to_vec();
        }
        "uint16" => {
            let value: u16 = data_value.parse()?;
            data = value.to_be_bytes().to_vec();
        }
        "uint8" => {
            let value: u8 = data_value.parse()?;
            data = vec![value];
        }
        "bool" => {
            data = vec![if data_value == "true" { 1 } else { 0 }];
        }
        _ => {
            println!("Unknown data type `{}`!", data_type);
            return Ok(());
        }
    }

    println!("XOR'ing {} bytes of data...", data.len());
    x(&mut data);
    for byte in &data {
        print!("\\x{:02X}", byte);
    }
    println!();

    Ok(())
}
