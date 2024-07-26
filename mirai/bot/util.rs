use std::ffi::CString;
use std::io::{self, Read};
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::os::unix::io::AsRawFd;
use std::str;

fn util_strlen(s: &str) -> usize {
    s.len()
}

fn util_strncmp(str1: &str, str2: &str, len: usize) -> bool {
    str1.chars().take(len).eq(str2.chars().take(len))
}

fn util_strcmp(str1: &str, str2: &str) -> bool {
    str1 == str2
}

fn util_strcpy(dst: &mut String, src: &str) -> usize {
    dst.clear();
    dst.push_str(src);
    src.len()
}

fn util_memcpy(dst: &mut [u8], src: &[u8]) {
    dst[..src.len()].copy_from_slice(src);
}

fn util_zero(buf: &mut [u8]) {
    buf.fill(0);
}

fn util_atoi(s: &str, base: i32) -> i64 {
    let is_negative = s.starts_with('-');
    let trimmed = s.trim_start_matches('-').trim_start_matches('+');
    let mut acc = 0;
    let mut any = false;

    for c in trimmed.chars() {
        let digit = c.to_digit(base as u32).unwrap_or_else(|| {
            if c.is_ascii_alphabetic() {
                c.to_digit(36).unwrap() - 10
            } else {
                0
            }
        });

        if digit < (base as u32) {
            any = true;
            acc = acc * base as i64 + digit as i64;
        } else {
            break;
        }
    }

    if any {
        if is_negative {
            -acc
        } else {
            acc
        }
    } else {
        0
    }
}

fn util_itoa(value: i32, radix: i32, buf: &mut String) -> &str {
    buf.clear();
    let mut value = value;
    if value < 0 && radix == 10 {
        buf.push('-');
        value = -value;
    }

    let mut digits = vec![];
    while value != 0 {
        let digit = (value % radix) as u8;
        let ch = if digit < 10 {
            digit + b'0'
        } else {
            digit - 10 + b'A'
        };
        digits.push(ch);
        value /= radix;
    }

    if digits.is_empty() {
        buf.push('0');
    } else {
        for &ch in digits.iter().rev() {
            buf.push(ch as char);
        }
    }

    buf
}

fn util_memsearch(buf: &[u8], mem: &[u8]) -> Option<usize> {
    buf.windows(mem.len()).position(|window| window == mem)
}

fn util_stristr(haystack: &str, needle: &str) -> Option<usize> {
    haystack.to_lowercase().find(&needle.to_lowercase())
}

fn util_local_addr() -> Option<Ipv4Addr> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:53").ok()?;
    socket.local_addr().ok().and_then(|addr| match addr {
        SocketAddr::V4(addr) => Some(*addr.ip()),
        SocketAddr::V6(_) => None,
    })
}

fn util_fdgets(buffer: &mut String, fd: i32) -> io::Result<usize> {
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    let mut buf = [0u8; 1];
    let mut total = 0;

    while total < buffer.capacity() && file.read(&mut buf)? == 1 {
        buffer.push(buf[0] as char);
        total += 1;
        if buf[0] == b'\n' {
            break;
        }
    }

    Ok(total)
}

fn util_isupper(c: char) -> bool {
    c.is_ascii_uppercase()
}

fn util_isalpha(c: char) -> bool {
    c.is_ascii_alphabetic()
}

fn util_isspace(c: char) -> bool {
    c.is_ascii_whitespace()
}

fn util_isdigit(c: char) -> bool {
    c.is_ascii_digit()
}
