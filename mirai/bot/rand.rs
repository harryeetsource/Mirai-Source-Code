use std::time::{SystemTime, UNIX_EPOCH};
use std::process;
use std::ptr;
use rand::Rng;

static mut X: u32 = 0;
static mut Y: u32 = 0;
static mut Z: u32 = 0;
static mut W: u32 = 0;

pub fn rand_init() {
    unsafe {
        X = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs() as u32;
        Y = process::id();
        Z = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_nanos() as u32;
        W = Z ^ Y;
    }
}

pub fn rand_next() -> u32 {
    unsafe {
        let t = X;
        let t = t ^ (t << 11);
        let t = t ^ (t >> 8);
        X = Y;
        Y = Z;
        Z = W;
        W = W ^ (W >> 19);
        W = W ^ t;
        W
    }
}

pub fn rand_str(buf: &mut [u8]) {
    let len = buf.len();
    let mut idx = 0;
    while idx < len {
        if len - idx >= 4 {
            let rnd = rand_next();
            buf[idx..idx + 4].copy_from_slice(&rnd.to_ne_bytes());
            idx += 4;
        } else if len - idx >= 2 {
            let rnd = (rand_next() & 0xFFFF) as u16;
            buf[idx..idx + 2].copy_from_slice(&rnd.to_ne_bytes());
            idx += 2;
        } else {
            buf[idx] = (rand_next() & 0xFF) as u8;
            idx += 1;
        }
    }
}

pub fn rand_alphastr(buf: &mut [u8]) {
    const ALPHASET: &[u8] = b"abcdefghijklmnopqrstuvw012345678";

    let len = buf.len();
    let mut idx = 0;
    while idx < len {
        if len - idx >= 4 {
            let mut entropy = rand_next();
            for _ in 0..4 {
                let tmp = (entropy & 0xFF) >> 3;
                buf[idx] = ALPHASET[tmp as usize];
                idx += 1;
                entropy >>= 8;
            }
        } else {
            buf[idx] = ALPHASET[(rand_next() % ALPHASET.len() as u32) as usize];
            idx += 1;
        }
    }
}
