// Copyright 2019 Red Hat
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![allow(unconditional_recursion)]

mod header;

use std::collections::HashMap;
use std::os::raw::{c_int, c_void};
use std::sync::{Arc, RwLock};

use lazy_static::lazy_static;

// This redefinition is due to the following bindgen bug:
// https://github.com/rust-lang/rust-bindgen/issues/1594
const IPPROTO_TLS: c_int = header::IPPROTO_TLS as c_int;

// ============================================================================
// Index Implementation

type Index = RwLock<HashMap<c_int, Arc<RwLock<Socket>>>>;

trait Indexed {
    fn del(&self, fd: c_int) -> bool;
    fn put(&self, fd: c_int, socket: Socket);
    fn get(&self, fd: c_int) -> Option<Arc<RwLock<Socket>>>;
}

impl Indexed for Index {
    fn del(&self, fd: c_int) -> bool {
        let mut lock = self.write().unwrap();
        lock.remove(&fd).is_some()
    }

    fn put(&self, fd: c_int, socket: Socket) {
        let mut lock = self.write().unwrap();
        lock.insert(fd, Arc::new(RwLock::new(socket)));
    }

    fn get(&self, fd: c_int) -> Option<Arc<RwLock<Socket>>> {
        let lock = self.read().unwrap();
        Some(lock.get(&fd)?.clone())
    }
}

lazy_static! {
    static ref INDEX: Index = RwLock::new(HashMap::new());
}

// ============================================================================

#[derive(Copy, Clone)]
struct Parameters {
    client: bool,
}

enum Socket {
    Created,

    Bound(Parameters),
    Listening(Parameters),
    Connected,
    Established,

    Client(rustls::ClientSession),
    Server(rustls::ServerSession),
    Shutdown,
}

fn error<T>(errno: c_int, rv: T) -> T {
    errno::set_errno(errno::Errno(errno));
    rv
}

#[inline]
unsafe fn lookup<T: Copy>(name: &'static str) -> T {
    use std::hint::unreachable_unchecked;
    // We don't use a null byte in our `name`, so we use `unreachable_unchecked` and safe some bytes.
    let n = std::ffi::CString::new(name).unwrap_or_else(|_| unreachable_unchecked());
    let f = libc::dlsym(libc::RTLD_NEXT, n.as_ptr());
    assert!(!f.is_null());
    std::mem::transmute_copy(&*f)
}

#[no_mangle]
pub extern "C" fn accept(
    fd: c_int,
    addr: *mut libc::sockaddr,
    addr_len: *mut libc::socklen_t,
) -> c_int {
    accept4(fd, addr, addr_len, 0)
}

lazy_static! {
    static ref ACCEPT4_NEXT: extern "C" fn(
        fd: c_int,
        addr: *mut libc::sockaddr,
        addr_len: *mut libc::socklen_t,
        flags: c_int,
    ) -> c_int = unsafe { lookup("accept4") };
}

#[no_mangle]
pub extern "C" fn accept4(
    fd: c_int,
    addr: *mut libc::sockaddr,
    addr_len: *mut libc::socklen_t,
    flags: c_int,
) -> c_int {
    let con = ACCEPT4_NEXT(fd, addr, addr_len, flags);

    // If this isn't a TLS socket, just return.
    let lock = match INDEX.get(fd) {
        None => return con,
        Some(s) => s,
    };

    let _sock = lock.write().unwrap();

    // TODO: update TLS context here...

    -1 as c_int
}

lazy_static! {
    static ref BIND_NEXT: extern "C" fn(fd: c_int, addr: *const libc::sockaddr, len: libc::socklen_t) -> c_int =
        unsafe { lookup("bind") };
}

#[no_mangle]
pub extern "C" fn bind(fd: c_int, addr: *const libc::sockaddr, len: libc::socklen_t) -> c_int {
    let lock = match INDEX.get(fd) {
        None => return BIND_NEXT(fd, addr, len),
        Some(s) => s,
    };

    let mut sock = lock.write().unwrap();

    if let Socket::Created = *sock {
        return match BIND_NEXT(fd, addr, len) {
            0 => {
                *sock = Socket::Bound(Parameters { client: false });
                0
            }
            r => r,
        };
    }

    error(libc::EBADFD, -1)
}

lazy_static! {
    static ref SEND_NEXT: extern "C" fn(fd: c_int, buf: *const c_void, n: usize, flags: c_int) -> isize =
        unsafe { lookup("send") };
}

#[no_mangle]
pub extern "C" fn send(fd: c_int, buf: *const c_void, n: usize, flags: c_int) -> isize {
    match INDEX.get(fd) {
        None => return SEND_NEXT(fd, buf, n, flags),
        Some(s) => (),
    }

    match flags {
        0 => 0, //TODO: tls_write() implement
        _ => error(libc::EINVAL, -1),
    }
}

lazy_static! {
    static ref SENDTO_NEXT: extern "C" fn(
        fd: c_int,
        buf: *const c_void,
        n: usize,
        flags: c_int,
        addr: *const libc::sockaddr,
        addr_len: libc::socklen_t,
    ) -> isize = unsafe { lookup("sendto") };
}

#[no_mangle]
pub extern "C" fn sendto(
    fd: c_int,
    buf: *const c_void,
    n: usize,
    flags: c_int,
    addr: *const libc::sockaddr,
    addr_len: libc::socklen_t,
) -> isize {
    if addr.is_null() && addr_len == 0 {
        return send(fd, buf, n, flags);
    }

    match INDEX.get(fd) {
        Some(_) => error(libc::ENOSYS, -1),
        None => SENDTO_NEXT(fd, buf, n, flags, addr, addr_len),
    }
}

lazy_static! {
    static ref SENDMSG_NEXT: extern "C" fn(fd: c_int, message: *const c_void, flags: c_int) -> isize =
        unsafe { lookup("sendmsg") };
}

#[no_mangle]
pub extern "C" fn sendmsg(fd: c_int, message: *const c_void, flags: c_int) -> isize {
    match INDEX.get(fd) {
        Some(_) => error(libc::ENOSYS, -1isize),
        None => SENDMSG_NEXT(fd, message, flags),
    }
}

lazy_static! {
    static ref SOCKET_NEXT: extern "C" fn(domain: c_int, socktype: c_int, protocol: c_int) -> c_int =
        unsafe { lookup("socket") };
}

#[no_mangle]
pub extern "C" fn socket(domain: c_int, socktype: c_int, protocol: c_int) -> c_int {
    let protocol = if protocol == IPPROTO_TLS {
        libc::IPPROTO_TCP
    } else {
        protocol
    };

    let fd = SOCKET_NEXT(domain, socktype, protocol);
    if fd >= 0 && protocol == IPPROTO_TLS {
        INDEX.put(fd, Socket::Created)
    }

    fd
}

//#[no_mangle]
//pub extern "C" fn write(
// fd: c_int,
// buf: *const c_void,
// count: usize,
// ) -> isize {
//}
lazy_static! {
    static ref CONNECT_NEXT: extern "C" fn(fd: c_int, addr: *const libc::sockaddr, len: libc::socklen_t) -> c_int =
        unsafe { lookup("connect") };
}

#[no_mangle]
pub extern "C" fn connect(fd: c_int, addr: *const libc::sockaddr, len: libc::socklen_t) -> c_int {
    let lock = match INDEX.get(fd) {
        None => return CONNECT_NEXT(fd, addr, len),
        Some(s) => s,
    };

    let mut sock = lock.write().unwrap();

    if let Socket::Created = *sock {
        return match CONNECT_NEXT(fd, addr, len) {
            0 => {
                *sock = Socket::Connected;
                0
            }
            r => r,
        };
    }

    error(libc::EBADFD, -1)
}
lazy_static! {
    static ref RECV_NEXT: extern "C" fn(fd: c_int, buf: *mut c_void, n: usize, flags: c_int) -> isize =
        unsafe { lookup("recv") };
}

#[no_mangle]
pub extern "C" fn recv(fd: c_int, buf: *mut c_void, n: usize, flags: c_int) -> isize {
    match INDEX.get(fd) {
        None => return RECV_NEXT(fd, buf, n, flags),
        Some(s) => (),
    }

    match flags {
        0 => 0, //TODO: tls_read() implement
        _ => error(libc::EINVAL, -1),
    }
}
lazy_static! {
    static ref RECVFROM_NEXT: extern "C" fn(
        fd: c_int,
        buf: *mut c_void,
        n: usize,
        flags: c_int,
        addr: *mut libc::sockaddr,
        addr_len: *mut libc::socklen_t,
    ) -> isize = unsafe { lookup("recvfrom") };
}

#[no_mangle]
pub extern "C" fn recvfrom(
    fd: c_int,
    buf: *mut c_void,
    n: usize,
    flags: c_int,
    addr: *mut libc::sockaddr,
    addr_len: *mut libc::socklen_t,
) -> isize {
    if addr.is_null() && addr_len.is_null() {
        return recv(fd, buf, n, flags);
    }

    match INDEX.get(fd) {
        None => RECVFROM_NEXT(fd, buf, n, flags, addr, addr_len),
        Some(_) => error(libc::ENOSYS, -1),
    }
}
/*
#[no_mangle]
pub extern "C" fn getsockopt(
    fd: c_int,
    level: c_int,
    optname: c_int,
    optval: *mut c_void,
    optlen: *mut socklen_t,
) -> c_int {
}
*/
lazy_static! {
    static ref SETSOCKOPT_NEXT: extern "C" fn(
        fd: c_int,
        level: c_int,
        optname: c_int,
        optval: *const c_void,
        optlen: libc::socklen_t,
    ) -> c_int = unsafe { lookup("setsockopt") };
}

#[no_mangle]
pub extern "C" fn setsockopt(
    fd: c_int,
    level: c_int,
    optname: c_int,
    optval: *const c_void,
    optlen: libc::socklen_t,
) -> c_int {
    if level == IPPROTO_TLS {
        match INDEX.get(fd) {
            None => return error(libc::EINVAL, -1),
            Some(s) => (),
        }

        match optname {
            _ => (), // TODO:TLS level case definition
        }
    }

    if level != libc::SOL_SOCKET || optname != libc::SO_PROTOCOL {
        return SETSOCKOPT_NEXT(fd, level, optname, optval, optlen);
    }

    if optlen != std::mem::size_of::<c_int>() as libc::socklen_t {
        return error(libc::EINVAL, -1);
    }

    let protocol = optval as *const c_int;

    if unsafe { *protocol == IPPROTO_TLS } {
        -1 // TODO: Create the new TLS instance
    } else {
        match INDEX.del(fd) {
            false => {
                let error_number: i32 = errno::errno().into();
                if error_number == libc::ENOENT {
                    return error(libc::EALREADY, -1);
                }
                -1
            }
            true => 0,
        }
    }
}

lazy_static! {
    static ref LISTEN_NEXT: extern "C" fn(fd: c_int, n: c_int) -> c_int =
        unsafe { lookup("listen") };
}

#[no_mangle]
pub extern "C" fn listen(fd: c_int, n: c_int) -> c_int {
    let lock = match INDEX.get(fd) {
        Some(s) => s,
        None => return LISTEN_NEXT(fd, n),
    };

    let mut sock = lock.write().unwrap();

    if let Socket::Bound(p) = *sock {
        return match LISTEN_NEXT(fd, n) {
            0 => {
                *sock = Socket::Listening(p);
                0
            }
            r => r,
        };
    }

    error(libc::EBADFD, -1)
}
lazy_static! {
    static ref SHUTDOWN_NEXT: extern "C" fn(fd: c_int, how: c_int) -> c_int =
        unsafe { lookup("shutdown") };
}

#[no_mangle]
pub extern "C" fn shutdown(fd: c_int, how: c_int) -> c_int {
    let lock = match INDEX.get(fd) {
        None => return SHUTDOWN_NEXT(fd, how),
        Some(s) => s,
    };

    let mut sock = lock.write().unwrap();

    if let Socket::Established = *sock {
        return match SHUTDOWN_NEXT(fd, how) {
            0 => {
                *sock = Socket::Shutdown;
                0
            }
            r => r,
        };
    }

    error(libc::EBADFD, -1)
}
