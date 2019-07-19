#![allow(unconditional_recursion)]

mod header;

use std::os::raw::{c_int, c_void};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use lazy_static::lazy_static;

// This redefinition is due to the following bindgen bug:
// https://github.com/rust-lang/rust-bindgen/issues/1594
const IPPROTO_TLS: c_int = header::IPPROTO_TLS as c_int;

// ============================================================================
// Index Implementation

type Index = RwLock<HashMap<c_int, Arc<RwLock<Socket>>>>;

trait Indexed {
    fn del(&self, fd: c_int);
    fn put(&self, fd: c_int, socket: Socket);
    fn get(&self, fd: c_int) -> Option<Arc<RwLock<Socket>>>;
}

impl Indexed for Index {
    fn del(&self, fd: c_int) {
        let mut lock = self.write().unwrap();
        lock.remove(&fd);
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
    Shutdown
}

fn error<T>(errno: c_int, rv: T) -> T {
    errno::set_errno(errno::Errno(errno));
    rv
}

#[inline]
unsafe fn lookup<T>(_: T, name: &'static str) -> T {
    let n = std::ffi::CString::new(name).unwrap();
    let f = libc::dlsym(libc::RTLD_NEXT, n.as_ptr());
    assert!(!f.is_null());
    std::mem::transmute_copy(&*f)
}

macro_rules! next {
    ($name:ident($($arg:expr),*)) => {
        unsafe {
            lookup($name, stringify!($name))($($arg),*)
        }
    };
}

#[no_mangle]
pub extern "C" fn accept(
    fd: c_int,
    addr: *mut libc::sockaddr,
    addr_len: *mut libc::socklen_t,
) -> c_int {
    accept4(fd, addr, addr_len, 0)
}

#[no_mangle]
pub extern "C" fn accept4(
    fd: c_int,
    addr: *mut libc::sockaddr,
    addr_len: *mut libc::socklen_t,
    flags: c_int,
) -> c_int {
    let con = next!(accept4(fd, addr, addr_len, flags));

    // If this isn't a TLS socket, just return.
    let lock = match INDEX.get(fd) {
        None => return con,
        Some(s) => s,
    };

    let sock = lock.write().unwrap();

    // TODO: update TLS context here...

    -1 as c_int
}

#[no_mangle]
pub extern "C" fn bind(
    fd: c_int,
    addr: *const libc::sockaddr,
    len: libc::socklen_t,
) -> c_int {
    let lock = match INDEX.get(fd) {
        None => return next!(bind(fd, addr, len)),
        Some(s) => s,
    };

    let mut sock = lock.write().unwrap();

    match *sock {
        Socket::Created => (),
        _ => return error(libc::EBADFD, -1),
    }

    if next!(bind(fd, addr, len)) == -1 {
        return -1;
    }

    *sock = Socket::Bound(Parameters { client: false });
    0
}

/*#[no_mangle]
pub extern "C" fn send(
    fd: c_int,
    buf: *const c_void,
    n: usize, flags: c_int,
) -> isize {
    match INDEX.get(fd) {
        Some(s) => s.send(fd, buf, n, flags),
        None => SEND(fd, buf, n, flags),
    }
}*/

/*#[no_mangle]
pub extern "C" fn sendto(
    fd: c_int,
    buf: *const c_void,
    n: usize,
    flags: c_int,
    addr: *const sockaddr,
    addr_len: socklen_t,
) -> isize {
    if addr.is_null() && addr_len == 0 {
        return send(fd, buf, n, flags);
    }

    match INDEX.get(fd) {
        Some(_) => error(libc::ENOSYS, -1isize),
        None => SENDTO(fd, buf, n, flags, addr, addr_len),
    }
}*/

#[no_mangle]
pub extern "C" fn sendmsg(
    fd: c_int,
    message: *const c_void,
    flags: c_int,
) -> isize {
    match INDEX.get(fd) {
        Some(_) => error(libc::ENOSYS, -1isize),
        None => next!(sendmsg(fd, message, flags)),
    }
}


#[no_mangle]
pub extern "C" fn socket(
    domain: c_int,
    socktype: c_int,
    protocol: c_int,
) -> c_int {
    let protocol = if protocol == IPPROTO_TLS {
        libc::IPPROTO_TCP
    } else {
        protocol
    };

    let fd = next!(socket(domain, socktype, protocol));
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




#[no_mangle]
pub extern "C" fn connect(
    fd: c_int,
    addr: *const libc::sockaddr,
    len: libc::socklen_t,
) -> c_int {
    let lock = match INDEX.get(fd) {
        None => return next!(connect(fd, addr, len)),
        Some(s) => s,
    };

    let mut sock = lock.write().unwrap();

    match *sock {
        Socket::Created => (),
        _ => return error(libc::EBADFD, -1),
    }

    if next!(connect(fd, addr, len)) == -1 {
        return -1;
    }

    *sock = Socket::Connected;
    0
}

/*

#[no_mangle]
pub extern "C" fn recv(
    fd: c_int,
    buf: *mut c_void,
    n: usize,
    flags: c_int,
) -> isize {}


#[no_mangle]
pub extern "C" fn recvfrom(
    fd: c_int,
    buf: *mut c_void,
    n: usize,
    flags: c_int,
    addr: *mut sockaddr,
    addr_len: *mut socklen_t,
) -> isize {
}

#[no_mangle]
pub extern "C" fn getsockopt(
    fd: c_int,
    level: c_int,
    optname: c_int,
    optval: *mut c_void,
    optlen: *mut socklen_t,
) -> c_int {
}

#[no_mangle]
pub extern "C" fn setsockopt(
    fd: c_int,
    level: c_int,
    optname: c_int,
    optval: *const c_void,
    optlen: socklen_t,
) -> c_int {
}*/

#[no_mangle]
pub extern "C" fn listen(fd: c_int, n: c_int) -> c_int {
    let lock = match INDEX.get(fd) {
        Some(s) => s,
        None => return next!(listen(fd, n)),
    };

    let mut sock = lock.write().unwrap();

    if let Socket::Bound(p) = *sock {
        match next!(listen(fd, n)) {
            0 => {
                *sock = Socket::Listening(p);
                return 0;
            },
            r => r,
        };
    }

    error(libc::EBADFD, -1)
}


/*#[no_mangle]
pub extern "C" fn shutdown(fd: c_int, how: c_int) -> c_int {}

*/
