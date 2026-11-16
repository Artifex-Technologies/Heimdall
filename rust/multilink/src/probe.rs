//! Health checks: a TCP connection opened through one link (bound to its device and to its address, so our source rule
//! sends it out of that link whatever the multipath route says) to a server on the internet, and closed as soon as it is
//! made. All the links are checked at once, so a round takes at most the timeout. A refused connection counts as reached:
//! something on the far side answered. Nothing is sent but the TCP handshake.

use std::net::{IpAddr, SocketAddr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::time::{Duration, Instant};

pub struct Check {
    pub dev: String,
    pub source: IpAddr,
    pub target: SocketAddr,
}

/// Each check's time to connect; None: no answer in time (or the socket could not be made).
pub fn run(checks: &[Check], timeout: Duration) -> Vec<Option<Duration>> {
    let start = Instant::now();
    let socks: Vec<Option<OwnedFd>> = checks.iter().map(start_one).collect();
    let mut done: Vec<Option<Option<Duration>>> = socks.iter().map(|s| if s.is_none() { Some(None) } else { None }).collect();
    loop {
        let waiting: Vec<usize> = (0..checks.len()).filter(|&i| done[i].is_none()).collect();
        let left = timeout.saturating_sub(start.elapsed());
        if waiting.is_empty() || left.is_zero() {
            break;
        }
        let mut fds: Vec<libc::pollfd> = waiting
            .iter()
            .map(|&i| libc::pollfd { fd: socks[i].as_ref().map_or(-1, |s| s.as_raw_fd()), events: libc::POLLOUT, revents: 0 })
            .collect();
        // SAFETY: fds is a live array of pollfd for the length given
        let n = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, left.as_millis().max(1) as libc::c_int) };
        if n < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            break;
        }
        for (k, &i) in waiting.iter().enumerate() {
            if fds[k].revents == 0 {
                continue;
            }
            let err = so_error(socks[i].as_ref().map_or(-1, |s| s.as_raw_fd()));
            done[i] = Some((err == 0 || err == libc::ECONNREFUSED).then(|| start.elapsed()));
        }
    }
    done.into_iter().map(|d| d.flatten()).collect()
}

fn so_error(fd: i32) -> i32 {
    let mut e: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: e and len are ours and sized for SO_ERROR
    let r = unsafe { libc::getsockopt(fd, libc::SOL_SOCKET, libc::SO_ERROR, (&mut e as *mut libc::c_int).cast(), &mut len) };
    if r < 0 {
        libc::EIO
    } else {
        e
    }
}

fn sockaddr(a: SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    // SAFETY: sockaddr_storage is plain data; all zeroes is a valid value
    let mut ss: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let len = match a {
        SocketAddr::V4(v4) => {
            let sin = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: v4.port().to_be(),
                sin_addr: libc::in_addr { s_addr: u32::from_ne_bytes(v4.ip().octets()) },
                sin_zero: [0; 8],
            };
            // SAFETY: sockaddr_storage is larger than sockaddr_in and suitably aligned
            unsafe { std::ptr::write((&mut ss as *mut libc::sockaddr_storage).cast(), sin) };
            std::mem::size_of::<libc::sockaddr_in>()
        }
        SocketAddr::V6(v6) => {
            let sin6 = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: v6.port().to_be(),
                sin6_flowinfo: 0,
                sin6_addr: libc::in6_addr { s6_addr: v6.ip().octets() },
                sin6_scope_id: v6.scope_id(),
            };
            // SAFETY: as above, for sockaddr_in6
            unsafe { std::ptr::write((&mut ss as *mut libc::sockaddr_storage).cast(), sin6) };
            std::mem::size_of::<libc::sockaddr_in6>()
        }
    };
    (ss, len as libc::socklen_t)
}

fn start_one(c: &Check) -> Option<OwnedFd> {
    if c.source.is_ipv4() != c.target.is_ipv4() {
        return None;
    }
    let family = if c.target.is_ipv4() { libc::AF_INET } else { libc::AF_INET6 };
    // SAFETY: a new socket of our own; wrapped in OwnedFd at once so it is closed on every path
    let fd = unsafe { libc::socket(family, libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return None;
    }
    // SAFETY: fd was just returned by socket() and is owned by nothing else
    let sock = unsafe { OwnedFd::from_raw_fd(fd) };
    let dev = c.dev.as_bytes();
    // SAFETY: the option value is the device name's bytes, with its length
    if unsafe { libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_BINDTODEVICE, dev.as_ptr().cast(), dev.len() as libc::socklen_t) } < 0 {
        return None;
    }
    let (src, slen) = sockaddr(SocketAddr::new(c.source, 0));
    // SAFETY: src holds a valid sockaddr of slen bytes
    if unsafe { libc::bind(fd, (&src as *const libc::sockaddr_storage).cast(), slen) } < 0 {
        return None;
    }
    let (dst, dlen) = sockaddr(c.target);
    // SAFETY: dst holds a valid sockaddr of dlen bytes
    let r = unsafe { libc::connect(fd, (&dst as *const libc::sockaddr_storage).cast(), dlen) };
    if r < 0 {
        let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        if e != libc::EINPROGRESS && e != libc::ECONNREFUSED {
            return None;
        }
    }
    Some(sock)
}

/// The health of one link in one address family: down after three failed checks in a row, up again after two good ones
/// (the first good one counts when the link is new).
#[derive(Clone, Debug, Default)]
pub struct Health {
    pub up: bool,
    known: bool,
    fails: u32,
    goods: u32,
    pub rtt: Option<Duration>,
}

pub const DOWN_AFTER: u32 = 3;
pub const UP_AFTER: u32 = 2;

impl Health {
    pub fn record(&mut self, r: Option<Duration>) {
        match r {
            Some(t) => {
                self.fails = 0;
                self.goods += 1;
                self.rtt = Some(t);
                if !self.known || self.goods >= UP_AFTER {
                    self.up = true;
                }
            }
            None => {
                self.goods = 0;
                self.fails += 1;
                if !self.known || self.fails >= DOWN_AFTER {
                    self.up = false;
                }
            }
        }
        self.known = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn down_after_three_fails_up_after_two_goods() {
        let mut h = Health::default();
        h.record(Some(Duration::from_millis(10)));
        assert!(h.up, "a new link is up at its first good check");
        h.record(None);
        h.record(None);
        assert!(h.up);
        h.record(None);
        assert!(!h.up);
        h.record(Some(Duration::from_millis(10)));
        assert!(!h.up);
        h.record(Some(Duration::from_millis(10)));
        assert!(h.up);
    }

    #[test]
    fn a_new_link_that_fails_is_down_at_once() {
        let mut h = Health::default();
        h.record(None);
        assert!(!h.up);
    }

    #[test]
    fn a_local_listener_answers_and_a_refusal_counts() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let open = l.local_addr().unwrap();
        drop(l);
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let checks = [
            Check { dev: "lo".into(), source: "127.0.0.1".parse().unwrap(), target: l.local_addr().unwrap() },
            Check { dev: "lo".into(), source: "127.0.0.1".parse().unwrap(), target: open },
            Check { dev: "lo".into(), source: "::1".parse().unwrap(), target: open },
        ];
        let r = run(&checks, Duration::from_millis(500));
        assert!(r[0].is_some());
        assert!(r[1].is_some(), "refused: the far side answered");
        assert!(r[2].is_none(), "mixed families never connect");
    }
}
