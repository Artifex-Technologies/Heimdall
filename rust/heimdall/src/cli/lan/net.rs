//! The sockets and interface facts the scan needs, made as Go's `net` package makes them (Linux): every UDP socket with
//! SO_BROADCAST, the multicast one bound to 0.0.0.0:5353 with SO_REUSEADDR, sending on the interface's first IPv4 address
//! without hearing itself; the interface's addresses and hardware address as the kernel lists them.

use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::time::Duration;

/// A UDP socket (IPv4).
pub struct Udp {
    fd: OwnedFd,
}

fn last() -> std::io::Error {
    std::io::Error::last_os_error()
}

fn sockaddr(ip: Ipv4Addr, port: u16) -> libc::sockaddr_in {
    // SAFETY: an all-zero sockaddr_in is valid
    let mut a: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    a.sin_family = libc::AF_INET as libc::sa_family_t;
    a.sin_port = port.to_be();
    a.sin_addr = libc::in_addr { s_addr: u32::from_ne_bytes(ip.octets()) };
    a
}

fn in_addr(ip: Ipv4Addr) -> libc::in_addr {
    libc::in_addr { s_addr: u32::from_ne_bytes(ip.octets()) }
}

impl Udp {
    fn new() -> std::io::Result<Udp> {
        // SAFETY: plain socket(2); the descriptor is owned from here on
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
        if fd < 0 {
            return Err(last());
        }
        let u = Udp { fd: unsafe { OwnedFd::from_raw_fd(fd) } };
        u.opt(libc::SOL_SOCKET, libc::SO_BROADCAST, &1i32)?;
        Ok(u)
    }

    fn opt<T>(&self, level: i32, name: i32, v: &T) -> std::io::Result<()> {
        // SAFETY: v points at a live T of the size given
        let r = unsafe {
            libc::setsockopt(self.fd.as_raw_fd(), level, name, v as *const T as *const libc::c_void, std::mem::size_of::<T>() as u32)
        };
        if r < 0 {
            Err(last())
        } else {
            Ok(())
        }
    }

    fn bind_to(&self, ip: Ipv4Addr, port: u16) -> std::io::Result<()> {
        let a = sockaddr(ip, port);
        // SAFETY: a is a sockaddr_in of the size given
        let r = unsafe {
            libc::bind(self.fd.as_raw_fd(), &a as *const _ as *const libc::sockaddr, std::mem::size_of::<libc::sockaddr_in>() as u32)
        };
        if r < 0 {
            Err(last())
        } else {
            Ok(())
        }
    }

    /// Go's `net.ListenUDP("udp4", &UDPAddr{IP: ip, Port: port})`.
    pub fn bind(ip: Ipv4Addr, port: u16) -> std::io::Result<Udp> {
        let u = Udp::new()?;
        u.bind_to(ip, port)?;
        Ok(u)
    }

    /// Go's `net.ListenMulticastUDP("udp4", ifc, group:port)` followed by heimdalld's own IP_MULTICAST_IF (the local address)
    /// and IP_MULTICAST_LOOP off.
    pub fn multicast(group: Ipv4Addr, port: u16, _ifindex: u32, local: Ipv4Addr) -> std::io::Result<Udp> {
        let u = Udp::new()?;
        u.opt(libc::SOL_SOCKET, libc::SO_REUSEADDR, &1i32)?;
        u.bind_to(Ipv4Addr::UNSPECIFIED, port)?;
        u.opt(libc::IPPROTO_IP, libc::IP_MULTICAST_IF, &in_addr(local))?;
        u.opt(libc::IPPROTO_IP, libc::IP_MULTICAST_LOOP, &0i32)?;
        let m = libc::ip_mreq { imr_multiaddr: in_addr(group), imr_interface: in_addr(local) };
        u.opt(libc::IPPROTO_IP, libc::IP_ADD_MEMBERSHIP, &m)?;
        let _ = u.opt(libc::IPPROTO_IP, libc::IP_MULTICAST_IF, &in_addr(local));
        let _ = u.opt(libc::IPPROTO_IP, libc::IP_MULTICAST_LOOP, &0i32);
        Ok(u)
    }

    /// Go's `net.Dial("udp", ip:port)`: a connected socket (it hears only that address, and its refusals).
    pub fn connect(ip: Ipv4Addr, port: u16) -> std::io::Result<Udp> {
        let u = Udp::new()?;
        let a = sockaddr(ip, port);
        // SAFETY: a is a sockaddr_in of the size given
        let r = unsafe {
            libc::connect(u.fd.as_raw_fd(), &a as *const _ as *const libc::sockaddr, std::mem::size_of::<libc::sockaddr_in>() as u32)
        };
        if r < 0 {
            return Err(last());
        }
        Ok(u)
    }

    pub fn send_to(&self, b: &[u8], ip: Ipv4Addr, port: u16) -> std::io::Result<usize> {
        let a = sockaddr(ip, port);
        // SAFETY: b and a are live for the call
        let r = unsafe {
            libc::sendto(
                self.fd.as_raw_fd(),
                b.as_ptr() as *const libc::c_void,
                b.len(),
                0,
                &a as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as u32,
            )
        };
        if r < 0 {
            Err(last())
        } else {
            Ok(r as usize)
        }
    }

    pub fn send(&self, b: &[u8]) -> std::io::Result<usize> {
        // SAFETY: b is live for the call
        let r = unsafe { libc::send(self.fd.as_raw_fd(), b.as_ptr() as *const libc::c_void, b.len(), 0) };
        if r < 0 {
            Err(last())
        } else {
            Ok(r as usize)
        }
    }

    fn wait(&self, timeout: Duration) -> std::io::Result<()> {
        let mut p = libc::pollfd { fd: self.fd.as_raw_fd(), events: libc::POLLIN, revents: 0 };
        let ms = timeout.as_millis().clamp(1, i32::MAX as u128) as i32;
        loop {
            // SAFETY: one pollfd
            let r = unsafe { libc::poll(&mut p, 1, ms) };
            if r < 0 && last().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            if r < 0 {
                return Err(last());
            }
            if r == 0 {
                return Err(std::io::ErrorKind::TimedOut.into());
            }
            return Ok(());
        }
    }

    /// One datagram and its sender, waiting at most `timeout`.
    pub fn recv_from(&self, buf: &mut [u8], timeout: Duration) -> std::io::Result<(usize, Ipv4Addr)> {
        self.wait(timeout)?;
        // SAFETY: an all-zero sockaddr_in is valid; buf and a are live for the call
        let mut a: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::sockaddr_in>() as u32;
        let r = unsafe {
            libc::recvfrom(
                self.fd.as_raw_fd(),
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                0,
                &mut a as *mut _ as *mut libc::sockaddr,
                &mut len,
            )
        };
        if r < 0 {
            return Err(last());
        }
        Ok((r as usize, Ipv4Addr::from(a.sin_addr.s_addr.to_ne_bytes())))
    }
}

/// What the scan needs to know about one interface: its index, its first IPv4 address with the prefix length, its
/// hardware address as Go writes it (lowercase, colons; empty when it has none).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Iface {
    pub index: u32,
    pub v4: Option<(Ipv4Addr, u32)>,
    pub hw: String,
}

/// Go's `net.InterfaceByName` and `ifaceNet`: None when there is no such interface.
pub fn iface(name: &str) -> Option<Iface> {
    let cname = std::ffi::CString::new(name).ok()?;
    // SAFETY: a NUL-terminated name
    let index = unsafe { libc::if_nametoindex(cname.as_ptr()) };
    if index == 0 {
        return None;
    }
    let mut out = Iface { index, ..Iface::default() };
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs fills head with a list freed below
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return Some(out);
    }
    let mut p = head;
    while !p.is_null() {
        // SAFETY: p is an element of the list getifaddrs returned
        let ifa = unsafe { &*p };
        p = ifa.ifa_next;
        if ifa.ifa_addr.is_null() || ifa.ifa_name.is_null() {
            continue;
        }
        // SAFETY: ifa_name is a NUL-terminated string in the list
        let n = unsafe { std::ffi::CStr::from_ptr(ifa.ifa_name) }.to_string_lossy();
        // an IPv4 address with a label ("eth0:1") belongs to the interface as well, as Go lists addresses by index
        let ours = n == name || n.strip_prefix(name).is_some_and(|r| r.starts_with(':'));
        if !ours {
            continue;
        }
        // SAFETY: ifa_addr is non-null and its family says which sockaddr it is
        let family = unsafe { (*ifa.ifa_addr).sa_family } as i32;
        if family == libc::AF_INET && out.v4.is_none() {
            let a = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in) };
            let ip = Ipv4Addr::from(a.sin_addr.s_addr.to_ne_bytes());
            let ones = if ifa.ifa_netmask.is_null() {
                32
            } else {
                let m = unsafe { &*(ifa.ifa_netmask as *const libc::sockaddr_in) };
                u32::from_be(m.sin_addr.s_addr).leading_ones()
            };
            out.v4 = Some((ip, ones));
        } else if family == libc::AF_PACKET && n == name {
            let l = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_ll) };
            let len = (l.sll_halen as usize).min(8);
            out.hw = l.sll_addr[..len].iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":");
        }
    }
    // SAFETY: head came from getifaddrs
    unsafe { libc::freeifaddrs(head) };
    Some(out)
}
