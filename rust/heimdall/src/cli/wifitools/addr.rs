//! Addresses as the Python helpers handle them: Python's `ipaddress.ip_address` (strict IPv4, IPv6 with `::`, an IPv4 tail
//! and a scope, numbers as addresses), `str()` of an address, `is_private`, and the C library's `getaddrinfo` called with
//! the hints Python's `socket.getaddrinfo` passes, its answers written as `inet_ntop` writes them (what Python returns).

use super::py::{PyErr, PyResult, Val};
use std::ffi::{CStr, CString};

/// An address Python's `ipaddress` read.
#[derive(Clone, Debug, PartialEq)]
pub enum Ip {
    V4(u32),
    V6(u128, Option<String>),
}

/// `IPv4Address(s)` of a string.
pub fn parse_v4(s: &str) -> Option<u32> {
    if s.is_empty() || s.contains('/') {
        return None;
    }
    let octets: Vec<&str> = s.split('.').collect();
    if octets.len() != 4 {
        return None;
    }
    let mut v = 0u32;
    for o in octets {
        if o.is_empty() || o.len() > 3 || !o.bytes().all(|b| b.is_ascii_digit()) || (o != "0" && o.starts_with('0')) {
            return None;
        }
        let n: u32 = o.parse().ok()?;
        if n > 255 {
            return None;
        }
        v = v << 8 | n;
    }
    Some(v)
}

fn hextet(h: &str) -> Option<u128> {
    if !h.bytes().all(|b| b.is_ascii_hexdigit()) || h.len() > 4 || h.is_empty() {
        return None;
    }
    u128::from_str_radix(h, 16).ok()
}

/// `IPv6Address(s)` of a string: the address and its scope.
pub fn parse_v6(s: &str) -> Option<(u128, Option<String>)> {
    if s.contains('/') {
        return None;
    }
    let (addr, scope) = match s.split_once('%') {
        None => (s, None),
        Some((_, sc)) if sc.is_empty() || sc.contains('%') => return None,
        Some((a, sc)) => (a, Some(sc.to_string())),
    };
    if addr.is_empty() || addr.chars().count() > 45 {
        return None;
    }
    // split(':', maxsplit=9)
    let mut parts: Vec<String> = Vec::new();
    let mut rest = addr;
    while parts.len() < 9 {
        match rest.split_once(':') {
            Some((a, b)) => {
                parts.push(a.to_string());
                rest = b;
            }
            None => break,
        }
    }
    parts.push(rest.to_string());
    if parts.len() < 3 {
        return None;
    }
    if parts.last().unwrap().contains('.') {
        let v4 = parse_v4(&parts.pop().unwrap())?;
        parts.push(format!("{:x}", v4 >> 16 & 0xffff));
        parts.push(format!("{:x}", v4 & 0xffff));
    }
    if parts.len() > 9 {
        return None;
    }
    let mut skip = None;
    for (i, p) in parts.iter().enumerate().take(parts.len() - 1).skip(1) {
        if p.is_empty() {
            if skip.is_some() {
                return None;
            }
            skip = Some(i);
        }
    }
    let n = parts.len();
    let (hi, lo, skipped) = match skip {
        Some(i) => {
            let (mut hi, mut lo) = (i, n - i - 1);
            if parts[0].is_empty() {
                hi -= 1;
                if hi > 0 {
                    return None;
                }
            }
            if parts[n - 1].is_empty() {
                lo -= 1;
                if lo > 0 {
                    return None;
                }
            }
            let skipped = 8i32 - (hi + lo) as i32;
            if skipped < 1 {
                return None;
            }
            (hi, lo, skipped as u32)
        }
        None => {
            if n != 8 || parts[0].is_empty() || parts[n - 1].is_empty() {
                return None;
            }
            (n, 0, 0)
        }
    };
    let mut v: u128 = 0;
    for p in &parts[..hi] {
        v = v << 16 | hextet(p)?;
    }
    v = v.checked_shl(16 * skipped).unwrap_or(0);
    for p in &parts[n - lo..] {
        v = v << 16 | hextet(p)?;
    }
    Some((v, scope))
}

/// `ipaddress.ip_address(v)` of a value from a file: a string, or a number (True is 1).
pub fn ip_address(v: &Val) -> PyResult<Ip> {
    let bad = || PyErr::value(format!("{} does not appear to be an IPv4 or IPv6 address", super::py::repr(v)));
    match v {
        Val::Str(s) => {
            if let Some(a) = parse_v4(s) {
                return Ok(Ip::V4(a));
            }
            parse_v6(s).map(|(a, sc)| Ip::V6(a, sc)).ok_or_else(bad)
        }
        Val::Bool(b) => Ok(Ip::V4(*b as u32)),
        Val::Int(i) => {
            if i.starts_with('-') {
                return Err(bad());
            }
            if let Ok(n) = i.parse::<u32>() {
                return Ok(Ip::V4(n));
            }
            i.parse::<u128>().map(|n| Ip::V6(n, None)).map_err(|_| bad())
        }
        _ => Err(bad()),
    }
}

impl Ip {
    pub fn version(&self) -> u8 {
        match self {
            Ip::V4(_) => 4,
            Ip::V6(..) => 6,
        }
    }
}

fn v4_str(a: u32) -> String {
    format!("{}.{}.{}.{}", a >> 24, a >> 16 & 255, a >> 8 & 255, a & 255)
}

impl std::fmt::Display for Ip {
    /// `str()` of the address: IPv6 compressed as Python does (the first longest run of two or more zero groups; an
    /// IPv4-mapped address with its IPv4 tail), the scope after `%`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Ip::V4(a) => write!(f, "{}", v4_str(*a)),
            Ip::V6(a, scope) => {
                let text = if *a >> 32 == 0xffff {
                    format!("::ffff:{}", v4_str(*a as u32))
                } else {
                    let hx: Vec<String> = (0..8).map(|i| format!("{:x}", (a >> (112 - 16 * i)) & 0xffff)).collect();
                    let (mut best, mut best_len, mut cur, mut cur_len) = (None, 0, None, 0);
                    for (i, h) in hx.iter().enumerate() {
                        if h == "0" {
                            cur_len += 1;
                            if cur.is_none() {
                                cur = Some(i);
                            }
                            if cur_len > best_len {
                                best_len = cur_len;
                                best = cur;
                            }
                        } else {
                            cur_len = 0;
                            cur = None;
                        }
                    }
                    match best {
                        Some(b) if best_len > 1 => {
                            let head = hx[..b].join(":");
                            let tail = hx[b + best_len..].join(":");
                            format!("{head}::{tail}")
                        }
                        _ => hx.join(":"),
                    }
                };
                match scope {
                    Some(s) => write!(f, "{text}%{s}"),
                    None => write!(f, "{text}"),
                }
            }
        }
    }
}

/// `IPv4Address(a).is_private` (Python 3.13 and later: the special-purpose registry, two anycast addresses excepted).
pub fn v4_is_private(a: u32) -> bool {
    const NETS: &[(u32, u32)] = &[
        (0x0000_0000, 8),
        (0x0a00_0000, 8),
        (0x7f00_0000, 8),
        (0xa9fe_0000, 16),
        (0xac10_0000, 12),
        (0xc000_0000, 24),
        (0xc000_00aa, 31),
        (0xc000_0200, 24),
        (0xc0a8_0000, 16),
        (0xc612_0000, 15),
        (0xc633_6400, 24),
        (0xcb00_7100, 24),
        (0xf000_0000, 4),
        (0xffff_ffff, 32),
    ];
    let inside = |net: u32, bits: u32| a >> (32 - bits) == net >> (32 - bits);
    NETS.iter().any(|&(n, b)| inside(n, b)) && a != 0xc000_0009 && a != 0xc000_000a
}

/// `inet_ntop` of an IPv6 address, as glibc writes it (an IPv4-compatible or -mapped address with its dotted tail).
pub fn ntop6(b: [u8; 16]) -> String {
    let w: Vec<u16> = (0..8).map(|i| u16::from_be_bytes([b[2 * i], b[2 * i + 1]])).collect();
    let (mut best, mut cur): ((i32, i32), (i32, i32)) = ((-1, 0), (-1, 0));
    for (i, &x) in w.iter().enumerate() {
        if x == 0 {
            if cur.0 == -1 {
                cur = (i as i32, 1);
            } else {
                cur.1 += 1;
            }
        } else if cur.0 != -1 {
            if best.0 == -1 || cur.1 > best.1 {
                best = cur;
            }
            cur.0 = -1;
        }
    }
    if cur.0 != -1 && (best.0 == -1 || cur.1 > best.1) {
        best = cur;
    }
    if best.0 != -1 && best.1 < 2 {
        best.0 = -1;
    }
    let mut out = String::new();
    for i in 0..8i32 {
        if best.0 != -1 && i >= best.0 && i < best.0 + best.1 {
            if i == best.0 {
                out.push(':');
            }
            continue;
        }
        if i != 0 {
            out.push(':');
        }
        if i == 6 && best.0 == 0 && (best.1 == 6 || (best.1 == 5 && w[5] == 0xffff)) {
            out.push_str(&format!("{}.{}.{}.{}", b[12], b[13], b[14], b[15]));
            return out;
        }
        out.push_str(&format!("{:x}", w[i as usize]));
    }
    if best.0 != -1 && best.0 + best.1 == 8 {
        out.push(':');
    }
    out
}

/// Python's `host.encode("idna")` for an ASCII name (labels not empty, shorter than 64); a name that is not ASCII is not
/// converted (Python's IDNA 2003 is not carried over: NetworkManager and the WireGuard files give ASCII names).
pub fn idna(host: &str) -> PyResult<String> {
    if !host.is_ascii() {
        return Err(PyErr::new("gaierror", "a name that is not ASCII is not looked up"));
    }
    let labels: Vec<&str> = host.split('.').collect();
    if labels[..labels.len() - 1].iter().any(|l| l.is_empty()) {
        return Err(PyErr::new("UnicodeEncodeError", "'idna' codec can't encode: label empty"));
    }
    if labels.iter().any(|l| l.len() >= 64) {
        return Err(PyErr::new("UnicodeEncodeError", "'idna' codec can't encode: label too long"));
    }
    Ok(host.to_string())
}

/// `socket.getaddrinfo(host, port, family, socktype, proto)`: the socket addresses, in the C library's order (duplicates
/// kept, one per socket type). The error is Python's `socket.gaierror`.
pub fn getaddrinfo_sock(host: &str, service: &str, family: i32, socktype: i32, proto: i32) -> PyResult<Vec<std::net::SocketAddr>> {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
    let h = idna(host)?;
    let ch = CString::new(h).map_err(|_| PyErr::value("embedded null character"))?;
    let cs = CString::new(service).map_err(|_| PyErr::value("embedded null character"))?;
    let mut hints: libc::addrinfo = unsafe { std::mem::zeroed() };
    hints.ai_family = family;
    hints.ai_socktype = socktype;
    hints.ai_protocol = proto;
    let mut res: *mut libc::addrinfo = std::ptr::null_mut();
    let rc = unsafe { libc::getaddrinfo(ch.as_ptr(), cs.as_ptr(), &hints, &mut res) };
    if rc != 0 {
        let msg = unsafe { CStr::from_ptr(libc::gai_strerror(rc)) }.to_string_lossy().into_owned();
        return Err(PyErr::new("gaierror", format!("[Errno {rc}] {msg}")));
    }
    let mut out = Vec::new();
    let mut p = res;
    while !p.is_null() {
        let ai = unsafe { &*p };
        if !ai.ai_addr.is_null() {
            match ai.ai_family {
                libc::AF_INET => {
                    let sa = unsafe { &*(ai.ai_addr as *const libc::sockaddr_in) };
                    let ip = Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr));
                    out.push(SocketAddr::V4(SocketAddrV4::new(ip, u16::from_be(sa.sin_port))));
                }
                libc::AF_INET6 => {
                    let sa = unsafe { &*(ai.ai_addr as *const libc::sockaddr_in6) };
                    let ip = Ipv6Addr::from(sa.sin6_addr.s6_addr);
                    out.push(SocketAddr::V6(SocketAddrV6::new(ip, u16::from_be(sa.sin6_port), sa.sin6_flowinfo, sa.sin6_scope_id)));
                }
                _ => {}
            }
        }
        p = ai.ai_next;
    }
    unsafe { libc::freeaddrinfo(res) };
    Ok(out)
}

/// The address of a socket address as Python gives it (`a[4][0]`: `inet_ntop`).
pub fn host_of(a: &std::net::SocketAddr) -> String {
    match a {
        std::net::SocketAddr::V4(v) => v.ip().to_string(),
        std::net::SocketAddr::V6(v) => ntop6(v.ip().octets()),
    }
}

/// `socket.getaddrinfo(host, port, family, 0, proto)`, the addresses as text.
pub fn getaddrinfo(host: &str, service: &str, family: i32, proto: i32) -> PyResult<Vec<String>> {
    Ok(getaddrinfo_sock(host, service, family, 0, proto)?.iter().map(host_of).collect())
}

/// `ipaddress.ip_address(s).is_loopback` of a string (Python 3.13 and later: an IPv4-mapped address as its IPv4 address).
pub fn is_loopback(s: &str) -> Option<bool> {
    if let Some(a) = parse_v4(s) {
        return Some(a >> 24 == 127);
    }
    let (a, _) = parse_v6(s)?;
    Some(if a >> 32 == 0xffff { (a as u32) >> 24 == 127 } else { a == 1 })
}
