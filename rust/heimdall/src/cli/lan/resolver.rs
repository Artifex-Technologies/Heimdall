//! The router's reverse names (Go: `reverseNames`, which runs Go's own resolver, `net.Resolver{PreferGo: true}`, with every
//! question sent to the router's port 53). The parts of Go's resolver that decide what is sent and what is believed are
//! carried over: the order of /etc/hosts and DNS from /etc/nsswitch.conf, /etc/hosts itself, the number of servers, attempts,
//! timeout and trust-ad from /etc/resolv.conf (each "server" is the router here), the question (a random id, recursion
//! desired, one PTR question, an EDNS0 record for 1232 bytes), which answers are taken (the same id, question and type; one
//! question), when the next server is tried (no answer, a refusal, a server failure, a lame referral, a message that does not
//! read) and when not (no such name), a truncated answer asked again once, and names that are not domain names refusing the
//! whole answer.

use super::net::Udp;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

/// Where names come from first (Go's hostLookupOrder for addresses, the Go resolver forced).
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Order {
    Files,
    Dns,
    FilesDns,
    DnsFiles,
}

/// Go's lookupOrder from /etc/nsswitch.conf's "hosts" line (sources Go does not know are passed over).
pub fn order(nsswitch: Option<&str>) -> Order {
    let Some(text) = nsswitch else { return Order::FilesDns };
    let mut srcs: Vec<String> = Vec::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("");
        let line = line.trim_matches([' ', '\t', '\r', '\n']);
        if line.is_empty() {
            continue;
        }
        let Some(colon) = line.find(':') else { return Order::FilesDns };
        let db = line[..colon].trim_matches([' ', '\t', '\r', '\n']);
        let mut rest = &line[colon + 1..];
        loop {
            rest = rest.trim_matches([' ', '\t', '\r', '\n']);
            if rest.is_empty() {
                break;
            }
            let (src, r) = match rest.find(' ') {
                Some(sp) => (&rest[..sp], rest[sp + 1..].trim_matches([' ', '\t', '\r', '\n'])),
                None => (rest, ""),
            };
            rest = r;
            if rest.starts_with('[') {
                let Some(close) = rest.find(']') else { return Order::FilesDns };
                rest = &rest[close + 1..];
            }
            if db == "hosts" {
                srcs.push(src.to_string());
            }
        }
    }
    if srcs.is_empty() {
        return Order::FilesDns;
    }
    let (mut files, mut dns, mut first) = (false, false, "");
    for s in &srcs {
        if s == "files" || s == "dns" {
            if s == "files" {
                files = true;
            } else {
                dns = true;
            }
            if first.is_empty() {
                first = s;
            }
        }
    }
    match (files, dns) {
        (true, true) if first == "files" => Order::FilesDns,
        (true, true) => Order::DnsFiles,
        (true, false) => Order::Files,
        (false, true) => Order::Dns,
        _ => Order::FilesDns,
    }
}

/// Go's lookupStaticAddr: the names /etc/hosts gives the address (a name with a dot gets a trailing dot, as Go's
/// absDomainName).
pub fn hosts_names(hosts: Option<&str>, ip: Ipv4Addr) -> Vec<String> {
    let mut out = Vec::new();
    for line in hosts.unwrap_or("").lines() {
        let line = line.split('#').next().unwrap_or("");
        let f: Vec<&str> = line.split([' ', '\r', '\t', '\n']).filter(|s| !s.is_empty()).collect();
        if f.len() < 2 {
            continue;
        }
        match crate::gonet::parse_ip(f[0]) {
            Some(std::net::IpAddr::V4(a)) if a == ip && !f[0].contains(':') => {}
            _ => continue,
        }
        for n in &f[1..] {
            out.push(if n.contains('.') && !n.ends_with('.') { format!("{n}.") } else { n.to_string() });
        }
    }
    out
}

/// What /etc/resolv.conf says, as Go reads it.
#[derive(Clone, Debug, PartialEq)]
pub struct Conf {
    pub servers: usize,
    pub attempts: usize,
    pub timeout: Duration,
    pub trust_ad: bool,
}

pub fn conf(resolv: Option<&str>) -> Conf {
    let mut c = Conf { servers: 0, attempts: 2, timeout: Duration::from_secs(5), trust_ad: false };
    for line in resolv.unwrap_or("").lines() {
        if line.starts_with(';') || line.starts_with('#') {
            continue;
        }
        let f: Vec<&str> = line.split([' ', '\r', '\t', '\n']).filter(|s| !s.is_empty()).collect();
        match f.first().copied() {
            Some("nameserver") if f.len() > 1 && c.servers < 3 => {
                if f[1].parse::<std::net::IpAddr>().is_ok() || parse_zoned(f[1]) {
                    c.servers += 1;
                }
            }
            Some("options") => {
                for s in &f[1..] {
                    if let Some(n) = s.strip_prefix("timeout:") {
                        c.timeout = Duration::from_secs(dtoi(n).max(1) as u64);
                    } else if let Some(n) = s.strip_prefix("attempts:") {
                        c.attempts = dtoi(n).max(1) as usize;
                    } else if *s == "trust-ad" {
                        c.trust_ad = true;
                    }
                }
            }
            _ => {}
        }
    }
    if c.servers == 0 {
        c.servers = 2; // Go's defaultNS: 127.0.0.1:53 and [::1]:53
    }
    c
}

/// An IPv6 address with a zone ("fe80::1%eth0"), which netip.ParseAddr takes.
fn parse_zoned(s: &str) -> bool {
    s.split_once('%').is_some_and(|(a, z)| !z.is_empty() && a.parse::<std::net::Ipv6Addr>().is_ok())
}

/// Go's dtoi: the leading decimal digits (big values stop at 0xFFFFFF).
fn dtoi(s: &str) -> i64 {
    let mut n: i64 = 0;
    for b in s.bytes() {
        if !b.is_ascii_digit() {
            break;
        }
        n = n * 10 + (b - b'0') as i64;
        if n >= 0xFF_FFFF {
            return 0xFF_FFFF;
        }
    }
    n
}

/// Go's isDomainName.
pub fn is_domain_name(s: &str) -> bool {
    if s == "." {
        return true;
    }
    let b = s.as_bytes();
    let l = b.len();
    if l == 0 || l > 254 || (l == 254 && b[l - 1] != b'.') {
        return false;
    }
    let (mut last, mut non_numeric, mut partlen) = (b'.', false, 0);
    for &c in b {
        match c {
            b'a'..=b'z' | b'A'..=b'Z' | b'_' => {
                non_numeric = true;
                partlen += 1;
            }
            b'0'..=b'9' => partlen += 1,
            b'-' => {
                if last == b'.' {
                    return false;
                }
                partlen += 1;
                non_numeric = true;
            }
            b'.' => {
                if last == b'.' || last == b'-' || partlen > 63 || partlen == 0 {
                    return false;
                }
                partlen = 0;
            }
            _ => return false,
        }
        last = c;
    }
    if last == b'-' || partlen > 63 {
        return false;
    }
    non_numeric
}

/// The question Go's resolver sends: id, recursion desired (and AD with trust-ad), one question, an EDNS0 record.
pub fn question(id: u16, name: &str, ad: bool) -> Vec<u8> {
    let mut b = Vec::with_capacity(64);
    b.extend_from_slice(&id.to_be_bytes());
    b.extend_from_slice(&(0x0100u16 | if ad { 0x0020 } else { 0 }).to_be_bytes());
    b.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 1]);
    for label in name.trim_end_matches('.').split('.') {
        b.push(label.len() as u8);
        b.extend_from_slice(label.as_bytes());
    }
    b.push(0);
    b.extend_from_slice(&[0, 12, 0, 1]); // PTR, IN
    b.extend_from_slice(&[0, 0, 41, 0x04, 0xD0, 0, 0, 0, 0, 0, 0]); // ".", OPT, 1232, ttl 0, no data
    b
}

/// dnsmessage's name text ("a.b." or "."), or None where dnsmessage refuses it.
fn name_at(m: &[u8], off: usize) -> Option<(String, usize)> {
    let (mut cur, mut next, mut ptrs) = (off, off, 0);
    let mut name: Vec<u8> = Vec::new();
    loop {
        let c = *m.get(cur)? as usize;
        cur += 1;
        match c & 0xC0 {
            0x00 => {
                if c == 0 {
                    break;
                }
                let end = cur + c;
                if end > m.len() || m[cur..end].contains(&b'.') {
                    return None;
                }
                name.extend_from_slice(&m[cur..end]);
                name.push(b'.');
                cur = end;
            }
            0xC0 => {
                let c1 = *m.get(cur)? as usize;
                cur += 1;
                if ptrs == 0 {
                    next = cur;
                }
                ptrs += 1;
                if ptrs > 10 {
                    return None;
                }
                cur = ((c ^ 0xC0) << 8) | c1;
            }
            _ => return None,
        }
    }
    if name.is_empty() {
        name.push(b'.');
    }
    if name.len() > 255 {
        return None;
    }
    if ptrs == 0 {
        next = cur;
    }
    Some((crate::gotext::lossy(&name), next))
}

struct Rr {
    rtype: u16,
    ttl: u32,
    data: usize,
    len: usize,
}

/// One resource header at `off`: the record and the offset of its data.
fn rr_at(m: &[u8], off: usize) -> Option<Rr> {
    let (_, o) = name_at(m, off)?;
    if o + 10 > m.len() {
        return None;
    }
    let rtype = u16::from_be_bytes([m[o], m[o + 1]]);
    let ttl = u32::from_be_bytes([m[o + 4], m[o + 5], m[o + 6], m[o + 7]]);
    let len = u16::from_be_bytes([m[o + 8], m[o + 9]]) as usize;
    Some(Rr { rtype, ttl, data: o + 10, len })
}

/// What one answer meant to Go's resolver.
#[derive(Debug, PartialEq)]
pub enum Verdict {
    /// the names in the PTR records
    Names(Vec<String>),
    /// no such name: no other server is asked
    NotFound,
    /// try the next server
    Next,
    /// not an answer to this question: keep waiting
    Ignore,
    /// truncated: ask again (once)
    Truncated,
    /// the answer was taken but its records do not read: Go returns the error, asking no one else
    Fail,
}

/// Judges one datagram that came back for question `q` (id, name).
pub fn judge(m: &[u8], id: u16, qname: &str, retried_truncated: bool) -> Verdict {
    if m.len() < 12 {
        return Verdict::Ignore;
    }
    let bits = u16::from_be_bytes([m[2], m[3]]);
    let count = |i: usize| u16::from_be_bytes([m[i], m[i + 1]]) as usize;
    let (qd, an, ns, ar) = (count(4), count(6), count(8), count(10));
    if qd == 0 {
        return Verdict::Ignore;
    }
    let Some((qn, o)) = name_at(m, 12) else { return Verdict::Ignore };
    if o + 4 > m.len() {
        return Verdict::Ignore;
    }
    let (qt, qc) = (u16::from_be_bytes([m[o], m[o + 1]]), u16::from_be_bytes([m[o + 2], m[o + 3]]));
    if bits & 0x8000 == 0 || u16::from_be_bytes([m[0], m[1]]) != id || qt != 12 || qc != 1 || !qn.eq_ignore_ascii_case(qname) {
        return Verdict::Ignore;
    }
    if qd > 1 {
        return Verdict::Next; // Go: errInvalidDNSResponse
    }
    let start = o + 4;
    if bits & 0x0200 != 0 && !retried_truncated {
        return Verdict::Truncated;
    }
    // the extended response code: past the answers and authorities to an OPT record among the additionals
    let mut rcode = (bits & 0x000F) as u32;
    let mut has_add = false;
    'ext: {
        let mut off = start;
        for _ in 0..an + ns {
            match rr_at(m, off) {
                Some(r) if r.data + r.len <= m.len() => off = r.data + r.len,
                _ => break 'ext,
            }
        }
        for _ in 0..ar {
            let Some(r) = rr_at(m, off) else { break 'ext };
            has_add = true;
            if r.rtype == 41 {
                rcode |= (r.ttl >> 24) << 4;
                break 'ext;
            }
            if r.data + r.len > m.len() {
                break 'ext;
            }
            off = r.data + r.len;
        }
    }
    if rcode == 3 {
        return Verdict::NotFound;
    }
    let first = if an == 0 { None } else { rr_at(m, start) };
    if an > 0 && first.is_none() {
        return Verdict::Next;
    }
    if rcode == 0 && bits & 0x0400 == 0 && bits & 0x0080 == 0 && an == 0 && !has_add {
        return Verdict::Next; // a lame referral
    }
    if rcode != 0 {
        return Verdict::Next;
    }
    // to the first PTR answer
    let mut off = start;
    let mut i = 0;
    loop {
        if i == an {
            return Verdict::NotFound;
        }
        let Some(r) = rr_at(m, off) else { return Verdict::Next };
        if r.rtype == 12 {
            break;
        }
        if r.data + r.len > m.len() {
            return Verdict::Next;
        }
        off = r.data + r.len;
        i += 1;
    }
    // every PTR answer from there (an error now is final: Go's resolver has already taken this answer)
    let mut names = Vec::new();
    while i < an {
        let Some(r) = rr_at(m, off) else { return Verdict::Fail };
        if r.rtype != 12 {
            if r.data + r.len > m.len() {
                return Verdict::Fail;
            }
        } else {
            let Some((n, _)) = name_at(m, r.data) else { return Verdict::Fail };
            names.push(n);
        }
        off = r.data + r.len;
        i += 1;
    }
    Verdict::Names(names)
}

/// Go's `Resolver.LookupAddr` with every question sent to `router`: the names, None when Go returns an error (no name, no
/// answer, or a name in the answer that is not a domain name).
pub fn lookup_addr(router: Ipv4Addr, ip: Ipv4Addr, files: &Files, deadline: Instant) -> Option<Vec<String>> {
    let names = match files.order {
        Order::Files => {
            let n = hosts_names(files.hosts.as_deref(), ip);
            return if n.is_empty() { None } else { filter(n) };
        }
        Order::FilesDns => {
            let n = hosts_names(files.hosts.as_deref(), ip);
            if !n.is_empty() {
                return filter(n);
            }
            dns(router, ip, &files.conf, deadline)
        }
        Order::Dns => dns(router, ip, &files.conf, deadline),
        Order::DnsFiles => match dns(router, ip, &files.conf, deadline) {
            Err(true) => {
                let n = hosts_names(files.hosts.as_deref(), ip);
                if n.is_empty() {
                    return None;
                }
                return filter(n);
            }
            other => other,
        },
    };
    names.ok().and_then(filter)
}

fn filter(names: Vec<String>) -> Option<Vec<String>> {
    if names.iter().all(|n| is_domain_name(n)) {
        Some(names)
    } else {
        None
    }
}

/// The files the resolver reads, read once per scan.
#[derive(Clone, Debug)]
pub struct Files {
    pub order: Order,
    pub hosts: Option<String>,
    pub conf: Conf,
}

impl Files {
    pub fn read() -> Files {
        let rd = |p: &str| std::fs::read(p).ok().map(|b| crate::gotext::lossy(&b));
        Files { order: order(rd("/etc/nsswitch.conf").as_deref()), hosts: rd("/etc/hosts"), conf: conf(rd("/etc/resolv.conf").as_deref()) }
    }
}

fn random_id() -> u16 {
    let mut b = [0u8; 2];
    if std::fs::File::open("/dev/urandom").and_then(|mut f| std::io::Read::read_exact(&mut f, &mut b)).is_err() {
        let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().subsec_nanos();
        b = (t as u16 ^ (t >> 16) as u16).to_be_bytes();
    }
    u16::from_be_bytes(b)
}

/// The DNS half: Err(true) when the name does not exist, Err(false) for any other failure.
fn dns(router: Ipv4Addr, ip: Ipv4Addr, c: &Conf, deadline: Instant) -> Result<Vec<String>, bool> {
    let o = ip.octets();
    let qname = format!("{}.{}.{}.{}.in-addr.arpa.", o[3], o[2], o[1], o[0]);
    for _ in 0..c.attempts {
        for _ in 0..c.servers {
            let id = random_id();
            let q = question(id, &qname, c.trust_ad);
            let mut truncated = false;
            // up to two rounds: "udp", and after a truncated answer the same question again ("tcp", which the router dial
            // makes UDP)
            let mut verdict = Verdict::Next;
            for round in 0..2 {
                let now = Instant::now();
                if now >= deadline {
                    verdict = Verdict::Next;
                    break;
                }
                let until = deadline.min(now + c.timeout);
                let Ok(sock) = Udp::connect(router, 53) else {
                    verdict = Verdict::Next;
                    break;
                };
                if sock.send(&q).is_err() {
                    verdict = Verdict::Next;
                    break;
                }
                let mut buf = vec![0u8; 1232];
                verdict = loop {
                    let now = Instant::now();
                    if now >= until {
                        break Verdict::Next;
                    }
                    match sock.recv_from(&mut buf, until - now) {
                        Err(_) => break Verdict::Next,
                        Ok((n, _)) => match judge(&buf[..n], id, &qname, truncated) {
                            Verdict::Ignore => continue,
                            v => break v,
                        },
                    }
                };
                if verdict == Verdict::Truncated && round == 0 {
                    truncated = true;
                    continue;
                }
                break;
            }
            match verdict {
                Verdict::Names(n) => return Ok(n),
                Verdict::NotFound => return Err(true),
                Verdict::Fail => return Err(false),
                _ => {}
            }
        }
    }
    Err(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn orders_and_names_as_go() {
        assert_eq!(order(Some("hosts: mymachines resolve [!UNAVAIL=return] files myhostname dns\n")), Order::FilesDns);
        assert_eq!(order(Some("hosts: files\n")), Order::Files);
        assert_eq!(order(Some("hosts: dns files\n")), Order::DnsFiles);
        assert_eq!(order(Some("passwd: files\n")), Order::FilesDns);
        assert_eq!(order(None), Order::FilesDns);
        assert!(is_domain_name("tv.lan.") && is_domain_name("localhost") && !is_domain_name("my tv.lan.") && !is_domain_name("123."));
        assert_eq!(hosts_names(Some("192.0.2.5 tv.lan tv # x\n"), Ipv4Addr::new(192, 0, 2, 5)), vec!["tv.lan.", "tv"]);
        assert_eq!(conf(Some("nameserver 192.0.2.1\noptions attempts:3 timeout:0\n")).attempts, 3);
    }
}
