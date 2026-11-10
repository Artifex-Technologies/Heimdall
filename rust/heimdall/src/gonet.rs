//! IP addresses read and judged as Go's net package does (ParseIP, SplitHostPort, IsPrivate, ...), since detectors decide on
//! them and must decide alike.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Go's `net.ParseIP`: dotted IPv4 (no leading zeros), or IPv6 (with an IPv4 tail allowed), no zone. An IPv4-mapped IPv6
/// address is the IPv4 address, as Go's `To4` makes it.
pub fn parse_ip(s: &str) -> Option<IpAddr> {
    if s.contains('%') {
        return None;
    }
    let ip: IpAddr = s.parse().ok()?;
    Some(canonical(ip))
}

/// IPv4-mapped IPv6 as IPv4 (Go treats them as the same address).
pub fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

/// Go's `IsPrivate`: 10/8, 172.16/12, 192.168/16, fc00::/7.
pub fn is_private(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            o[0] == 10 || (o[0] == 172 && o[1] & 0xf0 == 16) || (o[0] == 192 && o[1] == 168)
        }
        IpAddr::V6(v6) => v6.octets()[0] & 0xfe == 0xfc,
    }
}

/// Go's `IsLinkLocalUnicast`: 169.254/16, fe80::/10.
pub fn is_link_local_unicast(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            o[0] == 169 && o[1] == 254
        }
        IpAddr::V6(v6) => {
            let o = v6.octets();
            o[0] == 0xfe && o[1] & 0xc0 == 0x80
        }
    }
}

pub fn is_unspecified(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => *v4 == Ipv4Addr::UNSPECIFIED,
        IpAddr::V6(v6) => *v6 == Ipv6Addr::UNSPECIFIED,
    }
}

pub fn is_multicast(ip: &IpAddr) -> bool {
    ip.is_multicast()
}

pub fn is_loopback(ip: &IpAddr) -> bool {
    ip.is_loopback()
}

/// Go's `net.SplitHostPort`.
pub fn split_host_port(hp: &str) -> Option<(&str, &str)> {
    if let Some(rest) = hp.strip_prefix('[') {
        let end = rest.find(']')?;
        let host = &rest[..end];
        let after = &rest[end + 1..];
        let port = after.strip_prefix(':')?;
        if port.contains(':') || port.contains('[') || port.contains(']') || host.contains('[') {
            return None;
        }
        return Some((host, port));
    }
    let i = hp.rfind(':')?;
    let (host, port) = (&hp[..i], &hp[i + 1..]);
    if host.contains(':') || host.contains('[') || host.contains(']') || port.contains('[') || port.contains(']') {
        return None;
    }
    Some((host, port))
}

/// fmt.Sscan into an int, as far as Heimdall uses it: leading space, a sign, Go's base prefixes (0x, 0o, 0b, a leading 0 for
/// octal), digits with underscores; it stops at the first character that cannot continue the number.
pub fn sscan_int(s: &str) -> Option<i64> {
    let t = s.trim_start_matches([' ', '\t', '\n', '\r']);
    let (neg, t) = match t.as_bytes().first() {
        Some(b'-') => (true, &t[1..]),
        Some(b'+') => (false, &t[1..]),
        _ => (false, t),
    };
    let (base, digits, have) = if let Some(r) = t.strip_prefix('0') {
        match r.as_bytes().first() {
            Some(b'x' | b'X') => (16, &r[1..], false),
            Some(b'o' | b'O') => (8, &r[1..], false),
            Some(b'b' | b'B') => (2, &r[1..], false),
            _ => (8, r, true),
        }
    } else {
        (10, t, false)
    };
    let mut v: i64 = 0;
    let mut any = have;
    for c in digits.chars() {
        if c == '_' {
            continue;
        }
        let Some(d) = c.to_digit(base) else { break };
        v = v.checked_mul(base as i64)?.checked_add(d as i64)?;
        any = true;
    }
    if !any {
        return None;
    }
    Some(if neg { -v } else { v })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_like_go() {
        assert!(parse_ip("192.168.1.10").is_some());
        assert!(parse_ip("01.2.3.4").is_none(), "Go refuses leading zeros");
        assert!(parse_ip("fe80::1%eth0").is_none());
        assert_eq!(parse_ip("::ffff:10.0.0.1"), parse_ip("10.0.0.1"));
        assert!(is_private(&parse_ip("::ffff:10.0.0.1").unwrap()));
        assert!(is_private(&parse_ip("fd00::1").unwrap()));
        assert!(is_link_local_unicast(&parse_ip("fe80::1").unwrap()));
        assert!(!is_private(&parse_ip("172.32.0.1").unwrap()));
    }

    #[test]
    fn split_like_go() {
        assert_eq!(split_host_port("100.64.0.2:8931"), Some(("100.64.0.2", "8931")));
        assert_eq!(split_host_port("[fd00::2]:8931"), Some(("fd00::2", "8931")));
        assert_eq!(split_host_port("fd00::2:8931"), None);
        assert_eq!(split_host_port("1.2.3.4:"), Some(("1.2.3.4", "")));
    }

    #[test]
    fn sscan_like_go() {
        assert_eq!(sscan_int("32768\t60999\n"), Some(32768));
        assert_eq!(sscan_int(" 443"), Some(443));
        assert_eq!(sscan_int("010"), Some(8));
        assert_eq!(sscan_int("0x1f"), Some(31));
        assert_eq!(sscan_int("12ab"), Some(12));
        assert_eq!(sscan_int("abc"), None);
        assert_eq!(sscan_int("0"), Some(0));
    }
}
