//! Discovery (Go: internal/lan/discover.go): only what any device on a home network does to find printers and TVs. Every
//! answer it waits for is one the firewall already lets in: multicast DNS answers go to the group, and the unicast questions
//! (the router's reverse names, NetBIOS names) get replies the firewall matches to the question. SSDP is left out on purpose.

use super::dns::{self, Record, TYPE_A, TYPE_PTR, TYPE_SRV, TYPE_TXT};
use super::net::Udp;
use super::text::{clean, equal_fold, index, to_lower};
use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

/// What discovery learned about one address.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Found {
    /// best first
    pub names: Vec<String>,
    pub model: String,
    pub services: BTreeSet<String>,
}

/// Service types asked for by name as well as through the catalogue (_services._dns-sd._udp), because some devices answer
/// only for their own types.
pub const COMMON_TYPES: &[&str] = &[
    "_googlecast._tcp.local",
    "_airplay._tcp.local",
    "_raop._tcp.local",
    "_amzn-wplay._tcp.local",
    "_spotify-connect._tcp.local",
    "_ipp._tcp.local",
    "_printer._tcp.local",
    "_hap._tcp.local",
    "_smb._tcp.local",
    "_device-info._tcp.local",
    "_companion-link._tcp.local",
    "_workstation._tcp.local",
    "_ssh._tcp.local",
    "_sonos._tcp.local",
    "_androidtvremote2._tcp.local",
];

/// Go's `contains`: EqualFold membership.
fn contains(list: &[String], s: &str) -> bool {
    list.iter().any(|x| equal_fold(x, s))
}

/// Files the records of one answer under the address that sent it (a device answers for itself) and notes the service types
/// the catalogue named.
pub fn absorb(out: &mut BTreeMap<String, Found>, types: &mut BTreeSet<String>, from: Ipv4Addr, recs: &[Record]) {
    let from_s = from.to_string();
    let f = out.entry(from_s.clone()).or_default();
    let (mut instance, mut host, mut cast, mut model): (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) = Default::default();
    for r in recs {
        let lname = to_lower(&r.name);
        match r.rtype {
            TYPE_PTR => {
                if lname == "_services._dns-sd._udp.local" {
                    types.insert(to_lower(&r.ptr));
                    continue;
                }
                let typ = service_type(&lname);
                if typ.is_empty() {
                    continue;
                }
                f.services.insert(typ.clone());
                if let Some(name) = instance_name(&r.ptr, &typ) {
                    if !name.is_empty() && instance.is_empty() && typ != "_device-info._tcp" {
                        instance = name;
                    }
                }
            }
            TYPE_SRV => {
                if host.is_empty() {
                    let p = r.ptr.strip_suffix(b".").unwrap_or(&r.ptr);
                    host = p.strip_suffix(b".local").unwrap_or(p).to_vec();
                }
            }
            TYPE_A => {
                if host.is_empty() && lname.ends_with(".local") {
                    host = r.name.strip_suffix(b".local").unwrap_or(&r.name).to_vec();
                }
            }
            TYPE_TXT => {
                for kv in &r.txt {
                    let (k, v) = match kv.iter().position(|&b| b == b'=') {
                        Some(i) => (&kv[..i], &kv[i + 1..]),
                        None => (&kv[..], &kv[..0]),
                    };
                    let k = to_lower(k);
                    if k == "fn" || k == "dn" || (k == "n" && service_type(&lname) == "_amzn-wplay._tcp") {
                        // the name its owner gave it: Chromecast / Google TV (fn), Matter devices (DN), Fire TV (n)
                        if cast.is_empty() {
                            cast = v.to_vec();
                        }
                    } else if (k == "md" || k == "model" || k == "am" || k == "ty") && model.is_empty() {
                        model = v.to_vec();
                    }
                }
            }
            _ => {}
        }
    }
    for n in [cast, instance, host] {
        let n = clean(&n);
        if !n.is_empty() && !contains(&f.names, &n) && !looks_generated(&n, &from_s) && !looks_id(&n) {
            f.names.push(n);
        }
    }
    if f.model.is_empty() {
        f.model = clean(&model);
    }
}

/// "Name._airplay._tcp.local" or "_airplay._tcp.local" reduced to "_airplay._tcp".
pub fn service_type(name: &str) -> String {
    let parts: Vec<&str> = name.strip_suffix('.').unwrap_or(name).split('.').collect();
    for i in 0..parts.len().saturating_sub(1) {
        if parts[i].starts_with('_') && (parts[i + 1] == "_tcp" || parts[i + 1] == "_udp") {
            return format!("{}.{}", parts[i], parts[i + 1]);
        }
    }
    String::new()
}

/// The human part of "Living Room._googlecast._tcp.local"; AirPlay audio names look like "A1B2C3D4E5F6@Kitchen". Go cuts the
/// name at the place it found the type in the lowercased name; where lowercasing made the name longer than the cut, Go
/// panics (a slice out of range): that is None here, and the name is not used.
pub fn instance_name(full: &[u8], typ: &str) -> Option<Vec<u8>> {
    let lower = to_lower(full);
    let i = match index(lower.as_bytes(), format!(".{typ}").as_bytes()) {
        Some(i) if i > 0 => i,
        _ => return Some(Vec::new()),
    };
    if i > full.len() {
        return None;
    }
    let mut n = &full[..i];
    if typ == "_raop._tcp" {
        if let Some(at) = n.iter().position(|&b| b == b'@') {
            n = &n[at + 1..];
        }
    }
    if matches!(typ, "_googlecast._tcp" | "_amzn-wplay._tcp" | "_matterd._udp" | "_matter._tcp") {
        return Some(Vec::new()); // these instance names are ids; the friendly name comes from TXT (fn, n, DN)
    }
    Some(n.to_vec())
}

/// Names a router makes up from the address ("192-168-1-20", "host-20", "dhcp20").
pub fn looks_generated(n: &str, ip: &str) -> bool {
    let digits: String = n.chars().filter(char::is_ascii_digit).collect();
    !digits.is_empty() && ip.replace('.', "").contains(&digits) && digits.len() >= n.len() / 2
}

/// Names that are machine ids: long runs of hex digits ("0F1E2D3C4B5A6978", "02AB34CD56EF") or "a:b:c" tokens.
pub fn looks_id(n: &str) -> bool {
    if n.matches(':').count() >= 2 {
        return true;
    }
    let hex = n.chars().filter(char::is_ascii_hexdigit).count();
    n.len() >= 8 && hex == n.len()
}

/// The first unique workstation name (suffix 0x00) of a NetBIOS node status answer.
pub fn nb_name(m: &[u8]) -> String {
    // header 12, name 34, type/class 4, ttl 4, rdlength 2, count 1
    const OFF: usize = 12 + 34 + 4 + 4 + 2;
    if m.len() <= OFF || m[2] & 0x80 == 0 {
        return String::new();
    }
    let count = m[OFF] as usize;
    for i in 0..count {
        let e = OFF + 1 + i * 18;
        if e + 18 > m.len() {
            return String::new();
        }
        let flags = u16::from_be_bytes([m[e + 16], m[e + 17]]);
        if m[e + 15] == 0x00 && flags & 0x8000 == 0 {
            let mut name = &m[e..e + 15];
            while let Some((&last, rest)) = name.split_last() {
                if last == b' ' || last == 0 {
                    name = rest;
                } else {
                    break;
                }
            }
            return clean(name);
        }
    }
    String::new()
}

/// The NetBIOS node status question (Go's bytes: id 0x1337, the wildcard name "*", NBSTAT, IN).
pub fn netbios_query() -> Vec<u8> {
    let mut q = vec![0x13, 0x37, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0x20, b'C', b'K'];
    q.extend(std::iter::repeat_n(b'A', 30));
    q.extend_from_slice(&[0, 0, 0x21, 0, 1]);
    q
}

/// Sends one tiny UDP datagram (port 9, "discard") to every address of a small subnet so the kernel asks each one for its
/// hardware address (ARP). Subnets larger than /22 are not swept. The pace is Go's: 15 ms after every 32nd address (the
/// address of this computer skips the pause, as in Go).
pub fn sweep(local: Ipv4Addr, network: Ipv4Addr, ones: u32) {
    if !(22..=30).contains(&ones) {
        return;
    }
    let Ok(c) = Udp::bind(local, 0) else { return };
    let base = u32::from(network);
    let n: u32 = 1 << (32 - ones);
    for i in 1..n - 1 {
        let ip = Ipv4Addr::from(base.wrapping_add(i));
        if ip == local {
            continue;
        }
        let _ = c.send_to(&[0], ip, 9);
        if i % 32 == 0 {
            std::thread::sleep(Duration::from_millis(15));
        }
    }
}

/// Reads answers until `deadline`, giving each datagram and its sender to `f`.
fn listen(c: &Udp, buf: &mut [u8], deadline: Instant, mut f: impl FnMut(&[u8], Ipv4Addr)) {
    loop {
        let now = Instant::now();
        if now >= deadline {
            return;
        }
        match c.recv_from(buf, deadline - now) {
            Ok((n, from)) => f(&buf[..n], from),
            Err(_) => return,
        }
    }
}

/// Asks the network which services exist, then for each type, and listens for the answers for `wait` each round.
pub fn mdns(ifindex: u32, local: Ipv4Addr, wait: Duration) -> BTreeMap<String, Found> {
    let mut out = BTreeMap::new();
    let group = Ipv4Addr::new(224, 0, 0, 251);
    let Ok(c) = Udp::multicast(group, 5353, ifindex, local) else { return out };
    let mut types: BTreeSet<String> = BTreeSet::new();
    let ask = |names: &[&str]| {
        for chunk in names.chunks(12) {
            let _ = c.send_to(&dns::query(chunk), group, 5353);
        }
    };
    let mut buf = vec![0u8; 9000];
    let mut first: Vec<&str> = vec!["_services._dns-sd._udp.local"];
    first.extend_from_slice(COMMON_TYPES);
    ask(&first);
    listen(&c, &mut buf, Instant::now() + wait, |m, from| {
        let (recs, _) = dns::parse(m);
        absorb(&mut out, &mut types, from, &recs);
    });
    let common: Vec<String> = COMMON_TYPES.iter().map(|s| s.to_string()).collect();
    let mut more: Vec<&String> = types.iter().filter(|t| !contains(&common, t)).collect();
    more.truncate(36); // the set is sorted already, as Go sorts them
    if !more.is_empty() {
        let names: Vec<&str> = more.iter().map(|s| s.as_str()).collect();
        ask(&names);
        listen(&c, &mut buf, Instant::now() + wait, |m, from| {
            let (recs, _) = dns::parse(m);
            let mut ignored = BTreeSet::new();
            absorb(&mut out, &mut ignored, from, &recs);
            types.extend(ignored);
        });
    }
    out
}

/// Asks each address for its Windows name (a node status query to UDP 137; Windows computers and Samba answer).
pub fn netbios(ips: &[String]) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let Ok(c) = Udp::bind(Ipv4Addr::UNSPECIFIED, 0) else { return out };
    let q = netbios_query();
    for ip in ips {
        if let Some(a) = crate::gonet::parse_ip(ip).and_then(|a| match a {
            std::net::IpAddr::V4(v) => Some(v),
            std::net::IpAddr::V6(v) => v.to_ipv4_mapped(),
        }) {
            let _ = c.send_to(&q, a, 137);
        }
    }
    let mut buf = vec![0u8; 1500];
    listen(&c, &mut buf, Instant::now() + Duration::from_millis(1500), |m, from| {
        let name = nb_name(m);
        if !name.is_empty() {
            out.insert(from.to_string(), name);
        }
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_that_are_not_names() {
        for (n, ip, bad) in [
            ("198-51-100-25", "198.51.100.25", true),
            ("0F1E2D3C4B5A6978", "", true),
            ("02AB34CD56EF", "", true),
            ("amzn.dmgr:00FF:ab:1", "", true),
            ("iPhone-3", "198.51.100.170", false),
            ("Clock-1A2B3C", "198.51.100.212", false),
            ("Cafe", "", false),
        ] {
            assert_eq!(looks_generated(n, ip) || looks_id(n), bad, "{n}");
        }
        assert_eq!(service_type("living room._airplay._tcp.local"), "_airplay._tcp");
        assert_eq!(instance_name(b"A1B2@Kitchen._raop._tcp.local", "_raop._tcp"), Some(b"Kitchen".to_vec()));
        assert_eq!(instance_name(&[0xff; 40].iter().copied().chain(*b"._ipp._tcp").collect::<Vec<u8>>(), "_ipp._tcp"), None);
    }
}
