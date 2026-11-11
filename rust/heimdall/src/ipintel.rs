//! Where an address belongs, offline (Go: internal/ipintel): a reader of the MaxMind DB format over a read-only mapping of
//! the file (the pages a lookup touches are the kernel's page cache, shared and reclaimable, not the daemon's heap), the
//! origin the alerts name, and the threat lists.
//!
//! A file cut short in place while mapped would fault on a read past its new end. Go turns that fault into an error; here the
//! file's size is checked (fstat on the open file) before each lookup, and a file that shrank is not read until it is opened
//! again. Updates rename a new file over the old one, so the old mapping stays valid until the next reload.

use crate::gonet;
use crate::gotext;
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::time::{Duration, Instant, SystemTime};

const META_MARKER: &[u8] = b"\xab\xcd\xefMaxMind.com";
const MAX_DEPTH: usize = 32;

/// A value of the MaxMind DB data section.
#[derive(Clone, Debug, PartialEq)]
pub enum Val {
    Str(String),
    F64(f64),
    Bytes(Vec<u8>),
    U64(u64),
    I64(i64),
    Map(BTreeMap<String, Val>),
    Arr(Vec<Val>),
    Bool(bool),
}

struct Decoder<'a> {
    buf: &'a [u8],
}

type R<T> = Result<T, String>;

impl<'a> Decoder<'a> {
    fn byte(&self, off: usize) -> R<u8> {
        self.buf.get(off).copied().ok_or_else(|| "value runs past the end".into())
    }
    fn bytes(&self, off: usize, n: usize) -> R<&'a [u8]> {
        let end = off.checked_add(n).ok_or("value runs past the end")?;
        self.buf.get(off..end).ok_or_else(|| "value runs past the end".into())
    }

    fn decode(&self, mut off: usize, depth: usize) -> R<(Val, usize)> {
        if depth > MAX_DEPTH {
            return Err("values nested too deeply".into());
        }
        let ctrl = self.byte(off)?;
        off += 1;
        let mut typ = (ctrl >> 5) as usize;
        if typ == 1 {
            let (ss, vvv) = (((ctrl >> 3) & 3) as usize, (ctrl & 7) as usize);
            let b = self.bytes(off, ss + 1)?;
            let p = match ss {
                0 => vvv << 8 | b[0] as usize,
                1 => (vvv << 16 | (b[0] as usize) << 8 | b[1] as usize) + 2048,
                2 => (vvv << 24 | (b[0] as usize) << 16 | (b[1] as usize) << 8 | b[2] as usize) + 526_336,
                _ => u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize,
            };
            let (v, _) = self.decode(p, depth + 1)?;
            return Ok((v, off + ss + 1));
        }
        if typ == 0 {
            typ = 7 + self.byte(off)? as usize;
            off += 1;
        }
        let mut size = (ctrl & 0x1f) as usize;
        if size >= 29 {
            let n = size - 28;
            let b = self.bytes(off, n)?;
            off += n;
            size = match size {
                29 => 29 + b[0] as usize,
                30 => 285 + ((b[0] as usize) << 8 | b[1] as usize),
                _ => 65_821 + ((b[0] as usize) << 16 | (b[1] as usize) << 8 | b[2] as usize),
            };
        }
        match typ {
            2 => Ok((Val::Str(gotext::lossy(self.bytes(off, size)?)), off + size)),
            3 => {
                let b = self.bytes(off, 8).map_err(|_| "bad double")?;
                if size != 8 {
                    return Err("bad double".into());
                }
                Ok((Val::F64(f64::from_be_bytes(b.try_into().expect("8 bytes"))), off + 8))
            }
            4 => Ok((Val::Bytes(self.bytes(off, size)?.to_vec()), off + size)),
            5 | 6 | 9 | 10 => {
                if size > 16 {
                    return Err("integer too long".into());
                }
                // uint128 keeps its low 64 bits, as in Go
                let v = self.bytes(off, size)?.iter().fold(0u64, |v, &x| v.wrapping_shl(8) | x as u64);
                Ok((Val::U64(v), off + size))
            }
            8 => {
                if size > 4 {
                    return Err("int32 too long".into());
                }
                let v = self.bytes(off, size)?.iter().fold(0u32, |v, &x| v.wrapping_shl(8) | x as u32);
                Ok((Val::I64(v as i32 as i64), off + size))
            }
            7 => {
                let mut m = BTreeMap::new();
                for _ in 0..size {
                    let (k, next) = self.decode(off, depth + 1)?;
                    let Val::Str(key) = k else { return Err("map key is not a string".into()) };
                    let (v, next2) = self.decode(next, depth + 1)?;
                    m.insert(key, v);
                    off = next2;
                }
                Ok((Val::Map(m), off))
            }
            11 => {
                let mut a = Vec::with_capacity(size.min(64));
                for _ in 0..size {
                    let (v, next) = self.decode(off, depth + 1)?;
                    a.push(v);
                    off = next;
                }
                Ok((Val::Arr(a), off))
            }
            14 => Ok((Val::Bool(size != 0), off)),
            15 => {
                let b = self.bytes(off, 4).map_err(|_| "bad float")?;
                if size != 4 {
                    return Err("bad float".into());
                }
                Ok((Val::F64(f32::from_be_bytes(b.try_into().expect("4 bytes")) as f64), off + 4))
            }
            t => Err(format!("unknown value type {t}")),
        }
    }
}

fn to_u64(v: Option<&Val>) -> u64 {
    match v {
        Some(Val::U64(x)) => *x,
        Some(Val::I64(x)) if *x > 0 => *x as u64,
        _ => 0,
    }
}

enum Buf {
    Mapped(memmap2::Mmap, std::fs::File),
    Owned(Vec<u8>),
}

/// One MaxMind DB file.
pub struct Db {
    buf: Buf,
    node_count: usize,
    record_size: usize,
    ip_version: u64,
    data_start: usize,
    tree_size: usize,
    v4_start: usize,
    pub db_type: String,
    pub build_epoch: u64,
}

impl Db {
    /// Maps the file read-only (or reads it, where it cannot be mapped).
    pub fn open(path: &str) -> R<Db> {
        let f = std::fs::File::open(path).map_err(|e| crate::sources::go_path_error("open", path, &e))?;
        let md = f.metadata().map_err(|e| e.to_string())?;
        if md.is_file() && md.len() > 0 {
            // SAFETY: a read-only shared mapping; the file is only ever replaced by rename, and a shrink in place is caught
            // by the size check before each lookup.
            if let Ok(m) = unsafe { memmap2::Mmap::map(&f) } {
                return Db::from_buf(Buf::Mapped(m, f));
            }
        }
        let b = std::fs::read(path).map_err(|e| e.to_string())?;
        Db::from_buf(Buf::Owned(b))
    }

    pub fn from_bytes(b: Vec<u8>) -> R<Db> {
        Db::from_buf(Buf::Owned(b))
    }

    fn bytes(&self) -> &[u8] {
        match &self.buf {
            Buf::Mapped(m, _) => m,
            Buf::Owned(v) => v,
        }
    }

    fn from_buf(buf: Buf) -> R<Db> {
        let b = match &buf {
            Buf::Mapped(m, _) => &m[..],
            Buf::Owned(v) => &v[..],
        };
        let i = b.windows(META_MARKER.len()).rposition(|w| w == META_MARKER).ok_or("not an IP database (no metadata marker)")?;
        let d = Decoder { buf: &b[i + META_MARKER.len()..] };
        let (v, _) = d.decode(0, 0).map_err(|e| format!("metadata: {e}"))?;
        let Val::Map(meta) = v else { return Err("metadata is not a map".into()) };
        let node_count = to_u64(meta.get("node_count")) as usize;
        let record_size = to_u64(meta.get("record_size")) as usize;
        let ip_version = to_u64(meta.get("ip_version"));
        if ![24, 28, 32].contains(&record_size) {
            return Err(format!("unsupported record size {record_size}"));
        }
        if ip_version != 4 && ip_version != 6 {
            return Err(format!("unsupported ip version {ip_version}"));
        }
        let tree_size = node_count.checked_mul(record_size).ok_or("search tree is larger than the file")? / 4;
        let data_start = tree_size + 16;
        if node_count == 0 || data_start > i {
            return Err("search tree is larger than the file".into());
        }
        let db_type = match meta.get("database_type") {
            Some(Val::Str(s)) => s.clone(),
            _ => String::new(),
        };
        let mut db = Db {
            buf,
            node_count,
            record_size,
            ip_version,
            data_start,
            tree_size,
            v4_start: 0,
            db_type,
            build_epoch: to_u64(meta.get("build_epoch")),
        };
        if ip_version == 6 {
            let mut node = 0;
            for _ in 0..96 {
                if node >= db.node_count {
                    break;
                }
                node = db.record(node, 0)?;
            }
            db.v4_start = node;
        }
        Ok(db)
    }

    fn record(&self, node: usize, bit: usize) -> R<usize> {
        let off = node * self.record_size / 4;
        if off + self.record_size / 4 > self.tree_size {
            return Err("search tree is broken".into());
        }
        let b = &self.bytes()[off..];
        Ok(match self.record_size {
            24 => {
                let b = &b[bit * 3..];
                (b[0] as usize) << 16 | (b[1] as usize) << 8 | b[2] as usize
            }
            28 if bit == 0 => ((b[3] & 0xF0) as usize) << 20 | (b[0] as usize) << 16 | (b[1] as usize) << 8 | b[2] as usize,
            28 => ((b[3] & 0x0F) as usize) << 24 | (b[4] as usize) << 16 | (b[5] as usize) << 8 | b[6] as usize,
            _ => u32::from_be_bytes([b[bit * 4], b[bit * 4 + 1], b[bit * 4 + 2], b[bit * 4 + 3]]) as usize,
        })
    }

    /// Whether the mapped file is still as long as the mapping (a file cut short in place must not be read).
    fn intact(&self) -> bool {
        match &self.buf {
            Buf::Mapped(m, f) => f.metadata().is_ok_and(|md| md.len() >= m.len() as u64),
            Buf::Owned(_) => true,
        }
    }

    /// The record for an address (None: no data for it).
    pub fn lookup(&self, ip: &IpAddr) -> R<Option<BTreeMap<String, Val>>> {
        if !self.intact() {
            return Err("the database file was cut short while in use".into());
        }
        let ip = gonet::canonical(*ip);
        let (bits, nbits, mut node): (Vec<u8>, usize, usize) = match ip {
            IpAddr::V4(v4) => (v4.octets().to_vec(), 32, if self.ip_version == 6 { self.v4_start } else { 0 }),
            IpAddr::V6(v6) => {
                if self.ip_version == 4 {
                    return Ok(None);
                }
                (v6.octets().to_vec(), 128, 0)
            }
        };
        for k in 0..nbits {
            if node >= self.node_count {
                break;
            }
            let bit = ((bits[k / 8] >> (7 - k % 8)) & 1) as usize;
            node = self.record(node, bit)?;
        }
        if node <= self.node_count {
            return Ok(None);
        }
        let off = node - self.node_count - 16;
        if self.data_start + off >= self.bytes().len() {
            return Err("data pointer outside the file".into());
        }
        let d = Decoder { buf: &self.bytes()[self.data_start..] };
        let (v, _) = d.decode(off, 0)?;
        Ok(match v {
            Val::Map(m) => Some(m),
            _ => None,
        })
    }
}

/// Where an address belongs.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Origin {
    pub scope: String,
    pub country_code: String,
    pub country: String,
    pub asn: String,
    pub as_name: String,
    pub as_domain: String,
}

impl Origin {
    /// The short sentence the alerts carry.
    pub fn text(&self) -> String {
        if self.scope != "public" {
            return format!("{} network", self.scope);
        }
        let mut parts = Vec::new();
        if !self.country.is_empty() {
            parts.push(self.country.clone());
        } else if !self.country_code.is_empty() {
            parts.push(self.country_code.clone());
        }
        if !self.asn.is_empty() || !self.as_name.is_empty() {
            parts.push(gotext::trim_space(&format!("{} {}", self.asn, self.as_name)).to_owned());
        }
        if parts.is_empty() {
            return "unknown origin".into();
        }
        parts.join(", ")
    }

    /// The fields, each with the prefix, the empty ones left out.
    pub fn fields(&self, prefix: &str) -> Vec<(String, String)> {
        [
            ("scope", &self.scope),
            ("country_code", &self.country_code),
            ("country", &self.country),
            ("asn", &self.asn),
            ("as_name", &self.as_name),
            ("as_domain", &self.as_domain),
        ]
        .iter()
        .filter(|(_, v)| !v.is_empty())
        .map(|(k, v)| (format!("{prefix}{k}"), (*v).clone()))
        .collect()
    }

    pub fn from_record(m: &BTreeMap<String, Val>) -> Origin {
        let s = |v: Option<&Val>| match v {
            Some(Val::Str(s)) => s.clone(),
            _ => String::new(),
        };
        let mut o =
            Origin { scope: "public".into(), country_code: s(m.get("country_code")), country: s(m.get("country")), ..Default::default() };
        if let Some(Val::Map(c)) = m.get("country") {
            o.country = String::new();
            o.country_code = s(c.get("iso_code"));
            if let Some(Val::Map(n)) = c.get("names") {
                o.country = s(n.get("en"));
            }
        }
        o.asn = s(m.get("asn"));
        if let Some(Val::U64(n)) = m.get("autonomous_system_number") {
            if *n > 0 {
                o.asn = format!("AS{n}");
            }
        }
        o.as_name = s(m.get("as_name"));
        if o.as_name.is_empty() {
            o.as_name = s(m.get("autonomous_system_organization"));
        }
        o.as_domain = s(m.get("as_domain"));
        o
    }
}

/// Go's scope of an address: "public", or why it is not.
pub fn scope(ip: &IpAddr) -> &'static str {
    let ip = gonet::canonical(*ip);
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            if o[0] == 127 {
                "loopback"
            } else if gonet::is_private(&ip) {
                "private"
            } else if gonet::is_link_local_unicast(&ip) || (o[0] == 224 && o[1] == 0 && o[2] == 0) {
                "link-local"
            } else if o[0] == 100 && o[1] & 0xc0 == 64 {
                "carrier-grade NAT"
            } else if o[0] & 0xf0 == 224 {
                "multicast"
            } else if o == [0, 0, 0, 0] || o == [255, 255, 255, 255] {
                "reserved"
            } else {
                "public"
            }
        }
        IpAddr::V6(v6) => {
            let o = v6.octets();
            if v6.is_loopback() {
                "loopback"
            } else if gonet::is_private(&ip) {
                "private"
            } else if gonet::is_link_local_unicast(&ip) || (o[0] == 0xff && o[1] & 0x0f == 2) {
                "link-local"
            } else if o[0] == 0xff {
                "multicast"
            } else if v6.is_unspecified() {
                "reserved"
            } else {
                "public"
            }
        }
    }
}

/// Several databases; the first that knows an address answers each part. Reloaded when a file's time changes (looked at
/// once a minute at most).
pub struct Resolver {
    paths: Vec<String>,
    dbs: Option<Vec<Db>>,
    mtime: Vec<Option<SystemTime>>,
    check: Option<Instant>,
}

impl Resolver {
    pub fn new(paths: &[String]) -> Resolver {
        Resolver { paths: paths.to_vec(), dbs: None, mtime: Vec::new(), check: None }
    }

    fn reload(&mut self) {
        if self.dbs.is_some() && self.check.is_some_and(|c| c.elapsed() < Duration::from_secs(60)) {
            return;
        }
        self.check = Some(Instant::now());
        let mt: Vec<Option<SystemTime>> = self.paths.iter().map(|p| std::fs::metadata(p).ok().and_then(|m| m.modified().ok())).collect();
        if self.dbs.is_some() && mt == self.mtime {
            return;
        }
        self.dbs = Some(self.paths.iter().filter_map(|p| Db::open(p).ok()).collect());
        self.mtime = mt;
    }

    pub fn available(&mut self) -> bool {
        self.reload();
        self.dbs.as_ref().is_some_and(|d| !d.is_empty())
    }

    pub fn lookup(&mut self, ip: &IpAddr) -> Origin {
        let mut o = Origin { scope: scope(ip).into(), ..Default::default() };
        if o.scope != "public" {
            return o;
        }
        self.reload();
        for db in self.dbs.iter().flatten() {
            let Ok(Some(m)) = db.lookup(ip) else { continue };
            let f = Origin::from_record(&m);
            if o.country_code.is_empty() {
                o.country_code = f.country_code;
                o.country = f.country;
            }
            if o.asn.is_empty() && o.as_name.is_empty() {
                o.asn = f.asn;
                o.as_name = f.as_name;
                o.as_domain = f.as_domain;
            }
        }
        o
    }
}

/// An address as a number with its family (4 or 6), for ranges.
fn key(ip: &IpAddr) -> (u8, u128) {
    match gonet::canonical(*ip) {
        IpAddr::V4(v) => (4, u32::from(v) as u128),
        IpAddr::V6(v) => (6, u128::from(v)),
    }
}

/// One threat list: merged, non-overlapping ranges.
pub struct List {
    pub name: String,
    pub entries: usize,
    ranges: Vec<((u8, u128), u128)>,
}

/// Reads a threat list (one address or CIDR a line; `#` and `;` comments; Spamhaus's JSON lines).
pub fn parse_list(name: &str, data: &[u8]) -> Option<List> {
    let text = gotext::lossy(data);
    let mut prefixes: Vec<((u8, u128), u128)> = Vec::new();
    for line in text.lines() {
        let mut line = gotext::trim_space(line).to_owned();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('{') {
            #[derive(Default)]
            struct J {
                cidr: String,
            }
            crate::go_struct!(J { cidr: "cidr" });
            match crate::gojson::unmarshal(line.as_bytes(), J::default()) {
                Ok(j) if !j.cidr.is_empty() => line = j.cidr,
                _ => continue,
            }
        }
        let first = line.split(';').next().unwrap_or("").split('#').next().unwrap_or("");
        let Some(tok) = gotext::fields(first).next() else { continue };
        let (addr, bits) = match tok.split_once('/') {
            Some((a, bs)) => {
                // netip.ParsePrefix: decimal bits, no sign, no leading zero
                let plain = !bs.is_empty() && bs.bytes().all(|c| c.is_ascii_digit()) && (bs == "0" || !bs.starts_with('0'));
                match (a.parse::<IpAddr>(), bs.parse::<u32>()) {
                    (Ok(a), Ok(n)) if plain && n <= if a.is_ipv4() { 32 } else { 128 } => (a, n),
                    _ => continue,
                }
            }
            None => match tok.parse::<IpAddr>() {
                Ok(a) => (a, if a.is_ipv4() { 32 } else { 128 }),
                Err(_) => continue,
            },
        };
        // netip keeps a v4-mapped prefix as IPv6; Go's scope then sees the IPv4 address
        let (fam, width) = if addr.is_ipv4() { (4u8, 32u32) } else { (6, 128) };
        let raw: u128 = match addr {
            IpAddr::V4(v) => u32::from(v) as u128,
            IpAddr::V6(v) => u128::from(v),
        };
        let full: u128 = !0u128 >> (128 - width);
        let host: u128 = 1u128.checked_shl(width - bits).map_or(!0, |h| h - 1) & full;
        let start = raw & full & !host;
        let end = start | host;
        let start_ip = if fam == 4 { IpAddr::V4((start as u32).into()) } else { IpAddr::V6(start.into()) };
        if scope(&start_ip) != "public" || bits < 8 {
            continue;
        }
        prefixes.push(((fam, start), end));
    }
    if prefixes.is_empty() {
        return None;
    }
    let entries = prefixes.len();
    prefixes.sort_by_key(|p| p.0);
    let mut ranges: Vec<((u8, u128), u128)> = Vec::new();
    for (start, end) in prefixes {
        if let Some(last) = ranges.last_mut() {
            if last.0 .0 == start.0 && last.1.checked_add(1).is_some_and(|n| n >= start.1) {
                if last.1 < end {
                    last.1 = end;
                }
                continue;
            }
        }
        ranges.push((start, end));
    }
    Some(List { name: name.into(), entries, ranges })
}

impl List {
    /// How many IPv4 addresses the list covers (Go's `V4Addresses`; `intel-check` compares an update with the last copy).
    pub fn v4_addresses(&self) -> u64 {
        self.ranges.iter().filter(|r| r.0 .0 == 4).map(|r| (r.1 - r.0 .1) as u64 + 1).sum()
    }

    pub fn contains(&self, ip: &IpAddr) -> bool {
        let k = key(ip);
        let i = self.ranges.partition_point(|r| r.0 <= k);
        i > 0 && self.ranges[i - 1].0 .0 == k.0 && self.ranges[i - 1].1 >= k.1
    }
}

/// The threat lists of a folder (*.list), reloaded when a file changes (looked at once a minute at most).
pub struct Lists {
    dir: String,
    lists: Vec<List>,
    stamp: String,
    check: Option<Instant>,
}

impl Lists {
    pub fn new(dir: &str) -> Lists {
        Lists { dir: dir.into(), lists: Vec::new(), stamp: String::new(), check: None }
    }

    fn reload(&mut self) {
        if !self.stamp.is_empty() && self.check.is_some_and(|c| c.elapsed() < Duration::from_secs(60)) {
            return;
        }
        self.check = Some(Instant::now());
        let files = crate::sources::glob_suffix(&self.dir, ".list");
        let mut stamp = String::new();
        for f in &files {
            if let Ok(md) = std::fs::metadata(f) {
                stamp.push_str(&format!("{f}:{}:{};", md.len(), crate::sources::mtime(&md).unix_nanos()));
            }
        }
        if stamp == self.stamp {
            return;
        }
        self.lists = files
            .iter()
            .filter_map(|f| {
                let b = std::fs::read(f).ok()?;
                let name = f.rsplit('/').next().unwrap_or(f).trim_end_matches(".list");
                parse_list(name, &b)
            })
            .collect();
        self.stamp = if stamp.is_empty() { "none".into() } else { stamp };
    }

    /// The names of the lists holding a public address.
    pub fn matching(&mut self, ip: &IpAddr) -> Vec<String> {
        if scope(ip) != "public" {
            return Vec::new();
        }
        self.reload();
        self.lists.iter().filter(|l| l.contains(ip)).map(|l| l.name.clone()).collect()
    }

    pub fn count(&mut self) -> (usize, usize) {
        self.reload();
        (self.lists.len(), self.lists.iter().map(|l| l.entries).sum())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scopes_like_go() {
        for (ip, want) in [
            ("10.1.2.3", "private"),
            ("127.0.0.1", "loopback"),
            ("100.64.0.2", "carrier-grade NAT"),
            ("224.0.0.251", "link-local"),
            ("239.1.1.1", "multicast"),
            ("255.255.255.255", "reserved"),
            ("203.0.113.9", "public"),
            ("fe80::1", "link-local"),
            ("ff02::fb", "link-local"),
            ("ff05::1", "multicast"),
            ("::", "reserved"),
            ("2001:db8::1", "public"),
        ] {
            assert_eq!(scope(&ip.parse().unwrap()), want, "{ip}");
        }
    }

    #[test]
    fn lists_merge_and_match() {
        let l = parse_list("drop", b"# c\n203.0.113.0/25 ; x\n203.0.113.128/25\n10.0.0.0/8\n{\"cidr\":\"198.51.100.7/32\"}\n{\"type\":\"metadata\"}\n2001:db8::/32\n1.0.0.0/4\n").unwrap();
        assert_eq!(l.entries, 4);
        assert!(l.contains(&"203.0.113.200".parse().unwrap()));
        assert!(l.contains(&"::ffff:198.51.100.7".parse().unwrap()));
        assert!(!l.contains(&"198.51.100.8".parse().unwrap()));
        assert!(l.contains(&"2001:db8::5".parse().unwrap()));
        assert!(!l.contains(&"10.1.1.1".parse().unwrap()), "private ranges are never listed");
    }
}
