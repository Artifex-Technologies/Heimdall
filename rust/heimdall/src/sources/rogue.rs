//! A second router on the network (Go: netsource.RogueRouterWatcher): a DHCP server other than the one that answered first
//! (or than the one a trusted network remembers), a device other than the router announcing itself as the IPv6 router, a new
//! IPv6 prefix in the middle of a connection, IPv6 appearing on a network that never had it. It sends nothing: DHCP comes from
//! the dispatcher 91-heimdall-netid's lines, IPv6 from the kernel's table (/proc/net/ipv6_route). What a trusted or home network
//! remembers is kept as hashes (mode 0600); nothing is kept for any other network.

use super::{Msg, Source};
use crate::event::{Event, Fields};
use crate::gotime::Time;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Seek, SeekFrom};
use std::time::{Duration, Instant};

const LEARN_AFTER: i64 = 3;
const LATE_IPV6: i64 = 120;

#[derive(Default)]
struct Line {
    t: i64,
    action: String,
    iface: String,
    uuid: String,
    dhcp4_server: String,
    dhcp4_routers: String,
    dns4: String,
    dns6: String,
}
crate::go_struct!(Line {
    t: "t",
    action: "action",
    iface: "iface",
    uuid: "uuid",
    dhcp4_server: "dhcp4_server",
    dhcp4_routers: "dhcp4_routers",
    dns4: "dns4",
    dns6: "dns6"
});

#[derive(Default)]
struct Current {
    ssid: String,
    uuid: String,
    trusted: bool,
    level: String,
}
crate::go_struct!(Current { ssid: "ssid", uuid: "uuid", trusted: "trusted", level: "level" });

#[derive(Default)]
struct Known {
    conns: i64,
    ipv6: bool,
    values: BTreeMap<String, Vec<String>>,
    pending: BTreeMap<String, i64>,
}
crate::go_struct!(Known { conns: "conns", ipv6: "ipv6", values: "values", pending: "pending" });

#[derive(Default)]
struct State {
    nets: BTreeMap<String, Known>,
}
crate::go_struct!(State { nets: "nets" });

struct Conn {
    uuid: String,
    up: i64,
    first: BTreeMap<String, String>,
    ra: Vec<String>,
    ra_first: i64,
    prefixes: BTreeSet<String>,
    counted: BTreeSet<String>,
    reported: BTreeSet<String>,
}

impl Conn {
    fn new(uuid: &str, up: i64) -> Conn {
        Conn {
            uuid: uuid.into(),
            up,
            first: BTreeMap::new(),
            ra: Vec::new(),
            ra_first: 0,
            prefixes: BTreeSet::new(),
            counted: BTreeSet::new(),
            reported: BTreeSet::new(),
        }
    }
}

struct Signal {
    kind: &'static str,
    before: String,
    after: String,
}

fn hash(parts: &[&str]) -> String {
    let d = Sha256::digest(parts.join("|").as_bytes());
    d[..16].iter().map(|b| format!("{b:02x}")).collect()
}

/// The watch (Go: RogueRouterWatcher).
pub struct RogueSource {
    netid: String,
    current: String,
    state_path: String,
    proc_root: String,
    started: Option<i64>,
    off: u64,
    conns: BTreeMap<String, Conn>,
    state: State,
    loaded: bool,
    next: Instant,
}

impl RogueSource {
    pub fn new(netid: &str, current: &str, state: &str, proc_root: &str) -> RogueSource {
        RogueSource {
            netid: netid.into(),
            current: current.into(),
            state_path: state.into(),
            proc_root: proc_root.into(),
            started: None,
            off: 0,
            conns: BTreeMap::new(),
            state: State::default(),
            loaded: false,
            next: Instant::now(),
        }
    }

    /// One look at the given time (Unix seconds): the dispatcher's new lines, then the kernel's IPv6 routes.
    pub fn poll_at(&mut self, now: i64) -> Vec<Event> {
        let started = *self.started.get_or_insert(now);
        if !self.loaded {
            self.loaded = true;
            if let Ok(b) = std::fs::read(&self.state_path) {
                if let Ok(s) = crate::gojson::unmarshal(&b, State::default()) {
                    self.state = s;
                }
            }
        }
        let cur = std::fs::read(&self.current).ok().and_then(|b| crate::gojson::unmarshal(&b, Current::default()).ok()).unwrap_or_default();
        let mut out = Vec::new();
        let mut changed = false;
        for l in self.new_lines() {
            let quiet = l.t < started - 300;
            let (ev, ch) = self.line(&l, &cur, quiet, now);
            out.extend(ev);
            changed |= ch;
        }
        let table = std::fs::read_to_string(format!("{}/net/ipv6_route", self.proc_root)).unwrap_or_default();
        let ifaces: Vec<String> = self.conns.keys().cloned().collect();
        for iface in ifaces {
            let (ev, ch) = self.routes(&iface, &table, &cur, now);
            out.extend(ev);
            changed |= ch;
        }
        if changed {
            self.save();
        }
        out
    }

    fn new_lines(&mut self) -> Vec<Line> {
        let Ok(mut f) = std::fs::File::open(&self.netid) else { return Vec::new() };
        if f.metadata().is_ok_and(|m| m.len() < self.off) {
            self.off = 0;
        }
        if f.seek(SeekFrom::Start(self.off)).is_err() {
            return Vec::new();
        }
        let mut buf = Vec::new();
        let _ = f.read_to_end(&mut buf);
        let mut out = Vec::new();
        let mut rest = &buf[..];
        while let Some(i) = rest.iter().position(|&c| c == b'\n') {
            self.off += i as u64 + 1;
            if let Ok(l) = crate::gojson::unmarshal(rest[..i].trim_ascii(), Line::default()) {
                if !l.iface.is_empty() {
                    out.push(l);
                }
            }
            rest = &rest[i + 1..];
        }
        out
    }

    /// The key of a trusted or home network's memory; None for any other network (nothing is kept for those).
    fn known_key(&mut self, uuid: &str, cur: &Current) -> Option<String> {
        if uuid.is_empty() || cur.uuid != uuid || !(cur.trusted || cur.level == "trusted" || cur.level == "home") {
            return None;
        }
        let key = hash(&["net", uuid]);
        self.state.nets.entry(key.clone()).or_default();
        Some(key)
    }

    /// Go: learn. True when the value contradicts what the network remembers.
    fn learn(k: &mut Known, c: &mut Conn, kind: &str, value: &str) -> bool {
        let h = hash(&[&c.uuid, kind, value]);
        let list = k.values.entry(kind.to_string()).or_default();
        if list.contains(&h) {
            return false;
        }
        if list.is_empty() {
            list.push(h);
            return false;
        }
        if c.counted.insert(h.clone()) {
            let n = k.pending.entry(h.clone()).or_default();
            *n += 1;
            if *n >= LEARN_AFTER {
                k.pending.remove(&h);
                list.push(h);
                if list.len() > 4 {
                    list.remove(0);
                }
            }
        }
        true
    }

    fn line(&mut self, l: &Line, cur: &Current, quiet: bool, now: i64) -> (Option<Event>, bool) {
        if l.action == "down" {
            self.conns.remove(&l.iface);
            return (None, false);
        }
        let mut changed = false;
        let fresh = self.conns.get(&l.iface).is_none_or(|c| c.uuid != l.uuid) || l.action == "up";
        if fresh {
            self.conns.insert(l.iface.clone(), Conn::new(&l.uuid, l.t));
            if l.action == "up" {
                if let Some(key) = self.known_key(&l.uuid, cur) {
                    self.state.nets.get_mut(&key).unwrap().conns += 1;
                    changed = true;
                }
            }
        }
        let key = self.known_key(&l.uuid, cur);
        let c = self.conns.get_mut(&l.iface).unwrap();
        let mut learned = false;
        let mut sigs = Vec::new();
        for (kind, v) in [("dhcp_server", &l.dhcp4_server), ("dhcp_router", &l.dhcp4_routers), ("dns4", &l.dns4), ("dns6", &l.dns6)] {
            if v.is_empty() {
                continue;
            }
            let had = c.first.get(kind).cloned();
            if had.is_none() {
                c.first.insert(kind.into(), v.clone());
            }
            let first = had.clone().unwrap_or_default();
            if let Some(key) = &key {
                changed = true;
                if Self::learn(self.state.nets.get_mut(key).unwrap(), c, kind, v) {
                    learned = true;
                    sigs.push(Signal { kind, before: first, after: v.clone() });
                    continue;
                }
            }
            if had.is_some() && *v != first {
                sigs.push(Signal { kind, before: first, after: v.clone() });
            }
        }
        if quiet || sigs.is_empty() {
            return (None, changed);
        }
        (event(&l.iface, c, cur, "dhcp", &sigs, learned, now), changed)
    }

    fn routes(&mut self, iface: &str, table: &str, cur: &Current, now: i64) -> (Option<Event>, bool) {
        let (routers, prefixes) = ipv6_routes(table, iface);
        let uuid = self.conns[iface].uuid.clone();
        let key = self.known_key(&uuid, cur);
        let c = self.conns.get_mut(iface).unwrap();
        let (mut changed, mut learned) = (false, false);
        let mut sigs = Vec::new();
        for r in &routers {
            if c.ra.contains(r) {
                continue;
            }
            let first_router = c.ra.is_empty();
            c.ra.push(r.clone());
            if first_router {
                c.ra_first = now;
                c.prefixes.extend(prefixes.iter().cloned());
            }
            if let Some(key) = &key {
                let k = self.state.nets.get_mut(key).unwrap();
                changed = true;
                if first_router && !k.ipv6 && k.conns >= LEARN_AFTER {
                    learned = true;
                    sigs.push(Signal { kind: "ipv6_new", before: String::new(), after: r.clone() });
                    Self::learn(k, c, "ra_router", r);
                    let h = hash(&[&c.uuid, "ipv6"]);
                    let n = k.pending.entry(h.clone()).or_default();
                    *n += 1;
                    if *n >= LEARN_AFTER {
                        k.pending.remove(&h);
                        k.ipv6 = true;
                    }
                } else {
                    k.ipv6 = true;
                    if Self::learn(k, c, "ra_router", r) {
                        learned = true;
                        sigs.push(Signal { kind: "ra_router", before: String::new(), after: r.clone() });
                    } else if !first_router {
                        sigs.push(Signal { kind: "ra_router", before: c.ra[0].clone(), after: r.clone() });
                    }
                }
            } else if first_router && now - c.up > LATE_IPV6 {
                sigs.push(Signal { kind: "ipv6_late", before: String::new(), after: r.clone() });
            } else if !first_router {
                sigs.push(Signal { kind: "ra_router", before: c.ra[0].clone(), after: r.clone() });
            }
        }
        if !c.ra.is_empty() {
            for p in &prefixes {
                if c.prefixes.insert(p.clone()) && now - c.ra_first > 60 {
                    sigs.push(Signal { kind: "ra_prefix", before: String::new(), after: p.clone() });
                }
            }
        }
        if sigs.is_empty() {
            return (None, changed);
        }
        (event(iface, c, cur, "ra", &sigs, learned, now), changed)
    }

    /// Go: save (json.Marshal's shape: keys sorted, no spaces), mode 0600, by a rename.
    fn save(&self) {
        if self.state_path.is_empty() {
            return;
        }
        let mut s = String::from("{\"nets\":{");
        for (i, (key, k)) in self.state.nets.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            crate::gojson::write_str(&mut s, key);
            s.push_str(&format!(":{{\"conns\":{},\"ipv6\":{},\"values\":{{", k.conns, k.ipv6));
            for (j, (kind, list)) in k.values.iter().enumerate() {
                if j > 0 {
                    s.push(',');
                }
                crate::gojson::write_str(&mut s, kind);
                s.push_str(":[");
                for (m, h) in list.iter().enumerate() {
                    if m > 0 {
                        s.push(',');
                    }
                    crate::gojson::write_str(&mut s, h);
                }
                s.push(']');
            }
            s.push_str("},\"pending\":{");
            for (j, (h, n)) in k.pending.iter().enumerate() {
                if j > 0 {
                    s.push(',');
                }
                crate::gojson::write_str(&mut s, h);
                s.push_str(&format!(":{n}"));
            }
            s.push_str("}}");
        }
        s.push_str("}}\n");
        use std::os::unix::fs::OpenOptionsExt;
        let tmp = format!("{}.tmp", self.state_path);
        let _ = std::fs::remove_file(&tmp);
        let ok = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp).and_then(|mut f| {
            use std::io::Write;
            f.write_all(s.as_bytes())
        });
        if ok.is_ok() {
            let _ = std::fs::rename(&tmp, &self.state_path);
        }
    }
}

/// Go: ipv6Routes. The routers of iface's default routes (link-local next hops) and its on-link prefixes.
pub fn ipv6_routes(table: &str, iface: &str) -> (Vec<String>, Vec<String>) {
    let (mut routers, mut prefixes) = (Vec::new(), Vec::new());
    let zero = "0".repeat(32);
    for line in table.split('\n') {
        let x: Vec<&str> = crate::gotext::fields(line).collect();
        if x.len() < 10 || x[9] != iface || x[0].len() != 32 || x[4].len() != 32 {
            continue;
        }
        let (dest, plen, hop) = (x[0], x[1], x[4]);
        if plen == "00" && dest == zero && hop.starts_with("fe8") {
            routers.push(hex_ipv6(hop));
        } else if plen != "00" && plen != "80" && hop == zero && !dest.starts_with("fe8") && !dest.starts_with("ff") {
            let n = i64::from_str_radix(plen, 16).unwrap_or(0);
            prefixes.push(format!("{}/{n}", hex_ipv6(dest)));
        }
    }
    (routers, prefixes)
}

/// Go: hexIPv6 (the short form, the longest run of two or more zero groups as ::).
pub fn hex_ipv6(h: &str) -> String {
    let b: Option<Vec<u8>> = (0..h.len() / 2).map(|i| h.get(2 * i..2 * i + 2).and_then(|s| u8::from_str_radix(s, 16).ok())).collect();
    let Some(b) = b.filter(|b| b.len() == 16 && h.len() == 32) else { return h.to_string() };
    let g: Vec<u16> = (0..8).map(|i| (b[2 * i] as u16) << 8 | b[2 * i + 1] as u16).collect();
    let (mut bs, mut bl) = (usize::MAX, 0);
    let mut i = 0;
    while i < 8 {
        let mut j = i;
        while j < 8 && g[j] == 0 {
            j += 1;
        }
        if j - i > bl && j - i >= 2 {
            bs = i;
            bl = j - i;
        }
        i = if j == i { i + 1 } else { j };
    }
    let mut s = String::new();
    let mut i = 0;
    while i < 8 {
        if i == bs {
            s.push_str("::");
            i += bl;
            continue;
        }
        if i > 0 && (bs == usize::MAX || i != bs + bl) {
            s.push(':');
        }
        s.push_str(&format!("{:x}", g[i]));
        i += 1;
    }
    s
}

fn what(s: &Signal, learned: bool, c: &Conn, now: i64) -> String {
    let was = if s.before.is_empty() {
        if learned {
            " (not the one remembered for this network)".to_string()
        } else {
            String::new()
        }
    } else {
        format!(" (it was {})", s.before)
    };
    match s.kind {
        "dhcp_server" => format!("a DHCP server {} answered{was}", s.after),
        "dhcp_router" => format!("the router handed out is {}{was}", s.after),
        "dns4" | "dns6" => format!("the DNS servers handed out are {}{}", s.after, was.replacen("it was", "they were", 1)),
        "ra_router" => format!("a device {} announced itself as the IPv6 router{was}", s.after),
        "ra_prefix" => format!("a new IPv6 network {} was announced in the middle of the connection", s.after),
        "ipv6_new" => format!("an IPv6 router {} appeared on a network that never had IPv6", s.after),
        "ipv6_late" => {
            format!("an IPv6 router {} appeared {} minutes after joining, on a network that had none", s.after, (now - c.up) / 60)
        }
        k => format!("{k} {}", s.after),
    }
}

/// Go: event. One alert of the signals that changed together, once per connection for the same values.
fn event(iface: &str, c: &mut Conn, cur: &Current, via: &str, sigs: &[Signal], learned: bool, now: i64) -> Option<Event> {
    let kinds: Vec<&str> = sigs.iter().map(|s| s.kind).collect();
    let before: Vec<String> =
        sigs.iter().map(|s| format!("{}={}", s.kind, if s.before.is_empty() && learned { "remembered" } else { &s.before })).collect();
    let after: Vec<String> = sigs.iter().map(|s| format!("{}={}", s.kind, s.after)).collect();
    let text = sigs.iter().map(|s| what(s, learned, c, now)).collect::<Vec<_>>().join("; ");
    if !c.reported.insert(format!("{via}|{}", after.join(";"))) {
        return None;
    }
    let conf = if learned && sigs.len() >= 2 {
        "high"
    } else if learned || sigs.len() >= 2 {
        "medium"
    } else {
        "low"
    };
    let (mut ssid, mut level) = (String::new(), String::new());
    if cur.uuid == c.uuid && !c.uuid.is_empty() {
        ssid = cur.ssid.clone();
        level = cur.level.clone();
        if level.is_empty() && cur.trusted {
            level = "home".into();
        }
    }
    let f: Fields = [
        ("ssid", ssid),
        ("iface", iface.to_string()),
        ("level", level),
        ("via", via.to_string()),
        ("signals", kinds.join(",")),
        ("before", before.join(";")),
        ("after", after.join(";")),
        ("learned", learned.to_string()),
        ("confidence", conf.to_string()),
        ("what", text.clone()),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v))
    .collect();
    Some(Event {
        source: "host-lan".into(),
        session_id: String::new(),
        time: Time::from_unix(now, 0),
        kind: "rogue_router".into(),
        text,
        fields: f,
    })
}

impl Source for RogueSource {
    fn name(&self) -> &'static str {
        "rogue-router"
    }
    fn due(&self) -> Option<Instant> {
        Some(self.next)
    }
    fn run(&mut self, now: Instant, out: &mut Vec<Msg>) {
        self.next = now + Duration::from_secs(10);
        out.extend(self.poll_at(Time::now().unix()).into_iter().map(Msg::Event));
    }
}
