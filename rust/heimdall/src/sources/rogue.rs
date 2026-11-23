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
    gw_mac: String,
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
            gw_mac: String::new(),
            prefixes: BTreeSet::new(),
            counted: BTreeSet::new(),
            reported: BTreeSet::new(),
        }
    }
}

/// Go: rogueSignal. learned: it contradicts what a trusted network remembers; during: it changed in the middle of a connection.
struct Signal {
    kind: &'static str,
    before: String,
    after: String,
    learned: bool,
    during: bool,
}

fn sig(kind: &'static str, before: &str, after: &str, learned: bool, during: bool) -> Signal {
    Signal { kind, before: before.into(), after: after.into(), learned, during }
}

fn hash(parts: &[&str]) -> String {
    let d = Sha256::digest(parts.join("|").as_bytes());
    d[..16].iter().map(|b| format!("{b:02x}")).collect()
}

/// The watch (Go: RogueRouterWatcher).
pub struct RogueSource {
    netid: String,
    current: String,
    /// /etc/heimdall/wifi-trusted.json: the kind of network the owner set (heimdall-wifi-guard kind)
    pub trusted: String,
    state_path: String,
    proc_root: String,
    /// where `phone_usb` reads an interface's driver (tests point it at a fake tree)
    pub sys_root: String,
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
            trusted: "/etc/heimdall/wifi-trusted.json".into(),
            state_path: state.into(),
            proc_root: proc_root.into(),
            sys_root: "/sys".into(),
            started: None,
            off: 0,
            conns: BTreeMap::new(),
            state: State::default(),
            loaded: false,
            next: Instant::now(),
        }
    }

    /// Go: kind. The kind of network the owner set for uuid; none set is a home router.
    fn kind(&self, uuid: &str) -> &'static str {
        let Ok(b) = std::fs::read(&self.trusted) else { return "home-router" };
        let Ok(crate::gojson::Value::Object(t)) = crate::gojson::parse(&b) else { return "home-router" };
        for (k, v) in t.iter().rev() {
            if k == uuid {
                if let crate::gojson::Value::Object(e) = v {
                    for (ek, ev) in e.iter().rev() {
                        if ek == "kind" {
                            if let crate::gojson::Value::String(s) = ev {
                                if let Some(x) = ["mesh", "phone-hotspot", "travel", "other"].iter().find(|x| **x == s.as_str()) {
                                    return x;
                                }
                            }
                        }
                    }
                }
            }
        }
        "home-router"
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
        // Go: readARP (IP address, HW type, Flags, HW address, Mask, Device; flags 0x0 means incomplete)
        let arp: Vec<(String, String, String)> = std::fs::read_to_string(format!("{}/net/arp", self.proc_root))
            .unwrap_or_default()
            .lines()
            .skip(1)
            .filter_map(|line| {
                let x: Vec<&str> = crate::gotext::fields(line).collect();
                (x.len() >= 6 && x[2] != "0x0" && x[3] != "00:00:00:00:00:00")
                    .then(|| (x[0].to_string(), x[3].to_uppercase(), x[5].to_string()))
            })
            .collect();
        let ifaces: Vec<String> = self.conns.keys().cloned().collect();
        for iface in ifaces {
            let (ev, ch) = self.routes(&iface, &table, &arp, &cur, now);
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
        let kind = self.kind_if_known(&l.uuid, cur);
        let c = self.conns.get_mut(&l.iface).unwrap();
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
                    sigs.push(sig(kind, &first, v, true, had.is_some()));
                    continue;
                }
            }
            if had.is_some() && *v != first {
                sigs.push(sig(kind, &first, v, false, true));
            }
        }
        if quiet || sigs.is_empty() {
            return (None, changed);
        }
        (event(&l.iface, c, cur, "dhcp", &sigs, kind, now), changed)
    }

    /// Go: kindIfKnown. The kind of a trusted or home network ("" for any other network).
    fn kind_if_known(&mut self, uuid: &str, cur: &Current) -> &'static str {
        if self.known_key(uuid, cur).is_none() {
            return "";
        }
        self.kind(uuid)
    }

    fn routes(&mut self, iface: &str, table: &str, arp: &[(String, String, String)], cur: &Current, now: i64) -> (Option<Event>, bool) {
        let (routers, prefixes) = ipv6_routes(table, iface);
        let uuid = self.conns[iface].uuid.clone();
        let key = self.known_key(&uuid, cur);
        let kind = self.kind_if_known(&uuid, cur);
        let hotspot = kind == "phone-hotspot";
        let usb = phone_usb(&self.sys_root, iface);
        let c = self.conns.get_mut(iface).unwrap();
        let mut changed = false;
        let mut sigs = Vec::new();
        // the router's hardware address (the kernel's neighbour table, for the router the DHCP server handed out)
        let gw = c.first.get("dhcp_router").and_then(|r| crate::gotext::fields(r).next().map(str::to_string));
        if let Some(gw) = gw {
            let home = cur.uuid == c.uuid && (cur.level == "home" || (cur.level.is_empty() && cur.trusted));
            for (ip, mac, dev) in arp {
                if dev != iface || *ip != gw {
                    continue;
                }
                if c.gw_mac.is_empty() {
                    c.gw_mac = mac.clone();
                    // a phone hotspot makes up a new address when it restarts: expected, not remembered
                    if let (Some(key), false) = (&key, hotspot) {
                        changed = true;
                        if Self::learn(self.state.nets.get_mut(key).unwrap(), c, "gateway_mac", mac) {
                            sigs.push(sig("gateway_mac", "", mac, true, false));
                        }
                    }
                } else if *mac != c.gw_mac && home {
                    // in the middle of a connection, on every kind (the router watch covers every network but home)
                    sigs.push(sig("gateway_mac", &c.gw_mac.clone(), mac, false, true));
                    c.gw_mac = mac.clone();
                }
            }
        }
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
                    sigs.push(sig("ipv6_new", "", r, true, false));
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
                    if hotspot && first_router {
                        continue; // a restarted hotspot's router address is new too
                    }
                    if Self::learn(k, c, "ra_router", r) {
                        sigs.push(sig("ra_router", "", r, true, !first_router));
                    } else if !first_router {
                        sigs.push(sig("ra_router", &c.ra[0].clone(), r, false, true));
                    }
                }
            } else if first_router && now - c.up > LATE_IPV6 {
                sigs.push(sig("ipv6_late", "", r, false, true));
            } else if !first_router {
                sigs.push(sig("ra_router", &c.ra[0].clone(), r, false, true));
            }
        }
        if !c.ra.is_empty() {
            for p in &prefixes {
                if c.prefixes.insert(p.clone()) && now - c.ra_first > 60 {
                    if usb {
                        // the owner's decision, 2026-11-22: noted, not an alert
                        eprintln!("rogue-router: {iface} is a phone's USB link: its new IPv6 network {p} is noted, not reported (only the phone is on the cable)");
                        continue;
                    }
                    sigs.push(sig("ra_prefix", "", p, false, true));
                }
            }
        }
        if sigs.is_empty() {
            return (None, changed);
        }
        (event(iface, c, cur, "ra", &sigs, kind, now), changed)
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

/// Go: phoneUSB. Whether `iface` is a phone's own USB link (an iPhone's ipheth, an Android phone's RNDIS): only the phone is on
/// that cable, so a new IPv6 network there is the phone's own (carriers change the prefixes they hand out), not a second
/// router.
pub fn phone_usb(sys_root: &str, iface: &str) -> bool {
    std::fs::canonicalize(format!("{sys_root}/class/net/{iface}/device/driver"))
        .ok()
        .and_then(|d| d.file_name().map(|n| n.to_string_lossy().into_owned()))
        .is_some_and(|n| n == "ipheth" || n == "rndis_host")
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

fn what(s: &Signal, c: &Conn, now: i64) -> String {
    let was = if s.before.is_empty() {
        if s.learned {
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
        "gateway_mac" => format!("the router's hardware address is {}{was}", s.after),
        "ra_router" => format!("a device {} announced itself as the IPv6 router{was}", s.after),
        "ra_prefix" => format!("a new IPv6 network {} was announced in the middle of the connection", s.after),
        "ipv6_new" => format!("an IPv6 router {} appeared on a network that never had IPv6", s.after),
        "ipv6_late" => {
            format!("an IPv6 router {} appeared {} minutes after joining, on a network that had none", s.after, (now - c.up) / 60)
        }
        k => format!("{k} {}", s.after),
    }
}

/// Go: rogueJudge. One thing about a trusted network's router differing from last time is "info"; two or more at once, an
/// unknown router in the middle of a connection, or the router's hardware address changing during a connection, "critical";
/// anything else a "warning" (IPv6 appearing on a network that never had it is never less).
fn judge(sigs: &[Signal]) -> &'static str {
    let mut start = 0;
    for s in sigs {
        if (s.learned && s.during) || (s.kind == "gateway_mac" && s.during) {
            return "critical";
        }
        if s.learned {
            start += 1;
        }
    }
    if start >= 2 {
        "critical"
    } else if start == 1 && sigs.len() == 1 && sigs[0].kind != "ipv6_new" {
        "info"
    } else {
        "warning"
    }
}

/// Go: event. One alert of the signals that changed together, once per connection for the same values.
fn event(iface: &str, c: &mut Conn, cur: &Current, via: &str, sigs: &[Signal], kind: &str, now: i64) -> Option<Event> {
    let learned = sigs.iter().any(|s| s.learned);
    let kinds: Vec<&str> = sigs.iter().map(|s| s.kind).collect();
    let before: Vec<String> =
        sigs.iter().map(|s| format!("{}={}", s.kind, if s.before.is_empty() && s.learned { "remembered" } else { &s.before })).collect();
    let after: Vec<String> = sigs.iter().map(|s| format!("{}={}", s.kind, s.after)).collect();
    let text = sigs.iter().map(|s| what(s, c, now)).collect::<Vec<_>>().join("; ");
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
        ("judged", judge(sigs).to_string()),
        ("network_kind", kind.to_string()),
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
