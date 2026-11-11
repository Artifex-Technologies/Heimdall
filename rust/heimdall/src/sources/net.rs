//! /proc/net/tcp{,6} read once per interval and shared by the port, connection and listener watchers (Go:
//! internal/sources/netsource, tables.go, netsource.go, lan.go, conn.go, procinfo.go). A socket's owner is looked for once
//! (an inode not seen before), the programs that already hold connections first.

use super::{Msg, Source};
use crate::event::{Event, Fields};
use crate::gojson;
use crate::gonet;
use crate::gotime::Time;
use crate::ipintel::{Lists, Resolver};
use crate::remoteaccess::Identifier;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

const ESTABLISHED: u8 = 0x01;
const LISTEN: u8 = 0x0A;

#[derive(Clone, Debug, PartialEq)]
pub struct Socket {
    pub local: IpAddr,
    pub local_port: u16,
    pub remote: IpAddr,
    pub remote_port: u16,
    pub state: u8,
    pub uid: i64,
    pub inode: u64,
}

/// An address of /proc/net as Go's net.IP.String writes it.
pub fn ip_text(ip: &IpAddr) -> String {
    gonet::canonical(*ip).to_string()
}

fn hex_ip(s: &str) -> Option<IpAddr> {
    if s.len() % 2 != 0 || !s.bytes().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let mut raw = [0u8; 16];
    let n = s.len() / 2;
    if n != 4 && n != 16 {
        return None;
    }
    let hexv = |c: u8| (c as char).to_digit(16).unwrap_or(0) as u8;
    for (i, pair) in s.as_bytes().chunks_exact(2).enumerate() {
        raw[i] = hexv(pair[0]) << 4 | hexv(pair[1]);
    }
    match n {
        4 => Some(IpAddr::V4(Ipv4Addr::new(raw[3], raw[2], raw[1], raw[0]))),
        16 => {
            let mut b = [0u8; 16];
            for g in 0..4 {
                let o = g * 4;
                b[o..o + 4].copy_from_slice(&[raw[o + 3], raw[o + 2], raw[o + 1], raw[o]]);
            }
            Some(gonet::canonical(IpAddr::V6(Ipv6Addr::from(b))))
        }
        _ => None,
    }
}

fn hex_addr(f: &str) -> Option<(IpAddr, u16)> {
    let (ip, port) = f.split_once(':')?;
    Some((hex_ip(ip)?, u16::from_str_radix(port, 16).ok()?))
}

/// The rows of a /proc/net/tcp-shaped file (the header line skipped).
pub fn parse_proc_net(text: &str) -> Vec<Socket> {
    let mut out = Vec::new();
    for line in text.lines().skip(1) {
        // /proc is ASCII: splitting on ASCII white space is strings.Fields here, and much cheaper than the Unicode table
        let f: Vec<&str> = line.split_ascii_whitespace().collect();
        if f.len() < 4 {
            continue;
        }
        let (Some((local, lp)), Some((remote, rp))) = (hex_addr(f[1]), hex_addr(f[2])) else { continue };
        let Ok(state) = u8::from_str_radix(f[3], 16) else { continue };
        let (mut uid, mut inode) = (0, 0);
        if f.len() > 9 {
            uid = crate::gotext::atoi(f[7]).unwrap_or(0);
            inode = f[9].parse().unwrap_or(0);
        }
        out.push(Socket { local, local_port: lp, remote, remote_port: rp, state, uid, inode });
    }
    out
}

/// Reads the socket tables (Go: readTables): the entries of every file that opened; the last error when none did.
pub fn read_tables(paths: &[String]) -> std::io::Result<Vec<Socket>> {
    let mut out = Vec::new();
    let mut last = None;
    let mut opened = 0;
    for p in paths {
        match std::fs::read_to_string(p) {
            Ok(t) => {
                opened += 1;
                out.extend(parse_proc_net(&t));
            }
            Err(e) => last = Some(e),
        }
    }
    if opened == 0 {
        return Err(last.unwrap_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound)));
    }
    Ok(out)
}

fn net_event(kind: &str, text: String, f: Fields) -> Event {
    Event { source: "host-network".into(), session_id: String::new(), time: Time::now(), kind: kind.into(), text, fields: f }
}

/// The ecosystem's own ports off loopback (Go: PortWatcher).
pub struct PortWatcher {
    ports: BTreeSet<u16>,
    binds: BTreeSet<u16>,
    peers: BTreeSet<String>,
    first: bool,
}

impl PortWatcher {
    pub fn new(ports: &[i64]) -> PortWatcher {
        PortWatcher {
            ports: ports.iter().filter_map(|&p| u16::try_from(p).ok()).collect(),
            binds: BTreeSet::new(),
            peers: BTreeSet::new(),
            first: true,
        }
    }

    /// A watcher whose first look reports what it sees, as Go's `PortWatcher.Poll` does when called alone (`heimdalld scan`);
    /// the daemon's first look only learns.
    pub fn reporting_first(mut self) -> PortWatcher {
        self.first = false;
        self
    }

    pub fn observe(&mut self, entries: &[Socket]) -> Vec<Event> {
        let mut events = Vec::new();
        let (mut binds, mut peers) = (BTreeSet::new(), BTreeSet::new());
        for e in entries {
            if !self.ports.contains(&e.local_port) {
                continue;
            }
            match e.state {
                LISTEN if !e.local.is_loopback() => {
                    binds.insert(e.local_port);
                    if !self.binds.contains(&e.local_port) {
                        let a = ip_text(&e.local);
                        events.push(net_event(
                            "non_loopback_bind",
                            format!("port {} bound on {a}", e.local_port),
                            Fields::from([("port".to_string(), e.local_port.to_string()), ("address".to_string(), a)]),
                        ));
                    }
                }
                ESTABLISHED if !e.remote.is_loopback() => {
                    let r = ip_text(&e.remote);
                    let key = format!("{}|{r}|{}", e.local_port, e.remote_port);
                    peers.insert(key.clone());
                    if !self.peers.contains(&key) {
                        events.push(net_event(
                            "non_loopback_peer",
                            format!("port {} connected from {r}:{}", e.local_port, e.remote_port),
                            Fields::from([
                                ("local_port".to_string(), e.local_port.to_string()),
                                ("remote_addr".to_string(), r),
                                ("remote_port".to_string(), e.remote_port.to_string()),
                            ]),
                        ));
                    }
                }
                _ => {}
            }
        }
        self.binds = binds;
        self.peers = peers;
        // the daemon's first look only learns (Go: Tables.Ports)
        if std::mem::take(&mut self.first) {
            return Vec::new();
        }
        events
    }
}

/// Programs starting to listen off loopback (Go: ListenWatcher).
pub struct ListenWatcher {
    pub proc_root: String,
    known: BTreeSet<String>,
    learned: bool,
}

const EXPECTED_UDP: [u16; 4] = [68, 546, 5353, 1900];

impl ListenWatcher {
    pub fn new(proc_root: &str) -> ListenWatcher {
        ListenWatcher { proc_root: proc_root.into(), known: BTreeSet::new(), learned: false }
    }

    fn listening(&self, tcp: &[Socket]) -> Vec<String> {
        let mut out: Vec<String> =
            tcp.iter().filter(|e| !e.local.is_loopback() && e.state == LISTEN).map(|e| format!("tcp/{}", e.local_port)).collect();
        let (mut lo, mut hi) = (32768i64, 60999i64);
        if let Ok(s) = std::fs::read_to_string(format!("{}/sys/net/ipv4/ip_local_port_range", self.proc_root)) {
            let mut it = s.split_whitespace();
            if let Some(l) = it.next().and_then(gonet::sscan_int) {
                lo = l;
                if let Some(h) = it.next().and_then(gonet::sscan_int) {
                    hi = h;
                }
            }
        }
        for f in ["net/udp", "net/udp6"] {
            let Ok(t) = std::fs::read_to_string(format!("{}/{f}", self.proc_root)) else { continue };
            for e in parse_proc_net(&t) {
                let p = e.local_port as i64;
                if e.local.is_loopback()
                    || e.state != 0x07
                    || !gonet::is_unspecified(&e.remote)
                    || EXPECTED_UDP.contains(&e.local_port)
                    || (p >= lo && p <= hi)
                {
                    continue;
                }
                out.push(format!("udp/{}", e.local_port));
            }
        }
        out.sort();
        out
    }

    pub fn observe(&mut self, tcp: &[Socket]) -> Vec<Event> {
        let mut events = Vec::new();
        for k in self.listening(tcp) {
            if !self.known.insert(k.clone()) || !self.learned {
                continue;
            }
            let (proto, port) = k.split_once('/').unwrap_or((&k, ""));
            events.push(net_event(
                "new_listener",
                format!("a program started listening for connections from the network on {k}"),
                Fields::from([("proto".to_string(), proto.to_string()), ("port".to_string(), port.to_string())]),
            ));
        }
        self.learned = true;
        events
    }
}

const INTERPRETERS: [&str; 8] = ["python", "python3", "ruby", "perl", "java", "node", "bash", "sh"];

/// The file an interpreter runs (Go: scriptOf): never other arguments.
pub fn script_of(exe: &str, argv: &[String], cwd: &str) -> String {
    let b = crate::remoteaccess::base(exe);
    if !INTERPRETERS.contains(&b) && !INTERPRETERS.contains(&b.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.')) {
        return String::new();
    }
    let join = |a: &str, b: &str| super::clean_path(&format!("{a}/{b}"));
    let mut i = 1;
    while i < argv.len() {
        let a = &argv[i];
        if a == "-jar" && i + 1 < argv.len() {
            let j = &argv[i + 1];
            if !j.starts_with('/') && !cwd.is_empty() {
                return join(cwd, j);
            }
            return j.clone();
        }
        if a == "-m" || a == "-c" || a == "-e" {
            return String::new();
        }
        if a.starts_with('-') {
            i += 1;
            continue;
        }
        if a.starts_with('/') {
            return super::clean_path(a);
        }
        if cwd.starts_with('/') {
            return join(cwd, a);
        }
        return String::new();
    }
    String::new()
}

/// The AI agent among a process's parents (Go: agentAncestor).
pub fn agent_ancestor(proc_root: &str, mut pid: i64) -> String {
    for _ in 0..64 {
        if pid <= 1 {
            break;
        }
        let Ok(b) = std::fs::read(format!("{proc_root}/{pid}/stat")) else { return String::new() };
        let s = crate::gotext::lossy(&b);
        let (Some(open), Some(close)) = (s.find('('), s.rfind(')')) else { return String::new() };
        if close < open {
            return String::new();
        }
        let comm = &s[open + 1..close];
        if comm == "sarina" {
            return comm.to_owned();
        }
        let rest: Vec<&str> = crate::gotext::fields(&s[close + 1..]).collect();
        let Some(next) = rest.get(1).and_then(|r| crate::gotext::atoi(r)) else { return String::new() };
        if next == pid {
            return String::new();
        }
        pid = next;
    }
    String::new()
}

fn argv_of(proc_root: &str, pid: i64) -> Vec<String> {
    let Ok(b) = std::fs::read(format!("{proc_root}/{pid}/cmdline")) else { return Vec::new() };
    let s = crate::gotext::lossy(&b);
    s.trim_end_matches('\0').split('\0').map(str::to_owned).collect()
}

fn readlink(p: &str) -> String {
    std::fs::read_link(p).map(|l| crate::gotext::lossy(std::os::unix::ffi::OsStrExt::as_bytes(l.as_os_str()))).unwrap_or_default()
}

#[derive(Clone, Debug, Default)]
struct Owner {
    pid: i64,
    comm: String,
    app: String,
    exe: String,
    script: String,
    agent: String,
}

#[derive(Default)]
struct StateFile {
    known: Vec<String>,
}
crate::go_struct!(StateFile { known: "known" });

/// Which process connects to which remote address (Go: ConnWatcher). No packet contents, ever.
pub struct ConnWatcher {
    proc_root: String,
    state_path: String,
    policy_path: String,
    known: HashSet<String>,
    loaded: bool,
    learning: bool,
    pub origins: Option<Resolver>,
    pub threats: Option<Lists>,
    pub remote_access: Option<Identifier>,
    owned: HashMap<u64, Option<Owner>>,
}

/// systemd's app slice name of a cgroup line (Settings' per-app network policy), sanitised as Go does.
fn app_of(cgroup: &str) -> String {
    let Some(i) = cgroup.find("lapp_") else { return String::new() };
    let rest = &cgroup[i + 5..];
    let Some(end) = rest.find(".slice") else { return String::new() };
    let name = &rest[..end];
    if name.is_empty() || name.contains('/') {
        return String::new();
    }
    sanitize_app(name)
}

fn sanitize_app(s: &str) -> String {
    s.chars().map(|c| if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '-') { c } else { '_' }).collect()
}

impl ConnWatcher {
    pub fn new(proc_root: &str, state_path: &str, policy_path: &str) -> ConnWatcher {
        ConnWatcher {
            proc_root: proc_root.into(),
            state_path: state_path.into(),
            policy_path: policy_path.into(),
            known: HashSet::new(),
            loaded: false,
            learning: false,
            origins: None,
            threats: None,
            remote_access: None,
            owned: HashMap::new(),
        }
    }

    fn load(&mut self) {
        self.loaded = true;
        match std::fs::read(&self.state_path) {
            Err(_) => self.learning = true,
            Ok(b) => {
                if let Ok(s) = gojson::unmarshal(&b, StateFile::default()) {
                    self.known.extend(s.known);
                }
            }
        }
    }

    fn save(&self) -> std::io::Result<()> {
        if self.state_path.is_empty() {
            return Ok(());
        }
        let mut keys: Vec<&String> = self.known.iter().collect();
        keys.sort();
        let mut out = String::from("{\"known\":[");
        for (i, k) in keys.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            gojson::write_str(&mut out, k);
        }
        out.push_str("]}");
        crate::state::write_atomic(&self.state_path, out.as_bytes(), 0o600)
    }

    fn blocked_apps(&self) -> HashSet<String> {
        #[derive(Default)]
        struct Policy {
            rules: BTreeMap<String, BTreeMap<String, String>>,
        }
        crate::go_struct!(Policy { rules: "rules" });
        let Ok(b) = std::fs::read(&self.policy_path) else { return HashSet::new() };
        let Ok(p) = gojson::unmarshal(&b, Policy::default()) else { return HashSet::new() };
        p.rules.values().flat_map(|apps| apps.iter().filter(|(_, m)| *m == "block").map(|(a, _)| sanitize_app(a))).collect()
    }

    fn sockets_of(&self, pid: i64, want: &HashSet<u64>, out: &mut HashMap<u64, Owner>) -> bool {
        let fd_dir = format!("{}/{pid}/fd", self.proc_root);
        let Ok(rd) = std::fs::read_dir(&fd_dir) else { return false };
        let mut o: Option<Owner> = None;
        for fd in rd.flatten() {
            let link = readlink(&format!("{fd_dir}/{}", fd.file_name().to_string_lossy()));
            let Some(ino) = link.strip_prefix("socket:[").and_then(|l| l.strip_suffix(']')).and_then(|n| n.parse::<u64>().ok()) else {
                continue;
            };
            if !want.contains(&ino) || out.contains_key(&ino) {
                continue;
            }
            let owner = o.get_or_insert_with(|| {
                let base = format!("{}/{pid}", self.proc_root);
                let comm = std::fs::read(format!("{base}/comm"))
                    .map(|b| crate::gotext::trim_space(&crate::gotext::lossy(&b)).to_owned())
                    .unwrap_or_default();
                let cg = std::fs::read(format!("{base}/cgroup")).map(|b| crate::gotext::lossy(&b)).unwrap_or_default();
                let exe = readlink(&format!("{base}/exe"));
                let cwd = readlink(&format!("{base}/cwd"));
                let script = script_of(&exe, &argv_of(&self.proc_root, pid), &cwd);
                Owner { pid, comm, app: app_of(&cg), agent: agent_ancestor(&self.proc_root, pid), exe, script }
            });
            out.insert(ino, owner.clone());
            if out.len() == want.len() {
                return true;
            }
        }
        false
    }

    fn resolve(&mut self, want: &HashSet<u64>) -> HashMap<u64, Owner> {
        let unseen: HashSet<u64> = want.iter().filter(|i| !self.owned.contains_key(i)).copied().collect();
        if !unseen.is_empty() {
            // the programs already holding connections first, busiest first
            let mut count: HashMap<i64, usize> = HashMap::new();
            for o in self.owned.values().flatten() {
                *count.entry(o.pid).or_default() += 1;
            }
            let mut hot: Vec<i64> = count.keys().copied().collect();
            hot.sort_by(|a, b| count[b].cmp(&count[a]).then(a.cmp(b)));
            let mut found = HashMap::new();
            let mut done = HashSet::new();
            let mut complete = false;
            for pid in hot {
                done.insert(pid);
                if self.sockets_of(pid, &unseen, &mut found) {
                    complete = true;
                    break;
                }
            }
            if !complete {
                if let Ok(rd) = std::fs::read_dir(&self.proc_root) {
                    for d in rd.flatten() {
                        let Some(pid) = d.file_name().to_str().and_then(crate::gotext::atoi) else { continue };
                        if done.contains(&pid) {
                            continue;
                        }
                        if self.sockets_of(pid, &unseen, &mut found) {
                            break;
                        }
                    }
                }
            }
            for ino in unseen {
                self.owned.insert(ino, found.remove(&ino));
            }
        }
        self.owned.retain(|ino, _| want.contains(ino)); // the connection is gone
        self.owned.iter().filter_map(|(i, o)| o.clone().map(|o| (*i, o))).collect()
    }

    pub fn observe(&mut self, all: &[Socket]) -> (Vec<Event>, Option<std::io::Error>) {
        if !self.loaded {
            self.load();
        }
        let entries: Vec<&Socket> =
            all.iter().filter(|e| e.state == ESTABLISHED && !e.remote.is_loopback() && !gonet::is_unspecified(&e.remote)).collect();
        let want: HashSet<u64> = entries.iter().map(|e| e.inode).collect();
        let owners = self.resolve(&want);
        let blocked = self.blocked_apps();
        let mut events = Vec::new();
        let mut fresh = false;
        for e in entries {
            let o = owners.get(&e.inode);
            let def = Owner::default();
            let ow = o.unwrap_or(&def);
            let proc_ = if ow.comm.is_empty() { "unknown".to_string() } else { ow.comm.clone() };
            let r = ip_text(&e.remote);
            let key = format!("{proc_}|{r}|{}", e.remote_port);
            if !self.known.insert(key) {
                continue;
            }
            fresh = true;
            let mut f = Fields::from([
                ("process".to_string(), proc_.clone()),
                ("pid".to_string(), ow.pid.to_string()),
                ("app".to_string(), ow.app.clone()),
                ("uid".to_string(), e.uid.to_string()),
                ("remote_addr".to_string(), r.clone()),
                ("remote_port".to_string(), e.remote_port.to_string()),
                ("local_port".to_string(), e.local_port.to_string()),
            ]);
            for (k, v) in [("exe", &ow.exe), ("script", &ow.script), ("agent", &ow.agent)] {
                if !v.is_empty() {
                    f.insert(k.into(), v.clone());
                }
            }
            let mut text = format!("{proc_} (pid {}) connected to {r}:{}", ow.pid, e.remote_port);
            if let Some(res) = &mut self.origins {
                let og = res.lookup(&e.remote);
                f.extend(og.fields("remote_"));
                let t = og.text();
                f.insert("remote_origin".into(), t.clone());
                text += &format!(" ({t})");
            }
            if let Some(l) = &mut self.threats {
                let names = l.matching(&e.remote);
                if !names.is_empty() {
                    let joined = names.join(",");
                    text += &format!(" [on threat lists: {joined}]");
                    f.insert("remote_listed".into(), joined);
                }
            }
            if self.learning {
                f.insert("learning".into(), "1".into());
            }
            if !ow.app.is_empty() && blocked.contains(&ow.app) {
                f.insert("blocked".into(), "1".into());
            }
            if let (Some(id), Some(o)) = (&mut self.remote_access, o) {
                if let Some((p, sig)) = id.identify(&o.exe, &o.comm) {
                    f.insert("ra_provider".into(), p.id);
                    f.insert("provider_name".into(), p.name);
                    f.insert("ra_kind".into(), p.kind);
                    f.insert("ra_signal".into(), sig.into());
                    f.insert("exe".into(), o.exe.clone());
                }
            }
            events.push(net_event("new_connection", text, f));
        }
        self.learning = false;
        let err = if fresh { self.save().err() } else { None };
        (events, err)
    }
}

struct User {
    every: Duration,
    last: Option<Instant>,
    kind: UserKind,
}

enum UserKind {
    Ports(PortWatcher),
    Conns(Box<ConnWatcher>),
    Listen(ListenWatcher),
}

/// One read of the TCP tables per tick, shared by every watcher whose interval came (Go: Tables).
pub struct Tables {
    paths: Vec<String>,
    users: Vec<User>,
    next: Instant,
    first: bool,
    off: bool,
}

impl Tables {
    pub fn new(proc_root: &str) -> Tables {
        Tables {
            paths: vec![format!("{proc_root}/net/tcp"), format!("{proc_root}/net/tcp6")],
            users: Vec::new(),
            next: Instant::now(),
            first: true,
            off: false,
        }
    }
    pub fn ports(&mut self, w: PortWatcher, every: Duration) {
        self.users.push(User { every, last: None, kind: UserKind::Ports(w) });
    }
    pub fn connections(&mut self, w: ConnWatcher, every: Duration) {
        self.users.push(User { every, last: None, kind: UserKind::Conns(Box::new(w)) });
    }
    pub fn listeners(&mut self, w: ListenWatcher, every: Duration) {
        self.users.push(User { every, last: None, kind: UserKind::Listen(w) });
    }
    pub fn is_empty(&self) -> bool {
        self.users.is_empty()
    }
    fn tick(&self) -> Duration {
        self.users.iter().map(|u| u.every).min().unwrap_or(Duration::from_secs(15))
    }
}

impl Source for Tables {
    fn name(&self) -> &'static str {
        "netsource"
    }
    fn due(&self) -> Option<Instant> {
        (!self.off && !self.users.is_empty()).then_some(self.next)
    }
    fn run(&mut self, now: Instant, out: &mut Vec<Msg>) {
        let tick = self.tick();
        self.next = now + tick;
        let first = std::mem::take(&mut self.first);
        let entries = match read_tables(&self.paths) {
            Ok(e) => e,
            Err(e) => {
                let text = super::go_errno(&e);
                if first && e.kind() == std::io::ErrorKind::NotFound {
                    self.off = true;
                    out.push(Msg::Log(format!("network watches unavailable, disabling: {text}")));
                } else {
                    out.push(Msg::Log(format!("network watch error: {text}")));
                }
                return;
            }
        };
        for u in &mut self.users {
            if u.last.is_some_and(|l| now.duration_since(l) + tick / 2 < u.every) {
                continue;
            }
            u.last = Some(now);
            let events = match &mut u.kind {
                UserKind::Ports(w) => w.observe(&entries),
                UserKind::Listen(w) => w.observe(&entries),
                UserKind::Conns(w) => {
                    let (ev, err) = w.observe(&entries);
                    if let Some(e) = err {
                        out.push(Msg::Log(format!("connection watch error: {}", super::go_errno(&e))));
                    }
                    ev
                }
            };
            out.extend(events.into_iter().map(Msg::Event));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_proc_net_like_go() {
        let t = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12345 1\n   1: 0A00000A:01BB 0500000A:C82A 01 00000000:00000000 00:00000000 00000000  1000        0 999 1\n";
        let s = parse_proc_net(t);
        assert_eq!(s.len(), 2);
        assert_eq!(ip_text(&s[0].local), "127.0.0.1");
        assert_eq!(s[0].local_port, 8080);
        assert_eq!(ip_text(&s[1].remote), "10.0.0.5");
        assert_eq!((s[1].uid, s[1].inode), (1000, 999));
        let v6 = hex_ip("00000000000000000000000001000000").unwrap();
        assert_eq!(ip_text(&v6), "::1");
        let mapped = hex_ip("0000000000000000FFFF00000100007F").unwrap();
        assert_eq!(ip_text(&mapped), "127.0.0.1");
    }

    #[test]
    fn scripts_like_go() {
        let a = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(script_of("/usr/bin/python3.14", &a(&["python3", "-u", "sqlmap.py"]), "/opt/sqlmap"), "/opt/sqlmap/sqlmap.py");
        assert_eq!(script_of("/usr/bin/java", &a(&["java", "-jar", "/usr/share/burp/burp.jar"]), "/"), "/usr/share/burp/burp.jar");
        assert_eq!(script_of("/usr/bin/python3", &a(&["python3", "-c", "x"]), "/"), "");
        assert_eq!(script_of("/usr/bin/curl", &a(&["curl", "x"]), "/"), "");
        assert_eq!(
            app_of("0::/user.slice/user-1000.slice/user@1000.service/app.slice/lapp_org.mozilla.firefox.slice/x.scope"),
            "org.mozilla.firefox"
        );
    }
}
