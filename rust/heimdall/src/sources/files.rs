//! The small file-fed sources (Go: wifisource, lansource, netsource RouterWatcher, rasource): heimdall-wifi-check's results,
//! the trusted network's new devices, the router of an untrusted Wi-Fi, and remote-access tools by package and interface.

use super::{Msg, Source};
use crate::event::{Event, Fields};
use crate::gojson;
use crate::gotime::Time;
use crate::remoteaccess::Catalog;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Seek, SeekFrom};
use std::time::{Duration, Instant};

/// Reads a kept offset (a decimal number; anything else is 0, as in Go).
fn read_offset(path: &str) -> Option<u64> {
    std::fs::read_to_string(path).ok().map(|s| crate::gotext::trim_space(&s).parse().unwrap_or(0))
}

/// Complete lines of a JSON-lines file after `off` (both Go watchers' way: the file read again from the top when it shrank,
/// at most 4 MiB a look) and the offset after them; None when the file is not there.
fn new_lines(path: &str, mut off: u64) -> std::io::Result<(Vec<Vec<u8>>, Option<u64>)> {
    let mut f = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((Vec::new(), None)),
        Err(e) => return Err(e),
    };
    if f.metadata().is_ok_and(|m| m.len() < off) {
        off = 0;
    }
    f.seek(SeekFrom::Start(off))?;
    let mut buf = Vec::new();
    f.take(4 << 20).read_to_end(&mut buf)?;
    let mut lines = Vec::new();
    let mut rest = &buf[..];
    while let Some(i) = rest.iter().position(|&c| c == b'\n') {
        lines.push(rest[..=i].to_vec());
        off += i as u64 + 1;
        rest = &rest[i + 1..];
    }
    Ok((lines, Some(off)))
}

fn sanitize(s: &str, wide: bool) -> String {
    let s: String = s
        .chars()
        .map(|r| {
            let c = r as u32;
            if c < 0x20
                || c == 0x7f
                || (0x202a..=0x202e).contains(&c)
                || (0x2066..=0x2069).contains(&c)
                || (wide && (0x200b..=0x200f).contains(&c))
            {
                '?'
            } else {
                r
            }
        })
        .collect();
    if s.chars().count() > 600 {
        return format!("{}...", s.chars().take(600).collect::<String>());
    }
    s
}

#[derive(Default)]
struct Check {
    status: String,
    detail: String,
}
crate::go_struct!(Check { status: "status", detail: "detail" });

#[derive(Default)]
struct WifiResult {
    time: String,
    ssid: String,
    bssid: String,
    security: String,
    verdict: String,
    checks: Vec<Check>,
}
crate::go_struct!(WifiResult { time: "time", ssid: "ssid", bssid: "bssid", security: "security", verdict: "verdict", checks: "checks" });

/// One line of heimdall-wifi-check's results as an event.
pub fn wifi_line(line: &[u8]) -> Option<Event> {
    let r = gojson::unmarshal(line, WifiResult::default()).ok().filter(|r| !r.verdict.is_empty())?;
    let reasons: Vec<&str> = r.checks.iter().filter(|c| c.status == "bad" || c.status == "warn").map(|c| c.detail.as_str()).collect();
    let time = Time::parse_rfc3339(&r.time).unwrap_or_else(Time::now);
    let ssid = sanitize(&r.ssid, true);
    Some(Event {
        source: "host-wifi".into(),
        session_id: String::new(),
        time,
        kind: "wifi_check".into(),
        text: format!("Wi-Fi network {}: {}", crate::gotext::quote(&ssid), r.verdict),
        fields: Fields::from([
            ("ssid".to_string(), ssid),
            ("bssid".to_string(), r.bssid),
            ("security".to_string(), sanitize(&r.security, true)),
            ("verdict".to_string(), r.verdict),
            ("reasons".to_string(), sanitize(&reasons.join(" | "), true)),
            ("problems".to_string(), reasons.len().to_string()),
        ]),
    })
}

#[derive(Default)]
struct Device {
    mac: String,
    ip: String,
    name: String,
    vendor: String,
    model: String,
    kind: String,
    owner_kind: String,
    private_mac: bool,
    first_seen: Time,
    last_seen: Time,
    names: Vec<String>,
    services: Vec<String>,
}
crate::go_struct!(Device {
    mac: "mac",
    ip: "ip",
    name: "name",
    vendor: "vendor",
    model: "model",
    kind: "kind",
    owner_kind: "owner_kind",
    private_mac: "private_mac",
    first_seen: "first_seen",
    last_seen: "last_seen",
    names: "names",
    services: "services",
});

#[derive(Default)]
struct NewDevice {
    time: Time,
    ssid: String,
    device: Device,
    change: String,
    was_mac: String,
    was_name: String,
    other_ip: String,
}
crate::go_struct!(NewDevice {
    time: "time",
    ssid: "ssid",
    device: "device",
    change: "change",
    was_mac: "was_mac",
    was_name: "was_name",
    other_ip: "other_ip"
});

/// One line of the trusted network's events.jsonl (heimdalld lan scan) as an event.
pub fn lan_line(line: &[u8]) -> Option<Event> {
    let nd = gojson::unmarshal(line, NewDevice::default()).ok().filter(|n| !n.device.mac.is_empty())?;
    let d = nd.device;
    if !nd.change.is_empty() {
        let text = if nd.change == "address_taken" {
            format!("a known device's address on {} is answered by another device: {}", nd.ssid, d.ip)
        } else {
            format!("a known device's name on {} is announced by another device: {}", nd.ssid, d.name)
        };
        return Some(Event {
            source: "host-lan".into(),
            session_id: String::new(),
            time: nd.time,
            kind: "lan_device_changed".into(),
            text,
            fields: Fields::from([
                ("ssid".to_string(), nd.ssid),
                ("ip".to_string(), d.ip),
                ("mac".to_string(), d.mac),
                ("vendor".to_string(), d.vendor),
                ("name".to_string(), d.name),
                ("private_mac".to_string(), d.private_mac.to_string()),
                ("change".to_string(), nd.change),
                ("was_mac".to_string(), nd.was_mac),
                ("was_name".to_string(), nd.was_name),
                ("other_ip".to_string(), nd.other_ip),
            ]),
        });
    }
    Some(Event {
        source: "host-lan".into(),
        session_id: String::new(),
        time: nd.time,
        kind: "new_lan_device".into(),
        text: format!("a new device on {}: {}", nd.ssid, d.ip),
        fields: Fields::from([
            ("ssid".to_string(), nd.ssid),
            ("ip".to_string(), d.ip),
            ("mac".to_string(), d.mac),
            ("vendor".to_string(), d.vendor),
            ("name".to_string(), d.name),
            ("model".to_string(), d.model),
            ("kind".to_string(), d.kind),
            ("private_mac".to_string(), d.private_mac.to_string()),
        ]),
    })
}

/// A JSON-lines file read every interval (the Wi-Fi results, the device list's events). The offset is kept in a file (Go's
/// name, next to the results), and in memory too, so a file that cannot be written never makes a line come twice.
pub struct LinesSource {
    name: &'static str,
    path: String,
    offset_path: String,
    /// Where the first offset is read when `offset_path` holds none yet (shadow mode: the Go daemon's, read-only).
    start_path: String,
    off: Option<u64>,
    parse: fn(&[u8]) -> Option<Event>,
    interval: Duration,
    next: Instant,
    label: &'static str,
    /// The last problem logged, so one that stays is logged once, not on every look.
    last_err: Option<String>,
}

impl LinesSource {
    fn new(name: &'static str, path: String, offset: String, parse: fn(&[u8]) -> Option<Event>, secs: u64, label: &'static str) -> Self {
        LinesSource {
            name,
            path,
            start_path: offset.clone(),
            offset_path: offset,
            off: None,
            parse,
            interval: Duration::from_secs(secs),
            next: Instant::now(),
            label,
            last_err: None,
        }
    }

    pub fn wifi(path: &str) -> LinesSource {
        LinesSource::new("wifi", path.into(), format!("{path}.offset"), wifi_line, 10, "wifi results")
    }

    pub fn lan(dir: &str) -> LinesSource {
        LinesSource::new("lan", format!("{dir}/events.jsonl"), format!("{dir}/events.offset"), lan_line, 15, "device list")
    }

    /// Shadow mode: the offset is kept in `state_dir` (the shadow daemon's own folder; the results' folder is the Go daemon's
    /// and read-only to it), starting from the Go daemon's offset the first time, so old lines are not raised again.
    pub fn offset_in(mut self, state_dir: &str) -> LinesSource {
        let file = if self.name == "wifi" { "wifi-results.offset" } else { "lan-events.offset" };
        self.offset_path = format!("{}/{file}", state_dir.trim_end_matches('/'));
        self
    }

    pub fn offset_path(&self) -> &str {
        &self.offset_path
    }

    fn problem(&mut self, msg: Option<String>, out: &mut Vec<Msg>) {
        if msg == self.last_err {
            return;
        }
        match &msg {
            Some(m) => out.push(Msg::Log(format!("{}: {m}", self.label))),
            None => out.push(Msg::Log(format!("{}: working again", self.label))),
        }
        self.last_err = msg;
    }
}

impl Source for LinesSource {
    fn name(&self) -> &'static str {
        self.name
    }
    fn due(&self) -> Option<Instant> {
        Some(self.next)
    }
    fn run(&mut self, now: Instant, out: &mut Vec<Msg>) {
        self.next = now + self.interval;
        let start = match self.off {
            Some(o) => o,
            None => read_offset(&self.offset_path).or_else(|| read_offset(&self.start_path)).unwrap_or(0),
        };
        match new_lines(&self.path, start) {
            Ok((lines, off)) => {
                out.extend(lines.iter().filter_map(|l| (self.parse)(l)).map(Msg::Event));
                let mut err = None;
                if let Some(off) = off {
                    self.off = Some(off);
                    if let Err(e) = crate::state::write_mode(&self.offset_path, off.to_string().as_bytes(), 0o600) {
                        err = Some(format!("cannot keep the offset in {}: {}", self.offset_path, super::go_errno(&e)));
                    }
                }
                self.problem(err, out);
            }
            Err(e) => self.problem(Some(super::go_errno(&e)), out),
        }
    }
}

#[cfg(test)]
mod lines_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn tmp(name: &str) -> String {
        let d = std::env::temp_dir().join(format!("heimdall-lines-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d.to_string_lossy().into_owned()
    }

    fn line(ip: &str) -> String {
        format!("{{\"time\":\"2026-11-10T10:00:00Z\",\"ssid\":\"home\",\"device\":{{\"ip\":\"{ip}\",\"mac\":\"02:00:00:00:00:01\"}}}}\n")
    }

    fn events(out: &[Msg]) -> Vec<String> {
        out.iter().filter_map(|m| if let Msg::Event(e) = m { Some(e.f("ip").to_string()) } else { None }).collect()
    }

    fn logs(out: &[Msg]) -> usize {
        out.iter().filter(|m| matches!(m, Msg::Log(_))).count()
    }

    #[test]
    fn a_read_only_results_folder_raises_a_line_once_and_logs_once() {
        let root = tmp("ro");
        let dir = format!("{root}/lan");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(format!("{dir}/events.jsonl"), line("192.0.2.10")).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o555)).unwrap();
        let root_writes_anyway = std::fs::write(format!("{dir}/probe"), b"").is_ok();
        let mut s = LinesSource::lan(&dir);
        let mut all = Vec::new();
        for _ in 0..5 {
            s.run(Instant::now(), &mut all);
        }
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(events(&all).len() <= 1, "{all:?}");
        if !root_writes_anyway {
            assert_eq!(events(&all), vec!["192.0.2.10"], "raised once although its offset cannot be written");
            assert_eq!(logs(&all), 1, "logged once, not on every look: {all:?}");
        }
    }

    #[test]
    fn shadow_mode_keeps_its_offset_in_its_own_folder_starting_from_go_s() {
        let root = tmp("shadow");
        let dir = format!("{root}/lan");
        let own = format!("{root}/rs");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::create_dir_all(&own).unwrap();
        let old = line("192.0.2.10");
        std::fs::write(format!("{dir}/events.jsonl"), format!("{old}{}", line("192.0.2.11"))).unwrap();
        // the Go daemon has read the first line
        std::fs::write(format!("{dir}/events.offset"), old.len().to_string()).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o555)).unwrap();
        let mut s = LinesSource::lan(&dir).offset_in(&own);
        let mut out = Vec::new();
        s.run(Instant::now(), &mut out);
        assert_eq!(events(&out), vec!["192.0.2.11"]);
        assert_eq!(logs(&out), 0, "{out:?}");
        let kept = std::fs::read_to_string(format!("{own}/lan-events.offset")).unwrap();
        assert_eq!(kept, std::fs::metadata(format!("{dir}/events.jsonl")).unwrap().len().to_string());
        assert_eq!(std::fs::read_to_string(format!("{dir}/events.offset")).unwrap(), old.len().to_string(), "Go's file untouched");
        // a restart starts from its own offset, not from Go's
        let mut s = LinesSource::lan(&dir).offset_in(&own);
        let mut out = Vec::new();
        s.run(Instant::now(), &mut out);
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(out.is_empty(), "{out:?}");
    }
}

#[derive(Default)]
struct Current {
    ssid: String,
    iface: String,
    gateway: String,
    gateway_mac: String,
    trusted: bool,
}
crate::go_struct!(Current { ssid: "ssid", iface: "iface", gateway: "gateway", gateway_mac: "gateway_mac", trusted: "trusted" });

/// The router of an untrusted Wi-Fi watched for impersonation (Go: RouterWatcher), from the kernel's tables only.
pub struct RouterSource {
    current: String,
    proc_root: String,
    reported: BTreeSet<String>,
    next: Instant,
}

impl RouterSource {
    pub fn new(current: &str, proc_root: &str) -> RouterSource {
        RouterSource { current: current.into(), proc_root: proc_root.into(), reported: BTreeSet::new(), next: Instant::now() }
    }

    fn gateway(&self, iface: &str) -> String {
        let Ok(t) = std::fs::read_to_string(format!("{}/net/route", self.proc_root)) else { return String::new() };
        for line in t.lines() {
            let x: Vec<&str> = crate::gotext::fields(line).collect();
            if x.len() >= 3 && x[0] == iface && x[1] == "00000000" {
                if let Ok(g) = u32::from_str_radix(x[2], 16) {
                    if g != 0 {
                        return format!("{}.{}.{}.{}", g as u8, (g >> 8) as u8, (g >> 16) as u8, (g >> 24) as u8);
                    }
                }
            }
        }
        String::new()
    }

    pub fn poll(&mut self) -> Vec<Event> {
        let Ok(b) = std::fs::read(&self.current) else { return Vec::new() };
        let Ok(c) = gojson::unmarshal(&b, Current::default()) else { return Vec::new() };
        if c.trusted || c.iface.is_empty() || c.gateway.is_empty() || c.gateway_mac.is_empty() || self.gateway(&c.iface) != c.gateway {
            return Vec::new();
        }
        let mut out = Vec::new();
        let Ok(arp) = std::fs::read_to_string(format!("{}/net/arp", self.proc_root)) else { return out };
        for line in arp.lines().skip(1) {
            let x: Vec<&str> = crate::gotext::fields(line).collect();
            if x.len() < 6 || x[2] == "0x0" || x[3] == "00:00:00:00:00:00" || x[5] != c.iface {
                continue;
            }
            let (ip, mac) = (x[0].to_string(), x[3].to_uppercase());
            let mut emit = |kind: &str, key: String, text: String, mut f: Fields| {
                if !self.reported.insert(key) {
                    return;
                }
                f.insert("ssid".into(), c.ssid.clone());
                f.insert("gateway".into(), c.gateway.clone());
                f.insert("expected_mac".into(), c.gateway_mac.clone());
                out.push(Event {
                    source: "host-lan".into(),
                    session_id: String::new(),
                    time: Time::now(),
                    kind: kind.into(),
                    text,
                    fields: f,
                });
            };
            if ip == c.gateway && mac != c.gateway_mac {
                emit(
                    "router_changed",
                    format!("{}|{mac}", c.gateway),
                    format!(
                        "the router {} of {} now answers with hardware address {mac} (it was {})",
                        c.gateway,
                        crate::gotext::quote(&c.ssid),
                        c.gateway_mac
                    ),
                    Fields::from([("new_mac".to_string(), mac.clone())]),
                );
            }
            if ip != c.gateway && mac == c.gateway_mac {
                emit(
                    "router_impersonated",
                    format!("{ip}|{mac}"),
                    format!("{ip} answers with the router's hardware address {mac} on {}", crate::gotext::quote(&c.ssid)),
                    Fields::from([("other_ip".to_string(), ip.clone()), ("new_mac".to_string(), mac.clone())]),
                );
            }
        }
        out
    }
}

impl Source for RouterSource {
    fn name(&self) -> &'static str {
        "router"
    }
    fn due(&self) -> Option<Instant> {
        Some(self.next)
    }
    fn run(&mut self, now: Instant, out: &mut Vec<Msg>) {
        self.next = now + Duration::from_secs(10);
        out.extend(self.poll().into_iter().map(Msg::Event));
    }
}

/// A pacman entry's package name ("name-version-release").
pub fn package_name(entry: &str) -> String {
    let parts: Vec<&str> = entry.split('-').collect();
    if parts.len() < 3 {
        return String::new();
    }
    parts[..parts.len() - 2].join("-")
}

/// Remote-access tools by installed package and network interface (Go: rasource), and the kernel's side (HEI-12): a catalog
/// kernel module loaded, a raw packet socket held by a program outside the usual ones, a shell reading a network socket.
pub struct RaSource {
    catalog: Catalog,
    pacman: String,
    net_dir: String,
    /// /proc (a test's own root in tests).
    pub proc_dir: String,
    pkg_seen: BTreeSet<String>,
    pkg_mtime: i128,
    iface_seen: BTreeSet<String>,
    waited: BTreeMap<String, u32>,
    started: bool,
    next: Instant,
    mod_seen: BTreeSet<String>,
    raw_seen: BTreeSet<String>,
    shell_seen: BTreeSet<String>,
    /// What makes a program start by itself (HEI-11, footholds.rs).
    pub footholds: super::footholds::FootholdWatch,
}

/// Go's rawAllowed: the programs that hold raw packet sockets for their work (by process name).
const RAW_ALLOWED: &[&str] = &[
    "NetworkManager",
    "dhcpcd",
    "dhclient",
    "udhcpc",
    "systemd-network",
    "connmand",
    "wpa_supplicant",
    "iwd",
    "hostapd",
    "dnsmasq",
    "dhcpd",
    "kea-dhcp4",
    "pppd",
    "tcpdump",
    "dumpcap",
    "tshark",
    "wireshark",
    "arp-scan",
    "nmap",
    "lldpd",
    "avahi-autoipd",
];

/// Go's shells: the command interpreters a reverse shell runs.
const SHELLS: &[&str] = &["sh", "bash", "dash", "zsh", "ksh", "mksh", "ash", "fish", "tcsh", "csh", "busybox", "pwsh"];

/// Go's remoteLogin (HEI-79): the programs that hold a terminal for someone logged in over the network by design.
const REMOTE_LOGIN: &[&str] = &["sshd", "sshd-session", "dropbear", "mosh-server"];

fn ra_event(text: String, f: Fields) -> Event {
    Event { source: "remote-access".into(), session_id: String::new(), time: Time::now(), kind: "remote_access".into(), text, fields: f }
}

impl RaSource {
    pub fn new(catalog: Catalog, pacman: &str, net_dir: &str) -> RaSource {
        RaSource {
            catalog,
            pacman: pacman.into(),
            net_dir: net_dir.into(),
            proc_dir: "/proc".into(),
            pkg_seen: BTreeSet::new(),
            pkg_mtime: 0,
            iface_seen: BTreeSet::new(),
            waited: BTreeMap::new(),
            started: false,
            next: Instant::now(),
            mod_seen: BTreeSet::new(),
            raw_seen: BTreeSet::new(),
            shell_seen: BTreeSet::new(),
            footholds: Default::default(),
        }
    }

    /// Go's modules: a catalog kernel module loaded (one read of /proc/modules), those loaded before the start included.
    fn modules(&mut self) -> Vec<Event> {
        let Ok(text) = std::fs::read_to_string(format!("{}/modules", self.proc_dir)) else { return Vec::new() };
        let mut now = BTreeSet::new();
        let mut out = Vec::new();
        for line in text.lines() {
            let Some(name) = line.split_ascii_whitespace().next() else { continue };
            now.insert(name.to_string());
            if self.mod_seen.contains(name) {
                continue;
            }
            if let Some(p) = self.catalog.match_module(name) {
                out.push(ra_event(
                    format!("the kernel module {name} ({}) was loaded", p.name),
                    Fields::from([
                        ("provider".to_string(), p.id.clone()),
                        ("provider_name".to_string(), p.name.clone()),
                        ("ra_kind".to_string(), p.kind.clone()),
                        ("signal".to_string(), "module".to_string()),
                        ("module".to_string(), name.to_string()),
                    ]),
                ));
            }
        }
        self.mod_seen = now;
        out
    }

    fn proc_name(&self, pid: &str) -> String {
        std::fs::read_to_string(format!("{}/{pid}/comm", self.proc_dir)).map(|s| s.trim().to_string()).unwrap_or_default()
    }

    fn pids(&self) -> Vec<String> {
        Self::sorted_names(&self.proc_dir).into_iter().filter(|n| !n.is_empty() && n.bytes().all(|c| c.is_ascii_digit())).collect()
    }

    /// The inode a "socket:[N]" link names.
    fn socket_inode(link: &std::path::Path) -> Option<String> {
        let s = link.to_str()?;
        Some(s.strip_prefix("socket:[")?.strip_suffix(']')?.to_string())
    }

    /// Go's socketOwners: the process (pid, name) holding each wanted socket inode.
    fn socket_owners(&self, want: &BTreeSet<String>) -> BTreeMap<String, (String, String)> {
        let mut out = BTreeMap::new();
        for pid in self.pids() {
            let dir = format!("{}/{pid}/fd", self.proc_dir);
            let Ok(rd) = std::fs::read_dir(&dir) else { continue };
            let mut fds: Vec<String> = rd.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
            fds.sort();
            for fd in fds {
                let Some(ino) = std::fs::read_link(format!("{dir}/{fd}")).ok().and_then(|l| Self::socket_inode(&l)) else { continue };
                if want.contains(&ino) && !out.contains_key(&ino) {
                    out.insert(ino, (pid.clone(), self.proc_name(&pid)));
                }
            }
            if out.len() == want.len() {
                break;
            }
        }
        out
    }

    /// Go's rawListeners: a program outside RAW_ALLOWED holding a raw packet socket (owner looked up for new sockets only).
    fn raw_listeners(&mut self) -> Vec<Event> {
        let Ok(text) = std::fs::read_to_string(format!("{}/net/packet", self.proc_dir)) else { return Vec::new() };
        let mut now = BTreeSet::new();
        let mut want = BTreeSet::new();
        let mut proto = BTreeMap::new();
        for (i, line) in text.split('\n').enumerate() {
            let f: Vec<&str> = line.split_ascii_whitespace().collect();
            if i == 0 || f.len() < 9 || f[8] == "0" {
                continue;
            }
            now.insert(f[8].to_string());
            if !self.raw_seen.contains(f[8]) {
                want.insert(f[8].to_string());
                proto.insert(f[8].to_string(), f[3].to_string());
            }
        }
        let mut out = Vec::new();
        if !want.is_empty() {
            let owners = self.socket_owners(&want);
            for ino in &want {
                let Some((pid, comm)) = owners.get(ino) else { continue };
                if comm.is_empty() || RAW_ALLOWED.contains(&comm.as_str()) {
                    continue;
                }
                out.push(ra_event(
                    format!("{comm} (pid {pid}) reads raw network packets"),
                    Fields::from([
                        ("provider".to_string(), comm.clone()),
                        ("ra_kind".to_string(), "kernel".to_string()),
                        ("signal".to_string(), "raw-listener".to_string()),
                        ("program".to_string(), comm.clone()),
                        ("pid".to_string(), pid.clone()),
                        ("proto".to_string(), proto.get(ino).cloned().unwrap_or_default()),
                    ]),
                ));
            }
        }
        self.raw_seen = now;
        out
    }

    /// Go's inetSockets: the TCP and UDP sockets by inode, each as "tcp LOCAL -> REMOTE".
    fn inet_sockets(&self) -> BTreeMap<String, String> {
        self.inet_conns(false)
    }

    /// Go's inetConns: inet_sockets, with `outside` only those connected to another computer (not listening, not loopback).
    fn inet_conns(&self, outside: bool) -> BTreeMap<String, String> {
        let hostport = |ip: &std::net::IpAddr, port: u16| {
            let t = super::net::ip_text(ip);
            if t.contains(':') {
                format!("[{t}]:{port}")
            } else {
                format!("{t}:{port}")
            }
        };
        let mut out = BTreeMap::new();
        for name in ["tcp", "tcp6", "udp", "udp6"] {
            let Ok(text) = std::fs::read_to_string(format!("{}/net/{name}", self.proc_dir)) else { continue };
            for s in super::net::parse_proc_net(&text) {
                if outside && (crate::gonet::is_unspecified(&s.remote) || crate::gonet::is_loopback(&s.remote)) {
                    continue;
                }
                out.insert(
                    s.inode.to_string(),
                    format!(
                        "{} {} -> {}",
                        name.trim_end_matches('6'),
                        hostport(&s.local, s.local_port),
                        hostport(&s.remote, s.remote_port)
                    ),
                );
            }
        }
        out
    }

    /// Go's socketShells: a shell whose input (fd 0) is a TCP or UDP socket; a Unix socket is not the network. A shell on a
    /// terminal (/dev/pts/N) is looked at once, by pty_shells.
    fn socket_shells(&mut self) -> Vec<Event> {
        let mut now = BTreeSet::new();
        let mut inet: Option<BTreeMap<String, String>> = None;
        let mut out = Vec::new();
        let mut on_pty: Vec<(String, String, String)> = Vec::new(); // pid, name, terminal number of new shells on a terminal
        for pid in self.pids() {
            let comm = self.proc_name(&pid);
            if !SHELLS.contains(&comm.as_str()) {
                continue;
            }
            let Ok(link) = std::fs::read_link(format!("{}/{pid}/fd/0", self.proc_dir)) else { continue };
            if let Some(n) = link.to_str().and_then(|l| l.strip_prefix("/dev/pts/")) {
                // Go's strconv.Atoi: an optional sign, then digits
                let digits = n.strip_prefix(['+', '-']).unwrap_or(n);
                if !digits.is_empty() && digits.bytes().all(|c| c.is_ascii_digit()) {
                    let key = format!("{pid}|/dev/pts/{n}");
                    if !self.shell_seen.contains(&key) {
                        on_pty.push((pid.clone(), comm.clone(), n.to_string()));
                    }
                    now.insert(key);
                }
                continue;
            }
            let Some(ino) = Self::socket_inode(&link) else { continue };
            let key = format!("{pid}|{ino}");
            now.insert(key.clone());
            if self.shell_seen.contains(&key) {
                continue;
            }
            let conns = inet.get_or_insert_with(|| self.inet_sockets());
            let Some(conn) = conns.get(&ino).cloned() else { continue };
            out.push(ra_event(
                format!("the shell {comm} (pid {pid}) takes its input from a network connection ({conn})"),
                Fields::from([
                    ("provider".to_string(), comm.clone()),
                    ("ra_kind".to_string(), "kernel".to_string()),
                    ("signal".to_string(), "socket-shell".to_string()),
                    ("program".to_string(), comm.clone()),
                    ("pid".to_string(), pid.clone()),
                    ("connection".to_string(), conn),
                ]),
            ));
        }
        self.shell_seen = now;
        out.extend(self.pty_shells(&on_pty));
        out
    }

    /// Go's ptyShells (HEI-79): a shell whose terminal is fed from the network. Its input is /dev/pts/N and a program
    /// holding the terminal's master (/dev/ptmx with tty-index N in its fdinfo) has a TCP or UDP connection to another
    /// computer: Python's pty.spawn and socat's pty option. A remote login (REMOTE_LOGIN) and a holder whose connections stay
    /// on this computer or only listen are passed over.
    fn pty_shells(&self, on_pty: &[(String, String, String)]) -> Vec<Event> {
        if on_pty.is_empty() {
            return Vec::new();
        }
        let want: BTreeSet<String> = on_pty.iter().map(|s| s.2.clone()).collect();
        let holders = self.pty_holders(&want);
        let mut conns: Option<BTreeMap<String, String>> = None;
        let mut out = Vec::new();
        for (pid, comm, n) in on_pty {
            for h in holders.get(n).map(Vec::as_slice).unwrap_or_default() {
                let name = self.proc_name(h);
                if name.is_empty() || REMOTE_LOGIN.contains(&name.as_str()) {
                    continue;
                }
                let conns = conns.get_or_insert_with(|| self.inet_conns(true));
                let Some(conn) = self.first_conn(h, conns) else { continue };
                out.push(ra_event(
                    format!("the shell {comm} (pid {pid}) takes its input from a network connection through the terminal /dev/pts/{n}, held by {name} (pid {h}) ({conn})"),
                    Fields::from([
                        ("provider".to_string(), comm.clone()),
                        ("ra_kind".to_string(), "kernel".to_string()),
                        ("signal".to_string(), "socket-shell".to_string()),
                        ("program".to_string(), comm.clone()),
                        ("pid".to_string(), pid.clone()),
                        ("connection".to_string(), conn),
                        ("terminal".to_string(), format!("/dev/pts/{n}")),
                        ("holder".to_string(), name.clone()),
                        ("holder_pid".to_string(), h.clone()),
                    ]),
                ));
                break;
            }
        }
        out
    }

    /// Go's ptyHolders: the processes holding the master of each wanted terminal number, in /proc's order.
    fn pty_holders(&self, want: &BTreeSet<String>) -> BTreeMap<String, Vec<String>> {
        let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for pid in self.pids() {
            let mut held = BTreeSet::new();
            for fd in self.fds(&pid) {
                let Ok(link) = std::fs::read_link(format!("{}/{pid}/fd/{fd}", self.proc_dir)) else { continue };
                if link.as_os_str() != "/dev/ptmx" && link.as_os_str() != "/dev/pts/ptmx" {
                    continue;
                }
                let n = Self::tty_index(&format!("{}/{pid}/fdinfo/{fd}", self.proc_dir));
                if want.contains(&n) && held.insert(n.clone()) {
                    out.entry(n).or_default().push(pid.clone());
                }
            }
        }
        out
    }

    /// A process's open file numbers, in Go's os.ReadDir order (by name).
    fn fds(&self, pid: &str) -> Vec<String> {
        let Ok(rd) = std::fs::read_dir(format!("{}/{pid}/fd", self.proc_dir)) else { return Vec::new() };
        let mut fds: Vec<String> = rd.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
        fds.sort();
        fds
    }

    /// Go's ttyIndex: the terminal number in a pty master's fdinfo ("tty-index:\t3"), "" when there is none.
    fn tty_index(path: &str) -> String {
        let Ok(text) = std::fs::read_to_string(path) else { return String::new() };
        text.split('\n').find_map(|l| l.strip_prefix("tty-index:")).map(|v| v.trim().to_string()).unwrap_or_default()
    }

    /// Go's firstConn: the first of a process's sockets (in fd order) found in conns.
    fn first_conn(&self, pid: &str, conns: &BTreeMap<String, String>) -> Option<String> {
        self.fds(pid).into_iter().find_map(|fd| {
            let ino = std::fs::read_link(format!("{}/{pid}/fd/{fd}", self.proc_dir)).ok().and_then(|l| Self::socket_inode(&l))?;
            conns.get(&ino).cloned()
        })
    }

    fn sorted_names(dir: &str) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(dir)
            .map(|rd| rd.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect())
            .unwrap_or_default();
        v.sort();
        v
    }

    fn packages(&mut self) -> Vec<Event> {
        let Ok(md) = std::fs::metadata(&self.pacman) else { return Vec::new() };
        let mt = super::mtime(&md).unix_nanos();
        if mt == self.pkg_mtime {
            return Vec::new();
        }
        self.pkg_mtime = mt;
        let mut now = BTreeSet::new();
        let mut out = Vec::new();
        for e in Self::sorted_names(&self.pacman) {
            let name = package_name(&e);
            if name.is_empty() {
                continue;
            }
            now.insert(name.clone());
            if self.pkg_seen.contains(&name) {
                continue;
            }
            if let Some(p) = self.catalog.match_package(&name) {
                out.push(ra_event(
                    format!("the package {name} ({}) is installed", p.name),
                    Fields::from([
                        ("provider".to_string(), p.id.clone()),
                        ("provider_name".to_string(), p.name.clone()),
                        ("ra_kind".to_string(), p.kind.clone()),
                        ("signal".to_string(), "package".to_string()),
                        ("package".to_string(), name),
                    ]),
                ));
            }
        }
        self.pkg_seen = now;
        out
    }

    fn tunnel_kind(dir: &str) -> &'static str {
        if std::fs::read_to_string(format!("{dir}/uevent")).is_ok_and(|s| s.contains("DEVTYPE=wireguard")) {
            return "wireguard";
        }
        if std::fs::metadata(format!("{dir}/tun_flags")).is_ok() {
            return "tun";
        }
        ""
    }

    fn interfaces(&mut self) -> Vec<Event> {
        if std::fs::metadata(&self.net_dir).is_err() {
            return Vec::new();
        }
        let mut now = BTreeSet::new();
        let mut out = Vec::new();
        for name in Self::sorted_names(&self.net_dir) {
            now.insert(name.clone());
            if self.iface_seen.contains(&name) {
                continue;
            }
            if let Some(p) = self.catalog.match_iface(&name) {
                out.push(ra_event(
                    format!("the network interface {name} ({}) appeared", p.name),
                    Fields::from([
                        ("provider".to_string(), p.id.clone()),
                        ("provider_name".to_string(), p.name.clone()),
                        ("ra_kind".to_string(), p.kind.clone()),
                        ("signal".to_string(), "iface".to_string()),
                        ("iface".to_string(), name.clone()),
                    ]),
                ));
                continue;
            }
            let dir = format!("{}/{name}", self.net_dir);
            let k = Self::tunnel_kind(&dir);
            if k.is_empty() || !self.started {
                continue;
            }
            let master = std::fs::read_link(format!("{dir}/master")).ok();
            let guest = name.strip_prefix("vl-").filter(|g| !g.is_empty());
            // Limbo's own tap on its own bridge
            if guest
                .is_some_and(|g| master.as_ref().is_some_and(|m| m.file_name().is_some_and(|b| b.to_string_lossy() == format!("lb-{g}"))))
            {
                continue;
            }
            let unplugged = name.starts_with("vl-") && std::fs::symlink_metadata(format!("{dir}/master")).is_err();
            if unplugged && self.waited.get(&name).copied().unwrap_or(0) < 3 {
                *self.waited.entry(name.clone()).or_default() += 1;
                now.remove(&name);
                continue;
            }
            out.push(ra_event(
                format!("a new {k} tunnel interface {name} appeared"),
                Fields::from([
                    ("signal".to_string(), "tunnel".to_string()),
                    ("iface".to_string(), name.clone()),
                    ("tunnel".to_string(), k.to_string()),
                ]),
            ));
        }
        self.iface_seen = now;
        out
    }
}

impl RaSource {
    /// One look: packages, interfaces, then the kernel's side (Go: Poll).
    pub fn poll(&mut self) -> Vec<Event> {
        let mut ev = self.packages();
        ev.extend(self.interfaces());
        ev.extend(self.modules());
        ev.extend(self.raw_listeners());
        ev.extend(self.socket_shells());
        ev.extend(self.footholds.poll(&self.catalog));
        self.started = true;
        ev
    }
}

impl Source for RaSource {
    fn name(&self) -> &'static str {
        "remote-access"
    }
    fn due(&self) -> Option<Instant> {
        Some(self.next)
    }
    fn run(&mut self, now: Instant, out: &mut Vec<Msg>) {
        self.next = now + Duration::from_secs(15);
        let ev = self.poll();
        self.started = true;
        out.extend(ev.into_iter().map(Msg::Event));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The line Go's lan.Takeovers writes (internal/sources/lansource, TestATakenAddressIsCritical) is the same event here.
    #[test]
    fn a_taken_address_line() {
        let line = br#"{"time":"2026-11-16T10:00:00Z","ssid":"Home","device":{"mac":"02:00:00:00:00:66","ip":"192.0.2.30","kind":"","first_seen":"0001-01-01T00:00:00Z","last_seen":"0001-01-01T00:00:00Z"},"change":"address_taken","was_mac":"02:00:00:00:00:30","was_name":"TV","other_ip":"192.0.2.66"}"#;
        let e = lan_line(line).unwrap();
        assert_eq!(e.kind, "lan_device_changed");
        assert_eq!((e.f("was_name"), e.f("was_mac"), e.f("other_ip"), e.f("ip")), ("TV", "02:00:00:00:00:30", "192.0.2.66", "192.0.2.30"));
        let store = crate::cli::lan::store::Takeover {
            change: "address_taken",
            device: crate::cli::lan::store::devices_from_json(br#"[{"mac":"02:00:00:00:00:66","ip":"192.0.2.30"}]"#)[0].clone(),
            was_mac: "02:00:00:00:00:30".into(),
            was_name: "TV".into(),
            other_ip: "192.0.2.66".into(),
        };
        let dir = std::env::temp_dir().join(format!("heimdall-takeover-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("events.jsonl").to_string_lossy().into_owned();
        crate::cli::lan::store::append_changes(&p, "Home", &[store], crate::gotime::Time::parse_rfc3339("2026-11-16T10:00:00Z").unwrap())
            .unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), [&line[..], b"\n"].concat());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// HEI-12 and HEI-79, Go's TestTheKernelsSide on the same tree (internal/sources/rasource, fakeProc): the catalog's kernel
    /// modules, a raw packet listener outside the usual programs, a shell reading a TCP connection and one whose terminal
    /// python3 feeds from one are each one event, once; a login's terminal and terminals held by programs talking only to
    /// this computer or only listening are none.
    #[test]
    fn the_kernels_side() {
        let root = std::env::temp_dir().join(format!("heimdall-kernside-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let write = |rel: &str, text: &str| {
            let p = root.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, text).unwrap();
        };
        let link = |rel: &str, target: &str| {
            let p = root.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::os::unix::fs::symlink(target, p).unwrap();
        };
        write("modules", "ksmbd 344064 0 - Live 0x0000000000000000\next4 1101824 2 - Live 0x0000000000000000\nnvmet_tcp 45056 0 - Live 0x0000000000000000\n");
        write(
            "net/packet",
            "sk       RefCnt Type Proto  Iface R Rmem   User   Inode\n\
             0000000000000000 3      3    0003   2     1 0      0      100\n\
             0000000000000000 3      3    0800   0     1 0      0      200\n\
             0000000000000000 3      2    0003   3     1 0      0      300\n\
             0000000000000000 3      3    0003   0     1 0      0      0\n",
        );
        write(
            "net/tcp",
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
             \x20  0: 0A00000A:9C40 0500000A:115C 01 00000000:00000000 00:00000000 00000000  1000        0 500 1\n\
             \x20  1: 0A00000A:9C41 0600000A:115D 01 00000000:00000000 00:00000000 00000000  1000        0 700 1\n\
             \x20  2: 0A00000A:0016 0700000A:D431 01 00000000:00000000 00:00000000 00000000     0        0 800 1\n\
             \x20  3: 0100007F:1388 0100007F:A028 01 00000000:00000000 00:00000000 00000000  1000        0 900 1\n\
             \x20  4: 00000000:22B8 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 1000 1\n",
        );
        write("10/comm", "NetworkManager\n");
        link("10/fd/5", "socket:[100]");
        write("20/comm", "kworkerd\n");
        link("20/fd/0", "/dev/null");
        link("20/fd/3", "socket:[200]");
        write("30/comm", "bash\n");
        link("30/fd/0", "socket:[500]");
        write("31/comm", "bash\n");
        link("31/fd/0", "socket:[600]");
        write("32/comm", "bash\n");
        link("32/fd/0", "/dev/pts/1");
        for (holder, name, n, sock, shell) in [
            ("40", "python3", "2", "700", "41"),
            ("50", "sshd-session", "3", "800", "51"),
            ("60", "node", "4", "900", "61"),
            ("70", "ttyd", "5", "1000", "71"),
        ] {
            write(&format!("{holder}/comm"), &format!("{name}\n"));
            link(&format!("{holder}/fd/3"), "/dev/ptmx");
            write(&format!("{holder}/fdinfo/3"), &format!("pos:\t0\nflags:\t02100002\nmnt_id:\t40\nino:\t125\ntty-index:\t{n}\n"));
            link(&format!("{holder}/fd/4"), &format!("socket:[{sock}]"));
            write(&format!("{shell}/comm"), "bash\n");
            link(&format!("{shell}/fd/0"), &format!("/dev/pts/{n}"));
        }
        let none = root.join("none").to_string_lossy().into_owned();
        let mut w = RaSource::new(Catalog::builtin(), &none, &none);
        w.proc_dir = root.to_string_lossy().into_owned();
        w.footholds.root = none.clone(); // never this computer's /etc
        let got: Vec<String> = w
            .poll()
            .iter()
            .map(|e| format!("{} {} {} {}{} | {}", e.f("signal"), e.f("provider"), e.f("pid"), e.f("module"), e.f("connection"), e.text))
            .collect();
        assert_eq!(
            got,
            [
                "module ksmbd  ksmbd | the kernel module ksmbd (ksmbd, the kernel's SMB file server) was loaded",
                "module nvmet  nvmet_tcp | the kernel module nvmet_tcp (the kernel's NVMe over Fabrics target) was loaded",
                "raw-listener kworkerd 20  | kworkerd (pid 20) reads raw network packets",
                "socket-shell bash 30 tcp 10.0.0.10:40000 -> 10.0.0.5:4444 | the shell bash (pid 30) takes its input from a network connection (tcp 10.0.0.10:40000 -> 10.0.0.5:4444)",
                "socket-shell bash 41 tcp 10.0.0.10:40001 -> 10.0.0.6:4445 | the shell bash (pid 41) takes its input from a network connection through the terminal /dev/pts/2, held by python3 (pid 40) (tcp 10.0.0.10:40001 -> 10.0.0.6:4445)",
            ]
        );
        assert!(w.poll().is_empty(), "each once");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// HEI-21: the line Go's lan.NameMoves writes (internal/sources/lansource, TestANameMoveIsListedOrWarned) is the same event.
    #[test]
    fn a_name_move_line() {
        let line = br#"{"time":"2026-11-16T10:00:00Z","ssid":"Home","device":{"mac":"02:00:00:00:00:77","ip":"192.0.2.77","name":"Office-Printer","kind":"","first_seen":"0001-01-01T00:00:00Z","last_seen":"0001-01-01T00:00:00Z"},"change":"name_moved","was_mac":"00:11:22:00:00:30","was_name":"Office-Printer"}"#;
        let e = lan_line(line).unwrap();
        assert_eq!(
            (e.kind.as_str(), e.f("change"), e.f("was_mac"), e.f("name")),
            ("lan_device_changed", "name_moved", "00:11:22:00:00:30", "Office-Printer")
        );
        assert_eq!(e.text, "a known device's name on Home is announced by another device: Office-Printer");
    }

    #[test]
    fn lines_read_like_go() {
        let w = wifi_line(br#"{"time":"2026-11-07T10:00:00Z","ssid":"Cafe\u200b","verdict":"unsafe","checks":[{"status":"bad","detail":"open network"},{"status":"ok","detail":"x"}]}"#).unwrap();
        assert_eq!((w.f("ssid"), w.f("reasons"), w.f("problems")), ("Cafe?", "open network", "1"));
        assert!(wifi_line(br#"{"ssid":"x"}"#).is_none());
        let l = lan_line(br#"{"time":"2026-11-07T10:00:00Z","ssid":"Home","device":{"mac":"aa:bb","ip":"192.168.1.30","kind":"tv","private_mac":true,"first_seen":"2026-11-07T10:00:00Z","last_seen":"2026-11-07T10:00:00Z"}}"#).unwrap();
        assert_eq!((l.f("private_mac"), l.f("kind")), ("true", "tv"));
        assert_eq!(package_name("tailscale-1.76.1-1"), "tailscale");
        assert_eq!(package_name("x-1"), "");
    }
}
