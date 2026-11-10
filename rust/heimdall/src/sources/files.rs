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
}
crate::go_struct!(NewDevice { time: "time", ssid: "ssid", device: "device" });

/// One line of the trusted network's events.jsonl (heimdalld lan scan) as an event.
pub fn lan_line(line: &[u8]) -> Option<Event> {
    let nd = gojson::unmarshal(line, NewDevice::default()).ok().filter(|n| !n.device.mac.is_empty())?;
    let d = nd.device;
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

/// Remote-access tools by installed package and network interface (Go: rasource).
pub struct RaSource {
    catalog: Catalog,
    pacman: String,
    net_dir: String,
    pkg_seen: BTreeSet<String>,
    pkg_mtime: i128,
    iface_seen: BTreeSet<String>,
    waited: BTreeMap<String, u32>,
    started: bool,
    next: Instant,
}

fn ra_event(text: String, f: Fields) -> Event {
    Event { source: "remote-access".into(), session_id: String::new(), time: Time::now(), kind: "remote_access".into(), text, fields: f }
}

impl RaSource {
    pub fn new(catalog: Catalog, pacman: &str, net_dir: &str) -> RaSource {
        RaSource {
            catalog,
            pacman: pacman.into(),
            net_dir: net_dir.into(),
            pkg_seen: BTreeSet::new(),
            pkg_mtime: 0,
            iface_seen: BTreeSet::new(),
            waited: BTreeMap::new(),
            started: false,
            next: Instant::now(),
        }
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

impl Source for RaSource {
    fn name(&self) -> &'static str {
        "remote-access"
    }
    fn due(&self) -> Option<Instant> {
        Some(self.next)
    }
    fn run(&mut self, now: Instant, out: &mut Vec<Msg>) {
        self.next = now + Duration::from_secs(15);
        let mut ev = self.packages();
        ev.extend(self.interfaces());
        self.started = true;
        out.extend(ev.into_iter().map(Msg::Event));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
