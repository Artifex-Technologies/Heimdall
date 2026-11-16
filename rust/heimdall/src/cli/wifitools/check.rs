//! `heimdall-wifi-check` (packaging/arch/heimdall-wifi-check): is the Wi-Fi network this computer just joined safe to use?
//! Run by NetworkManager's dispatcher through heimdall-wifi-check@.service, as the heimdall account, sandboxed, on every
//! Wi-Fi connection. It reads what NetworkManager and the kernel know, looks up a few well-known names, opens a few
//! well-known pages, and listens for other devices (it scans none; the only one it may contact is a local address DNS gave
//! for a well-known name, asked for that name's certificate); the verdict goes to results.jsonl (Heimdall's alert),
//! current.json (the router watch) and /run/heimdall-wifi/last.json (the notification). Every step, file and tool call is
//! the Python program's.

use super::guard::{level_of, lock_holds, lock_name};
use super::py::{self, Dict, PyErr, PyResult, Val};
use super::{addr, net};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Well-known names and the networks (autonomous systems) their addresses belong to, wherever in the world one asks. An
/// answer elsewhere is not judged by its network alone: one secure connection to that address decides. Only a name's own
/// network is listed: a cloud anyone can rent space in (GitHub's other addresses are in Microsoft's) is asked too.
const PINNED: [(&str, &[&str]); 4] = [
    ("www.google.com", &["AS15169"]),
    ("github.com", &["AS36459"]),
    ("www.wikipedia.org", &["AS14907"]),
    ("www.cloudflare.com", &["AS13335"]),
];
/// Secure connections asked per name at most; an address beyond them is "could not confirm".
const PROBES: usize = 4;
/// Seconds to wait for heimdall-wifi-guard to finish bringing this connection up (its up runs beside the check).
const GUARD_WAIT: usize = 45;
/// The protections heimdall-wifi-guard checked that make other devices seeing this computer a covered exposure.
const COVERING: [(&str, &str); 3] = [
    ("firewall", "the firewall turning connections away"),
    ("not_announcing", "not announcing this computer"),
    ("own_address", "its own hardware address here (from the next connection on)"),
];
const GUARD_STATE: &str = "/run/heimdall-wifi-guard/state.json";
const TRUSTED: &str = "/etc/heimdall/wifi-trusted.json";
const TLS_HOSTS: [&str; 4] = ["www.google.com", "github.com", "www.wikipedia.org", "www.cloudflare.com"];

/// `split_nmcli(line)`: nmcli -t writes ':' and '\' in values as '\:' and '\\'; read left to right.
pub fn split_nmcli(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut it = line.chars().peekable();
    while let Some(c) = it.next() {
        if c == '\\' && matches!(it.peek(), Some(':' | '\\')) {
            cur.push(it.next().unwrap());
        } else if c == ':' {
            out.push(std::mem::take(&mut cur));
        } else {
            cur.push(c);
        }
    }
    out.push(cur);
    out
}

/// A network in NetworkManager's scan list.
#[derive(Clone, Debug, PartialEq)]
pub struct Net {
    pub active: bool,
    pub ssid: String,
    pub bssid: String,
    pub security: String,
}

/// The scan list (`nmcli -t -f ACTIVE,SSID,BSSID,SECURITY dev wifi list --rescan no`) read.
pub fn wifi_networks(out: &str) -> Vec<Net> {
    py::splitlines(out)
        .into_iter()
        .map(split_nmcli)
        .filter(|f| f.len() >= 4)
        .map(|f| Net { active: f[0] == "yes", ssid: f[1].clone(), bssid: py::upper(&f[2]), security: py::strip(&f[3]).to_string() })
        .collect()
}

/// open, wep or secured.
pub fn security_class(s: &str) -> &'static str {
    let s = py::upper(s);
    if s.is_empty() || s == "--" {
        "open"
    } else if s.contains("OWE") {
        "owe" // encrypted, but without a password: anyone can make a copy of a WPA2 network this way
    } else if s.contains("WEP") {
        "wep"
    } else {
        "secured"
    }
}

/// `re.search(r"\bAS\d+\b", text)` with Python's Unicode word characters and digits.
pub fn as_number(text: &str) -> Option<String> {
    let chars: Vec<char> = text.chars().collect();
    for i in 0..chars.len() {
        if chars[i] != 'A' || chars.get(i + 1) != Some(&'S') || (i > 0 && py::is_word(chars[i - 1])) {
            continue;
        }
        let mut j = i + 2;
        while j < chars.len() && py::decimal_value(chars[j]).is_some() {
            j += 1;
        }
        if j > i + 2 && (j == chars.len() || !py::is_word(chars[j])) {
            return Some(chars[i..j].iter().collect());
        }
    }
    None
}

/// `heimdalld origin` output read: address -> (AS number, the whole origin).
pub fn parse_origins(out: &str) -> Vec<(String, (String, String))> {
    let mut res: Vec<(String, (String, String))> = Vec::new();
    for line in py::splitlines(out) {
        let (ip, o) = line.split_once("  ").unwrap_or((line, ""));
        let v = (as_number(o).unwrap_or_default(), py::strip(o).to_string());
        match res.iter_mut().find(|(k, _)| k == ip) {
            Some(e) => e.1 = v,
            None => res.push((ip.to_string(), v)),
        }
    }
    res
}

/// `ss -tulnH` read: this computer's services listening beyond itself, as "proto/port", sorted.
pub fn listening_services(out: &str) -> Vec<String> {
    let mut res = Vec::new();
    for line in py::splitlines(out) {
        let f = py::split_ws(line);
        if f.len() < 5 {
            continue;
        }
        let (proto, local) = (f[0], f[4]);
        let (host, port) = local.rsplit_once(':').unwrap_or(("", local));
        let host = py::strip_chars(host, "[]").split('%').next().unwrap_or_default();
        match addr::is_loopback(host) {
            Some(true) => continue,
            Some(false) => {}
            None if host != "*" && !host.is_empty() => continue,
            None => {}
        }
        if proto == "udp" && matches!(port, "68" | "546" | "5353" | "1900") {
            continue; // the address request (DHCP) and local discovery
        }
        res.push(format!("{proto}/{port}"));
    }
    res.sort();
    res.dedup();
    res
}

/// The checks so far, shared with the watchdog that writes them when the check's time runs out.
#[derive(Clone, Default)]
struct Report {
    checks: Arc<Mutex<Vec<(String, String, String)>>>,
}

impl Report {
    fn add(&self, name: &str, status: &str, detail: &str) {
        self.checks.lock().unwrap().push((name.into(), status.into(), detail.into()));
    }
    fn list(&self) -> Vec<(String, String, String)> {
        self.checks.lock().unwrap().clone()
    }
    /// unsafe on any sign of an attack, caution on an exposure nothing covers, protected when every exposure is covered by a
    /// protection checked to be in force, safe otherwise. "bad" is never covered.
    fn verdict(&self) -> &'static str {
        let checks = self.list();
        if checks.iter().any(|c| c.1 == "bad") {
            "unsafe"
        } else if checks.iter().any(|c| c.1 == "warn") {
            "caution"
        } else if checks.iter().any(|c| c.1 == "covered") {
            "protected"
        } else {
            "safe"
        }
    }
    fn json(&self) -> Val {
        Val::List(
            self.list()
                .iter()
                .map(|(c, s, d)| {
                    let mut x = Dict::new();
                    x.set("check", py::s(c));
                    x.set("status", py::s(s));
                    x.set("detail", py::s(d));
                    Val::Dict(x)
                })
                .collect(),
        )
    }
}

/// The seconds the check may take: HEIMDALL_WIFI_CHECK_LIMIT, or 240 (its unit gives it 300).
pub fn limit() -> u64 {
    let v = std::env::var("HEIMDALL_WIFI_CHECK_LIMIT").unwrap_or_default();
    match v.parse::<u64>() {
        Ok(n) if !v.is_empty() && v.len() < 6 && v.bytes().all(|b| b.is_ascii_digit()) && n > 0 => n,
        _ => 240,
    }
}

/// What is known so far, for a check that runs out of time; `done` once one side (the check, or the watchdog) writes.
struct Partial {
    state: String,
    level: &'static str,
    done: bool,
}

/// `run(argv, timeout)`: a tool's output, "" when it is missing or too slow (a reply that is not UTF-8 stops the program,
/// as in Python).
fn run(argv: &[String], timeout: u64) -> PyResult<String> {
    match py::capture(argv, Some(Duration::from_secs(timeout))) {
        Ok(d) => Ok(d.stdout),
        Err(e) if e.is_os() || e.kind == "TimeoutExpired" => Ok(String::new()),
        Err(e) => Err(e),
    }
}

fn run_words(words: &[&str]) -> PyResult<String> {
    run(&py::argv(words), 15)
}

/// A value from a file as a program's argument.
fn arg(v: &Val) -> PyResult<String> {
    match v {
        Val::Str(s) => Ok(s.clone()),
        v => Err(PyErr::type_err(format!("expected str, bytes or os.PathLike object, not {}", v.type_name()))),
    }
}

fn is_value_error(e: &PyErr) -> bool {
    matches!(e.kind, "ValueError" | "UnicodeDecodeError" | "UnicodeEncodeError")
}

/// `try: json.loads(run(argv) or "[]") except ValueError: []`: a reply that is not UTF-8 or not JSON is an empty list.
fn run_json(argv: &[String]) -> PyResult<Val> {
    let empty = Val::List(Vec::new());
    match run(argv, 15) {
        Ok(text) => Ok(json(&text)?.unwrap_or(empty)),
        Err(e) if is_value_error(&e) => Ok(empty),
        Err(e) => Err(e),
    }
}

/// `json.loads(text or "[]")`, Python's ValueError as None.
fn json(text: &str) -> PyResult<Option<Val>> {
    match py::loads(if text.is_empty() { "[]" } else { text }) {
        Ok(v) => Ok(Some(v)),
        Err(py::JsonErr::Value) => Ok(None),
        Err(py::JsonErr::Recursion) => Err(PyErr::new("RecursionError", "maximum recursion depth exceeded")),
    }
}

struct Check {
    state: PathBuf,
    public: PathBuf,
    r: Report,
    /// when the check began, and the seconds it may take
    start: std::time::Instant,
    limit: u64,
}

impl Check {
    fn check_radio(&mut self) -> PyResult<Option<Net>> {
        let nets =
            wifi_networks(&run_words(&["nmcli", "-t", "-f", "ACTIVE,SSID,BSSID,SECURITY", "dev", "wifi", "list", "--rescan", "no"])?);
        let Some(me) = nets.iter().find(|n| n.active).cloned() else {
            self.r.add("network", "skip", "not on Wi-Fi");
            return Ok(None);
        };
        let cls = security_class(&me.security);
        match cls {
            "open" => self.r.add(
                "encryption",
                "warn",
                "open network: anything not encrypted by the site itself (plain web pages, some apps) can be read by anyone nearby",
            ),
            "wep" => self.r.add("encryption", "bad", "WEP encryption is broken and can be cracked in minutes"),
            _ => self.r.add("encryption", "ok", &format!("encrypted ({})", me.security)),
        }
        if nets.iter().any(|n| n.ssid == me.ssid && !n.ssid.is_empty() && security_class(&n.security) != cls) {
            self.r.add(
                "evil twin",
                "bad",
                &format!("another network with the same name ({}) but different security is nearby: someone may be imitating it", me.ssid),
            );
        } else {
            self.r.add("evil twin", "ok", "no copy of this network with different security nearby");
        }
        Ok(Some(me))
    }

    /// NetworkManager's own view (read, not re-tested); right after joining, give it a moment.
    fn connectivity(&self) -> PyResult<String> {
        let mut st = "unknown".to_string();
        for _ in 0..10 {
            st = py::strip(&run_words(&["nmcli", "-t", "-f", "CONNECTIVITY", "general"])?).to_string();
            if st.is_empty() {
                st = "unknown".into();
            }
            if st == "full" || st == "portal" {
                return Ok(st);
            }
            std::thread::sleep(Duration::from_secs(2));
        }
        Ok(st)
    }

    /// The default route's (gateway, device); (None, None) without one.
    fn gateway(&self) -> PyResult<(Val, Val)> {
        let routes = run_json(&py::argv(&["ip", "-j", "route", "show", "default"]))?;
        for rt in routes.iter()? {
            if rt.get("gateway", Val::None)?.truthy() {
                return Ok((rt.index("gateway")?, rt.get("dev", py::s(""))?));
            }
        }
        Ok((Val::None, Val::None))
    }

    fn neighbours(&self, dev: &Val) -> PyResult<Val> {
        let d = arg(dev)?;
        run_json(&py::argv(&["ip", "-j", "neigh", "show", "dev", &d]))
    }

    /// The router: one hardware address, the one seen here before. `hotspot(mac)`: whether a new one is expected (trusted as
    /// trusted, not home, and an address a phone hotspot makes up); anywhere else a new router address is still a warning.
    /// Returns the device and the router's hardware address.
    fn check_gateway(&mut self, me: &Net, known: &mut Dict, hotspot: &dyn Fn(&str) -> bool) -> PyResult<(Val, String)> {
        let (gw, dev) = self.gateway()?;
        if !gw.truthy() {
            self.r.add("router", "skip", "no default route");
            return Ok((dev, String::new()));
        }
        let neigh = self.neighbours(&dev)?;
        let items = neigh.iter()?;
        let mut mac = String::new();
        for n in &items {
            if py::eq(&n.get("dst", Val::None)?, &gw) && n.get("lladdr", Val::None)?.truthy() {
                mac = n.get("lladdr", py::s(""))?.upper()?;
                break;
            }
        }
        if mac.is_empty() {
            self.r.add("router", "skip", "the router's hardware address is not known yet");
            return Ok((dev, String::new()));
        }
        let mut others: Vec<Val> = Vec::new();
        for n in &items {
            if n.get("lladdr", py::s(""))?.upper()? == mac
                && !py::eq(&n.get("dst", Val::None)?, &gw)
                && !n.get("dst", py::s(""))?.contains(&py::s(":"))?
            {
                others.push(n.index("dst")?);
            }
        }
        if !others.is_empty() {
            let mut shown = Vec::new();
            for (i, o) in others.iter().take(3).enumerate() {
                match o {
                    Val::Str(s) => shown.push(s.clone()),
                    v => return Err(PyErr::type_err(format!("sequence item {i}: expected str instance, {} found", v.type_name()))),
                }
            }
            self.r.add(
                "router",
                "bad",
                &format!(
                    "another address ({}) answers with the router's hardware address: a sign of ARP spoofing (someone placing themselves between you and the router)",
                    shown.join(", ")
                ),
            );
        }
        let key = super::sha16(&format!("{}|{}", me.ssid, me.bssid));
        let seen = known.setdefault(&key, Val::List(Vec::new()));
        let m = py::s(&mac);
        if seen.truthy() && !seen.contains(&m)? {
            if hotspot(&mac) {
                self.r.add(
                    "router",
                    "ok",
                    "the router's hardware address changed to one its device made up (phone hotspots do this when they restart); this trusted network is recognized by its password",
                );
            } else {
                let hint = if locally_administered(&mac) { " (phone hotspots change it when they restart)" } else { "" };
                self.r.add(
                    "router",
                    "warn",
                    &format!(
                        "the router's hardware address is different from the last time on this network ({}): it may have been replaced, or someone is imitating it{hint}",
                        me.ssid
                    ),
                );
            }
        } else if others.is_empty() {
            let again = if seen.truthy() { " (same as before)" } else { "" };
            self.r.add("router", "ok", &format!("one router, as expected{again}"));
        }
        if !seen.contains(&m)? {
            match seen {
                Val::List(l) => {
                    l.push(m);
                    let n = l.len();
                    if n > 3 {
                        l.drain(..n - 3);
                    }
                }
                v => return Err(PyErr::new("AttributeError", format!("'{}' object has no attribute 'append'", v.type_name()))),
            }
        }
        Ok((dev, mac))
    }

    fn origins(&self, ips: &[String]) -> PyResult<Vec<(String, (String, String))>> {
        let mut argv = py::argv(&["heimdalld", "origin"]);
        if let Some(cfg) = std::env::var("HEIMDALL_CONFIG").ok().filter(|c| !c.is_empty()) {
            argv.extend(["--config".to_string(), cfg]);
        }
        argv.extend(ips.iter().cloned());
        Ok(parse_origins(&run(&argv, 20)?))
    }

    fn check_dns(&mut self) -> PyResult<()> {
        // a name that cannot exist must not get an answer
        let mut rnd = [0u8; 8];
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut rnd)
            .map_err(|_| PyErr::new("OSError", "no random numbers"))?;
        let fake = format!("heimdall-{}.com", rnd.iter().map(|b| format!("{b:02x}")).collect::<String>());
        match addr::getaddrinfo(&fake, "80", 0, 0) {
            Ok(_) => self.r.add(
                "dns: missing names",
                "warn",
                "this network's DNS invents answers for names that do not exist (it rewrites DNS; common on hotel and café networks, and a way to redirect you)",
            ),
            Err(e) if e.kind == "gaierror" => self.r.add("dns: missing names", "ok", "names that do not exist are reported as missing"),
            Err(e) => return Err(e),
        }
        // well-known names must point into their owners' networks
        let mut answers: Vec<(&str, Vec<String>)> = Vec::new();
        for (name, _) in PINNED {
            let mut v = match addr::getaddrinfo(name, "443", libc::AF_INET, 0) {
                Ok(v) => v,
                Err(e) if e.kind == "gaierror" => Vec::new(),
                Err(e) => return Err(e),
            };
            v.sort();
            v.dedup();
            answers.push((name, v));
        }
        let ips: Vec<String> = answers.iter().flat_map(|(_, v)| v.iter().cloned()).collect();
        let org = if ips.is_empty() { Vec::new() } else { self.origins(&ips)? };
        if !ips.is_empty() && !org.iter().any(|(_, (a, _))| !a.is_empty()) {
            self.r.add("dns: well-known names", "skip", "no IP database yet to check addresses against (heimdall-intel-update)");
            return Ok(());
        }
        // every distinct answer outside the name's own network is asked for the name's certificate (at most PROBES a name);
        // a local address must show it too, and one that sends the name to this computer itself is never the real site
        let (mut wrong, mut unsure, mut confirmed) = (Vec::new(), Vec::new(), Vec::new());
        for ((name, asns), (_, ips)) in PINNED.iter().zip(&answers) {
            let mut asked = 0;
            for ip in ips {
                let (got, desc) = org.iter().find(|(k, _)| k == ip).map(|(_, v)| v.clone()).unwrap_or_default();
                let local = addr::parse_v4(ip).is_some_and(addr::v4_is_private);
                let place = if local {
                    "a local address".to_string()
                } else if !got.is_empty() && !asns.contains(&got.as_str()) {
                    desc
                } else {
                    continue;
                };
                let said = format!("{name} -> {ip} ({place})");
                if this_computer(ip) {
                    wrong.push(format!("{said}, this computer itself"));
                    continue;
                }
                if asked >= PROBES {
                    unsure.push(format!("{said}, not asked (more than {PROBES} such answers)"));
                    continue;
                }
                if self.start.elapsed().as_secs_f64() > self.limit as f64 / 2.0 {
                    unsure.push(format!("{said}, not asked (the check is short of time)"));
                    continue;
                }
                asked += 1;
                match net::tls_probe_at(ip, name) {
                    "ok" => confirmed.push(said),
                    "cert" => wrong.push(format!("{said}, whose certificate this computer does not trust")),
                    _ if local => wrong.push(format!("{said}, which does not show the site's certificate")),
                    _ => unsure.push(format!("{said}, which did not answer a secure connection")),
                }
            }
        }
        let first = |v: &[String]| v.iter().take(3).cloned().collect::<Vec<_>>().join("; ");
        if !wrong.is_empty() {
            self.r.add(
                "dns: well-known names",
                "bad",
                &format!("well-known sites resolve to addresses that are not theirs: {}. This is DNS spoofing", first(&wrong)),
            );
        } else if !unsure.is_empty() {
            self.r.add(
                "dns: well-known names",
                "warn",
                &format!("could not confirm where well-known sites resolve, outside their own networks: {}", first(&unsure)),
            );
        } else if !confirmed.is_empty() {
            self.r.add(
                "dns: well-known names",
                "ok",
                &format!(
                    "well-known sites resolve into their own networks, or to another company's that shows their genuine certificate ({})",
                    first(&confirmed)
                ),
            );
        } else if answers.iter().any(|(_, v)| !v.is_empty()) {
            self.r.add("dns: well-known names", "ok", "well-known sites resolve into their own networks");
        } else {
            self.r.add("dns: well-known names", "skip", "names did not resolve");
        }
        Ok(())
    }

    fn check_tls(&mut self) {
        let (mut bad, mut blocked, mut ok) = (Vec::new(), Vec::new(), 0);
        for host in TLS_HOSTS {
            match net::tls_probe(host) {
                net::Tls::Ok(_) => ok += 1,
                net::Tls::Cert(why) => bad.push(format!("{host} ({})", if why.is_empty() { "not trusted" } else { &why })),
                net::Tls::Blocked => blocked.push(host),
            }
        }
        if !bad.is_empty() {
            let b: Vec<String> = bad.iter().take(3).cloned().collect();
            self.r.add(
                "https",
                "bad",
                &format!(
                    "secure connections are being intercepted: certificates this computer does not trust for {}. Someone is in the middle; do not sign in to anything here",
                    b.join(", ")
                ),
            );
        } else if ok > 0 {
            self.r.add("https", "ok", "secure connections to well-known sites have genuine certificates");
        }
        if !blocked.is_empty() && bad.is_empty() {
            self.r.add("https: blocked", if ok == 0 { "warn" } else { "ok" }, &format!("could not reach {}", blocked.join(", ")));
        }
    }

    fn check_http(&mut self, state: &str) {
        let tests: [(&str, u32, &[u8]); 2] = [
            ("http://detectportal.firefox.com/success.txt", 200, b"success\n"),
            ("http://connectivitycheck.gstatic.com/generate_204", 204, b""),
        ];
        let mut changed = Vec::new();
        for (url, code, body) in tests {
            let host = url.split('/').nth(2).unwrap_or_default();
            match net::urlopen(url) {
                Some((status, got)) => {
                    if status != code || got != body {
                        changed.push(host.to_string());
                    }
                }
                None => changed.push(format!("{host} (no answer)")),
            }
        }
        if changed.is_empty() {
            self.r.add("plain web pages", "ok", "plain web pages arrive unchanged");
        } else if state == "portal" {
            self.r.add("plain web pages", "warn", "plain web pages are replaced by a sign-in page; check again after signing in");
        } else {
            self.r.add(
                "plain web pages",
                "bad",
                &format!("plain web pages are changed on the way ({}): the network injects or replaces content", changed.join(", ")),
            );
        }
    }

    /// This computer's addresses (`ip -j addr`), as Python collects them into a set.
    fn own_addresses(&self) -> PyResult<Vec<Val>> {
        let mut out = Vec::new();
        let v = run_json(&py::argv(&["ip", "-j", "addr"]))?;
        for i in v.iter()? {
            for a in i.get("addr_info", Val::List(Vec::new()))?.iter()? {
                let x = a.get("local", py::s(""))?;
                if matches!(x, Val::List(_) | Val::Dict(_)) {
                    return Err(PyErr::type_err(format!("unhashable type: '{}'", x.type_name())));
                }
                out.push(x);
            }
        }
        Ok(out)
    }

    /// The router's (or the phone hotspot's) own addresses: the gateway, and any address with its hardware address.
    fn router_addresses(&self, dev: &Val, gw: &Val, gmac: &str) -> PyResult<Vec<String>> {
        let mut out = Vec::new();
        if let Val::Str(g) = gw {
            if !g.is_empty() {
                out.push(g.clone());
            }
        }
        if !gmac.is_empty() && dev.truthy() {
            for n in self.neighbours(dev)?.iter()? {
                if let Val::Dict(d) = &n {
                    if let (Some(Val::Str(ll)), Some(Val::Str(dst))) = (d.get("lladdr"), d.get("dst")) {
                        if py::upper(ll) == gmac && !dst.contains(':') {
                            out.push(dst.clone());
                        }
                    }
                }
            }
        }
        Ok(out)
    }

    /// Other devices heard, the router or hotspot itself not counted: expected at home; elsewhere covered when the guard
    /// verified the protections that make being seen harmless (`g`: its state for this connection), an exposure (warn)
    /// otherwise. Returns how many were heard (only the number goes to results.jsonl: nobody's address is kept).
    fn check_neighbourhood(&mut self, dev: &Val, level: &str, g: &Dict, gw: &Val, gmac: &str) -> PyResult<Val> {
        let heard = net::listen_for_devices(8.0, || self.own_addresses())?;
        let listened = heard.is_some();
        let mut found: Vec<String> = Vec::new();
        if let Some(heard) = heard {
            let skip = self.router_addresses(dev, gw, gmac)?;
            found = heard.into_iter().filter(|ip| !skip.contains(ip)).collect();
            found.sort();
            found.dedup();
        }
        let head = format!("{} other device(s) heard on this network (not counting the router or hotspot)", found.len());
        if !listened {
            self.r.add("isolation", "skip", "could not listen for other devices");
        } else if found.is_empty() {
            self.r.add(
                "isolation",
                "ok",
                "no other device heard in 8 seconds (not counting the router or hotspot): the network may keep devices apart (or they are quiet)",
            );
        } else if level == "home" {
            self.r.add("isolation", "ok", &head);
        } else {
            let p = match g.get("protections") {
                Some(Val::Dict(p)) => p.clone(),
                _ => Dict::new(),
            };
            // the owner let this computer announce itself here
            let disc = matches!(p.get("discoverable"), Some(Val::Bool(true)));
            let mut missing: Vec<String> = COVERING
                .iter()
                .filter(|(k, _)| !matches!(p.get(k), Some(Val::Bool(true))) && !(disc && *k == "not_announcing"))
                .map(|(_, l)| l.to_string())
                .collect();
            if let Some(Val::List(allowed)) = p.get("allowed_in") {
                if let Some(m) = missing.iter_mut().find(|m| *m == "the firewall turning connections away") {
                    if !allowed.is_empty() {
                        let names: Vec<String> = allowed.iter().take(6).map(py::str_of).collect();
                        m.push_str(&format!(" (a rule lets in {})", names.join(", ")));
                    }
                }
            }
            if missing.is_empty() {
                self.r.add(
                    "isolation",
                    "covered",
                    &format!(
                        "{head}{} its firewall turns their connections away (it answers pings, as ufw does by default) and it uses its own hardware address here",
                        if disc {
                            ": they can see this computer is here and what it announces (you made it discoverable here), but"
                        } else {
                            ": they can see this computer is here, but it does not announce itself,"
                        }
                    ),
                );
            } else {
                self.r.add(
                    "isolation",
                    "warn",
                    &format!(
                        "{head}, so devices are not kept apart and they can see this computer too; not in force here: {}",
                        missing.join(", ")
                    ),
                );
            }
        }
        let fw = py::strip(&run_words(&["systemctl", "is-active", "ufw"])?).to_string();
        let svc = listening_services(&run_words(&["ss", "-tulnH"])?);
        let first: Vec<String> = svc.iter().take(6).cloned().collect();
        if fw != "active" {
            let tail = if svc.is_empty() {
                String::new()
            } else {
                format!(": these services can be reached from this network: {}", first.join(", "))
            };
            self.r.add("firewall", "bad", &format!("the firewall is off{tail}"));
        } else if !svc.is_empty() {
            self.r.add(
                "ports",
                "ok",
                &format!(
                    "the firewall is on; services listening beyond this computer, blocked unless a rule allows them: {}",
                    first.join(", ")
                ),
            );
        } else {
            self.r.add("firewall", "ok", "the firewall is on and nothing on this computer listens for connections from the network");
        }
        Ok(Val::Int(found.len().to_string()))
    }

    /// The saved profile's network name and key management; Nones without a profile.
    fn profile(&self, uuid: &str) -> PyResult<(Option<String>, Option<String>)> {
        if uuid.is_empty() {
            return Ok((None, None));
        }
        let ssid = py::strip(&run_words(&["nmcli", "-g", "802-11-wireless.ssid", "connection", "show", uuid])?).to_string();
        let key = py::strip(&run_words(&["nmcli", "-g", "802-11-wireless-security.key-mgmt", "connection", "show", uuid])?).to_string();
        Ok((Some(ssid), Some(key)))
    }

    /// A network with the name of one the owner trusts but not its lock: a copy a stranger without the password can make
    /// (bad), or the trusted profile itself edited to a weaker lock (warn). Never quiet, whatever the level.
    fn check_trusted_name(&mut self, me: &Net, uuid: &str, key: &str, trusted: &Dict) {
        if uuid.is_empty() || me.ssid.is_empty() {
            return;
        }
        for (u, e) in &trusted.0 {
            let Val::Dict(d) = e else { continue };
            if level_of(Some(e), None, None, None) == "untrusted" || !matches!(d.get("ssid"), Some(Val::Str(x)) if *x == me.ssid) {
                continue;
            }
            if u == uuid && !d.contains_key("level") {
                continue; // an entry from before the levels recorded no lock to compare with
            }
            if lock_holds(d.get("key_mgmt"), key) {
                continue;
            }
            if u == uuid {
                self.r.add(
                    "trusted name",
                    "warn",
                    &format!(
                        "the saved profile of this trusted network now has a weaker lock ({}) than when you trusted it: it is treated as untrusted; trust it again if you changed it",
                        lock_name(key)
                    ),
                );
            } else {
                self.r.add(
                    "trusted name",
                    "bad",
                    &format!(
                        "this network has the name of one you trust ({}) but not its lock ({} now): someone may be imitating it; do not use it",
                        me.ssid,
                        lock_name(key)
                    ),
                );
            }
            return;
        }
    }
}

/// A hardware address made up by its device (the second hex digit has bit 2 set), as phone hotspots' are.
pub fn locally_administered(mac: &str) -> bool {
    mac.chars().count() > 1 && mac.chars().nth(1).is_some_and(|c| "2367ABEFabef".contains(c))
}

/// 0.0.0.0/8 and 127.0.0.0/8: an answer that sends a well-known name to this computer itself, never the real site.
pub fn this_computer(ip: &str) -> bool {
    ip.starts_with("0.") || ip.starts_with("127.")
}

/// heimdall-wifi-guard's state.json for this connection (empty for another network's, or none), waiting while the guard's
/// pre-up mark says this connection is still coming up (at most `GUARD_WAIT` seconds): its up runs beside the check.
fn guard_state(uuid: &str) -> PyResult<Dict> {
    let mut g = Dict::new();
    for _ in 0..GUARD_WAIT {
        g = py::load_dict(Path::new(GUARD_STATE))?;
        let coming = match (g.get("pending"), g.get("pending_at")) {
            (Some(Val::Str(u)), Some(Val::Str(at))) => {
                !uuid.is_empty()
                    && u == uuid
                    && py::utc_stamp_ago(120).as_str() <= at.as_str()
                    && at.as_str() <= py::utc_stamp_ago(-60).as_str()
            }
            _ => false,
        };
        if !coming {
            break;
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    Ok(if !uuid.is_empty() && py::eq(g.get("wifi").unwrap_or(&Val::None), &py::s(uuid)) { g } else { Dict::new() })
}

/// What the network can still see of this computer when the verdict is protected, said plainly; "" otherwise.
fn exposure(verdict: &str, me: &Net, g: &Dict) -> String {
    if verdict != "protected" {
        return String::new();
    }
    let vpn = matches!(g.get("protections"), Some(Val::Dict(p)) if matches!(p.get("vpn"), Some(Val::Bool(true))));
    let disc = matches!(g.get("protections"), Some(Val::Dict(p)) if matches!(p.get("discoverable"), Some(Val::Bool(true))));
    let tail = if vpn {
        "Still visible to the network itself: that this computer is there and how much it sends; the VPN hides where it goes."
    } else {
        "Still visible to the network itself: the names of the sites you visit (DNS is not encrypted) and how much you send. A VPN would hide both."
    };
    if disc {
        return format!(
            "Protected on {}: other devices can see this computer is there, what it announces (you made it discoverable here) and that it answers pings, but its firewall turns their connections away and it uses its own hardware address here. {tail}",
            me.ssid
        );
    }
    format!(
        "Protected on {}: other devices can see this computer is there and that it answers pings, but it does not announce itself, its firewall turns their connections away and it uses its own hardware address here. {tail}",
        me.ssid
    )
}

fn text_line(c: &(String, String, String)) -> String {
    let pad = |s: &str, w: usize| format!("{s}{}", " ".repeat(w.saturating_sub(s.chars().count())));
    format!("  {} {} {}", pad(&c.0, 22), pad(&c.1, 5), c.2)
}

/// The verdict for heimdalld (results.jsonl) and for the desktop notification (last.json; an OSError there is ignored).
fn write_results(dir: &Path, public: &Path, r: &Report, res: &Dict) -> PyResult<()> {
    // Heimdall's own (heimdalld reads it as heimdall): the networks joined are named in it, from the first byte on
    py::append_text_mode(&dir.join("results.jsonl"), &format!("{}\n", py::dumps(&Val::Dict(res.clone()), None)), 0o640)?;
    let _ = write_public(public, r, res);
    Ok(())
}

fn show(json: bool, r: &Report, res: &Dict) {
    if json {
        println!("{}", py::dumps(&Val::Dict(res.clone()), Some(2)));
    } else {
        println!("{}: {}", py::str_of(res.get("ssid").unwrap_or(&Val::None)), r.verdict());
        for ch in &r.list() {
            println!("{}", text_line(ch));
        }
    }
}

/// When the check's time runs out: what it found so far, with a warning, written as a whole result; then the program ends.
fn out_of_time(dir: &Path, public: &Path, r: &Report, me: &Net, p: &Partial, limit: u64, json: bool) {
    r.add(
        "finish",
        "warn",
        &format!("the check could not finish within {limit} seconds (the network answers too slowly, or holds answers back): the checks after these were not run"),
    );
    let mut res = Dict::new();
    res.set("time", py::s(&py::utc_stamp()));
    res.set("ssid", py::s(&me.ssid));
    res.set("bssid", py::s(&me.bssid));
    res.set("security", py::s(&me.security));
    res.set("connectivity", py::s(&p.state));
    res.set("trusted", Val::Bool(p.level == "home"));
    res.set("level", py::s(p.level));
    res.set("verdict", py::s(r.verdict()));
    res.set("checks", r.json());
    res.set("heard", Val::Int("0".into()));
    res.set("exposure", py::s(""));
    let code = match write_results(dir, public, r, &res) {
        Ok(()) => {
            show(json, r, &res);
            0
        }
        Err(e) => py::traceback("heimdall-wifi-check", &e),
    };
    use std::io::Write;
    let _ = std::io::stdout().flush();
    std::process::exit(code);
}

fn check(args: &[String]) -> PyResult<i32> {
    let start = std::time::Instant::now();
    let mut uuid = String::new();
    if let Some(i) = args.iter().position(|a| a == "--uuid") {
        uuid = args
            .get(i + 1)
            .map(|v| v.chars().filter(|c| c.is_ascii_digit() || ('a'..='f').contains(c) || *c == '-').collect())
            .unwrap_or_default();
    }
    let json = args.iter().any(|a| a == "--json");
    let guard = py::load_dict(Path::new(GUARD_STATE))?;
    let mut c = Check {
        state: std::env::var_os("HEIMDALL_WIFI_DIR").map_or_else(|| PathBuf::from("/var/lib/heimdall/wifi"), PathBuf::from),
        public: std::env::var_os("HEIMDALL_WIFI_PUBLIC").map_or_else(|| PathBuf::from("/run/heimdall-wifi/last.json"), PathBuf::from),
        r: Report::default(),
        start,
        limit: limit(),
    };
    py::makedirs(&c.state)?;
    let known_path = c.state.join("routers.json");
    let mut known = py::load_dict(&known_path)?;
    let Some(me) = c.check_radio()? else {
        println!("not on Wi-Fi");
        return Ok(0);
    };
    // the watchdog: at the check's limit, what was found so far is written (Python: the alarm)
    let partial = Arc::new(Mutex::new(Partial { state: "unknown".into(), level: "untrusted", done: false }));
    {
        let (r, partial, me, dir, public, limit) = (c.r.clone(), partial.clone(), me.clone(), c.state.clone(), c.public.clone(), c.limit);
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(limit));
            let mut p = partial.lock().unwrap();
            if p.done {
                return;
            }
            p.done = true;
            out_of_time(&dir, &public, &r, &me, &p, limit, json);
        });
    }
    let state = c.connectivity()?;
    partial.lock().unwrap().state = state.clone();
    if state == "portal" {
        c.r.add("sign-in", "warn", "the network wants you to sign in first (a captive portal); its sign-in page is not checked");
    } else if state == "none" || state == "limited" {
        c.r.add("internet", "skip", &format!("no internet yet ({state}): online checks skipped"));
    }
    let trusted_file = py::load_dict(Path::new(TRUSTED))?;
    let entry = if uuid.is_empty() { None } else { trusted_file.get(&uuid).cloned() };
    let (pssid, key) = c.profile(&uuid)?;
    let g = guard_state(&uuid)?;
    // the entry's own level: a home network's router stays bound to it, and only a trusted hotspot's may change, unless the
    // guard found its profile changed (its saved password)
    let own_trusted = matches!(&entry, Some(Val::Dict(e)) if matches!(e.get("level"), Some(Val::Str(l)) if l == "trusted"));
    let guard_untrusted = matches!(g.get("level"), Some(Val::Str(l)) if l == "untrusted");
    let hotspot = |mac: &str| {
        own_trusted
            && !guard_untrusted
            && level_of(entry.as_ref(), pssid.as_deref(), key.as_deref(), Some(mac)) == "trusted"
            && locally_administered(mac)
    };
    let (dev, router) = c.check_gateway(&me, &mut known, &hotspot)?;
    let mut level = level_of(entry.as_ref(), pssid.as_deref(), key.as_deref(), Some(&router));
    partial.lock().unwrap().level = level;
    c.check_trusted_name(&me, &uuid, key.as_deref().unwrap_or(""), &trusted_file);
    if guard.get("locked").is_some_and(Val::truthy) {
        c.r.add(
            "online checks",
            "skip",
            "untrusted network: all traffic is held for the VPN, so DNS, HTTPS and web pages are checked only through it",
        );
    } else if state != "none" && state != "limited" {
        c.check_dns()?;
        c.check_tls();
        c.check_http(&state);
    }
    let (gw, gdev) = c.gateway()?;
    let mut gmac = String::new();
    if gw.truthy() {
        let d = if gdev.truthy() { gdev.clone() } else { py::s("") };
        for n in c.neighbours(&d)?.iter()? {
            if py::eq(&n.get("dst", Val::None)?, &gw) {
                gmac = n.get("lladdr", py::s(""))?.upper()?;
                break;
            }
        }
    }
    let g = guard_state(&uuid)?;
    if matches!(g.get("level"), Some(Val::Str(l)) if l == "untrusted") {
        level = "untrusted"; // the guard knows more (the saved password, which only root can read): untrusted it is
        partial.lock().unwrap().level = level;
    }
    let heard = c.check_neighbourhood(&dev, level, &g, &gw, &gmac)?;
    {
        let mut p = partial.lock().unwrap();
        if p.done {
            // the watchdog writes the result and ends the program
            drop(p);
            loop {
                std::thread::sleep(Duration::from_secs(60));
            }
        }
        p.done = true; // done: the files are written whole
    }
    let time = py::utc_stamp();
    let verdict = c.r.verdict();
    let mut res = Dict::new();
    res.set("time", py::s(&time));
    res.set("ssid", py::s(&me.ssid));
    res.set("bssid", py::s(&me.bssid));
    res.set("security", py::s(&me.security));
    res.set("connectivity", py::s(&state));
    res.set("trusted", Val::Bool(level == "home"));
    res.set("level", py::s(level));
    res.set("verdict", py::s(verdict));
    res.set("checks", c.r.json());
    res.set("heard", heard);
    res.set("exposure", py::s(&exposure(verdict, &me, &g)));
    // what Heimdall's router watch follows while on this network: "trusted" means home (the watch is off only there)
    let mut cur = Dict::new();
    cur.set("time", py::s(&time));
    cur.set("ssid", py::s(&me.ssid));
    cur.set("uuid", py::s(&uuid));
    cur.set("iface", gdev);
    cur.set("gateway", gw);
    cur.set("gateway_mac", py::s(&gmac));
    cur.set("trusted", Val::Bool(level == "home"));
    cur.set("level", py::s(level));
    let tmp = c.state.join("current.json.tmp");
    py::write_text(&tmp, &py::dumps(&Val::Dict(cur), None))?;
    py::replace(&tmp, &c.state.join("current.json"))?;
    let ktmp = c.state.join("routers.json.tmp");
    py::write_text(&ktmp, &py::dumps(&Val::Dict(known), None))?;
    py::replace(&ktmp, &known_path)?;
    write_results(&c.state, &c.public, &c.r, &res)?;
    show(json, &c.r, &res);
    Ok(0)
}

/// The network's name and verdict for the desktop notification (an OSError here is ignored, as in Python).
fn write_public(public: &Path, r: &Report, res: &Dict) -> PyResult<()> {
    use std::os::unix::ffi::OsStrExt;
    let pb = public.as_os_str().as_bytes();
    py::makedirs(Path::new(std::ffi::OsStr::from_bytes(py::dirname_bytes(pb))))?;
    let mut pubd = Dict::new();
    pubd.set("time", res.get("time").cloned().unwrap_or(Val::None));
    pubd.set("ssid", res.get("ssid").cloned().unwrap_or(Val::None));
    pubd.set("verdict", res.get("verdict").cloned().unwrap_or(Val::None));
    let reasons: Vec<Val> = r.list().iter().filter(|x| x.1 == "bad" || x.1 == "warn").take(4).map(|x| py::s(&x.2)).collect();
    pubd.set("reasons", Val::List(reasons));
    pubd.set("exposure", res.get("exposure").cloned().unwrap_or(Val::None));
    let mut tb = pb.to_vec();
    tb.extend_from_slice(b".tmp");
    let tmp = PathBuf::from(std::ffi::OsStr::from_bytes(&tb));
    py::write_text(&tmp, &py::dumps(&Val::Dict(pubd), None))?;
    py::chmod(&tmp, 0o644)?;
    py::replace(&tmp, public)
}

/// The program (`args`: the words after its name).
pub fn main(args: &[String]) -> i32 {
    match check(args) {
        Ok(code) => code,
        Err(e) => py::traceback("heimdall-wifi-check", &e),
    }
}
