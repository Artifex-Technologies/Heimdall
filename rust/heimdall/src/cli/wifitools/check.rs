//! `heimdall-wifi-check` (packaging/arch/heimdall-wifi-check): is the Wi-Fi network this computer just joined safe to use?
//! Run by NetworkManager's dispatcher through heimdall-wifi-check@.service, as the heimdall account, sandboxed, on every
//! Wi-Fi connection. It reads what NetworkManager and the kernel know, looks up a few well-known names, opens a few
//! well-known pages, and listens (only) for other devices; the verdict goes to results.jsonl (Heimdall's alert),
//! current.json (the router watch) and /run/heimdall-wifi/last.json (the notification). Every step, file and tool call is
//! the Python program's.

use super::py::{self, Dict, PyErr, PyResult, Val};
use super::{addr, net};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Well-known names and the network (autonomous system) their addresses must belong to, wherever in the world one asks.
const PINNED: [(&str, &str); 4] =
    [("www.google.com", "AS15169"), ("github.com", "AS36459"), ("www.wikipedia.org", "AS14907"), ("www.cloudflare.com", "AS13335")];
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

struct Report {
    checks: Vec<(String, String, String)>,
}

impl Report {
    fn add(&mut self, name: &str, status: &str, detail: &str) {
        self.checks.push((name.into(), status.into(), detail.into()));
    }
    fn verdict(&self) -> &'static str {
        if self.checks.iter().any(|c| c.1 == "bad") {
            "unsafe"
        } else if self.checks.iter().any(|c| c.1 == "warn") {
            "caution"
        } else {
            "safe"
        }
    }
    fn json(&self) -> Val {
        Val::List(
            self.checks
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

    /// The router: one hardware address, the one seen here before; the device and the router's hardware address.
    fn check_gateway(&mut self, me: &Net, known: &mut Dict) -> PyResult<(Val, String)> {
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
            self.r.add(
                "router",
                "warn",
                &format!(
                    "the router's hardware address is different from the last time on this network ({}): it may have been replaced, or someone is imitating it",
                    me.ssid
                ),
            );
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
        let mut wrong = Vec::new();
        for ((name, asn), (_, ips)) in PINNED.iter().zip(&answers) {
            for ip in ips {
                let (got, desc) = org.iter().find(|(k, _)| k == ip).map(|(_, v)| v.clone()).unwrap_or_default();
                let private = addr::parse_v4(ip).is_some_and(addr::v4_is_private);
                if private {
                    wrong.push(format!("{name} -> {ip} (a local address)"));
                } else if !got.is_empty() && got != *asn {
                    wrong.push(format!("{name} -> {ip} ({desc})"));
                }
            }
        }
        if !wrong.is_empty() {
            let w: Vec<String> = wrong.into_iter().take(3).collect();
            self.r.add(
                "dns: well-known names",
                "bad",
                &format!("well-known sites resolve to addresses outside their own networks: {}. This is DNS spoofing", w.join("; ")),
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

    fn check_neighbourhood(&mut self, untrusted: bool) -> PyResult<()> {
        match net::listen_for_devices(8.0, || self.own_addresses())? {
            None => self.r.add("isolation", "skip", "could not listen for other devices"),
            Some(heard) if !heard.is_empty() => {
                let status = if untrusted { "warn" } else { "ok" };
                let tail = if untrusted { " (it does not announce itself here, and the firewall blocks connections in)" } else { "" };
                self.r.add(
                    "isolation",
                    status,
                    &format!(
                        "{} other device(s) heard on this network, so devices are not kept apart and they can see this computer too{tail}",
                        heard.len()
                    ),
                );
            }
            Some(_) => {
                self.r.add("isolation", "ok", "no other device heard in 8 seconds: the network may keep devices apart (or they are quiet)")
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
        Ok(())
    }
}

/// Trusted as heimdall-wifi-guard decides it: the profile was trusted, and its router (when known) is one remembered with it.
fn is_trusted(uuid: &str, mac: &str) -> PyResult<bool> {
    if uuid.is_empty() {
        return Ok(false);
    }
    let t = py::load_dict(Path::new(TRUSTED))?.get(uuid).cloned().unwrap_or(Val::None);
    if !t.truthy() {
        return Ok(false);
    }
    if mac.is_empty() {
        return Ok(false); // a router that did not answer is not trusted (as the guard decides)
    }
    t.get("routers", Val::List(Vec::new()))?.contains(&py::s(mac))
}

fn text_line(c: &(String, String, String)) -> String {
    let pad = |s: &str, w: usize| format!("{s}{}", " ".repeat(w.saturating_sub(s.chars().count())));
    format!("  {} {} {}", pad(&c.0, 22), pad(&c.1, 5), c.2)
}

fn check(args: &[String]) -> PyResult<i32> {
    let mut uuid = String::new();
    if let Some(i) = args.iter().position(|a| a == "--uuid") {
        uuid = args
            .get(i + 1)
            .map(|v| v.chars().filter(|c| c.is_ascii_digit() || ('a'..='f').contains(c) || *c == '-').collect())
            .unwrap_or_default();
    }
    let guard = py::load_dict(Path::new(GUARD_STATE))?;
    let mut c = Check {
        state: std::env::var_os("HEIMDALL_WIFI_DIR").map_or_else(|| PathBuf::from("/var/lib/heimdall/wifi"), PathBuf::from),
        public: std::env::var_os("HEIMDALL_WIFI_PUBLIC").map_or_else(|| PathBuf::from("/run/heimdall-wifi/last.json"), PathBuf::from),
        r: Report { checks: Vec::new() },
    };
    py::makedirs(&c.state)?;
    let known_path = c.state.join("routers.json");
    let mut known = py::load_dict(&known_path)?;
    let Some(me) = c.check_radio()? else {
        println!("not on Wi-Fi");
        return Ok(0);
    };
    let state = c.connectivity()?;
    if state == "portal" {
        c.r.add("sign-in", "warn", "the network wants you to sign in first (a captive portal); its sign-in page is not checked");
    } else if state == "none" || state == "limited" {
        c.r.add("internet", "skip", &format!("no internet yet ({state}): online checks skipped"));
    }
    let (_dev, router) = c.check_gateway(&me, &mut known)?;
    let trusted = is_trusted(&uuid, &router)?;
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
    c.check_neighbourhood(!trusted)?;
    let time = py::utc_stamp();
    let mut res = Dict::new();
    res.set("time", py::s(&time));
    res.set("ssid", py::s(&me.ssid));
    res.set("bssid", py::s(&me.bssid));
    res.set("security", py::s(&me.security));
    res.set("connectivity", py::s(&state));
    res.set("trusted", Val::Bool(trusted));
    res.set("verdict", py::s(c.r.verdict()));
    res.set("checks", c.r.json());
    // what Heimdall's router watch follows while on this network (untrusted networks only)
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
    let mut cur = Dict::new();
    cur.set("time", py::s(&time));
    cur.set("ssid", py::s(&me.ssid));
    cur.set("uuid", py::s(&uuid));
    cur.set("iface", gdev);
    cur.set("gateway", gw);
    cur.set("gateway_mac", py::s(&gmac));
    cur.set("trusted", Val::Bool(trusted));
    let tmp = c.state.join("current.json.tmp");
    py::write_text(&tmp, &py::dumps(&Val::Dict(cur), None))?;
    py::replace(&tmp, &c.state.join("current.json"))?;
    let ktmp = c.state.join("routers.json.tmp");
    py::write_text(&ktmp, &py::dumps(&Val::Dict(known), None))?;
    py::replace(&ktmp, &known_path)?;
    py::append_text(&c.state.join("results.jsonl"), &format!("{}\n", py::dumps(&Val::Dict(res.clone()), None)))?;
    let _ = write_public(&c, &time, &me, &res);
    if args.iter().any(|a| a == "--json") {
        println!("{}", py::dumps(&Val::Dict(res), Some(2)));
    } else {
        println!("{}: {}", me.ssid, c.r.verdict());
        for ch in &c.r.checks {
            println!("{}", text_line(ch));
        }
    }
    Ok(0)
}

/// The network's name and verdict for the desktop notification (an OSError here is ignored, as in Python).
fn write_public(c: &Check, time: &str, me: &Net, res: &Dict) -> PyResult<()> {
    use std::os::unix::ffi::OsStrExt;
    let pb = c.public.as_os_str().as_bytes();
    py::makedirs(Path::new(std::ffi::OsStr::from_bytes(py::dirname_bytes(pb))))?;
    let mut pubd = Dict::new();
    pubd.set("time", py::s(time));
    pubd.set("ssid", py::s(&me.ssid));
    pubd.set("verdict", res.get("verdict").cloned().unwrap_or(Val::None));
    let reasons: Vec<Val> = c.r.checks.iter().filter(|x| x.1 == "bad" || x.1 == "warn").take(4).map(|x| py::s(&x.2)).collect();
    pubd.set("reasons", Val::List(reasons));
    let mut tb = pb.to_vec();
    tb.extend_from_slice(b".tmp");
    let tmp = PathBuf::from(std::ffi::OsStr::from_bytes(&tb));
    py::write_text(&tmp, &py::dumps(&Val::Dict(pubd), None))?;
    py::chmod(&tmp, 0o644)?;
    py::replace(&tmp, &c.public)
}

/// The program (`args`: the words after its name).
pub fn main(args: &[String]) -> i32 {
    match check(args) {
        Ok(code) => code,
        Err(e) => py::traceback("heimdall-wifi-check", &e),
    }
}
