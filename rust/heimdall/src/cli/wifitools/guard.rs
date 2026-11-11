//! `heimdall-wifi-guard` (packaging/net/heimdall-wifi-guard): trusted and untrusted Wi-Fi networks, and the VPN with a kill
//! switch. NetworkManager's dispatcher calls `pre-up`, `up` and `down`; the owner calls `status`, `trust`, `untrust`,
//! `vpn-import`, `vpn-remove`, `sign-in`, `ruleset-check`. Every step, file and tool call is the Python program's
//! (`py.rs` carries Python's own rules where a file can hold anything).

use super::addr;
use super::py::{self, Dict, Done, PyErr, PyResult, Val};
use std::path::{Path, PathBuf};
use std::time::Duration;

const TABLE: &str = "heimdall_wifi_guard";
const VPN_NAME: &str = "Heimdall VPN";

/// The Python program's docstring, printed (with a newline) for a missing or unknown command.
pub const DOC: &str = r#"heimdall-wifi-guard: trusted and untrusted Wi-Fi networks, and the VPN with a kill switch.

A network is trusted when you said so while on it (sudo heimdall-wifi-guard trust): its NetworkManager profile and the hardware
address of its router are remembered together, so a stranger's network with the same name is not trusted. Every other network is
untrusted, and there:
  - before the connection comes up, nothing may leave this computer except the address request (DHCP) and the VPN's own traffic
    (a small nftables table of its own, beside ufw; removed when you leave the network);
  - once up, the VPN connects; if it cannot, or drops later, the Wi-Fi is disconnected (no traffic ever goes out unprotected);
  - this computer does not announce itself: Avahi is stopped while there, the profile stops sending the computer's name and uses a
    random hardware address per network from the next connection on.
With no VPN set up yet, untrusted networks are only made quiet (no lockdown, nothing dropped) and you are told.

  heimdall-wifi-guard status                    what is trusted, whether the VPN is set up, what is in force now
  heimdall-wifi-guard trust                     trust the Wi-Fi network you are on now (root)
  heimdall-wifi-guard untrust NAME              stop trusting it (root)
  heimdall-wifi-guard vpn-import FILE.conf      set up the VPN from a WireGuard file (from your Proton VPN account) (root)
  heimdall-wifi-guard vpn-remove                remove it (root)
  heimdall-wifi-guard sign-in                   on a network with a sign-in page: open it for 5 minutes, then the VPN (root)
NetworkManager's dispatcher calls the rest (pre-up, up, down, vpn-down).
"#;

/// `sys.exit(message)`: the message on standard error, exit 1.
fn exit(msg: impl Into<String>) -> PyErr {
    PyErr::new("SystemExit", msg)
}

/// A value from a file as a program's argument: Python passes only strings (and paths).
fn arg(v: &Val) -> PyResult<String> {
    match v {
        Val::Str(s) => Ok(s.clone()),
        v => Err(PyErr::type_err(format!("expected str, bytes or os.PathLike object, not {}", v.type_name()))),
    }
}

/// `re.split(r"(?<!\\):", line)`: split at every colon not right after a backslash; the escapes are left in.
pub fn split_unescaped_colons(line: &str) -> Vec<String> {
    let mut out = vec![String::new()];
    let mut prev = None;
    for c in line.chars() {
        if c == ':' && prev != Some('\\') {
            out.push(String::new());
        } else {
            out.last_mut().unwrap().push(c);
        }
        prev = Some(c);
    }
    out
}

/// Python's `re.match(r"\s*Endpoint\s*=\s*(\S+)", line, re.I)`: the value of an Endpoint line of a WireGuard file.
pub fn endpoint_value(line: &str) -> Option<&str> {
    let rest = line.trim_start_matches(py::is_space);
    // the letters of "Endpoint" as re.I matches them (Python also takes U+0130 and U+0131 for an i)
    let mut chars = rest.char_indices();
    for want in "endpoint".chars() {
        let (_, c) = chars.next()?;
        let ok = c.to_ascii_lowercase() == want || (want == 'i' && (c == '\u{130}' || c == '\u{131}'));
        if !ok {
            return None;
        }
    }
    let after = chars.next().map_or(rest.len(), |(i, _)| i);
    let rest = rest[after..].trim_start_matches(py::is_space);
    let rest = rest.strip_prefix('=')?.trim_start_matches(py::is_space);
    let end = rest.find(py::is_space).unwrap_or(rest.len());
    (end > 0).then(|| &rest[..end])
}

/// `parse_wg(text)`: the endpoints of a WireGuard file, an address of a name looked up as Python looks it up.
pub fn parse_wg(text: &str) -> PyResult<Vec<Val>> {
    let mut eps = Vec::new();
    for line in py::splitlines(text) {
        let Some(m) = endpoint_value(line) else { continue };
        let (host, port) = match m.rfind(':') {
            Some(i) => (&m[..i], &m[i + 1..]),
            None => ("", m),
        };
        let host = py::strip_chars(host, "[]");
        let ips = match addr::ip_address(&py::s(host)) {
            Ok(ip) => vec![ip.to_string()],
            Err(_) => {
                let p = py::int_str(port)?;
                let mut v = addr::getaddrinfo(host, &p, 0, libc::IPPROTO_UDP)?;
                v.sort();
                v.dedup();
                v
            }
        };
        for ip in ips {
            let p = py::int_str(port)?;
            let mut d = Dict::new();
            d.set("ip", py::s(&ip));
            d.set("port", Val::Int(p));
            eps.push(Val::Dict(d));
        }
    }
    Ok(eps)
}

/// The lockdown's nftables rules for `vpn` (outgoing traffic only; incoming stays with ufw).
pub fn ruleset(vpn: &Val) -> PyResult<String> {
    let mut allow = Vec::new();
    for ep in vpn.get("endpoints", Val::List(Vec::new()))?.iter()? {
        let ip = ep.index("ip")?;
        let port = py::int(&ep.index("port")?)?;
        let fam = if addr::ip_address(&ip)?.version() == 6 { "ip6" } else { "ip" };
        allow.push(format!("    {fam} daddr {} udp dport {port} accept", py::str_of(&ip)));
    }
    let iface = match vpn.get("iface", py::s(""))? {
        Val::Str(s) => s.chars().filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-')).collect::<String>(),
        v => return Err(PyErr::type_err(format!("expected string or bytes-like object, got '{}'", v.type_name()))),
    };
    let iface = if iface.is_empty() { "wg-heimdall".to_string() } else { iface };
    let mut lines = vec![
        format!("table inet {TABLE} {{"),
        "  chain output {".to_string(),
        "    type filter hook output priority 0; policy drop;".to_string(),
        "    oifname \"lo\" accept".to_string(),
        format!("    oifname \"{iface}\" accept"),
        "    udp dport { 67, 547 } accept".to_string(),
        "    icmpv6 type { nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert, mld2-listener-report } accept".to_string(),
    ];
    lines.extend(allow);
    lines.push("  }".into());
    lines.push("}".into());
    Ok(lines.join("\n") + "\n")
}

/// Whether a profile's cloned-mac-address setting means the real hardware address (unset, or "permanent"/"preserve").
pub fn mac_is_real(value: &str) -> bool {
    matches!(py::strip(value), "" | "permanent" | "preserve" | "--")
}

struct Guard {
    conf: PathBuf,
    trusted: PathBuf,
    run: PathBuf,
    argv: Vec<String>,
}

impl Guard {
    fn sh_t(&self, words: &[String], timeout: u64, check: bool) -> PyResult<Done> {
        let p = py::capture(words, Some(Duration::from_secs(timeout)))?;
        if check && p.code != 0 {
            let head = words[..words.len().min(3)].join(" ");
            let why = if p.stderr.is_empty() { &p.stdout } else { &p.stderr };
            return Err(PyErr::new("RuntimeError", format!("{head}: {}", py::strip(why))));
        }
        Ok(p)
    }
    fn sh(&self, words: &[&str]) -> PyResult<Done> {
        self.sh_t(&py::argv(words), 30, false)
    }
    fn out(&self, words: &[&str]) -> PyResult<String> {
        Ok(self.sh(words)?.stdout)
    }

    fn load(&self, p: &Path) -> PyResult<Dict> {
        py::load_dict(p)
    }

    fn save(&self, path: &Path, data: &Dict, mode: u32) -> PyResult<()> {
        use std::os::unix::ffi::OsStrExt;
        let pb = path.as_os_str().as_bytes();
        py::makedirs(Path::new(std::ffi::OsStr::from_bytes(py::dirname_bytes(pb))))?;
        let mut tb = pb.to_vec();
        tb.extend_from_slice(b".tmp");
        let tmp = PathBuf::from(std::ffi::OsStr::from_bytes(&tb));
        py::write_text(&tmp, &py::dumps(&Val::Dict(data.clone()), Some(1)))?;
        py::chmod(&tmp, mode)?;
        py::replace(&tmp, path)
    }

    /// For the desktop notification (heimdall-wifi-notify watches this file).
    fn note(&self, event: &str, ssid: &str, message: &str) -> PyResult<()> {
        py::makedirs(&self.run)?;
        py::chmod(&self.run, 0o755)?;
        let mut d = Dict::new();
        d.set("time", py::s(&py::utc_stamp()));
        d.set("event", py::s(event));
        d.set("ssid", py::s(ssid));
        d.set("message", py::s(message));
        self.save(&self.run.join("last.json"), &d, 0o644)
    }

    fn root(&self) -> PyResult<()> {
        if unsafe { libc::geteuid() } != 0 {
            return Err(exit(format!("this needs root: sudo heimdall-wifi-guard {}", self.argv.join(" "))));
        }
        Ok(())
    }

    /// (iface, uuid, ssid) of the active Wi-Fi connection.
    fn active_wifi(&self) -> PyResult<Option<(String, String, String)>> {
        let out = self.out(&["nmcli", "-t", "-f", "DEVICE,TYPE,STATE,CONNECTION", "device"])?;
        for line in py::splitlines(&out) {
            let f = split_unescaped_colons(line);
            if f.len() >= 4 && f[1] == "wifi" && f[2] == "connected" {
                let iface = f[0].clone();
                let uuid = py::strip(&self.out(&["nmcli", "-g", "GENERAL.CON-UUID", "device", "show", &iface])?).to_string();
                let ssid = py::strip(&self.out(&["nmcli", "-g", "802-11-wireless.ssid", "connection", "show", &uuid])?).to_string();
                return Ok(Some((iface, uuid, ssid)));
            }
        }
        Ok(None)
    }

    fn json(&self, text: &str) -> PyResult<Val> {
        let t = if text.is_empty() { "[]" } else { text };
        match py::loads(t) {
            Ok(v) => Ok(v),
            Err(py::JsonErr::Value) => Err(PyErr::value("Expecting value")),
            Err(py::JsonErr::Recursion) => Err(PyErr::new("RecursionError", "maximum recursion depth exceeded")),
        }
    }

    fn router_mac_inner(&self, iface: &str) -> PyResult<String> {
        let routes = self.json(&self.out(&["ip", "-j", "route", "show", "default", "dev", iface])?)?;
        let mut gw = None;
        for r in routes.iter()? {
            if r.get("gateway", Val::None)?.truthy() {
                gw = Some(r.index("gateway")?);
                break;
            }
        }
        let Some(gw) = gw.filter(Val::truthy) else { return Ok(String::new()) };
        let g = arg(&gw)?;
        for _ in 0..5 {
            let neigh = self.json(&self.out(&["ip", "-j", "neigh", "show", &g, "dev", iface])?)?;
            let mut mac = py::s("");
            for n in neigh.iter()? {
                if n.get("lladdr", Val::None)?.truthy() {
                    mac = n.get("lladdr", py::s(""))?;
                    break;
                }
            }
            if mac.truthy() {
                return mac.upper();
            }
            self.sh(&["ping", "-c", "1", "-W", "1", &g])?; // the router itself, to learn its hardware address
        }
        Ok(String::new())
    }

    /// The router's hardware address; "" when it cannot be read (Python's `except (ValueError, OSError)`).
    fn router_mac(&self, iface: &str) -> PyResult<String> {
        match self.router_mac_inner(iface) {
            Err(e) if e.is_os() || matches!(e.kind, "ValueError" | "UnicodeDecodeError" | "UnicodeEncodeError") => Ok(String::new()),
            r => r,
        }
    }

    fn is_wifi(&self, iface: &str) -> bool {
        Path::new(&format!("/sys/class/net/{iface}/wireless")).is_dir()
    }

    fn is_trusted(&self, uuid: &str, mac: Option<&str>) -> PyResult<bool> {
        let t = self.load(&self.trusted)?.get(uuid).cloned().unwrap_or(Val::None);
        if !t.truthy() {
            return Ok(false);
        }
        match mac {
            None | Some("") => Ok(true),
            Some(m) => t.get("routers", Val::List(Vec::new()))?.contains(&py::s(m)),
        }
    }

    // ---- the lockdown

    fn state_path(&self) -> PathBuf {
        self.run.join("state.json")
    }

    fn set_state(&self, kw: &[(&str, Val)]) -> PyResult<()> {
        py::makedirs(&self.run)?;
        py::chmod(&self.run, 0o755)?;
        let mut d = self.load(&self.state_path())?;
        for (k, v) in kw {
            d.set(k, v.clone());
        }
        self.save(&self.state_path(), &d, 0o644)
    }

    fn lock(&self, vpn: &Val) -> PyResult<()> {
        self.sh(&["nft", "delete", "table", "inet", TABLE])?;
        let rs = ruleset(vpn)?;
        let p = py::run(&py::Run {
            argv: &py::argv(&["nft", "-f", "-"]),
            env: Some(py::TOOL_ENV),
            input: Some(&rs),
            capture: true,
            timeout: None,
        })?;
        if p.code != 0 {
            return Err(PyErr::new("RuntimeError", format!("the lockdown could not be set: {}", py::strip(&p.stderr))));
        }
        self.set_state(&[("locked", Val::Bool(true))]) // Heimdall's Wi-Fi check reads this: its online tests are held too
    }

    fn unlock(&self) -> PyResult<()> {
        self.sh(&["nft", "delete", "table", "inet", TABLE])?;
        self.set_state(&[("locked", Val::Bool(false))])
    }

    fn locked(&self) -> PyResult<bool> {
        Ok(self.sh(&["nft", "list", "table", "inet", TABLE])?.code == 0)
    }

    // ---- quiet on untrusted networks

    fn quiet(&self, uuid: &str, on: bool) -> PyResult<()> {
        let mut state = self.load(&self.state_path())?;
        if on {
            if py::strip(&self.out(&["systemctl", "is-active", "avahi-daemon.service"])?) == "active" {
                state.set("avahi_was_on", Val::Bool(true));
                self.sh(&["systemctl", "stop", "avahi-daemon.socket", "avahi-daemon.service"])?;
            }
            // from the next connection on: no computer name in address requests, and not the real hardware address
            let mut args = vec!["nmcli", "connection", "modify", uuid, "ipv4.dhcp-send-hostname", "no", "ipv6.dhcp-send-hostname", "no"];
            if mac_is_real(&self.out(&["nmcli", "-g", "802-11-wireless.cloned-mac-address", "connection", "show", uuid])?) {
                args.extend(["802-11-wireless.cloned-mac-address", "stable"]);
            }
            self.sh(&args)?;
        } else if state.pop("avahi_was_on").is_some_and(|v| v.truthy()) {
            self.sh(&["systemctl", "start", "avahi-daemon.socket", "avahi-daemon.service"])?;
        }
        let kw: Vec<(&str, Val)> = state.0.iter().map(|(k, v)| (k.as_str(), v.clone())).collect();
        self.set_state(&kw)?;
        if !on {
            self.set_state(&[("avahi_was_on", Val::Bool(false))])?;
        }
        Ok(())
    }

    fn vpn(&self) -> PyResult<Val> {
        Ok(self.load(&self.conf)?.get("vpn").cloned().unwrap_or(Val::None))
    }

    fn ssid_of(&self, uuid: &str) -> PyResult<String> {
        Ok(py::strip(&self.out(&["nmcli", "-g", "802-11-wireless.ssid", "connection", "show", uuid])?).to_string())
    }

    // ---- events from NetworkManager's dispatcher

    fn pre_up(&self, iface: &str, uuid: &str) -> PyResult<()> {
        let vpn = self.vpn()?;
        if !self.is_wifi(iface) {
            return Ok(());
        }
        if self.is_trusted(uuid, None)? {
            return self.unlock();
        }
        if vpn.truthy() {
            self.lock(&vpn)?; // before any traffic: only DHCP and the VPN may leave
        }
        Ok(())
    }

    fn up(&self, iface: &str, uuid: &str) -> PyResult<()> {
        if !self.is_wifi(iface) {
            return Ok(());
        }
        let ssid = self.ssid_of(uuid)?;
        let mac = self.router_mac(iface)?;
        if self.is_trusted(uuid, Some(&mac))? {
            self.unlock()?;
            self.quiet(uuid, false)?;
            return self.set_state(&[("wifi", py::s(uuid)), ("iface", py::s(iface)), ("trusted", Val::Bool(true))]);
        }
        if self.is_trusted(uuid, None)? {
            // the profile is trusted but its router is not the one remembered: treat it as a stranger
            self.note(
                "router-changed",
                &ssid,
                "This network has the name of a trusted one, but its router is different: treating it as untrusted.",
            )?;
        }
        self.quiet(uuid, true)?;
        let vpn = self.vpn()?;
        self.set_state(&[("wifi", py::s(uuid)), ("iface", py::s(iface)), ("trusted", Val::Bool(false))])?;
        if !vpn.truthy() {
            return self.note(
                "no-vpn",
                &ssid,
                "Untrusted network: this computer is not announcing itself, but there is no VPN set up to protect traffic (heimdall-wifi-guard vpn-import).",
            );
        }
        if !self.locked()? {
            self.lock(&vpn)?;
        }
        let vu = arg(&vpn.index("uuid")?)?;
        if self.sh_t(&py::argv(&["nmcli", "connection", "up", &vu]), 45, false)?.code == 0 {
            return self.note("vpn-up", &ssid, "Untrusted network: all traffic goes through the VPN.");
        }
        self.sh(&["nmcli", "device", "disconnect", iface])?;
        self.note(
            "dropped",
            &ssid,
            "The VPN could not connect, so the Wi-Fi was disconnected (nothing went out unprotected). On a network with a sign-in page: sudo heimdall-wifi-guard sign-in.",
        )
    }

    fn down(&self, iface: &str, uuid: &str) -> PyResult<()> {
        let st = self.load(&self.state_path())?;
        let vpn = self.vpn()?;
        let sget = |k: &str| st.get(k).cloned().unwrap_or(Val::None);
        if vpn.truthy() && py::eq(&py::s(uuid), &vpn.get("uuid", Val::None)?) {
            // the VPN went down: if the untrusted Wi-Fi is still up, it goes too
            if sget("wifi").truthy() && !sget("trusted").truthy() && sget("iface").truthy() && !self.run.join("signing-in").exists() {
                let w = arg(&sget("wifi"))?;
                let ssid = self.ssid_of(&w)?;
                let i = arg(&sget("iface"))?;
                self.sh(&["nmcli", "device", "disconnect", &i])?;
                self.note("dropped", &ssid, "The VPN dropped, so the Wi-Fi was disconnected (nothing goes out unprotected).")?;
            }
            return Ok(());
        }
        if !self.is_wifi(iface) && !py::eq(&py::s(uuid), &sget("wifi")) {
            return Ok(());
        }
        if vpn.truthy() {
            let vu = arg(&vpn.index("uuid")?)?;
            self.sh(&["nmcli", "connection", "down", &vu])?;
        }
        self.unlock()?;
        self.quiet(uuid, false)?;
        self.set_state(&[("wifi", Val::None), ("iface", Val::None), ("trusted", Val::None)])
    }

    // ---- commands

    fn trust(&self) -> PyResult<()> {
        self.root()?;
        let Some((iface, uuid, ssid)) = self.active_wifi()?.filter(|w| !w.1.is_empty()) else {
            return Err(exit("not connected to Wi-Fi"));
        };
        let mac = self.router_mac(&iface)?;
        if mac.is_empty() {
            return Err(exit("the router's hardware address could not be read; try again in a moment"));
        }
        let mut t = self.load(&self.trusted)?;
        let mut fresh = Dict::new();
        fresh.set("ssid", py::s(&ssid));
        fresh.set("routers", Val::List(Vec::new()));
        let e = t.setdefault(&uuid, Val::Dict(fresh));
        let Val::Dict(e) = e else {
            let what = match e {
                Val::List(_) => "list indices must be integers or slices, not str".to_string(),
                v => format!("'{}' object does not support item assignment", v.type_name()),
            };
            return Err(PyErr::type_err(what));
        };
        e.set("ssid", py::s(&ssid));
        let routers = e.get_mut("routers").ok_or_else(|| PyErr::new("KeyError", "'routers'"))?;
        if !routers.contains(&py::s(&mac))? {
            match routers {
                Val::List(l) => l.push(py::s(&mac)),
                v => return Err(PyErr::new("AttributeError", format!("'{}' object has no attribute 'append'", v.type_name()))),
            }
        }
        self.save(&self.trusted, &t, 0o644)?;
        // at home the computer may use its own hardware address and name (routers show it, and reservations keep working)
        self.sh(&[
            "nmcli",
            "connection",
            "modify",
            &uuid,
            "802-11-wireless.cloned-mac-address",
            "permanent",
            "ipv4.dhcp-send-hostname",
            "yes",
            "ipv6.dhcp-send-hostname",
            "yes",
        ])?;
        self.unlock()?;
        self.quiet(&uuid, false)?;
        println!("trusted: {ssid} (router {mac})");
        Ok(())
    }

    fn untrust(&self, name: &str) -> PyResult<()> {
        self.root()?;
        let mut t = self.load(&self.trusted)?;
        let mut gone = Vec::new();
        for (u, e) in &t.0 {
            let ssid = e.get("ssid", Val::None)?;
            if u == name || py::eq_in(&ssid, &py::s(name)) {
                gone.push(u.clone());
            }
        }
        for u in &gone {
            t.pop(u);
        }
        self.save(&self.trusted, &t, 0o644)?;
        if gone.is_empty() {
            println!("no trusted network by that name");
        } else {
            println!("no longer trusted: {} network(s)", gone.len());
        }
        Ok(())
    }

    fn vpn_import(&self, path: &str) -> PyResult<()> {
        self.root()?;
        let b = std::fs::read(path).map_err(|e| PyErr::os(&e, path))?;
        let text = py::text(b)?;
        let endpoints = parse_wg(&text)?;
        if endpoints.is_empty() {
            return Err(exit(format!("no Endpoint in {path}: is it a WireGuard configuration?")));
        }
        let mut conf = self.load(&self.conf)?;
        if conf.get("vpn").is_some_and(Val::truthy) {
            let u = arg(&conf.get("vpn").unwrap().index("uuid")?)?;
            self.sh(&["nmcli", "connection", "delete", &u])?;
        }
        let iface = "wg-heimdall";
        let tmp = format!("/run/{iface}.conf"); // NetworkManager names the connection after the file
        write_private(Path::new(&tmp), &text)?;
        let res = self.sh_t(&py::argv(&["nmcli", "connection", "import", "type", "wireguard", "file", &tmp]), 30, true);
        std::fs::remove_file(&tmp).map_err(|e| PyErr::os(&e, &tmp))?;
        let out = res?.stdout;
        let Some(uuid) = find_uuid(&out) else {
            return Err(exit(format!("NetworkManager did not say which connection it made: {out}")));
        };
        self.sh_t(
            &py::argv(&["nmcli", "connection", "modify", &uuid, "connection.id", VPN_NAME, "connection.autoconnect", "no"]),
            30,
            true,
        )?;
        let n = endpoints.len();
        let mut v = Dict::new();
        v.set("uuid", py::s(&uuid));
        v.set("iface", py::s(iface));
        v.set("endpoints", Val::List(endpoints));
        conf.set("vpn", Val::Dict(v));
        self.save(&self.conf, &conf, 0o644)?;
        println!("VPN set up ({n} endpoint(s)). It turns on by itself on untrusted Wi-Fi; if it fails there, the Wi-Fi is disconnected.");
        Ok(())
    }

    fn vpn_remove(&self) -> PyResult<()> {
        self.root()?;
        let mut conf = self.load(&self.conf)?;
        if conf.get("vpn").is_some_and(Val::truthy) {
            let u = arg(&conf.get("vpn").unwrap().index("uuid")?)?;
            self.sh(&["nmcli", "connection", "delete", &u])?;
            conf.pop("vpn");
            self.save(&self.conf, &conf, 0o644)?;
        }
        self.unlock()?;
        println!("VPN removed; untrusted networks are now only kept quiet");
        Ok(())
    }

    fn sign_in(&self) -> PyResult<()> {
        self.root()?;
        let w = self.active_wifi()?;
        let vpn = self.vpn()?;
        let Some((iface, _, ssid)) = w.filter(|w| !w.1.is_empty() && vpn.truthy()) else {
            return Err(exit("nothing to do: not on Wi-Fi, or no VPN set up"));
        };
        let flag = self.run.join("signing-in");
        py::write_text(&flag, "")?;
        let r = self.signing_in(&vpn, &iface, &ssid);
        let _ = std::fs::remove_file(&flag);
        r
    }

    fn signing_in(&self, vpn: &Val, iface: &str, ssid: &str) -> PyResult<()> {
        self.unlock()?;
        println!("The network is open for up to 5 minutes: sign in on its page now (the browser opens it, or try http://neverssl.com).");
        let deadline = std::time::Instant::now() + Duration::from_secs(300);
        while std::time::Instant::now() < deadline {
            if py::strip(&self.out(&["nmcli", "-t", "-f", "CONNECTIVITY", "general"])?) == "full" {
                break;
            }
            std::thread::sleep(Duration::from_secs(3));
        }
        self.lock(vpn)?;
        let vu = arg(&vpn.index("uuid")?)?;
        if self.sh_t(&py::argv(&["nmcli", "connection", "up", &vu]), 45, false)?.code == 0 {
            println!("Signed in; all traffic now goes through the VPN.");
            self.note("vpn-up", ssid, "Signed in; all traffic goes through the VPN.")
        } else {
            self.sh(&["nmcli", "device", "disconnect", iface])?;
            self.note("dropped", ssid, "The VPN could not connect after signing in, so the Wi-Fi was disconnected.")?;
            println!("The VPN could not connect, so the Wi-Fi was disconnected.");
            Ok(())
        }
    }

    fn status(&self) -> PyResult<()> {
        let t = self.load(&self.trusted)?;
        let vpn = self.vpn()?;
        println!("{}", if t.0.is_empty() { "trusted networks: none" } else { "trusted networks:" });
        for (_, e) in &t.0 {
            let ssid = py::str_of(&e.get("ssid", Val::None)?);
            let routers = e.get("routers", Val::List(Vec::new()))?;
            let items = match &routers {
                Val::List(_) | Val::Dict(_) | Val::Str(_) => routers.iter()?,
                _ => return Err(PyErr::type_err("can only join an iterable")),
            };
            let mut parts = Vec::new();
            for (i, x) in items.iter().enumerate() {
                match x {
                    Val::Str(s) => parts.push(s.clone()),
                    v => return Err(PyErr::type_err(format!("sequence item {i}: expected str instance, {} found", v.type_name()))),
                }
            }
            println!("  {ssid} (router {})", parts.join(", "));
        }
        let line = if vpn.truthy() {
            format!("set up, {} endpoint(s)", vpn.index("endpoints")?.py_len()?)
        } else {
            "not set up (heimdall-wifi-guard vpn-import FILE.conf)".into()
        };
        println!("VPN: {line}");
        if let Some((_, uuid, ssid)) = self.active_wifi()?.filter(|w| !w.1.is_empty()) {
            let tr = if self.is_trusted(&uuid, None)? { "trusted" } else { "untrusted" };
            println!("now on: {ssid}, {tr}");
        }
        if unsafe { libc::geteuid() } == 0 {
            println!("lockdown: {}", if self.locked()? { "on" } else { "off" });
        }
        Ok(())
    }

    fn ruleset_check(&self, file: Option<&str>) -> PyResult<i32> {
        self.root()?;
        let endpoints = match file {
            Some(f) => {
                let b = std::fs::read(f).map_err(|e| PyErr::os(&e, f))?;
                Val::List(parse_wg(&py::text(b)?)?)
            }
            None => {
                let mut d = Dict::new();
                d.set("ip", py::s("203.0.113.5"));
                d.set("port", Val::Int("51820".into()));
                Val::List(vec![Val::Dict(d)])
            }
        };
        let mut vpn = Dict::new();
        vpn.set("endpoints", endpoints);
        vpn.set("iface", py::s("wg-heimdall"));
        let rs = ruleset(&Val::Dict(vpn))?;
        println!("{rs}");
        let p = py::run(&py::Run {
            argv: &py::argv(&["nft", "-c", "-f", "-"]),
            env: Some(py::TOOL_ENV),
            input: Some(&rs),
            capture: true,
            timeout: None,
        })?;
        println!("nft check: {}", if p.code == 0 { "ok".to_string() } else { py::strip(&p.stderr).to_string() });
        Ok(p.code)
    }
}

/// The WireGuard file for NetworkManager's import: made private (0600) before the key is written into it. (The Python
/// program before 2026-11-11 wrote the key into a file of the default mode, usually 0644, and only then made it private.)
fn write_private(p: &Path, text: &str) -> PyResult<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let ps = p.to_string_lossy();
    let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(p).map_err(|e| PyErr::os(&e, &ps))?;
    f.set_permissions(std::fs::Permissions::from_mode(0o600)).map_err(|e| PyErr::os(&e, &ps))?;
    f.write_all(text.as_bytes()).map_err(|e| PyErr::os(&e, &ps))
}

/// `re.search(r"\(([0-9a-f-]{36})\)", out)`: the connection NetworkManager made.
pub fn find_uuid(out: &str) -> Option<String> {
    let b = out.as_bytes();
    (0..b.len()).find_map(|i| {
        let ok = b[i] == b'('
            && b.get(i + 37) == Some(&b')')
            && b[i + 1..i + 37].iter().all(|&c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c) || c == b'-');
        ok.then(|| out[i + 1..i + 37].to_string())
    })
}

fn env_or(k: &str, d: &str) -> PathBuf {
    std::env::var_os(k).map(PathBuf::from).unwrap_or_else(|| PathBuf::from(d))
}

fn dispatch(g: &Guard, a: &[String]) -> PyResult<i32> {
    let Some(c) = a.first() else {
        println!("{DOC}");
        return Ok(2);
    };
    match c.as_str() {
        "pre-up" | "up" | "down" if a.len() >= 3 => {
            g.root()?;
            match c.as_str() {
                "pre-up" => g.pre_up(&a[1], &a[2])?,
                "up" => g.up(&a[1], &a[2])?,
                _ => g.down(&a[1], &a[2])?,
            }
        }
        "status" => g.status()?,
        "trust" => g.trust()?,
        "untrust" if a.len() > 1 => g.untrust(&a[1])?,
        "vpn-import" if a.len() > 1 => g.vpn_import(&a[1])?,
        "vpn-remove" => g.vpn_remove()?,
        "sign-in" => g.sign_in()?,
        "ruleset-check" => return g.ruleset_check(a.get(1).map(String::as_str)),
        _ => {
            println!("{DOC}");
            return Ok(2);
        }
    }
    Ok(0)
}

/// The program (`args`: the words after its name).
pub fn main(args: &[String]) -> i32 {
    let g = Guard {
        conf: env_or("HEIMDALL_WIFI_GUARD_CONF", "/etc/heimdall/wifi-guard.json"),
        trusted: env_or("HEIMDALL_WIFI_TRUSTED", "/etc/heimdall/wifi-trusted.json"),
        run: PathBuf::from("/run/heimdall-wifi-guard"),
        argv: args.to_vec(),
    };
    match dispatch(&g, args) {
        Ok(code) => code,
        Err(e) if e.kind == "SystemExit" => {
            eprintln!("{}", e.msg);
            1
        }
        Err(e) if e.kind == "RuntimeError" => {
            eprintln!("heimdall-wifi-guard: {}", e.msg);
            1
        }
        Err(e) => py::traceback("heimdall-wifi-guard", &e),
    }
}
