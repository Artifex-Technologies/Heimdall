//! `heimdall-wifi-guard` (packaging/net/heimdall-wifi-guard): trusted and untrusted Wi-Fi networks, and the VPN with a kill
//! switch. NetworkManager's dispatcher calls `pre-up`, `up` and `down`; the owner calls `status`, `trust`, `untrust`,
//! `vpn-import`, `vpn-remove`, `sign-in`, `ruleset-check`. Every step, file and tool call is the Python program's
//! (`py.rs` carries Python's own rules where a file can hold anything).

use super::addr;
use super::py::{self, Dict, Done, PyErr, PyResult, Val};
use std::path::{Path, PathBuf};
use std::time::Duration;

const TABLE: &str = "heimdall_wifi_guard";
/// Heimdall's quiet table on Wi-Fi (`quiet_ruleset`).
pub const QUIET: &str = "heimdall_wifi_quiet";
/// In the quiet table's comment: a table of an older Heimdall is replaced, not kept.
pub const QUIET_MARK: &str = "heimdall quiet 4";
/// The same table with its discovery traffic let out (a network the owner made discoverable).
pub const QUIET_MARK_OPEN: &str = "heimdall quiet 4 discoverable";
const VPN_NAME: &str = "Heimdall VPN";
const UFW_DEFAULT: &str = "/etc/default/ufw";
const UFW_CONF: &str = "/etc/ufw/ufw.conf";
/// The rules `ufw allow` and `ufw limit` add.
const UFW_RULES: [&str; 2] = ["/etc/ufw/user.rules", "/etc/ufw/user6.rules"];
const HEIMDALL_CONFIG: &str = "/etc/heimdall/config.json";
/// The discovery traffic the quiet table keeps in on Wi-Fi: NetBIOS (137, 138), KDE Connect (1714-1764), SSDP (1900),
/// WS-Discovery (3702), mDNS (5353), LLMNR (5355), Dropbox LAN sync (17500), Syncthing (21027), Steam (27036), Spotify Connect
/// (57621; it also answers on 5353 and 1900, HEI-70); LLMNR and KDE Connect over TCP too.
pub const DISCOVERY_UDP: &str = "137, 138, 1714-1764, 1900, 3702, 5353, 5355, 17500, 21027, 27036, 57621";
pub const DISCOVERY_TCP: &str = "1714-1764, 5355";
/// The local network: discovery traffic is held back only on its way there (multicast, broadcast, private and link-local
/// addresses), never on its way to the internet (PPTP 1723 and H.323 1719/1720 share the KDE Connect ports).
pub const LOCAL4: &str = "10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16";
pub const LOCAL6: &str = "fc00::/7, fe80::/10";
/// Seconds a connection's pre-up counts as "coming up" without its up having finished.
pub const PENDING_FOR: i64 = 120;
/// The locks a trusted network may have: a password every device must prove it knows (WPA2-Personal, WPA3-Personal).
const TRUSTABLE: [&str; 2] = ["wpa-psk", "sae"];
/// NetworkManager's names for a profile's hardware: Wi-Fi and wired (Ethernet).
const WIFI: &str = "802-11-wireless";
const WIRED: &str = "802-3-ethernet";
/// IPv6 privacy on every network but home: temporary addresses for the connections this computer makes (RFC 8981), and an
/// interface ID that is not made from the hardware address (stable-privacy, RFC 7217: one of its own on each network).
const PRIVATE_IPV6: [&str; 4] = ["ipv6.ip6-privacy", "2", "ipv6.addr-gen-mode", "stable-privacy"];
/// What the guard checks is in force on a network, and how status names it.
const PROTECTIONS: [(&str, &str); 5] = [
    ("firewall", "the firewall drops connections in"),
    ("not_announcing", "not announcing this computer"),
    ("own_address", "its own hardware address here"),
    ("no_name", "no computer name sent"),
    ("vpn", "the VPN"),
];

/// The Python program's docstring, printed (with a newline) for a missing or unknown command.
pub const DOC: &str = r#"heimdall-wifi-guard: trusted and untrusted Wi-Fi networks, and the VPN with a kill switch.

Each Wi-Fi network is untrusted, trusted or home:
  - untrusted (every network you have not marked): before the connection comes up, nothing may leave this computer except the
    address request (DHCP) and the VPN's own traffic (a small nftables table of its own, beside ufw; removed when you leave the
    network); once up, the VPN connects, and if it cannot, or drops later, the Wi-Fi is disconnected (no traffic ever goes out
    unprotected). With no VPN set up yet, untrusted networks are only made quiet (no lockdown, nothing dropped) and you are told,
    once a day per network.
  - trusted (sudo heimdall-wifi-guard trust, while on it): no more "untrusted" notices, and that is all. Every protection stays:
    the firewall, not announcing this computer, its own hardware address for the network, no computer name sent, and the VPN if
    one is set up. A trusted network is recognized by its saved profile, its name and its lock (WPA2/WPA3-Personal): only a
    device that knows the password can finish the connection, so a phone hotspot that changes its hardware address stays
    trusted. Open, Enhanced Open (OWE), WEP and enterprise networks cannot be trusted.
  - home (sudo heimdall-wifi-guard trust --home): the device list (heimdalld lan scan), discovery (Avahi), no router watch and no
    VPN. It is also bound to the router's hardware address, as trust was before the levels. --real-address also sends the
    computer's real hardware address and name there.
On every network except home, this computer does not announce itself: Avahi is stopped and Heimdall's own nftables table drops
its discovery traffic on Wi-Fi (mDNS, LLMNR, SSDP, NetBIOS, WS-Discovery, KDE Connect, Syncthing, Steam and Dropbox discovery),
the profile stops sending the computer's name and uses a hardware address of its own for the network. The same table logs (does
not allow) each device on the network itself that starts a connection, sends a packet or pings this computer over Wi-Fi, once
per device an hour: heimdalld reports it. The firewall (ufw) itself is never changed.
Wired (Ethernet) networks are untrusted too, unless made home: their profile gets the same private settings (a made-up hardware
address, no computer name, DHCP identifiers from that address, IPv6 privacy addresses). Nothing else changes on them (no
lockdown, quiet table or VPN). A home wired network is bound to its router's hardware address, since a wired profile joins
whatever network its cable is plugged into; one whose router keeps an address for this computer needs --real-address.

  heimdall-wifi-guard status                    each network's level, the VPN, what is in force now
  heimdall-wifi-guard trust                     trust the Wi-Fi network you are on now: quiet, every protection stays (root)
  heimdall-wifi-guard trust --home              make it your home network: the device list, discovery, no VPN (root);
                                                with no Wi-Fi connected (or --uuid naming it), the wired network you are on
  heimdall-wifi-guard trust --home --real-address   ... and send the real hardware address and computer name there (root)
  heimdall-wifi-guard trust --uuid UUID [--home]    the same, only if UUID is the connection that is up now (root)
  heimdall-wifi-guard untrust NAME|UUID         back to untrusted; the profile goes back to a private address and no name (root)
  heimdall-wifi-guard discoverable [on|off] [--uuid UUID]   may this computer announce itself there? (on/off: root)
  heimdall-wifi-guard kind [KIND] [--uuid UUID]  what kind of trusted network it is: home-router, mesh, phone-hotspot,
                                                travel, other (setting it: root)
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

/// A name lookup: (host, port) to addresses, Python's `socket.getaddrinfo(host, port, proto=IPPROTO_UDP)`.
pub type Resolve<'a> = &'a dyn Fn(&str, &str) -> PyResult<Vec<String>>;

/// `parse_wg(text)`: the endpoints of a WireGuard file, an address of a name looked up as Python looks it up.
pub fn parse_wg(text: &str) -> PyResult<Vec<Val>> {
    parse_wg_with(text, &|h, p| addr::getaddrinfo(h, p, 0, libc::IPPROTO_UDP))
}

/// `parse_wg` with the lookup given (the tests and fuzz targets look nothing up).
pub fn parse_wg_with(text: &str, resolve: Resolve) -> PyResult<Vec<Val>> {
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
                let mut v = resolve(host, &p)?;
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

/// Whether a profile's lock (its key management now) still lets it be trusted: a password every device must prove it knows,
/// and no weaker than when it was trusted (WPA3 recorded, WPA2 now, is a downgrade). `recorded`: the entry's key_mgmt.
pub fn lock_holds(recorded: Option<&Val>, now: &str) -> bool {
    TRUSTABLE.contains(&now) && !(matches!(recorded, Some(Val::Str(r)) if r == "sae") && now != "sae")
}

/// A network's trust level from its entry in the trusted file: "untrusted", "trusted" or "home" (the Python `level_of`, the
/// check's too). A trusted network is recognized by its saved profile, the profile's network name and its lock: NetworkManager
/// brings the profile up only after the access point proved it knows the password, so a look-alike without it never gets this
/// far, whatever its hardware address. Home is also bound to its router; a home network whose router changed (or did not
/// answer) is only trusted. An entry from before the levels (no "level") is home exactly as it was. None: not known yet.
pub fn level_of(entry: Option<&Val>, ssid: Option<&str>, key_mgmt: Option<&str>, mac: Option<&str>) -> &'static str {
    let Some(Val::Dict(e)) = entry else { return "untrusted" };
    if e.0.is_empty() {
        return "untrusted";
    }
    let level = match e.get("level") {
        None => "home",
        Some(Val::Str(l)) if l == "trusted" => "trusted",
        Some(Val::Str(l)) if l == "home" => "home",
        _ => return "untrusted",
    };
    let routers: &[Val] = match e.get("routers") {
        Some(Val::List(l)) => l,
        _ => &[],
    };
    let remembered = |m: &str| !m.is_empty() && routers.iter().any(|r| matches!(r, Val::Str(x) if x == m));
    if !e.contains_key("level") {
        if mac.is_none_or(remembered) {
            return "home";
        }
        // the router is not the remembered one: still recognized by the password, unless the profile lost its lock
        return if key_mgmt.is_some_and(|k| lock_holds(None, k)) { "trusted" } else { "untrusted" };
    }
    if let Some(s) = ssid {
        if !matches!(e.get("ssid"), Some(Val::Str(x)) if x == s) {
            return "untrusted";
        }
    }
    if let Some(k) = key_mgmt {
        if !lock_holds(e.get("key_mgmt"), k) {
            return "untrusted";
        }
    }
    if level == "home" && mac.is_some_and(|m| !remembered(m)) {
        return "trusted";
    }
    level
}

/// The lock's name as the guard and the check say it.
pub fn lock_name(key: &str) -> String {
    match key {
        "wpa-psk" => "WPA2-Personal".into(),
        "sae" => "WPA3-Personal".into(),
        "" => "open".into(),
        k => k.into(),
    }
}

/// Why a network with this lock cannot be trusted.
fn untrustable(key: &str) -> &'static str {
    match key {
        "" => "it is open: there is no password, so anyone can make a network of the same name",
        "owe" => "it is Enhanced Open (OWE): encrypted, but nobody has to know a password, so anyone can make a network of the same name",
        "none" | "ieee8021x" => "it uses WEP, which is broken",
        "wpa-eap" | "wpa-eap-suite-b-192" => "it is an enterprise network (a sign-in per person), which cannot be trusted yet",
        _ => "only networks with a password (WPA2/WPA3-Personal) can be",
    }
}

/// Heimdall's quiet table, beside ufw (never instead of it), on Wi-Fi interfaces only: its output chain drops this computer's
/// discovery traffic (`DISCOVERY_UDP`, `DISCOVERY_TCP`) on its way to the local network, or lets everything out on a network
/// made discoverable; its input chain only logs and accepts what a device on the network itself starts (a new TCP SYN, a new
/// UDP packet or a ping aimed at this computer, from a private or link-local address), once per sender an hour, the router
/// (`router4`) once per connection; ufw's own chains still decide. Loaded and replaced in one transaction.
pub fn quiet_ruleset(discoverable: bool) -> String {
    let log = "log prefix \"heimdall-wifi-in: \" level info";
    let mut lines: Vec<String> = vec![
        format!("table inet {QUIET} {{}}"),
        format!("delete table inet {QUIET}"),
        format!("table inet {QUIET} {{"),
        format!("  comment \"{}\"", if discoverable { QUIET_MARK_OPEN } else { QUIET_MARK }),
        "  set seen4 { type ipv4_addr; flags dynamic, timeout; timeout 1h; size 16384; }".into(),
        "  set seen6 { type ipv6_addr; flags dynamic, timeout; timeout 1h; size 16384; }".into(),
        "  set router4 { type ipv4_addr; size 16; }".into(),
        "  chain in {".into(),
        "    type filter hook input priority -10; policy accept;".into(),
        "    iifname != \"wl*\" accept".into(),
        "    ct state != new accept".into(),
        "    fib daddr type != local accept".into(),
        format!("    ip saddr != {{ {LOCAL4} }} accept"),
        format!("    ip6 saddr != {{ {LOCAL6} }} accept"),
        "    meta l4proto != { tcp, udp, icmp, ipv6-icmp } accept".into(),
        "    tcp flags & (syn | ack) != syn accept".into(),
        "    icmp type != echo-request accept".into(),
        "    icmpv6 type != echo-request accept".into(),
        "    udp dport { 68, 546 } accept".into(),
        "    ip saddr @seen4 accept".into(),
        "    ip6 saddr @seen6 accept".into(),
        "    ip saddr @router4 limit rate 30/minute log prefix \"heimdall-wifi-in-router: \" level info add @seen4 { ip saddr timeout 7d } accept".into(),
        "    ip saddr @router4 accept".into(),
        format!("    meta nfproto ipv4 limit rate 30/minute {log} add @seen4 {{ ip saddr }}"),
        format!("    meta nfproto ipv6 limit rate 30/minute {log} add @seen6 {{ ip6 saddr }}"),
        "  }".into(),
        "  chain out {".into(),
        "    type filter hook output priority 0; policy accept;".into(),
        "    oifname != \"wl*\" accept".into(),
    ];
    if !discoverable {
        lines.extend([
            format!("    ip daddr != {{ {LOCAL4}, 224.0.0.0/4, 255.255.255.255 }} accept"),
            format!("    ip6 daddr != {{ {LOCAL6}, ff00::/8 }} accept"),
            format!("    udp dport {{ {DISCOVERY_UDP} }} counter drop"),
            format!("    udp sport {{ {DISCOVERY_UDP} }} counter drop"),
            format!("    tcp dport {{ {DISCOVERY_TCP} }} counter drop"),
        ]);
    }
    lines.extend(["  }".to_string(), "}".to_string()]);
    lines.join("\n") + "\n"
}

/// Whether a ufw rule's ports ("22", "80,443", "6000:6007", "any") take in `port`.
pub fn port_in(spec: &str, port: &str) -> bool {
    if spec == "any" {
        return true;
    }
    let num = |s: &str| (!s.is_empty() && s.len() < 6 && s.bytes().all(|b| b.is_ascii_digit())).then(|| s.parse::<u32>().unwrap());
    let Some(p) = num(port) else { return false };
    spec.split(',').any(|part| {
        let (lo, hi) = part.split_once(':').unwrap_or((part, ""));
        let hi = if hi.is_empty() { lo } else { hi };
        matches!((num(lo), num(hi)), (Some(a), Some(b)) if a <= p && p <= b)
    })
}

/// The (protocol, ports) of ufw's own rules that let connections in from the network, on every interface or a Wi-Fi one: the
/// `### tuple ###` lines of user.rules and user6.rules, read as ufw's backend reads them (a comment comes off first; logged
/// actions allow_log, limit_log...; application rules have two fields more; no direction is incoming; route: rules are not ours).
pub fn ufw_in_rules(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in py::splitlines(text) {
        let Some(rest) = line.strip_prefix("### tuple ### ") else { continue };
        let rest = match rest.find(" comment=") {
            Some(i) => &rest[..i],
            None => rest,
        };
        let f = py::split_ws(rest);
        if !(6..=9).contains(&f.len()) || !matches!(f[0].split('_').next(), Some("allow" | "limit")) {
            continue;
        }
        let direction = if f.len() == 6 || f.len() == 8 { "in" } else { f[f.len() - 1] };
        if direction == "in" || direction.starts_with("in_wl") {
            out.push((f[1].to_string(), f[2].to_string()));
        }
    }
    out
}

/// The services listening here ("tcp/22") that one of ufw's own rules lets in from the network.
pub fn ufw_allowed(services: &[String], rules: &[(String, String)]) -> Vec<String> {
    services
        .iter()
        .filter(|s| {
            let (proto, port) = s.split_once('/').unwrap_or((s, ""));
            rules.iter().any(|(rp, ports)| (rp == "any" || rp == proto) && port_in(ports, port))
        })
        .cloned()
        .collect()
}

/// The connection whose pre-up ran and whose up has not finished yet ("" for none); a mark older than `PENDING_FOR`
/// seconds does not count (Python's `pending`).
pub fn pending(st: &Dict) -> String {
    match (st.get("pending"), st.get("pending_at")) {
        (Some(Val::Str(u)), Some(Val::Str(at)))
            if !u.is_empty()
                && py::utc_stamp_ago(PENDING_FOR).as_str() <= at.as_str()
                && at.as_str() <= py::utc_stamp_ago(-60).as_str() =>
        {
            u.clone()
        }
        _ => String::new(),
    }
}

/// KEY=value from a shell-style settings file (/etc/default/ufw, /etc/ufw/ufw.conf), "" when it is not there or not text.
pub fn conf_value_in(text: &str, key: &str) -> String {
    let mut value = String::new();
    for line in py::splitlines(text) {
        let (k, v) = line.split_once('=').unwrap_or((line, ""));
        if py::strip(k) == key {
            value = py::strip(py::strip_chars(py::strip(v), "\"")).to_string();
        }
    }
    value
}

fn conf_value(path: &str, key: &str) -> String {
    match std::fs::read(path).map(py::text) {
        Ok(Ok(text)) => conf_value_in(&text, key),
        _ => String::new(),
    }
}

/// The discovery packets the quiet table held back, as status says it ("off" without the table).
pub fn counters_text(code: i32, out: &str) -> String {
    if code == 0 && out.contains(&format!("\"{QUIET_MARK_OPEN}\"")) {
        return "on, discoverable here: discovery traffic is let out".into();
    }
    if code != 0 || !out.contains(&format!("\"{QUIET_MARK}\"")) {
        return "off".into();
    }
    let mut n: u128 = 0;
    for word in out.split("counter packets ").skip(1) {
        let digits = word.split(' ').next().unwrap_or("");
        if !digits.is_empty() && digits.len() < 20 && digits.bytes().all(|b| b.is_ascii_digit()) {
            n += digits.parse::<u128>().unwrap_or(0);
        }
    }
    format!("on, {n} discovery packet(s) held back since it was loaded")
}

/// What a network can still see of this computer, in a line (p: the protections in force).
fn exposure(p: &Dict) -> String {
    let disc = matches!(p.get("discoverable"), Some(Val::Bool(true)));
    let seen =
        format!("that this computer is there{}", if disc { ", its name and the services it announces (discoverable here)" } else { "" });
    if p.get("vpn").is_some_and(Val::truthy) {
        format!("{seen} and how much it sends; the VPN hides where it goes")
    } else {
        format!("{seen}, the names of the sites it visits (DNS is not encrypted) and how much it sends; a VPN would hide the last two")
    }
}

/// The kinds of trusted network the owner may set (`kind`); none set is a home router.
pub const KINDS: [&str; 5] = ["home-router", "mesh", "phone-hotspot", "travel", "other"];

/// What kind of network a trusted one is, as the owner set it ("kind" in its entry); none set is a home router.
pub fn kind_of(entry: Option<&Val>) -> &'static str {
    match entry {
        Some(Val::Dict(e)) => match e.get("kind") {
            Some(Val::Str(k)) => KINDS.iter().find(|x| **x == k.as_str()).copied().unwrap_or("home-router"),
            _ => "home-router",
        },
        _ => "home-router",
    }
}

/// Whether the owner let this computer announce itself on the network of this entry (its "discoverable", for the network
/// named in it). Home always is.
pub fn discoverable_of(entry: Option<&Val>, ssid: &str) -> bool {
    matches!(entry, Some(Val::Dict(e)) if matches!(e.get("discoverable"), Some(Val::Bool(true))) && matches!(e.get("ssid"), Some(Val::Str(x)) if x == ssid))
}

struct Guard {
    conf: PathBuf,
    trusted: PathBuf,
    /// root's only (0600): a fingerprint of each trusted profile's saved password
    keys: PathBuf,
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
    /// `sh(argv, input=text)`.
    fn sh_in(&self, words: &[&str], input: &str) -> PyResult<Done> {
        py::run(&py::Run {
            argv: &py::argv(words),
            env: Some(py::TOOL_ENV),
            input: Some(input),
            capture: true,
            timeout: Some(Duration::from_secs(30)),
        })
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
        // made with its mode from the start (the keys file is root's only), also over a file left there before
        write_with_mode(&tmp, &py::dumps(&Val::Dict(data.clone()), Some(1)), mode)?;
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

    /// (iface, uuid, name) of the first connected wired (Ethernet) connection.
    fn active_wired(&self) -> PyResult<Option<(String, String, String)>> {
        let out = self.out(&["nmcli", "-t", "-f", "DEVICE,TYPE,STATE,CONNECTION", "device"])?;
        for line in py::splitlines(&out) {
            let f = split_unescaped_colons(line);
            if f.len() >= 4 && f[1] == "ethernet" && f[2] == "connected" {
                let iface = f[0].clone();
                let uuid = py::strip(&self.out(&["nmcli", "-g", "GENERAL.CON-UUID", "device", "show", &iface])?).to_string();
                let name = self.profile_name(&uuid)?;
                return Ok(Some((iface, uuid, name)));
            }
        }
        Ok(None)
    }

    /// A profile's name as NetworkManager shows it ("Wired connection 1"): what a wired network is called here.
    fn profile_name(&self, uuid: &str) -> PyResult<String> {
        Ok(py::strip(&self.out(&["nmcli", "-g", "connection.id", "connection", "show", uuid])?).to_string())
    }

    /// A profile's kind: "802-3-ethernet" (wired), "802-11-wireless", "wireguard", "vpn", "bridge"...
    fn connection_type(&self, uuid: &str) -> PyResult<String> {
        Ok(py::strip(&self.out(&["nmcli", "-g", "connection.type", "connection", "show", uuid])?).to_string())
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

    /// Whether `iface` is a phone's USB link that cannot take an address of its own: an iPhone's (the ipheth driver), whose address
    /// comes from the phone. NetworkManager's made-up address made that connection fail (2026-11-22). Nothing on that link but
    /// the phone sees the address, and the phone puts everything behind its own, so it keeps it; the rest of the private profile
    /// stays.
    fn phone_link(&self, iface: &str) -> bool {
        !iface.is_empty()
            && std::fs::read_link(format!("/sys/class/net/{iface}/device/driver"))
                .ok()
                .and_then(|p| p.file_name().map(|n| n == "ipheth"))
                .unwrap_or(false)
    }

    fn is_wifi(&self, iface: &str) -> bool {
        Path::new(&format!("/sys/class/net/{iface}/wireless")).is_dir()
    }

    /// The entry of a profile in the trusted file (None when it has none).
    fn entry(&self, uuid: &str) -> PyResult<Option<Val>> {
        Ok(self.load(&self.trusted)?.get(uuid).cloned())
    }

    /// The profile's key management: "wpa-psk", "sae", "owe", "none" (WEP), "wpa-eap"..., or "" (open).
    fn profile_key(&self, uuid: &str) -> PyResult<String> {
        Ok(py::strip(&self.out(&["nmcli", "-g", "802-11-wireless-security.key-mgmt", "connection", "show", uuid])?).to_string())
    }

    /// A fingerprint of the profile's saved password (only root can read it), for the root-only keys file; "" when
    /// NetworkManager keeps no password for the system (one in the desktop's keyring), and then nothing is compared.
    fn psk_pin(&self, uuid: &str) -> PyResult<String> {
        let out = self.out(&["nmcli", "-s", "-g", "802-11-wireless-security.psk", "connection", "show", uuid])?;
        let psk = py::strip(&out);
        Ok(if psk.is_empty() { String::new() } else { super::sha256_hex(&format!("heimdall wifi psk\n{uuid}\n{psk}")) })
    }

    /// Whether a trusted profile still has the password it had when it was trusted (none kept: nothing to compare).
    fn pin_holds(&self, uuid: &str) -> PyResult<bool> {
        match self.load(&self.keys)?.get(uuid) {
            Some(Val::Str(want)) if !want.is_empty() => Ok(self.psk_pin(uuid)? == *want),
            _ => Ok(true),
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

    // ---- quiet on every network but home

    /// From the next connection on: no computer name in address requests, DHCP identifiers made from the hardware address in
    /// use (the client ID and DHCPv6's DUID, not the machine-wide ones), no LLMNR or mDNS answers by the resolver, and not the
    /// real hardware address (one of its own for this network: locally administered, the mask that could keep a maker's prefix
    /// cleared); an address chosen in Settings is kept. Then IPv6 privacy addresses in a call of their own (a profile
    /// NetworkManager refuses them for keeps the rest). `wired`: an Ethernet profile.
    fn private_profile(&self, uuid: &str, wired: bool, iface: Option<&str>) -> PyResult<()> {
        let dev = if wired { WIRED } else { WIFI };
        let (cloned, mask) = (format!("{dev}.cloned-mac-address"), format!("{dev}.generate-mac-address-mask"));
        let mut args = vec![
            "nmcli",
            "connection",
            "modify",
            uuid,
            "ipv4.dhcp-send-hostname",
            "no",
            "ipv6.dhcp-send-hostname",
            "no",
            "ipv4.dhcp-client-id",
            "mac",
            "ipv6.dhcp-duid",
            "ll",
            "connection.llmnr",
            "no",
            "connection.mdns",
            "no",
        ];
        let iface = match iface {
            Some(i) => i.to_string(),
            None if wired => self.out(&["nmcli", "-g", "connection.interface-name", "connection", "show", uuid])?.trim().to_string(),
            None => String::new(),
        };
        // an iPhone's USB link keeps the address the phone gave it (`phone_link`)
        if !(wired && self.phone_link(&iface)) && mac_is_real(&self.out(&["nmcli", "-g", &cloned, "connection", "show", uuid])?) {
            args.extend([cloned.as_str(), "stable", mask.as_str(), ""]);
        }
        self.sh(&args)?;
        let mut v6 = vec!["nmcli", "connection", "modify", uuid];
        v6.extend(PRIVATE_IPV6);
        self.sh(&v6).map(|_| ())
    }

    /// Whether this version of the quiet table is in place, as asked: muting discovery, or letting it out (discoverable).
    fn quiet_loaded(&self, discoverable: bool) -> PyResult<bool> {
        let p = self.sh(&["nft", "list", "table", "inet", QUIET])?;
        let mark = if discoverable { QUIET_MARK_OPEN } else { QUIET_MARK };
        Ok(p.code == 0 && p.stdout.contains(&format!("\"{mark}\"")))
    }

    /// Load the quiet table (unless this version of it is in place), or remove it (home only).
    fn quiet_table(&self, on: bool, discoverable: bool) -> PyResult<bool> {
        if !on {
            self.sh(&["nft", "delete", "table", "inet", QUIET])?;
            return Ok(true);
        }
        if self.quiet_loaded(discoverable)? {
            return Ok(true);
        }
        Ok(self.sh_in(&["nft", "-f", "-"], &quiet_ruleset(discoverable))?.code == 0)
    }

    /// This connection's router (its IPv4 gateway) for the quiet table: reported once per connection, not once an hour.
    /// What the table remembers of the last network goes first (it stays from one network to the next): its router and the
    /// senders it saw, so the last router's week-long entry never hides a device of this network that has its address.
    fn quiet_router(&self, iface: &str) -> PyResult<()> {
        self.sh(&["nft", "flush", "set", "inet", QUIET, "router4"])?;
        self.sh(&["nft", "flush", "set", "inet", QUIET, "seen4"])?;
        let routes = match self.json(&self.out(&["ip", "-j", "route", "show", "default", "dev", iface])?) {
            Ok(v) => v,
            Err(e) if e.kind == "ValueError" => return Ok(()),
            Err(e) => return Err(e),
        };
        let gw = match &routes {
            Val::List(l) => l.iter().find_map(|r| match r {
                Val::Dict(d) if d.get("gateway").is_some_and(Val::truthy) => d.get("gateway").cloned(),
                _ => None,
            }),
            _ => None,
        };
        let Some(Val::Str(gw)) = gw else { return Ok(()) };
        if !matches!(addr::ip_address(&py::s(&gw)), Ok(ip) if ip.version() == 4) {
            return Ok(());
        }
        self.sh(&["nft", "add", "element", "inet", QUIET, "router4", &format!("{{ {gw} }}")])?;
        Ok(())
    }

    /// Whether ufw is on and drops (or refuses) incoming connections by default; Heimdall never changes ufw.
    fn ufw_drops(&self) -> PyResult<bool> {
        if py::strip(&self.out(&["systemctl", "is-active", "ufw"])?) != "active" {
            return Ok(false);
        }
        if conf_value(UFW_CONF, "ENABLED").to_lowercase() != "yes" {
            return Ok(false);
        }
        Ok(matches!(py::upper(&conf_value(UFW_DEFAULT, "DEFAULT_INPUT_POLICY")).as_str(), "DROP" | "REJECT"))
    }

    /// Whether the interface uses a hardware address other than its own (ip names the real one, permaddr, only then).
    fn own_address(&self, iface: &str) -> PyResult<bool> {
        let value = |e: &PyErr| matches!(e.kind, "ValueError" | "UnicodeDecodeError" | "UnicodeEncodeError");
        let text = match self.out(&["ip", "-j", "link", "show", "dev", iface]) {
            Ok(t) => t,
            Err(e) if value(&e) => return Ok(false),
            Err(e) => return Err(e),
        };
        let links = match self.json(&text) {
            Ok(v) => v,
            Err(e) if value(&e) => return Ok(false),
            Err(e) => return Err(e),
        };
        Ok(match links {
            Val::List(l) => l.iter().any(|n| matches!(n, Val::Dict(d) if d.get("permaddr").is_some_and(Val::truthy))),
            _ => false,
        })
    }

    /// This computer's services listening beyond itself (`ss -tulnH`, as the check reads it); none when ss is missing.
    fn listening_services(&self) -> PyResult<Vec<String>> {
        match self.sh(&["ss", "-tulnH"]) {
            Ok(p) => Ok(super::check::listening_services(&p.stdout)),
            Err(e) if e.is_os() => Ok(Vec::new()),
            Err(e) => Err(e),
        }
    }

    /// The services listening here that one of ufw's own rules lets in (Heimdall only reads ufw's rules).
    fn ufw_allowed(&self, services: &[String]) -> Vec<String> {
        let mut rules = Vec::new();
        for path in UFW_RULES {
            if let Ok(Ok(text)) = std::fs::read(path).map(py::text) {
                rules.extend(ufw_in_rules(&text));
            }
        }
        ufw_allowed(services, &rules)
    }

    /// What is in force on this network now, as checked (heimdall-wifi-check reads it from state.json): the firewall only
    /// when no service listening here is let in by one of its rules (allowed_in names them); not announcing is the quiet table.
    fn protections(&self, iface: &str, uuid: &str, vpn_up: bool, discoverable: bool) -> PyResult<Dict> {
        let services = self.listening_services()?;
        let allowed = self.ufw_allowed(&services);
        let firewall = self.ufw_drops()? && allowed.is_empty();
        let not_announcing = iface.starts_with("wl") && !discoverable && self.quiet_loaded(false)?;
        let own = self.own_address(iface)?;
        let no_name = py::strip(&self.out(&["nmcli", "-g", "ipv4.dhcp-send-hostname", "connection", "show", uuid])?) == "no";
        let mut d = Dict::new();
        d.set("firewall", Val::Bool(firewall));
        d.set("allowed_in", Val::List(allowed.iter().map(|a| py::s(a)).collect()));
        d.set("not_announcing", Val::Bool(not_announcing));
        d.set("discoverable", Val::Bool(discoverable));
        d.set("own_address", Val::Bool(own));
        d.set("no_name", Val::Bool(no_name));
        d.set("vpn", Val::Bool(vpn_up));
        Ok(d)
    }

    /// on: the private profile, and not announcing (Avahi stopped, remembered) unless the network was made discoverable; off
    /// (home, or no Wi-Fi any more): Avahi back if it ran.
    fn quiet(&self, uuid: &str, on: bool, discoverable: bool) -> PyResult<()> {
        let mut state = self.load(&self.state_path())?;
        let mute = on && !discoverable;
        if mute {
            if py::strip(&self.out(&["systemctl", "is-active", "avahi-daemon.service"])?) == "active" {
                state.set("avahi_was_on", Val::Bool(true));
                self.sh(&["systemctl", "stop", "avahi-daemon.socket", "avahi-daemon.service"])?;
            }
        } else if state.pop("avahi_was_on").is_some_and(|v| v.truthy()) {
            self.sh(&["systemctl", "start", "avahi-daemon.socket", "avahi-daemon.service"])?;
        }
        if on {
            self.private_profile(uuid, false, None)?;
        }
        let kw: Vec<(&str, Val)> = state.0.iter().map(|(k, v)| (k.as_str(), v.clone())).collect();
        self.set_state(&kw)?;
        if !mute {
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

    /// A note that would say the same thing on every connection: at most once a day (UTC) for each network.
    fn note_daily(&self, event: &str, uuid: &str, ssid: &str, message: &str) -> PyResult<()> {
        let path = self.run.join("notes.json");
        let mut seen = self.load(&path)?;
        let key = format!("{event} {uuid}");
        let stamp = py::utc_stamp();
        if let Some(Val::Str(last)) = seen.get(&key) {
            if py::prefix(last, 10) == py::prefix(&stamp, 10) {
                return Ok(());
            }
        }
        seen.set(&key, py::s(&stamp));
        self.save(&path, &seen, 0o644)?;
        self.note(event, ssid, message)
    }

    fn pre_up(&self, iface: &str, uuid: &str) -> PyResult<()> {
        let vpn = self.vpn()?;
        if !self.is_wifi(iface) {
            return Ok(());
        }
        self.set_state(&[("pending", py::s(uuid)), ("pending_at", py::s(&py::utc_stamp()))])?; // coming up: see pending()
        if level_of(self.entry(uuid)?.as_ref(), None, None, None) == "home" && self.pin_holds(uuid)? {
            return self.unlock();
        }
        self.quiet_table(true, false)?; // before any traffic: this computer's discovery traffic stays in
        if vpn.truthy() {
            self.lock(&vpn)?; // before any traffic: only DHCP and the VPN may leave
        }
        Ok(())
    }

    /// A wired connection came up: every wired network but home gets the private profile from the next connection on (nothing
    /// else: the lockdown, the VPN, the quiet table and the state are Wi-Fi's). Home is bound to its router: on another router
    /// the profile goes back to private, and if it used the real address there it says so. Told once a day, only while the real
    /// address is in use.
    fn wired_up(&self, iface: &str, uuid: &str) -> PyResult<()> {
        let entry = self.entry(uuid)?;
        let name = self.profile_name(uuid)?;
        let home = matches!(&entry, Some(Val::Dict(d)) if matches!(d.get("wired"), Some(Val::Bool(true)))
            && py::eq(d.get("level").unwrap_or(&Val::None), &py::s("home")));
        if home {
            let mac = self.router_mac(iface)?;
            if mac.is_empty() || level_of(entry.as_ref(), None, None, Some(&mac)) == "home" {
                return Ok(()); // home, or its router did not answer: left as it is
            }
            let real = !self.phone_link(iface) && !self.own_address(iface)?;
            self.private_profile(uuid, true, Some(iface))?;
            if real {
                self.note(
                    "wired",
                    &name,
                    "This is your home network's wired profile, but the router is a different one: this computer used its real hardware address and name here. From the next connection on it uses one of its own; back home: sudo heimdall-wifi-guard trust --home --real-address",
                )?;
            }
            return Ok(());
        }
        let real = !self.phone_link(iface) && !self.own_address(iface)?;
        self.private_profile(uuid, true, Some(iface))?;
        if real {
            self.note_daily(
                "wired",
                uuid,
                &name,
                "Untrusted wired network: from the next connection on, this computer uses a hardware address of its own here and sends no name. Your home network, where the router keeps an address for this computer? sudo heimdall-wifi-guard trust --home --real-address",
            )?;
        }
        Ok(())
    }

    fn up(&self, iface: &str, uuid: &str) -> PyResult<()> {
        if !self.is_wifi(iface) {
            if self.connection_type(uuid)? == WIRED {
                self.wired_up(iface, uuid)?;
            }
            return Ok(());
        }
        let ssid = self.ssid_of(uuid)?;
        let key = self.profile_key(uuid)?;
        let mac = self.router_mac(iface)?;
        let entry = self.entry(uuid)?;
        let mut level = level_of(entry.as_ref(), Some(&ssid), Some(&key), Some(&mac));
        // the profile's password is not the one trusted
        let repinned = level != "untrusted" && !self.pin_holds(uuid)?;
        if repinned {
            level = "untrusted";
        }
        if level == "home" {
            self.unlock()?;
            self.quiet_table(false, false)?;
            self.quiet(uuid, false, false)?;
            let p = self.protections(iface, uuid, false, true)?;
            return self.set_state(&[
                ("wifi", py::s(uuid)),
                ("iface", py::s(iface)),
                ("trusted", Val::Bool(true)),
                ("level", py::s("home")),
                ("protections", Val::Dict(p)),
                ("pending", Val::None),
            ]);
        }
        let named = level_of(entry.as_ref(), None, None, None);
        // the one note of this connection (notify shows the last one written): why the level is not the entry's
        let told = named != level;
        if named == "home" && level == "trusted" {
            // a phone hotspot trusted before the levels gets this after each restart: once a day is enough
            self.note_daily(
                "router-changed",
                uuid,
                &ssid,
                "Your home network's router is different (or did not answer). It is still recognized by its password, so it stays trusted, but the device list is paused and this computer stays private here. If it is a phone hotspot (they change their address when they restart): sudo heimdall-wifi-guard trust. If you replaced the router: sudo heimdall-wifi-guard trust --home",
            )?;
        } else if named != "untrusted" && level == "untrusted" {
            let named_as = "This network has the name of a trusted one, but ";
            let again = ". If you changed it yourself: sudo heimdall-wifi-guard trust";
            let e = match &entry {
                Some(Val::Dict(e)) => e.clone(),
                _ => Dict::new(),
            };
            let why = if repinned {
                format!("{named_as}its saved password changed since you trusted it: treating it as untrusted{again}")
            } else if !e.contains_key("level") {
                // an entry from before the levels: bound to its router
                let r = if mac.is_empty() { "its router did not answer" } else { "its router is different" };
                format!("{named_as}{r}: treating it as untrusted.")
            } else if !py::eq(e.get("ssid").unwrap_or(&Val::None), &py::s(&ssid)) {
                format!("The saved profile of a trusted network now names another network ({ssid}): treating it as untrusted{again}")
            } else {
                format!("{named_as}not its lock ({} now): treating it as untrusted.", lock_name(&key))
            };
            self.note("router-changed", &ssid, &why)?;
        }
        // discoverable: the owner let this computer announce itself here (not on a trusted profile found changed: told above)
        let disc = discoverable_of(entry.as_ref(), &ssid) && !(named != "untrusted" && level == "untrusted");
        self.quiet_table(true, disc)?;
        self.quiet(uuid, true, disc)?;
        self.quiet_router(iface)?;
        let vpn = self.vpn()?;
        let mut p = self.protections(iface, uuid, false, disc)?;
        self.set_state(&[
            ("wifi", py::s(uuid)),
            ("iface", py::s(iface)),
            ("trusted", Val::Bool(false)),
            ("level", py::s(level)),
            ("protections", Val::Dict(p.clone())),
            ("pending", Val::None),
        ])?;
        if !vpn.truthy() {
            if level == "untrusted" && !told {
                let quiet = if disc { "" } else { "this computer is not announcing itself, but " };
                self.note(
                    "no-vpn",
                    &ssid,
                    &format!("Untrusted network: {quiet}there is no VPN set up to protect traffic (heimdall-wifi-guard vpn-import)."),
                )?;
            }
            return Ok(());
        }
        if !self.locked()? {
            self.lock(&vpn)?;
        }
        let vu = arg(&vpn.index("uuid")?)?;
        if self.sh_t(&py::argv(&["nmcli", "connection", "up", &vu]), 45, false)?.code == 0 {
            p.set("vpn", Val::Bool(true));
            self.set_state(&[("protections", Val::Dict(p))])?;
            if level == "untrusted" && !told {
                self.note("vpn-up", &ssid, "Untrusted network: all traffic goes through the VPN.")?;
            }
            return Ok(());
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
            // the VPN went down: if the Wi-Fi it protected (any network but home) is still up, it goes too
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
        // NetworkManager does not wait for this job: it can run after the next connection's pre-up or up. That connection keeps
        // its state, its lockdown and its VPN: it is another one in the state, or it is coming up, or this interface is
        // connected again.
        let w = sget("wifi");
        if !(py::eq(&w, &Val::None) || py::eq(&w, &py::s(uuid))) || !pending(&st).is_empty() {
            return Ok(());
        }
        let now = self.active_wifi()?.filter(|w| !w.1.is_empty());
        if now.as_ref().is_some_and(|(i, _, _)| i == iface) {
            return Ok(());
        }
        if vpn.truthy() {
            let vu = arg(&vpn.index("uuid")?)?;
            self.sh(&["nmcli", "connection", "down", &vu])?;
        }
        self.unlock()?;
        // the quiet table stays, for the next network; Avahi comes back only when no Wi-Fi is connected any more
        if now.is_none() {
            self.quiet(uuid, false, false)?;
        }
        self.set_state(&[
            ("wifi", Val::None),
            ("iface", Val::None),
            ("trusted", Val::None),
            ("level", Val::None),
            ("protections", Val::None),
        ])
    }

    // ---- commands

    /// Trust the Wi-Fi network this computer is on (root): trusted keeps every protection and only stops the notices; --home
    /// is the separate choice to open up (the device list, discovery, no VPN).
    fn trust(&self, args: &[String]) -> PyResult<()> {
        self.root()?;
        let has = |w: &str| args.iter().any(|a| a == w);
        let (home, real) = (has("--home"), has("--real-address"));
        let mut want = None;
        let mut i = 0;
        while i < args.len() {
            if args[i] == "--uuid" {
                want = Some(args.get(i + 1).cloned().unwrap_or_default());
                i += 2;
                continue;
            }
            if args[i] != "--home" && args[i] != "--real-address" {
                return Err(exit(format!(
                    "trust: unknown option {} (trust [--home [--real-address]] [--uuid UUID]): nothing changed",
                    py::repr_str(&args[i])
                )));
            }
            i += 1;
        }
        if real && !home {
            return Err(exit("--real-address is for a home network: heimdall-wifi-guard trust --home --real-address"));
        }
        let (mut iface, mut uuid, mut ssid) = self.active_wifi()?.unwrap_or_default();
        let mut wired = false;
        if uuid.is_empty() || want.as_ref().is_some_and(|w| *w != uuid) {
            if let Some((wi, wu, wn)) = self.active_wired()? {
                if !wu.is_empty() && (uuid.is_empty() || want.as_ref() == Some(&wu)) {
                    (iface, uuid, ssid, wired) = (wi, wu, wn, true);
                }
            }
        }
        if uuid.is_empty() {
            return Err(exit("not connected to Wi-Fi or a wired network"));
        }
        if want.is_some_and(|w| w != uuid) {
            return Err(exit("the network connected now is not the one asked for: nothing changed"));
        }
        if wired {
            return self.trust_wired(&iface, &uuid, &ssid, home, real);
        }
        let key = self.profile_key(&uuid)?;
        if !TRUSTABLE.contains(&key.as_str()) {
            return Err(exit(format!("{ssid} cannot be trusted: {}", untrustable(&key))));
        }
        let mut mac = String::new();
        if home {
            mac = self.router_mac(&iface)?;
            if mac.is_empty() {
                return Err(exit("the router's hardware address could not be read; try again in a moment"));
            }
        }
        let mut t = self.load(&self.trusted)?;
        // home before (or an entry from before the levels): trusted now opens nothing, and closes what home opened
        let was = level_of(t.get(&uuid), None, None, None);
        let mut routers = match t.get(&uuid) {
            Some(Val::Dict(old)) if home => match old.get("routers") {
                Some(Val::List(l)) => l.clone(),
                _ => Vec::new(),
            },
            _ => Vec::new(),
        };
        if home && !Val::List(routers.clone()).contains(&py::s(&mac))? {
            routers.push(py::s(&mac));
        }
        let level = if home { "home" } else { "trusted" };
        let mut e = Dict::new();
        e.set("ssid", py::s(&ssid));
        e.set("level", py::s(level));
        e.set("key_mgmt", py::s(&key));
        e.set("trusted_at", py::s(&py::utc_stamp()));
        e.set("routers", Val::List(routers));
        // the owner's choice, whatever the level
        let disc = matches!(t.get(&uuid), Some(Val::Dict(old)) if matches!(old.get("discoverable"), Some(Val::Bool(true))));
        if disc {
            e.set("discoverable", Val::Bool(true));
        }
        // the owner's choice of kind, kept
        if let Some(Val::Dict(old)) = t.get(&uuid) {
            if let Some(Val::Str(k)) = old.get("kind") {
                if KINDS[1..].contains(&k.as_str()) {
                    e.set("kind", py::s(k));
                }
            }
        }
        t.set(&uuid, Val::Dict(e));
        self.save(&self.trusted, &t, 0o644)?;
        let mut pins = self.load(&self.keys)?;
        let pin = self.psk_pin(&uuid)?;
        if pin.is_empty() {
            pins.pop(&uuid); // the password is kept by the desktop's keyring, not the system: nothing to compare later
        } else {
            pins.set(&uuid, py::s(&pin));
        }
        self.save(&self.keys, &pins, 0o600)?;
        let vpn = self.vpn()?.truthy();
        if !home {
            // in force now, not only from the next connection: the quiet table, Avahi off and the private profile
            self.quiet_table(true, disc)?;
            self.quiet(&uuid, true, disc)?;
            self.quiet_router(&iface)?; // the table may be a fresh one: it learns this network's router again
        } else {
            if real {
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
            }
            self.unlock()?;
            self.quiet_table(false, false)?;
            self.quiet(&uuid, false, false)?;
        }
        let st = self.load(&self.state_path())?;
        if py::eq(st.get("wifi").unwrap_or(&Val::None), &py::s(&uuid)) {
            let vpn_on = matches!(st.get("protections"), Some(Val::Dict(p)) if matches!(p.get("vpn"), Some(Val::Bool(true))));
            let p = self.protections(&iface, &uuid, vpn_on, home || disc)?;
            self.set_state(&[("level", py::s(level)), ("trusted", Val::Bool(home)), ("protections", Val::Dict(p))])?;
        }
        if !home {
            println!("Trusted {ssid} ({}): no more notices that it is untrusted.", lock_name(&key));
            if was == "home" {
                let v = if vpn { " and the VPN" } else { "" };
                println!("It is not your home network any more: the device list and discovery are off here now. Reconnect to it (nmcli connection up {uuid}) so that its own hardware address here, no computer name sent{v} apply too.");
            } else {
                let v = if vpn { ", the VPN" } else { "" };
                println!("Protections unchanged: the firewall, not announcing this computer, its own hardware address here, no computer name sent{v}.");
            }
            let wpa3 = if key == "sae" { "" } else { ", and WPA3 if the network offers it," };
            println!("Anyone who knows its password can make a copy of this network: a long password{wpa3} keeps it yours.");
            return Ok(());
        }
        println!("Home network: {ssid} (router {mac}). The device list and discovery are on here, and the VPN is not used.");
        if real {
            println!("From the next connection on, this computer uses its real hardware address and sends its name here.");
        } else {
            println!("This computer still uses its own hardware address here and sends no name (--real-address changes that).");
        }
        Ok(())
    }

    /// trust on a wired network: only home means anything there (no notices to stop). Home is bound to the router's hardware
    /// address (a wired profile joins whatever network its cable is plugged into); --real-address gives the profile the real
    /// hardware address and name, for a router that keeps an address for this computer.
    fn trust_wired(&self, iface: &str, uuid: &str, name: &str, home: bool, real: bool) -> PyResult<()> {
        if !home {
            return Err(exit(format!("{name} is a wired network: trust alone changes nothing there (there are no notices to stop). Your home network: sudo heimdall-wifi-guard trust --home, with --real-address if its router keeps an address for this computer")));
        }
        let mac = self.router_mac(iface)?;
        if mac.is_empty() {
            return Err(exit("the router's hardware address could not be read; try again in a moment"));
        }
        let mut t = self.load(&self.trusted)?;
        let mut routers = match t.get(uuid) {
            Some(Val::Dict(old)) => match old.get("routers") {
                Some(Val::List(l)) => l.clone(),
                _ => Vec::new(),
            },
            _ => Vec::new(),
        };
        if !Val::List(routers.clone()).contains(&py::s(&mac))? {
            routers.push(py::s(&mac));
        }
        let mut e = Dict::new();
        e.set("name", py::s(name));
        e.set("wired", Val::Bool(true));
        e.set("level", py::s("home"));
        e.set("trusted_at", py::s(&py::utc_stamp()));
        e.set("routers", Val::List(routers));
        // the owner's choice of kind, kept
        if let Some(Val::Dict(old)) = t.get(uuid) {
            if let Some(Val::Str(k)) = old.get("kind") {
                if KINDS[1..].contains(&k.as_str()) {
                    e.set("kind", py::s(k));
                }
            }
        }
        t.set(uuid, Val::Dict(e));
        self.save(&self.trusted, &t, 0o644)?;
        if real {
            let cloned = format!("{WIRED}.cloned-mac-address");
            self.sh(&[
                "nmcli",
                "connection",
                "modify",
                uuid,
                &cloned,
                "permanent",
                "ipv4.dhcp-send-hostname",
                "yes",
                "ipv6.dhcp-send-hostname",
                "yes",
            ])?;
        }
        println!("Home network (wired): {name} (router {mac}). The device list may look around here.");
        if real {
            println!("From the next connection on (nmcli connection up {uuid}), this computer uses its real hardware address and sends its name here. On another router (the same profile plugged in elsewhere) it goes back to one of its own.");
        } else {
            println!("This computer still uses a hardware address of its own here and sends no name. If the router keeps an address for this computer: sudo heimdall-wifi-guard trust --home --real-address");
        }
        Ok(())
    }

    /// Back to untrusted, at once on the network connected now; whether a network is discoverable stays.
    fn untrust(&self, name: &str) -> PyResult<()> {
        self.root()?;
        let mut t = self.load(&self.trusted)?;
        let mut gone = Vec::new();
        let is_wired = |e: &Val| matches!(e, Val::Dict(d) if matches!(d.get("wired"), Some(Val::Bool(true))));
        for (u, e) in &t.0 {
            let named = |k: &str| matches!(e, Val::Dict(d) if py::eq(d.get(k).unwrap_or(&Val::None), &py::s(name)));
            let by_name = level_of(Some(e), None, None, None) != "untrusted" && (named("ssid") || (is_wired(e) && named("name")));
            if u == name || by_name {
                gone.push(u.clone());
            }
        }
        let wired: Vec<String> = gone.iter().filter(|u| t.get(u).is_some_and(is_wired)).cloned().collect();
        let names: Vec<String> = wired
            .iter()
            .map(|u| match t.get(u) {
                Some(Val::Dict(d)) => py::str_of(d.get("name").unwrap_or(&Val::None)),
                _ => String::new(),
            })
            .collect();
        let mut kept = Dict::new();
        for u in &gone {
            let e = t.pop(u);
            if let Some(Val::Dict(d)) = &e {
                if matches!(d.get("discoverable"), Some(Val::Bool(true))) {
                    let mut k = Dict::new();
                    k.set("ssid", d.get("ssid").cloned().unwrap_or(Val::None));
                    k.set("level", py::s("untrusted"));
                    k.set("discoverable", Val::Bool(true));
                    kept.set(u, Val::Dict(k.clone()));
                    t.set(u, Val::Dict(k));
                }
            }
        }
        self.save(&self.trusted, &t, 0o644)?;
        let mut pins = self.load(&self.keys)?;
        if gone.iter().any(|u| pins.contains_key(u)) {
            for u in &gone {
                pins.pop(u);
            }
            self.save(&self.keys, &pins, 0o600)?;
        }
        for u in &gone {
            // undoes --real-address (and trust before the levels): a private address, no name
            self.private_profile(u, wired.contains(u), None)?;
        }
        let (iface, now, ssid) = self.active_wifi()?.unwrap_or_default();
        let st = self.load(&self.state_path())?;
        if !now.is_empty() && gone.contains(&now) && py::eq(st.get("wifi").unwrap_or(&Val::None), &py::s(&now)) && !iface.is_empty() {
            let disc = discoverable_of(kept.get(&now), &ssid);
            self.quiet_table(true, disc)?;
            self.quiet(&now, true, disc)?;
            self.quiet_router(&iface)?;
            let vpn_on = matches!(st.get("protections"), Some(Val::Dict(p)) if matches!(p.get("vpn"), Some(Val::Bool(true))));
            let p = self.protections(&iface, &now, vpn_on, disc)?;
            self.set_state(&[("level", py::s("untrusted")), ("trusted", Val::Bool(false)), ("protections", Val::Dict(p))])?;
        }
        if gone.is_empty() {
            println!("no trusted network by that name");
            return Ok(());
        }
        println!("no longer trusted: {} network(s); from the next connection on they are untrusted", gone.len());
        for (u, n) in wired.iter().zip(&names) {
            println!("{n} (wired): from the next connection on (nmcli connection up {u}) it uses a hardware address of its own and sends no name.");
        }
        if !now.is_empty() && gone.contains(&now) {
            let stays = if kept.contains_key(&now) { " (it stays discoverable, as you chose)" } else { "" };
            let vpn = if self.vpn()?.truthy() { " and the VPN" } else { "" };
            println!("{ssid} is untrusted now: the device list and discovery are off here{stays}. Reconnect (nmcli connection up {now}) for the rest: its own hardware address, no computer name sent{vpn}.");
        }
        Ok(())
    }

    /// `kind [KIND] [--uuid UUID]`: what kind of network a trusted one is, the owner's choice (heimdalld judges a different router
    /// by it). Stored as "kind" in the network's entry; home-router (the default) removes it. Without KIND it only says it.
    fn kind(&self, args: &[String]) -> PyResult<()> {
        let (mut want, mut uuid): (Option<&str>, Option<String>) = (None, None);
        let mut i = 0;
        while i < args.len() {
            if args[i] == "--uuid" {
                uuid = Some(args.get(i + 1).cloned().unwrap_or_default());
                i += 2;
                continue;
            }
            let Some(k) = KINDS.iter().find(|k| **k == args[i]).filter(|_| want.is_none()) else {
                return Err(exit(format!(
                    "kind: unknown word {} (kind [{}] [--uuid UUID]): nothing changed",
                    py::repr_str(&args[i]),
                    KINDS.join("|")
                )));
            };
            want = Some(k);
            i += 1;
        }
        if let Some(u) = &uuid {
            if !is_uuid(u) {
                return Err(exit(format!("kind: {} is not a connection UUID: nothing changed", py::repr_str(u))));
            }
        }
        if want.is_some() {
            self.root()?;
        }
        let uuid = match uuid {
            Some(u) => u,
            None => self.active_wifi()?.unwrap_or_default().1,
        };
        if uuid.is_empty() {
            return Err(exit("not connected to Wi-Fi: name the network with --uuid UUID"));
        }
        let mut t = self.load(&self.trusted)?;
        let e = t.get(&uuid).cloned();
        if level_of(e.as_ref(), None, None, None) == "untrusted" {
            return Err(exit(format!("kind: {uuid} is not a trusted network (heimdall-wifi-guard trust first): nothing changed")));
        }
        let Some(Val::Dict(mut d)) = e else { return Ok(()) };
        let ssid = match d.get("ssid") {
            Some(Val::Str(s)) => s.clone(),
            _ => uuid.clone(),
        };
        let Some(want) = want else {
            println!("{ssid}: kind {}", kind_of(Some(&Val::Dict(d))));
            return Ok(());
        };
        if want == "home-router" {
            d.pop("kind");
        } else {
            d.set("kind", py::s(want));
        }
        t.set(&uuid, Val::Dict(d));
        self.save(&self.trusted, &t, 0o644)?;
        println!("{ssid}: kind {want}. Heimdall judges a different router on it by this.");
        Ok(())
    }

    /// `discoverable [on|off] [--uuid UUID]`: whether this computer may announce itself on a Wi-Fi network, the owner's choice
    /// whatever its trust level (home always is); every other protection stays. On the network connected now it applies at
    /// once. Without on/off it only says it (no root needed).
    fn discoverable(&self, args: &[String]) -> PyResult<()> {
        let (mut want, mut uuid): (Option<&str>, Option<String>) = (None, None);
        let mut i = 0;
        while i < args.len() {
            if args[i] == "--uuid" {
                uuid = Some(args.get(i + 1).cloned().unwrap_or_default());
                i += 2;
                continue;
            }
            if !(args[i] == "on" || args[i] == "off") || want.is_some() {
                return Err(exit(format!(
                    "discoverable: unknown word {} (discoverable [on|off] [--uuid UUID]): nothing changed",
                    py::repr_str(&args[i])
                )));
            }
            want = Some(if args[i] == "on" { "on" } else { "off" });
            i += 1;
        }
        if let Some(u) = &uuid {
            if !is_uuid(u) {
                return Err(exit(format!("discoverable: {} is not a connection UUID: nothing changed", py::repr_str(u))));
            }
        }
        if want.is_some() {
            self.root()?;
        }
        let (iface, now, _) = self.active_wifi()?.unwrap_or_default();
        let uuid = uuid.unwrap_or_else(|| now.clone());
        if uuid.is_empty() {
            return Err(exit("not connected to Wi-Fi: name the network with --uuid UUID"));
        }
        let ssid = py::strip(&self.out(&["nmcli", "-g", "802-11-wireless.ssid", "connection", "show", "uuid", &uuid])?).to_string();
        if ssid.is_empty() {
            return Err(exit(format!("{uuid} is not a saved Wi-Fi network: nothing changed")));
        }
        let mut t = self.load(&self.trusted)?;
        let e = t.get(&uuid).cloned();
        let home = level_of(e.as_ref(), None, None, None) == "home";
        let Some(want) = want else {
            let on = if home {
                "on (home)"
            } else if discoverable_of(e.as_ref(), &ssid) {
                "on"
            } else {
                "off"
            };
            println!("{ssid}: discoverable {on}");
            return Ok(());
        };
        match e {
            Some(Val::Dict(mut d)) => {
                if want == "on" {
                    d.set("discoverable", Val::Bool(true));
                    let keep = level_of(Some(&Val::Dict(d.clone())), None, None, None) != "untrusted";
                    let name = if keep { d.get("ssid").cloned().unwrap_or(Val::None) } else { py::s(&ssid) };
                    d.set("ssid", name);
                } else {
                    d.pop("discoverable");
                }
                if matches!(d.get("level"), Some(Val::Str(l)) if l == "untrusted") && !d.contains_key("discoverable") {
                    t.pop(&uuid); // nothing left to remember about it
                } else {
                    t.set(&uuid, Val::Dict(d));
                }
            }
            _ if want == "on" => {
                let mut d = Dict::new();
                d.set("ssid", py::s(&ssid));
                d.set("level", py::s("untrusted"));
                d.set("discoverable", Val::Bool(true));
                t.set(&uuid, Val::Dict(d));
            }
            _ => {}
        }
        self.save(&self.trusted, &t, 0o644)?;
        let st = self.load(&self.state_path())?;
        if uuid == now && py::eq(st.get("wifi").unwrap_or(&Val::None), &py::s(&now)) && !iface.is_empty() && !home {
            let disc = discoverable_of(t.get(&uuid), &ssid);
            self.quiet_table(true, disc)?;
            self.quiet(&uuid, true, disc)?;
            self.quiet_router(&iface)?; // a fresh table: it learns this network's router again
            let vpn_on = matches!(st.get("protections"), Some(Val::Dict(p)) if matches!(p.get("vpn"), Some(Val::Bool(true))));
            let p = self.protections(&iface, &uuid, vpn_on, disc)?;
            self.set_state(&[("protections", Val::Dict(p))])?;
        }
        if home {
            println!("{ssid} is your home network: this computer announces itself there anyway.");
        } else if want == "on" {
            println!("{ssid}: discoverable. This computer announces itself there (its name and services, through Avahi); every other protection stays.");
        } else {
            println!("{ssid}: not discoverable. This computer does not announce itself there.");
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

    /// Whether the alerts for devices reaching this computer can appear: heimdalld's firewall watch turns the quiet table's
    /// log into them, which needs heimdalld running, the systemd-journal group and the watch not turned off in its config.
    fn inbound_watch(&self) -> PyResult<String> {
        if py::strip(&self.out(&["systemctl", "is-active", "heimdall.service"])?) != "active" {
            return Ok("not reported: heimdalld is not running".into());
        }
        let groups = self.out(&["systemctl", "show", "-p", "SupplementaryGroups", "--value", "heimdall.service"])?;
        if !py::split_ws(&groups).contains(&"systemd-journal") {
            return Ok(
                "not reported: heimdalld cannot read the kernel log (install packaging/arch/heimdall-firewall.conf.example as its drop-in)"
                    .into(),
            );
        }
        if !matches!(self.load(Path::new(HEIMDALL_CONFIG))?.get("firewall"), None | Some(Val::Bool(true))) {
            return Ok("not reported: heimdalld's firewall watch is off (\"firewall\" in /etc/heimdall/config.json)".into());
        }
        Ok("reported (heimdalld's firewall watch reads the quiet table's log)".into())
    }

    fn status(&self) -> PyResult<()> {
        let t = self.load(&self.trusted)?;
        let vpn = self.vpn()?;
        let st = self.load(&self.state_path())?;
        println!("{}", if t.0.is_empty() { "networks you trust: none" } else { "networks you trust:" });
        for (_, e) in &t.0 {
            let Val::Dict(d) = e else { continue };
            let level = level_of(Some(e), None, None, None);
            let wired = matches!(d.get("wired"), Some(Val::Bool(true)));
            let label = py::str_of(d.get(if wired { "name" } else { "ssid" }).unwrap_or(&Val::None));
            let mut line = format!("  {label}: {level}{}", if wired { " (wired)" } else { "" });
            if matches!(d.get("discoverable"), Some(Val::Bool(true))) && level != "home" {
                line += ", discoverable";
            }
            if let Some(Val::Str(k)) = d.get("key_mgmt") {
                if TRUSTABLE.contains(&k.as_str()) {
                    line += &format!(" ({})", lock_name(k));
                }
            }
            if let (Some(Val::List(r)), "home") = (d.get("routers"), level) {
                let names: Vec<&str> = r.iter().filter_map(Val::as_str).collect();
                line += &format!(", router {}", names.join(", "));
            }
            println!("{line}");
        }
        let line = if vpn.truthy() {
            format!("set up, {} endpoint(s)", vpn.index("endpoints")?.py_len()?)
        } else {
            "not set up (heimdall-wifi-guard vpn-import FILE.conf)".into()
        };
        println!("VPN: {line}");
        if let Some((_, uuid, ssid)) = self.active_wifi()?.filter(|w| !w.1.is_empty()) {
            let key = self.profile_key(&uuid)?;
            let here = py::eq(st.get("wifi").unwrap_or(&Val::None), &py::s(&uuid));
            let level = match st.get("level") {
                Some(Val::Str(l)) if here && matches!(l.as_str(), "untrusted" | "trusted" | "home") => l.clone(),
                _ => level_of(t.get(&uuid), Some(&ssid), Some(&key), None).to_string(),
            };
            println!("now on: {ssid}, {level} ({})", lock_name(&key));
            if let (true, Some(Val::Dict(p))) = (here, st.get("protections")) {
                let parts: Vec<String> = PROTECTIONS
                    .iter()
                    .map(|(k, label)| format!("{label}: {}", if p.get(k).is_some_and(Val::truthy) { "yes" } else { "no" }))
                    .collect();
                println!("protections: {}", parts.join("; "));
                if matches!(p.get("discoverable"), Some(Val::Bool(true))) {
                    println!("discoverable here: yes (this computer announces itself; heimdall-wifi-guard discoverable off)");
                }
                if let Some(Val::List(allowed)) = p.get("allowed_in") {
                    if !allowed.is_empty() {
                        let names: Vec<String> = allowed.iter().map(py::str_of).collect();
                        println!("the firewall lets in (a ufw rule allows them, and they listen here): {}", names.join(", "));
                    }
                }
                println!("still visible to the network: {}", exposure(p));
            }
        }
        if let Some((wi, wu, wn)) = self.active_wired()?.filter(|w| !w.1.is_empty()) {
            let e = t.get(&wu);
            let level = match e {
                Some(Val::Dict(d)) if matches!(d.get("wired"), Some(Val::Bool(true))) => level_of(e, None, None, None),
                _ => "untrusted",
            };
            let own = if self.own_address(&wi)? { "yes" } else { "no" };
            println!("wired now: {wn}, {level}; a hardware address of its own here: {own}");
        }
        println!("devices reaching this computer: {}", self.inbound_watch()?);
        if unsafe { libc::geteuid() } == 0 {
            println!("lockdown: {}", if self.locked()? { "on" } else { "off" });
            let p = self.sh(&["nft", "list", "table", "inet", QUIET])?;
            println!("quiet table: {}", counters_text(p.code, &p.stdout));
        }
        Ok(())
    }

    /// Print and check Heimdall's quiet table, without applying it (root).
    fn quiet_check(&self) -> PyResult<i32> {
        self.root()?;
        let rs = quiet_ruleset(false);
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

/// `os.open(p, O_WRONLY | O_CREAT | O_TRUNC, mode)`, `os.fchmod(fd, mode)`, then the text written.
fn write_with_mode(p: &Path, text: &str, mode: u32) -> PyResult<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let ps = p.to_string_lossy();
    let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(mode).open(p).map_err(|e| PyErr::os(&e, &ps))?;
    f.set_permissions(std::fs::Permissions::from_mode(mode)).map_err(|e| PyErr::os(&e, &ps))?;
    f.write_all(text.as_bytes()).map_err(|e| PyErr::os(&e, &ps))
}

/// A connection UUID as NetworkManager writes it: 8-4-4-4-12 lowercase hex digits (`re.fullmatch` in Python).
pub fn is_uuid(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, &c)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                c == b'-'
            } else {
                c.is_ascii_digit() || (b'a'..=b'f').contains(&c)
            }
        })
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
        "trust" => g.trust(&a[1..])?,
        "untrust" if a.len() > 1 => g.untrust(&a[1])?,
        "discoverable" => g.discoverable(&a[1..])?,
        "kind" => g.kind(&a[1..])?,
        "vpn-import" if a.len() > 1 => g.vpn_import(&a[1])?,
        "vpn-remove" => g.vpn_remove()?,
        "sign-in" => g.sign_in()?,
        "ruleset-check" => return g.ruleset_check(a.get(1).map(String::as_str)),
        "quiet-check" => return g.quiet_check(),
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
        keys: env_or("HEIMDALL_WIFI_KEYS", "/etc/heimdall/wifi-trusted-keys.json"),
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
