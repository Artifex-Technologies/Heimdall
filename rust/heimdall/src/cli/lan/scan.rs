//! One scan of the current network (Go: internal/lan/scan.go): only on a connection the owner trusted whose router is the one
//! recorded then; the store updated and every new device recorded.

use super::discover::{self, Found};
use super::store::{self, Device, Store};
use super::text::{contains_fold, to_upper};
use crate::gotime::Time;
use std::collections::BTreeMap;
use std::io::BufRead;
use std::net::Ipv4Addr;
use std::time::Duration;

/// heimdall-wifi-guard's trusted networks: {uuid: {ssid, routers: [mac]}}.
pub const TRUSTED_PATH: &str = "/etc/heimdall/wifi-trusted.json";
pub const PROC_ROOT: &str = "/proc";

/// Go's bufio.Scanner lines (a trailing \r dropped; a line over 64 KiB ends the reading).
fn lines(path: &str) -> Vec<String> {
    let Ok(f) = std::fs::File::open(path) else { return Vec::new() };
    let mut r = std::io::BufReader::new(f);
    let mut out = Vec::new();
    let mut line = Vec::new();
    loop {
        line.clear();
        match r.read_until(b'\n', &mut line) {
            Ok(0) | Err(_) => return out,
            Ok(_) => {}
        }
        if line.last() == Some(&b'\n') {
            line.pop();
        }
        if line.len() >= 65536 {
            return out;
        }
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        out.push(crate::gotext::lossy(&line));
    }
}

/// Go's `fmt.Sscanf(s, "%X", &u32)`: the leading hex digits; None where Go's scan fails.
pub fn scan_hex32(s: &str) -> Option<u32> {
    let digits: String = s.chars().take_while(char::is_ascii_hexdigit).collect();
    if digits.is_empty() {
        return None;
    }
    let v = u64::from_str_radix(&digits, 16).ok()?;
    u32::try_from(v).ok()
}

/// The interface and gateway of the IPv4 default route with the lowest metric (/proc/net/route).
pub fn default_route(proc_root: &str) -> Option<(String, Ipv4Addr)> {
    let mut best: i64 = -1;
    let mut out = None;
    for line in lines(&format!("{proc_root}/net/route")) {
        let x: Vec<&str> = crate::gotext::fields(&line).collect();
        // Go indexes x[7] after checking for 7 fields; a line of exactly 7 would stop Go with a panic (the kernel writes 11)
        if x.len() < 8 || x[1] != "00000000" || x[7] != "00000000" {
            continue;
        }
        let g = match scan_hex32(x[2]) {
            Some(g) if g != 0 => g,
            _ => continue,
        };
        let metric = crate::gonet::sscan_int(x[6]).unwrap_or(0);
        if best < 0 || metric < best {
            best = metric;
            out = Some((x[0].to_string(), Ipv4Addr::from(g.to_le_bytes())));
        }
    }
    out
}

/// NetworkManager's connection on `iface` (read-only; any account may ask): its UUID and name.
pub fn active_connection(iface: &str) -> (String, String) {
    let out = match std::process::Command::new("nmcli")
        .args(["-t", "-f", "UUID,DEVICE,NAME", "connection", "show", "--active"])
        .stdin(std::process::Stdio::null())
        .output()
    {
        Ok(o) if o.status.success() => o.stdout,
        _ => return (String::new(), String::new()),
    };
    parse_nmcli(&crate::gotext::lossy(&out), iface)
}

/// The UUID and name of the line for `iface` in `nmcli -t -f UUID,DEVICE,NAME` output (NAME may hold escaped colons).
pub fn parse_nmcli(out: &str, iface: &str) -> (String, String) {
    for line in out.split('\n') {
        let p: Vec<&str> = line.splitn(3, ':').collect();
        if p.len() == 3 && p[1] == iface {
            return (p[0].to_string(), p[2].replace("\\:", ":").replace("\\\\", "\\"));
        }
    }
    (String::new(), String::new())
}

/// The kernel's neighbour table for `iface`: complete entries only, hardware addresses in capitals.
pub fn arp_table(proc_root: &str, iface: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for line in lines(&format!("{proc_root}/net/arp")).iter().skip(1) {
        let x: Vec<&str> = crate::gotext::fields(line).collect();
        if x.len() >= 6 && x[5] == iface && x[2] != "0x0" && x[3] != "00:00:00:00:00:00" {
            out.insert(x[0].to_string(), to_upper(x[3].as_bytes()));
        }
    }
    out
}

/// One trusted network as heimdall-wifi-guard records it.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Trusted {
    pub ssid: String,
    pub routers: Vec<String>,
}

static TRUSTED_NET: crate::gostruct::Ty = crate::gostruct::Ty::Struct(
    "lan.trustedNet",
    &[
        crate::gostruct::Field("ssid", &crate::gostruct::Ty::Str, false),
        crate::gostruct::Field("routers", &crate::gostruct::Ty::Slice(&crate::gostruct::Ty::Str), false),
    ],
);

/// wifi-trusted.json read as Go's json.Unmarshal into a map[string]trustedNet reads it: nothing on a syntax error, each
/// member decoded into a fresh value (the last of a duplicate key wins), a member of the wrong type kept as an empty value.
pub fn parse_trusted(b: &[u8]) -> BTreeMap<String, Trusted> {
    use crate::gojson::Value;
    use crate::gostruct::Val;
    let mut out = BTreeMap::new();
    let Ok(Value::Object(members)) = crate::gojson::parse(b) else { return out };
    for (k, v) in members {
        let mut val = crate::gostruct::zero(&TRUSTED_NET);
        let mut cx = crate::gostruct::Ctx { top: "", first: None };
        crate::gostruct::read(&TRUSTED_NET, &v, &mut val, "", &mut cx);
        let t = match &val {
            Val::Struct(f) => Trusted {
                ssid: match &f[0] {
                    Val::Str(s) => s.clone(),
                    _ => String::new(),
                },
                routers: match &f[1] {
                    Val::Slice(Some(r)) => r
                        .iter()
                        .map(|x| match x {
                            Val::Str(s) => s.clone(),
                            _ => String::new(),
                        })
                        .collect(),
                    _ => Vec::new(),
                },
            },
            _ => Trusted::default(),
        };
        out.insert(k, t);
    }
    out
}

/// What a scan says for the command line.
#[derive(Clone, Debug, Default)]
pub struct Outcome {
    pub status: String,
    pub devices: usize,
    pub new: Vec<Device>,
}

/// Looks at the current network if it is trusted, updates the store and records new devices. Err: Go's error text.
pub fn scan(dir: &str, wait: Duration, log: &dyn Fn(&str)) -> Result<Outcome, String> {
    let store_path = crate::gopath::join(&[dir, "devices.json"]);
    let events_path = crate::gopath::join(&[dir, "events.jsonl"]);
    let (mut st, err) = store::load(&store_path);
    if let Some(e) = err {
        return Err(e);
    }
    let now = Time::now().utc().truncate(1_000_000_000);
    let status = |st: &mut Store, s: &str, uuid: &str| -> Result<Outcome, String> {
        st.status = s.to_string();
        st.status_uuid = uuid.to_string();
        st.status_time = now;
        st.save(&store_path).map(|_| Outcome { status: s.to_string(), ..Outcome::default() })
    };

    let Some((iface, gateway)) = default_route(PROC_ROOT) else { return status(&mut st, "offline", "") };
    let (uuid, mut ssid) = active_connection(&iface);
    let trusted = std::fs::read(TRUSTED_PATH).map(|b| parse_trusted(&b)).unwrap_or_default();
    let t = match trusted.get(&uuid) {
        Some(t) if !uuid.is_empty() => t.clone(),
        _ => return status(&mut st, "not_trusted", &uuid),
    };
    if !t.ssid.is_empty() {
        ssid = t.ssid.clone();
    }
    let ifc = super::net::iface(&iface).ok_or_else(|| "route ip+net: no such network interface".to_string())?;
    let Some((local, ones)) = ifc.v4 else { return status(&mut st, "offline", &uuid) };
    let mask = if ones == 0 { 0 } else { u32::MAX << (32 - ones) };
    let network = Ipv4Addr::from(u32::from(local) & mask);

    // look: the sweep fills the neighbour table while multicast DNS answers come in
    let index = ifc.index;
    let md = std::thread::spawn(move || discover::mdns(index, local, wait));
    discover::sweep(local, network, ones);
    std::thread::sleep(wait);
    let md: BTreeMap<String, Found> = md.join().unwrap_or_default();

    let mut arp = arp_table(PROC_ROOT, &iface);
    let router_mac = arp.get(&gateway.to_string()).cloned().unwrap_or_default();
    if router_mac.is_empty() || !contains_fold(&t.routers, &router_mac) {
        // the same network name with a different router is not the network the owner trusted
        return status(&mut st, "router_changed", &uuid);
    }
    arp.insert(local.to_string(), to_upper(ifc.hw.as_bytes()));

    let in_net = |ip: &str| match crate::gonet::parse_ip(ip) {
        Some(std::net::IpAddr::V4(a)) => u32::from(a) & mask == u32::from(network),
        _ => false,
    };
    let ips: Vec<String> = arp.keys().filter(|ip| in_net(ip)).cloned().collect(); // sorted as strings, as Go sorts them
    let unnamed: Vec<String> = ips.iter().filter(|ip| md.get(*ip).is_none_or(|f| f.names.is_empty())).cloned().collect();
    let rdns = reverse_names(gateway, &ips);
    let nb = if unnamed.is_empty() { BTreeMap::new() } else { discover::netbios(&unnamed) };
    let macs: Vec<String> = ips.iter().map(|ip| arp[ip].clone()).collect();
    let vend = super::oui::vendors(super::oui::OUI_PATH, &macs);

    let mut seen = Vec::new();
    for ip in &ips {
        let mac = arp[ip].clone();
        let mut d = Device {
            vendor: vend.get(&mac).cloned().unwrap_or_default(),
            private_mac: super::oui::private_mac(&mac),
            mac,
            ip: ip.clone(),
            ..Device::default()
        };
        if let Some(f) = md.get(ip) {
            d.names.extend(f.names.iter().cloned());
            d.model = f.model.clone();
            d.services = f.services.iter().cloned().collect();
        }
        for n in [rdns.get(ip), nb.get(ip)].into_iter().flatten() {
            if !n.is_empty() && !contains_fold(&d.names, n) {
                d.names.push(n.clone());
            }
        }
        if let Some(n) = d.names.first() {
            d.name = n.clone();
        }
        d.kind = if *ip == gateway.to_string() {
            "router".into()
        } else if *ip == local.to_string() {
            "this".into()
        } else {
            store::kind_of(&d).into()
        };
        seen.push(d);
    }
    let count = seen.len();
    let n = st.network(&uuid, &ssid);
    let fresh = n.merge(seen, now);
    if let Err(e) = store::append_events(&events_path, &ssid, &fresh, now) {
        log(&format!("new devices could not be recorded: {e}"));
    }
    st.status = "scanned".into();
    st.status_uuid = uuid.clone();
    st.status_time = now;
    st.save(&store_path)?;
    Ok(Outcome { status: "scanned".into(), devices: count, new: fresh })
}

/// Asks the router for the names it gave out (most home routers answer reverse lookups for their DHCP clients), eight at a
/// time, 1.5 seconds each, as Go does.
pub fn reverse_names(router: Ipv4Addr, ips: &[String]) -> BTreeMap<String, String> {
    let files = super::resolver::Files::read();
    let out = std::sync::Mutex::new(BTreeMap::new());
    let next = std::sync::atomic::AtomicUsize::new(0);
    std::thread::scope(|s| {
        for _ in 0..8 {
            s.spawn(|| loop {
                let i = next.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let Some(ip) = ips.get(i) else { return };
                let Some(a) = (match crate::gonet::parse_ip(ip) {
                    Some(std::net::IpAddr::V4(a)) => Some(a),
                    _ => None,
                }) else {
                    continue;
                };
                let deadline = std::time::Instant::now() + Duration::from_millis(1500);
                let Some(names) = super::resolver::lookup_addr(router, a, &files, deadline) else { continue };
                let Some(first) = names.first() else { continue };
                let mut n = first.strip_suffix('.').unwrap_or(first);
                if let Some(i) = n.find('.') {
                    if i > 0 {
                        n = &n[..i]; // "tv.lan", "phone.home" -> the device part
                    }
                }
                let n = super::text::clean(n.as_bytes());
                if !n.is_empty() && !discover::looks_generated(&n, ip) {
                    out.lock().unwrap_or_else(|p| p.into_inner()).insert(ip.clone(), n);
                }
            });
        }
    });
    out.into_inner().unwrap_or_else(|p| p.into_inner())
}
