//! `heimdalld lan look [--wait SECONDS] [UUID]` (HEI-74; only in the Rust heimdalld): a look at one network made when the
//! owner opens that network's page in Settings, for the networks the timer never looks at (any network but home). It only
//! listens (the owner's decision, 2026-11-22): the neighbour table the kernel already keeps, and for `--wait` seconds the
//! multicast DNS announcements and answers that other devices send to the group anyway, heard only while this computer
//! already belongs to the group on that interface (joining would announce it). Its socket cannot send (`net::Ear`), it asks
//! no router and no device, and it writes nothing: it prints one JSON object and is gone. Any account may run it (no
//! password): nothing it reads needs more than the account has.

use super::discover::{self, Found};
use super::dns;
use super::net::{self, Ear};
use super::scan::{self, PROC_ROOT};
use super::store::{self, Device};
use super::text::to_upper;
use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

pub const MDNS_GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);

/// What one look found.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Look {
    /// "looked", or "offline" (no such connection, or it has no IPv4 address)
    pub status: &'static str,
    pub uuid: String,
    /// NetworkManager's name for the connection
    pub name: String,
    pub iface: String,
    /// "listened", "not_member" (this computer does not belong to the multicast DNS group there: not joined, not heard),
    /// "busy" (another program holds the port alone), or "" when offline
    pub mdns: &'static str,
    pub listened: u64,
    pub devices: Vec<Device>,
}

/// Whether `iface` belongs to the IPv4 multicast `group`, from /proc/net/igmp: an interface line ("2\twlan0     :     2
/// V3") followed by its groups ("\t\t\t\tFB0000E0     1 0:00000000\t\t0", the address as the kernel's number in hex).
pub fn member(igmp: &str, iface: &str, group: Ipv4Addr) -> bool {
    let mut on = false;
    for line in igmp.lines().skip(1) {
        if !line.starts_with(['\t', ' ']) {
            on = line.split_once('\t').and_then(|(_, r)| r.rsplit_once(':')).is_some_and(|(n, _)| n.trim() == iface);
        } else if on {
            let v = line.split_whitespace().next().and_then(|h| u32::from_str_radix(h, 16).ok());
            if v.is_some_and(|v| Ipv4Addr::from(v.to_ne_bytes()) == group) {
                return true;
            }
        }
    }
    false
}

/// The gateway of `iface`'s IPv4 default route with the lowest metric (/proc/net/route), as `scan::default_route` reads the
/// table but for one interface.
pub fn gateway_on(route: &str, iface: &str) -> Option<Ipv4Addr> {
    let mut best: Option<(i64, Ipv4Addr)> = None;
    for line in route.lines().skip(1) {
        let x: Vec<&str> = line.split_whitespace().collect();
        if x.len() < 8 || x[0] != iface || x[1] != "00000000" || x[7] != "00000000" {
            continue;
        }
        let Some(g) = scan::scan_hex32(x[2]).filter(|g| *g != 0) else { continue };
        let metric = x[6].parse::<i64>().unwrap_or(0);
        if best.is_none_or(|(m, _)| metric < m) {
            best = Some((metric, Ipv4Addr::from(g.to_le_bytes())));
        }
    }
    best.map(|(_, g)| g)
}

/// The device and name of active connection `uuid` in `nmcli -t -f UUID,DEVICE,NAME connection show --active` output.
pub fn connection_of(out: &str, uuid: &str) -> Option<(String, String)> {
    out.lines().find_map(|line| {
        let p: Vec<&str> = line.splitn(3, ':').collect();
        (p.len() == 3 && p[0] == uuid && !p[1].is_empty()).then(|| (p[1].to_string(), p[2].replace("\\:", ":").replace("\\\\", "\\")))
    })
}

/// The devices one look heard, in the order of their addresses as text (as the scan orders them): every complete neighbour
/// entry and every sender of multicast DNS on the interface's own subnet, and this computer. A sender the kernel has no
/// hardware address for (it never talked with this computer) is listed by its address alone. `maker` gives a hardware
/// address's maker and whether the address is made up (locally administered).
pub fn heard(
    arp: &BTreeMap<String, String>,
    md: &BTreeMap<String, Found>,
    (local, ones): (Ipv4Addr, u32),
    hw: &str,
    gateway: Option<Ipv4Addr>,
    maker: &dyn Fn(&str) -> (String, bool),
) -> Vec<Device> {
    let mask = if ones == 0 { 0 } else { u32::MAX << (32 - ones.min(32)) };
    let network = u32::from(local) & mask;
    let in_net = |ip: &str| ip.parse::<Ipv4Addr>().is_ok_and(|a| u32::from(a) & mask == network);
    let mut ips: BTreeSet<String> = arp.keys().chain(md.keys()).filter(|ip| in_net(ip)).cloned().collect();
    ips.insert(local.to_string());
    let mut out = Vec::new();
    for ip in ips {
        let mac = if ip == local.to_string() { to_upper(hw.as_bytes()) } else { arp.get(&ip).cloned().unwrap_or_default() };
        let (vendor, private_mac) = if mac.is_empty() { (String::new(), false) } else { maker(&mac) };
        let mut d = Device { mac, ip: ip.clone(), vendor, private_mac, ..Device::default() };
        if let Some(f) = md.get(&ip) {
            d.names = f.names.clone();
            d.model = f.model.clone();
            d.services = f.services.iter().cloned().collect();
        }
        d.name = d.names.first().cloned().unwrap_or_default();
        d.kind = if gateway.is_some_and(|g| g.to_string() == ip) {
            "router".into()
        } else if ip == local.to_string() {
            "this".into()
        } else {
            store::kind_of(&d).into()
        };
        out.push(d);
    }
    out
}

/// Hears multicast DNS for `wait`: every datagram's records filed under its sender, as the scan files the answers to its own
/// questions (a device that only asks is heard too, with nothing to its name).
fn hear(ear: &Ear, wait: Duration) -> BTreeMap<String, Found> {
    let mut out = BTreeMap::new();
    let mut types = BTreeSet::new();
    let mut buf = vec![0u8; 9000];
    let deadline = Instant::now() + wait;
    loop {
        let now = Instant::now();
        if now >= deadline {
            return out;
        }
        match ear.recv_from(&mut buf, deadline - now) {
            Ok((n, from)) => {
                let (recs, _) = dns::parse(&buf[..n]);
                discover::absorb(&mut out, &mut types, from, &recs);
            }
            Err(_) => return out,
        }
    }
}

/// One look at active connection `uuid` (None: the one with the default route).
pub fn look(uuid: Option<&str>, wait: Duration) -> Look {
    let found = match uuid {
        Some(u) => {
            let out = std::process::Command::new("nmcli")
                .args(["-t", "-f", "UUID,DEVICE,NAME", "connection", "show", "--active"])
                .stdin(std::process::Stdio::null())
                .output()
                .ok()
                .filter(|o| o.status.success())
                .map(|o| crate::gotext::lossy(&o.stdout))
                .unwrap_or_default();
            connection_of(&out, u).map(|(dev, name)| (dev, u.to_string(), name))
        }
        None => scan::default_route(PROC_ROOT).map(|(dev, _)| {
            let (u, name) = scan::active_connection(&dev);
            (dev, u, name)
        }),
    };
    let offline = |uuid: String, name: String, iface: String| Look { status: "offline", uuid, name, iface, ..Look::default() };
    let Some((iface, uuid, name)) = found else { return offline(uuid.unwrap_or_default().to_string(), String::new(), String::new()) };
    let Some(ifc) = net::iface(&iface) else { return offline(uuid, name, iface) };
    let Some(v4) = ifc.v4 else { return offline(uuid, name, iface) };
    let gateway = gateway_on(&std::fs::read_to_string(format!("{PROC_ROOT}/net/route")).unwrap_or_default(), &iface);
    let igmp = std::fs::read_to_string(format!("{PROC_ROOT}/net/igmp")).unwrap_or_default();
    let (mdns, md) = if !member(&igmp, &iface, MDNS_GROUP) {
        ("not_member", BTreeMap::new())
    } else {
        match Ear::bind(5353) {
            Ok(ear) => ("listened", hear(&ear, wait)),
            Err(_) => ("busy", BTreeMap::new()),
        }
    };
    let arp = scan::arp_table(PROC_ROOT, &iface);
    let makers = heimdall_macvendor::global();
    let maker = |mac: &str| {
        let a = makers.lookup_str(mac);
        (a.label().to_string(), a == heimdall_macvendor::Answer::Private)
    };
    let devices = heard(&arp, &md, v4, &ifc.hw, gateway, &maker);
    let listened = if mdns == "listened" { wait.as_secs() } else { 0 };
    Look { status: "looked", uuid, name, iface, mdns, listened, devices }
}

/// The look as Settings reads it: one JSON object (written with the crate's own JSON writer: the daemon has no serde).
pub fn to_json(l: &Look) -> String {
    use crate::gojson::Value;
    let st = |s: &str| Value::String(s.to_string());
    let list = |v: &[String]| Value::Array(v.iter().map(|s| st(s)).collect());
    let obj = |m: Vec<(&str, Value)>| Value::Object(m.into_iter().map(|(k, v)| (k.to_string(), v)).collect());
    let devices = l
        .devices
        .iter()
        .map(|d| {
            obj(vec![
                ("mac", st(&d.mac)),
                ("ip", st(&d.ip)),
                ("name", st(&d.name)),
                ("names", list(&d.names)),
                ("vendor", st(&d.vendor)),
                ("model", st(&d.model)),
                ("kind", st(&d.kind)),
                ("services", list(&d.services)),
                ("private_mac", Value::Bool(d.private_mac)),
            ])
        })
        .collect();
    let v = obj(vec![
        ("status", st(l.status)),
        ("uuid", st(&l.uuid)),
        ("name", st(&l.name)),
        ("interface", st(&l.iface)),
        ("mdns", st(l.mdns)),
        ("listened", Value::Number(l.listened.to_string())),
        ("devices", Value::Array(devices)),
    ]);
    let mut out = String::new();
    crate::gojson::write_value(&mut out, &v);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn membership_is_read_per_interface() {
        let igmp = "Idx\tDevice    : Count Querier\tGroup    Users Timer\tReporter\n\
                    1\tlo        :     1      V3\n\t\t\t\t010000E0     1 0:00000000\t\t0\n\
                    2\twlan0     :     2      V3\n\t\t\t\tFB0000E0     1 0:00000000\t\t0\n\t\t\t\t010000E0     1 0:00000000\t\t0\n\
                    5\tenp0s9f0u1c4i2:     1      V3\n\t\t\t\t010000E0     1 0:00000000\t\t0\n";
        if cfg!(target_endian = "little") {
            assert!(member(igmp, "wlan0", MDNS_GROUP));
        }
        assert!(!member(igmp, "lo", MDNS_GROUP), "lo has only all-hosts");
        assert!(!member(igmp, "enp0s9f0u1c4i2", MDNS_GROUP), "a long name with no space before the colon");
        assert!(!member(igmp, "wlan", MDNS_GROUP), "the whole name");
        assert!(!member("", "wlan0", MDNS_GROUP));
    }

    #[test]
    fn the_gateway_of_one_interface() {
        let route = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
                     eth0\t00000000\t010200C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n\
                     wlan0\t00000000\t0102A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n\
                     wlan0\t0002A8C0\t00000000\t0001\t0\t0\t600\t00FFFFFF\t0\t0\t0\n";
        assert_eq!(gateway_on(route, "wlan0"), Some(Ipv4Addr::new(192, 168, 2, 1)), "not eth0's, though eth0's metric is lower");
        assert_eq!(gateway_on(route, "eth0"), Some(Ipv4Addr::new(192, 0, 2, 1)));
        assert_eq!(gateway_on(route, "wlan1"), None);
    }

    #[test]
    fn a_connection_by_its_uuid() {
        let out = "u0:wlan0:Ca\\:fe\nu1:eth0:Wired\nu2::Down\n";
        assert_eq!(connection_of(out, "u0"), Some(("wlan0".into(), "Ca:fe".into())));
        assert_eq!(connection_of(out, "u2"), None, "no device: not up");
        assert_eq!(connection_of(out, "u9"), None);
    }

    #[test]
    fn what_a_look_heard() {
        let arp: BTreeMap<String, String> = [
            ("192.0.2.1", "02:00:00:00:00:01"),
            ("192.0.2.40", "02:00:00:00:00:40"),
            ("198.51.100.7", "02:00:00:00:00:07"), // another interface's subnet
        ]
        .into_iter()
        .map(|(a, b)| (a.to_string(), b.to_string()))
        .collect();
        let mut md = BTreeMap::new();
        md.insert(
            "192.0.2.20".to_string(),
            Found { names: vec!["Living TV".into()], model: "Chromecast".into(), services: ["_googlecast._tcp".to_string()].into() },
        );
        md.insert("203.0.113.9".to_string(), Found::default()); // heard from off the subnet: not this network's
        let maker = |mac: &str| (if mac.ends_with(":40") { "Ecobee".to_string() } else { String::new() }, mac.starts_with("02"));
        let d = heard(&arp, &md, (Ipv4Addr::new(192, 0, 2, 10), 24), "02:00:00:00:00:aa", Some(Ipv4Addr::new(192, 0, 2, 1)), &maker);
        let got: Vec<(&str, &str, &str, &str)> =
            d.iter().map(|d| (d.ip.as_str(), d.mac.as_str(), d.kind.as_str(), d.name.as_str())).collect();
        assert_eq!(
            got,
            vec![
                ("192.0.2.1", "02:00:00:00:00:01", "router", ""),
                ("192.0.2.10", "02:00:00:00:00:AA", "this", ""),
                ("192.0.2.20", "", "tv", "Living TV"),
                ("192.0.2.40", "02:00:00:00:00:40", "smart", ""),
            ]
        );
        assert_eq!(d[2].model, "Chromecast");
        assert!(!d[2].private_mac && d[2].vendor.is_empty(), "no hardware address: no maker");
        assert!(d[3].private_mac && d[3].vendor == "Ecobee");
        let j: serde_json::Value =
            serde_json::from_str(&to_json(&Look { status: "looked", mdns: "listened", listened: 8, devices: d, ..Look::default() }))
                .unwrap();
        assert_eq!(
            (j["status"].as_str(), j["mdns"].as_str(), j["devices"][2]["services"][0].as_str()),
            (Some("looked"), Some("listened"), Some("_googlecast._tcp"))
        );
        assert!(j["devices"][0].get("first_seen").is_none(), "a look keeps no times");
    }
}
