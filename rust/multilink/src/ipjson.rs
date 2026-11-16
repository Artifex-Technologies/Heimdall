//! What the kernel has now, from iproute2's JSON (`ip -j`). Reading through `ip` keeps this crate free of a netlink
//! library: `ip` is in every Arch install (base), and its JSON is stable. The parsers take the text, so the tests feed
//! them recorded answers.

use std::net::IpAddr;

use crate::plan::{Nexthop, Route, Rule, PROTO};

/// One network interface.
#[derive(Clone, Debug, PartialEq)]
pub struct Iface {
    pub index: u32,
    pub name: String,
    /// The driver kind of a virtual interface (`wireguard`, `tun`, `veth`...); None for a real one.
    pub kind: Option<String>,
    pub up: bool,
}

/// A default route NetworkManager (or whoever manages the link) put in the main table.
#[derive(Clone, Debug, PartialEq)]
pub struct Default {
    pub dev: String,
    /// None: a point-to-point link, the route has no gateway.
    pub gateway: Option<IpAddr>,
    pub metric: u64,
}

/// Interfaces whose default route means "everything goes through a tunnel": a VPN. The feature pauses then.
pub const TUNNEL_KINDS: [&str; 12] =
    ["wireguard", "tun", "ipip", "gre", "gretap", "ip6gre", "ip6gretap", "vti", "vti6", "xfrm", "ip6tnl", "ovpn"];

fn parse(text: &str) -> Vec<serde_json::Value> {
    serde_json::from_str::<serde_json::Value>(text).ok().and_then(|v| v.as_array().cloned()).unwrap_or_default()
}

/// `ip -j -d link show`
pub fn ifaces(text: &str) -> Vec<Iface> {
    parse(text)
        .iter()
        .filter_map(|l| {
            Some(Iface {
                index: l.get("ifindex")?.as_u64()? as u32,
                name: l.get("ifname")?.as_str()?.to_string(),
                kind: l.pointer("/linkinfo/info_kind").and_then(|k| k.as_str()).map(String::from),
                up: l.get("flags").and_then(|f| f.as_array()).is_some_and(|f| f.iter().any(|x| x == "UP")),
            })
        })
        .collect()
}

/// `ip -j -4|-6 route show table main default`: one entry per device (its lowest metric), multipath routes split.
pub fn defaults(text: &str) -> Vec<Default> {
    let mut out: Vec<Default> = Vec::new();
    for r in parse(text) {
        if r.get("dst").and_then(|d| d.as_str()) != Some("default") {
            continue;
        }
        if r.get("type").and_then(|t| t.as_str()).is_some_and(|t| t != "unicast") {
            continue;
        }
        let metric = r.get("metric").and_then(|m| m.as_u64()).unwrap_or(0);
        let hops: Vec<serde_json::Value> = match r.get("nexthops").and_then(|n| n.as_array()) {
            Some(n) => n.clone(),
            None => vec![r.clone()],
        };
        for h in hops {
            let Some(dev) = h.get("dev").and_then(|d| d.as_str()) else { continue };
            let gateway = h.get("gateway").and_then(|g| g.as_str()).and_then(|g| g.parse().ok());
            match out.iter_mut().find(|d| d.dev == dev) {
                Some(d) if d.metric > metric => *d = Default { dev: dev.into(), gateway, metric },
                Some(_) => {}
                None => out.push(Default { dev: dev.into(), gateway, metric }),
            }
        }
    }
    out
}

/// `ip -j -4|-6 addr show`: each device's global addresses (link-local and host-only ones are no use as a source).
pub fn addrs(text: &str) -> Vec<(String, IpAddr)> {
    let mut out = Vec::new();
    for l in parse(text) {
        let Some(dev) = l.get("ifname").and_then(|d| d.as_str()) else { continue };
        for a in l.get("addr_info").and_then(|a| a.as_array()).into_iter().flatten() {
            if a.get("scope").and_then(|s| s.as_str()) != Some("global") || a.get("tentative").is_some() {
                continue;
            }
            if let Some(ip) = a.get("local").and_then(|x| x.as_str()).and_then(|x| x.parse().ok()) {
                out.push((dev.to_string(), ip));
            }
        }
    }
    out
}

fn table_id(v: Option<&serde_json::Value>) -> u32 {
    match v.and_then(|t| t.as_str()) {
        None | Some("main") => 254,
        Some("local") => 255,
        Some("default") => 253,
        Some(t) => t.parse().unwrap_or(0),
    }
}

fn with_len(addr: Option<&serde_json::Value>, len: Option<&serde_json::Value>) -> Option<String> {
    let a = addr?.as_str()?;
    if a == "all" {
        return None;
    }
    let host = if a.contains(':') { 128 } else { 32 };
    Some(format!("{a}/{}", len.and_then(|l| l.as_u64()).unwrap_or(host)))
}

/// `ip -j -4|-6 rule show`: only ours (protocol 199).
pub fn our_rules(text: &str) -> Vec<Rule> {
    parse(text)
        .iter()
        .filter(|r| r.get("protocol").and_then(|p| p.as_str()) == Some(&PROTO.to_string()))
        .map(|r| Rule {
            prio: r.get("priority").and_then(|p| p.as_u64()).unwrap_or(0) as u32,
            from: with_len(r.get("src"), r.get("srclen")),
            to: with_len(r.get("dst"), r.get("dstlen")),
            iif_lo: r.get("iif").and_then(|i| i.as_str()) == Some("lo"),
            fwmark0: r.get("fwmark").and_then(|m| m.as_str()).is_some_and(|m| m == "0" || m == "0/0xffffffff"),
            table: table_id(r.get("table")),
            suppress0: r.get("suppress_prefixlen").and_then(|s| s.as_u64()) == Some(0),
        })
        .collect()
}

/// `ip -j -4|-6 route show table all proto 199`: our default routes, one per table.
pub fn our_routes(text: &str) -> Vec<Route> {
    parse(text)
        .iter()
        .filter(|r| r.get("dst").and_then(|d| d.as_str()) == Some("default"))
        .map(|r| {
            let hops: Vec<serde_json::Value> = match r.get("nexthops").and_then(|n| n.as_array()) {
                Some(n) => n.clone(),
                None => vec![r.clone()],
            };
            let mut nexthops: Vec<Nexthop> = hops
                .iter()
                .filter_map(|h| {
                    Some(Nexthop {
                        gateway: h.get("gateway").and_then(|g| g.as_str()).and_then(|g| g.parse().ok()),
                        dev: h.get("dev")?.as_str()?.to_string(),
                        weight: h.get("weight").and_then(|w| w.as_u64()).unwrap_or(1).clamp(1, 255) as u8,
                    })
                })
                .collect();
            if nexthops.len() == 1 {
                nexthops[0].weight = 1;
            }
            nexthops.sort();
            Route { table: table_id(r.get("table")), nexthops }
        })
        .collect()
}

/// A route (in any table) that sends everything, or each half of everything, through a tunnel: a VPN is on. Returns the
/// tunnel's name.
pub fn vpn_route(routes_all: &str, ifaces: &[Iface]) -> Option<String> {
    const WHOLE: [&str; 6] = ["default", "0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1", "::/0"];
    for r in parse(routes_all) {
        if !r.get("dst").and_then(|d| d.as_str()).is_some_and(|d| WHOLE.contains(&d)) {
            continue;
        }
        if r.get("type").and_then(|t| t.as_str()).is_some_and(|t| t != "unicast") {
            continue;
        }
        let devs: Vec<String> = match r.get("nexthops").and_then(|n| n.as_array()) {
            Some(n) => n.iter().filter_map(|h| h.get("dev").and_then(|d| d.as_str()).map(String::from)).collect(),
            None => r.get("dev").and_then(|d| d.as_str()).map(String::from).into_iter().collect(),
        };
        for d in devs {
            if ifaces.iter().any(|i| i.name == d && i.kind.as_deref().is_some_and(|k| TUNNEL_KINDS.contains(&k))) {
                return Some(d);
            }
        }
    }
    None
}

/// `nmcli -t -f TYPE,DEVICE connection show --active`: an active VPN or WireGuard connection, by device (or its type).
pub fn nm_vpn(text: &str) -> Option<String> {
    text.lines().find_map(|l| {
        let (ty, dev) = l.split_once(':').unwrap_or((l, ""));
        matches!(ty, "vpn" | "wireguard").then(|| if dev.is_empty() { ty.to_string() } else { dev.replace("\\:", ":") })
    })
}

/// `nmcli -g IP4.DNS,IP6.DNS device show DEV`: the device's DNS servers (lines, values split by " | ").
pub fn nm_dns(text: &str) -> Vec<IpAddr> {
    text.lines().flat_map(|l| l.split('|')).filter_map(|s| s.trim().replace("\\:", ":").parse().ok()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn links_and_their_kinds() {
        let t = r#"[{"ifindex":1,"ifname":"lo","flags":["LOOPBACK","UP"]},
            {"ifindex":3,"ifname":"wlan0","flags":["BROADCAST","UP","LOWER_UP"]},
            {"ifindex":9,"ifname":"wg0","flags":["UP"],"linkinfo":{"info_kind":"wireguard"}},
            {"ifindex":4,"ifname":"eth0","flags":["BROADCAST"]}]"#;
        let i = ifaces(t);
        assert_eq!(i.len(), 4);
        assert_eq!(i[2].kind.as_deref(), Some("wireguard"));
        assert!(i[1].up && !i[3].up);
    }

    #[test]
    fn default_routes_lowest_metric_per_device() {
        let t = r#"[{"dst":"default","gateway":"192.0.2.1","dev":"wlan0","protocol":"dhcp","metric":600,"flags":[]},
            {"dst":"default","gateway":"192.0.2.9","dev":"wlan0","metric":20600,"flags":[]},
            {"dst":"default","dev":"ppp0","metric":50,"flags":[]},
            {"type":"unreachable","dst":"default","dev":"lo","metric":4278198272,"flags":[]},
            {"dst":"default","nexthops":[{"gateway":"198.51.100.1","dev":"usb0","weight":1}],"metric":100}]"#;
        let d = defaults(t);
        assert_eq!(d.len(), 3);
        assert_eq!(d[0].gateway, Some("192.0.2.1".parse().unwrap()));
        assert_eq!(d[1].gateway, None);
        assert_eq!(d[2].dev, "usb0");
    }

    #[test]
    fn global_addresses_only() {
        let t = r#"[{"ifname":"wlan0","addr_info":[{"family":"inet6","local":"2001:db8::5","prefixlen":64,"scope":"global"},
            {"family":"inet6","local":"fe80::1","prefixlen":64,"scope":"link"},
            {"family":"inet6","local":"2001:db8::6","prefixlen":64,"scope":"global","tentative":true}]}]"#;
        assert_eq!(addrs(t), vec![("wlan0".to_string(), "2001:db8::5".parse().unwrap())]);
    }

    #[test]
    fn our_rules_and_routes_read_back() {
        let rules = r#"[{"priority":0,"src":"all","table":"local"},
            {"priority":32000,"src":"all","table":"main","suppress_prefixlen":0,"protocol":"199"},
            {"priority":32002,"src":"10.1.0.2","table":"7700003","protocol":"199","fwmark":"0"},
            {"priority":32001,"src":"all","dst":"192.0.2.53","dstlen":32,"iif":"lo","fwmark":"0","table":"7700003","protocol":"199"},
            {"priority":32003,"src":"all","fwmark":"0","iif":"lo","table":"7700000","protocol":"199"},
            {"priority":32766,"src":"all","table":"main"}]"#;
        let r = our_rules(rules);
        assert_eq!(r.len(), 4);
        assert!(r[0].suppress0 && r[0].table == 254);
        assert_eq!(r[1].from.as_deref(), Some("10.1.0.2/32"));
        assert_eq!(r[2].to.as_deref(), Some("192.0.2.53/32"));
        assert!(r[3].iif_lo && r[3].fwmark0 && r[3].table == 7_700_000);
        let routes = r#"[{"dst":"default","table":"7700000","protocol":"199","flags":[],"nexthops":[
            {"gateway":"10.2.0.1","dev":"p2","weight":3,"flags":["onlink"]},{"gateway":"10.1.0.1","dev":"p1","weight":7,"flags":["onlink"]}]},
            {"dst":"default","gateway":"10.1.0.1","dev":"p1","table":"7700003","protocol":"199","flags":["onlink"]}]"#;
        let r = our_routes(routes);
        assert_eq!(r[0].nexthops[0].dev, "p1", "sorted");
        assert_eq!(r[0].nexthops[0].weight, 7);
        assert_eq!(r[1].table, 7_700_003);
    }

    #[test]
    fn a_vpn_is_a_whole_or_half_default_through_a_tunnel() {
        let i = ifaces(
            r#"[{"ifindex":3,"ifname":"wlan0","flags":["UP"]},{"ifindex":5,"ifname":"tun0","flags":["UP"],"linkinfo":{"info_kind":"tun"}},
            {"ifindex":6,"ifname":"tailscale0","flags":["UP"],"linkinfo":{"info_kind":"tun"}}]"#,
        );
        // Tailscale without an exit node: only its own network's routes
        let quiet = r#"[{"dst":"default","gateway":"192.0.2.1","dev":"wlan0","flags":[]},{"dst":"100.64.0.0/10","dev":"tailscale0","table":"52","flags":[]}]"#;
        assert_eq!(vpn_route(quiet, &i), None);
        let openvpn = r#"[{"dst":"0.0.0.0/1","gateway":"10.8.0.1","dev":"tun0","flags":[]}]"#;
        assert_eq!(vpn_route(openvpn, &i).as_deref(), Some("tun0"));
        let exit_node = r#"[{"dst":"default","dev":"tailscale0","table":"52","flags":[]}]"#;
        assert_eq!(vpn_route(exit_node, &i).as_deref(), Some("tailscale0"));
    }

    #[test]
    fn networkmanager_answers() {
        assert_eq!(nm_vpn("802-11-wireless:wlan0\nwireguard:wg0\n").as_deref(), Some("wg0"));
        assert_eq!(nm_vpn("802-3-ethernet:eth0\n"), None);
        let d = nm_dns("192.0.2.53 | 198.51.100.53\n2001\\:db8\\:\\:53\n");
        assert_eq!(d.len(), 3);
        assert_eq!(d[2], "2001:db8::53".parse::<IpAddr>().unwrap());
    }
}
