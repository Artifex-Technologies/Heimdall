//! The routing this feature wants, worked out from the links. Nothing here touches the kernel; `apply` compares it with
//! what is there and changes only the difference.
//!
//! NetworkManager's routes in the main table are never touched. Ours live in tables of our own, reached by rules of our
//! own (all tagged protocol 199), placed just before the main table's rule (32766):
//!
//! | priority | rule | why |
//! |---|---|---|
//! | 32000 | `lookup main suppress_prefixlength 0` | every route of the main table but the default one keeps working as before (the local network, Limbo's bridges, Tailscale's addresses) |
//! | 32001 | `to DNS iif lo fwmark 0 lookup LINK` | a link's DNS server is asked over that link (an internet provider's server may answer its own customers only) |
//! | 32002 | `from ADDR fwmark 0 lookup LINK` | a connection that has a link's address stays on that link: established connections never move, the health checks test the link they are for, and replies pass the kernel's reverse path check |
//! | 32003 | `iif lo fwmark 0 lookup 7700000` | new connections of this computer's own programs take the multipath default route |
//!
//! Only traffic this computer makes (`iif lo`) and that nothing else marked (`fwmark 0`) is spread: forwarded traffic (Limbo's
//! guests, containers) and anything another program routes by mark (a VPN, Tailscale) keep their own way. When the rules or
//! tables are gone (the service stopped, or crashed and systemd ran `restore`), every lookup falls through to the main table:
//! NetworkManager's normal routing, untouched.

use std::net::IpAddr;

/// The protocol number on every rule and route of ours (rt_protos has no 199): `restore` removes exactly these.
pub const PROTO: u32 = 199;
pub const PRIO_MAIN: u32 = 32000;
pub const PRIO_DNS: u32 = 32001;
pub const PRIO_FROM: u32 = 32002;
pub const PRIO_SPREAD: u32 = 32003;
/// The multipath table; a link's own table is this plus its interface index.
pub const TABLE_SPREAD: u32 = 7_700_000;
pub const MAIN: u32 = 254;

pub fn link_table(ifindex: u32) -> u32 {
    TABLE_SPREAD + ifindex.min(1_000_000)
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Rule {
    pub prio: u32,
    /// "ADDR/LEN"
    pub from: Option<String>,
    pub to: Option<String>,
    pub iif_lo: bool,
    pub fwmark0: bool,
    pub table: u32,
    pub suppress0: bool,
}

impl Rule {
    /// The words after `ip rule add|del`.
    pub fn args(&self) -> Vec<String> {
        let mut a = vec!["priority".to_string(), self.prio.to_string()];
        if let Some(f) = &self.from {
            a.extend(["from".into(), f.clone()]);
        }
        if let Some(t) = &self.to {
            a.extend(["to".into(), t.clone()]);
        }
        if self.iif_lo {
            a.extend(["iif".into(), "lo".into()]);
        }
        if self.fwmark0 {
            a.extend(["fwmark".into(), "0/0xffffffff".into()]);
        }
        a.extend(["lookup".into(), if self.table == MAIN { "main".into() } else { self.table.to_string() }]);
        if self.suppress0 {
            a.extend(["suppress_prefixlength".into(), "0".into()]);
        }
        a.extend(["protocol".into(), PROTO.to_string()]);
        a
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Nexthop {
    /// None: straight out of the device (a point-to-point link)
    pub gateway: Option<IpAddr>,
    pub dev: String,
    pub weight: u8,
}

/// The default route of one of our tables.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Route {
    pub table: u32,
    /// Sorted; one nexthop has weight 1.
    pub nexthops: Vec<Nexthop>,
}

impl Route {
    /// The words after `ip route replace`.
    pub fn args(&self) -> Vec<String> {
        let mut a: Vec<String> = vec!["default".into(), "table".into(), self.table.to_string(), "proto".into(), PROTO.to_string()];
        let hop = |a: &mut Vec<String>, h: &Nexthop| {
            if let Some(g) = h.gateway {
                a.extend(["via".into(), g.to_string()]);
            }
            a.extend(["dev".into(), h.dev.clone()]);
        };
        if let [h] = self.nexthops.as_slice() {
            hop(&mut a, h);
            if h.gateway.is_some() {
                a.push("onlink".into());
            }
        } else {
            for h in &self.nexthops {
                a.push("nexthop".into());
                hop(&mut a, h);
                a.extend(["weight".into(), h.weight.to_string()]);
                if h.gateway.is_some() {
                    a.push("onlink".into());
                }
            }
        }
        a
    }
}

/// One link as one address family sees it.
#[derive(Clone, Debug, PartialEq)]
pub struct LinkPlan {
    pub dev: String,
    pub ifindex: u32,
    pub gateway: Option<IpAddr>,
    pub addrs: Vec<IpAddr>,
    pub dns: Vec<IpAddr>,
    /// In the multipath route, with this weight (1-100); None: not now (down, backup, over its cap).
    pub weight: Option<u8>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Plan {
    pub rules: Vec<Rule>,
    pub routes: Vec<Route>,
}

/// The rules and routes of one address family. `links` are the links this feature looks after (not the ones set to Off);
/// with none of them in the multipath route, the spreading rule goes too and everything takes the main table.
pub fn plan(links: &[LinkPlan]) -> Plan {
    let mut p = Plan::default();
    if links.is_empty() {
        return p;
    }
    p.rules.push(Rule { prio: PRIO_MAIN, from: None, to: None, iif_lo: false, fwmark0: false, table: MAIN, suppress0: true });
    let mut dns_seen: Vec<IpAddr> = Vec::new();
    for l in links {
        let t = link_table(l.ifindex);
        p.routes.push(Route { table: t, nexthops: vec![Nexthop { gateway: l.gateway, dev: l.dev.clone(), weight: 1 }] });
        for a in &l.addrs {
            let len = if a.is_ipv6() { 128 } else { 32 };
            p.rules.push(Rule {
                prio: PRIO_FROM,
                from: Some(format!("{a}/{len}")),
                to: None,
                iif_lo: false,
                fwmark0: true,
                table: t,
                suppress0: false,
            });
        }
        for d in &l.dns {
            // a server on a link's own network is reached through the main table already; one asked on two links once
            if dns_seen.contains(d) || d.is_loopback() {
                continue;
            }
            dns_seen.push(*d);
            let len = if d.is_ipv6() { 128 } else { 32 };
            p.rules.push(Rule {
                prio: PRIO_DNS,
                from: None,
                to: Some(format!("{d}/{len}")),
                iif_lo: true,
                fwmark0: true,
                table: t,
                suppress0: false,
            });
        }
    }
    let mut hops: Vec<Nexthop> =
        links.iter().filter_map(|l| l.weight.map(|w| Nexthop { gateway: l.gateway, dev: l.dev.clone(), weight: w.max(1) })).collect();
    if !hops.is_empty() {
        if hops.len() == 1 {
            hops[0].weight = 1;
        }
        hops.sort();
        p.routes.push(Route { table: TABLE_SPREAD, nexthops: hops });
        p.rules.push(Rule { prio: PRIO_SPREAD, from: None, to: None, iif_lo: true, fwmark0: true, table: TABLE_SPREAD, suppress0: false });
    }
    p.rules.sort();
    p.routes.sort();
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    fn link(dev: &str, idx: u32, gw: &str, addr: &str, weight: Option<u8>) -> LinkPlan {
        LinkPlan {
            dev: dev.into(),
            ifindex: idx,
            gateway: Some(gw.parse().unwrap()),
            addrs: vec![addr.parse().unwrap()],
            dns: vec![],
            weight,
        }
    }

    #[test]
    fn two_links_give_a_multipath_route_and_source_rules() {
        let p = plan(&[link("p1", 3, "10.1.0.1", "10.1.0.2", Some(70)), link("p2", 4, "10.2.0.1", "10.2.0.2", Some(30))]);
        let spread = p.routes.iter().find(|r| r.table == TABLE_SPREAD).unwrap();
        assert_eq!(spread.nexthops.len(), 2);
        assert_eq!(
            spread.args().join(" "),
            "default table 7700000 proto 199 nexthop via 10.1.0.1 dev p1 weight 70 onlink nexthop via 10.2.0.1 dev p2 weight 30 onlink"
        );
        assert!(p.rules.iter().any(|r| r.from.as_deref() == Some("10.1.0.2/32") && r.table == 7_700_003));
        let spread_rule = p.rules.iter().find(|r| r.prio == PRIO_SPREAD).unwrap();
        assert_eq!(spread_rule.args().join(" "), "priority 32003 iif lo fwmark 0/0xffffffff lookup 7700000 protocol 199");
        assert_eq!(p.rules[0].args().join(" "), "priority 32000 lookup main suppress_prefixlength 0 protocol 199");
    }

    #[test]
    fn a_link_out_of_the_group_keeps_its_own_table_and_source_rule() {
        let p = plan(&[link("p1", 3, "10.1.0.1", "10.1.0.2", Some(70)), link("p2", 4, "10.2.0.1", "10.2.0.2", None)]);
        let spread = p.routes.iter().find(|r| r.table == TABLE_SPREAD).unwrap();
        assert_eq!(spread.args().join(" "), "default table 7700000 proto 199 via 10.1.0.1 dev p1 onlink");
        assert!(p.routes.iter().any(|r| r.table == 7_700_004));
    }

    #[test]
    fn nothing_usable_means_no_spreading_rule() {
        let p = plan(&[link("p1", 3, "10.1.0.1", "10.1.0.2", None)]);
        assert!(p.rules.iter().all(|r| r.prio != PRIO_SPREAD));
        assert!(p.routes.iter().all(|r| r.table != TABLE_SPREAD));
        assert_eq!(plan(&[]), Plan::default());
    }

    #[test]
    fn dns_servers_once_and_point_to_point_links() {
        let mut a = link("p1", 3, "10.1.0.1", "10.1.0.2", Some(1));
        a.dns = vec!["192.0.2.53".parse().unwrap(), "127.0.0.1".parse().unwrap()];
        let b = LinkPlan {
            dev: "ppp0".into(),
            ifindex: 7,
            gateway: None,
            addrs: vec![],
            dns: vec!["192.0.2.53".parse().unwrap()],
            weight: Some(1),
        };
        let p = plan(&[a, b]);
        let dns: Vec<_> = p.rules.iter().filter(|r| r.prio == PRIO_DNS).collect();
        assert_eq!(dns.len(), 1);
        assert_eq!(dns[0].args().join(" "), "priority 32001 to 192.0.2.53/32 iif lo fwmark 0/0xffffffff lookup 7700003 protocol 199");
        let ppp = p.routes.iter().find(|r| r.table == 7_700_007).unwrap();
        assert_eq!(ppp.args().join(" "), "default table 7700007 proto 199 dev ppp0");
    }
}
