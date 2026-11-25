//! The service: look at the links, check them, work out the routing (plan.rs), make the kernel match it, and write what it
//! sees for Settings. One thread, one loop; it wakes once a second, and at once when the network changes.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::json;

use crate::config::{Config, Role};
use crate::ipjson::{self, Iface, TUNNEL_KINDS};
use crate::plan::{self, LinkPlan, Plan};
use crate::probe::{self, Health};
use crate::sys;
use crate::usage::{self, Usage};
use crate::weights::{self, Rate};

pub struct Paths {
    pub config: PathBuf,
    pub run: PathBuf,
    pub state: PathBuf,
}

impl Default for Paths {
    fn default() -> Self {
        Paths {
            config: "/etc/heimdall/multilink.json".into(),
            run: "/run/heimdall-multilink".into(),
            state: "/var/lib/heimdall-multilink".into(),
        }
    }
}

impl Paths {
    pub fn status(&self) -> PathBuf {
        self.run.join("status.json")
    }
    fn sysctl_orig(&self) -> PathBuf {
        self.run.join("sysctl.orig")
    }
    fn usage(&self) -> PathBuf {
        self.state.join("usage.json")
    }
}

/// A link: an interface with a default route in the main table that is not a tunnel.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Found {
    pub name: String,
    pub index: u32,
    pub up: bool,
    /// Some: it has an IPv4 default route (with this gateway, or none on a point-to-point link)
    pub gw4: Option<Option<IpAddr>>,
    pub gw6: Option<Option<IpAddr>>,
    pub addrs4: Vec<IpAddr>,
    pub addrs6: Vec<IpAddr>,
    pub dns: Vec<IpAddr>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Seen {
    pub links: Vec<Found>,
    /// A VPN carries everything (its interface, or "vpn"/"wireguard" from NetworkManager)
    pub vpn: Option<String>,
}

/// Look at the system as it is now.
pub fn discover(with_nm: bool) -> Result<Seen, String> {
    let ifaces = ipjson::ifaces(&sys::ip(&["-j", "-d", "link", "show"])?);
    let d4 = ipjson::defaults(&sys::ip(&["-j", "-4", "route", "show", "table", "main", "default"])?);
    let d6 = ipjson::defaults(&sys::ip(&["-j", "-6", "route", "show", "table", "main", "default"]).unwrap_or_default());
    let a4 = ipjson::addrs(&sys::ip(&["-j", "-4", "addr", "show"])?);
    let a6 = ipjson::addrs(&sys::ip(&["-j", "-6", "addr", "show"]).unwrap_or_default());
    let vpn = ipjson::vpn_route(&sys::ip(&["-j", "-4", "route", "show", "table", "all"]).unwrap_or_default(), &ifaces)
        .or_else(|| ipjson::vpn_route(&sys::ip(&["-j", "-6", "route", "show", "table", "all"]).unwrap_or_default(), &ifaces))
        .or_else(|| {
            with_nm
                .then(|| sys::nmcli(&["-t", "-f", "TYPE,DEVICE", "connection", "show", "--active"]))
                .flatten()
                .and_then(|t| ipjson::nm_vpn(&t))
        });
    let mut links: Vec<Found> = Vec::new();
    for d in d4.iter().chain(d6.iter()) {
        if links.iter().any(|l| l.name == d.dev) {
            continue;
        }
        let Some(i) = ifaces.iter().find(|i| i.name == d.dev) else { continue };
        if i.name == "lo" || i.kind.as_deref().is_some_and(|k| TUNNEL_KINDS.contains(&k)) {
            continue;
        }
        links.push(found(i, &d4, &d6, &a4, &a6));
    }
    if with_nm {
        for l in links.iter_mut() {
            if let Some(t) = sys::nmcli(&["-g", "IP4.DNS,IP6.DNS", "device", "show", &l.name]) {
                l.dns = ipjson::nm_dns(&t);
            }
        }
    }
    links.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(Seen { links, vpn })
}

fn found(i: &Iface, d4: &[ipjson::Default], d6: &[ipjson::Default], a4: &[(String, IpAddr)], a6: &[(String, IpAddr)]) -> Found {
    let addrs = |a: &[(String, IpAddr)]| a.iter().filter(|(d, _)| *d == i.name).map(|(_, ip)| *ip).collect();
    Found {
        name: i.name.clone(),
        index: i.index,
        up: i.up,
        gw4: d4.iter().find(|d| d.dev == i.name).map(|d| d.gateway),
        gw6: d6.iter().find(|d| d.dev == i.name).map(|d| d.gateway),
        addrs4: addrs(a4),
        addrs6: addrs(a6),
        dns: vec![],
    }
}

/// Remove every rule and route of ours (protocol 199) in both families. Used at the start (leftovers), at the end, by
/// `heimdall-multilink restore` (systemd's ExecStopPost, which runs after a crash too) and while a VPN is on.
pub fn clear_routing() -> Vec<String> {
    let mut errs = Vec::new();
    for f in ["-4", "-6"] {
        let rules = sys::ip(&["-j", f, "rule", "show"]).map(|t| ipjson::our_rules(&t)).unwrap_or_default();
        for r in rules {
            let mut a: Vec<String> = vec![f.into(), "rule".into(), "del".into()];
            a.extend(r.args());
            if let Err(e) = sys::ip(&a.iter().map(String::as_str).collect::<Vec<_>>()) {
                errs.push(e);
            }
        }
        let routes =
            sys::ip(&["-j", f, "route", "show", "table", "all", "proto", "199"]).map(|t| ipjson::our_routes(&t)).unwrap_or_default();
        for r in routes {
            let t = r.table.to_string();
            if let Err(e) = sys::ip(&[f, "route", "del", "default", "table", &t, "proto", "199"]) {
                errs.push(e);
            }
        }
    }
    errs
}

/// Back to normal: our routing gone, the sysctls as they were, no status file.
pub fn restore(paths: &Paths) -> Vec<String> {
    let errs = clear_routing();
    sys::sysctls_restore(&paths.sysctl_orig());
    let _ = std::fs::remove_file(paths.status());
    errs
}

/// Make the kernel's rules and routes of ours in one family match `want`: add what is missing, change what differs, remove
/// what is no longer wanted. Returns the errors (the rest is still done).
fn reconcile(fam: &str, want: &Plan) -> Vec<String> {
    let mut errs = Vec::new();
    let mut run = |a: Vec<String>| {
        if let Err(e) = sys::ip(&a.iter().map(String::as_str).collect::<Vec<_>>()) {
            errs.push(e);
            false
        } else {
            true
        }
    };
    let cur_rules = sys::ip(&["-j", fam, "rule", "show"]).map(|t| ipjson::our_rules(&t)).unwrap_or_default();
    let cur_routes =
        sys::ip(&["-j", fam, "route", "show", "table", "all", "proto", "199"]).map(|t| ipjson::our_routes(&t)).unwrap_or_default();
    // routes first, so a new rule never points at an empty table for long
    for r in &want.routes {
        if cur_routes.contains(r) {
            continue;
        }
        let mut a: Vec<String> = vec![fam.into(), "route".into(), "replace".into()];
        a.extend(r.args());
        if !run(a) {
            // an IPv6 multipath route that `replace` would not turn into another shape: remove it and add it again
            let t = r.table.to_string();
            run(vec![fam.into(), "route".into(), "del".into(), "default".into(), "table".into(), t, "proto".into(), "199".into()]);
            let mut a: Vec<String> = vec![fam.into(), "route".into(), "add".into()];
            a.extend(r.args());
            run(a);
        }
    }
    for r in &want.rules {
        if !cur_rules.contains(r) {
            let mut a: Vec<String> = vec![fam.into(), "rule".into(), "add".into()];
            a.extend(r.args());
            run(a);
        }
    }
    for r in cur_rules.iter().filter(|r| !want.rules.contains(r)) {
        let mut a: Vec<String> = vec![fam.into(), "rule".into(), "del".into()];
        a.extend(r.args());
        run(a);
    }
    for r in cur_routes.iter().filter(|r| !want.routes.iter().any(|w| w.table == r.table)) {
        run(vec![
            fam.into(),
            "route".into(),
            "del".into(),
            "default".into(),
            "table".into(),
            r.table.to_string(),
            "proto".into(),
            "199".into(),
        ]);
    }
    errs
}

#[derive(Default)]
struct LinkState {
    h4: Health,
    h6: Health,
    rate: Rate,
    /// the weights in the route now, per family
    w4: Option<u8>,
    w6: Option<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Active,
    Paused,
    Waiting,
}

pub struct Service {
    paths: Paths,
    with_nm: bool,
    cfg: Config,
    cfg_stamp: Option<SystemTime>,
    seen: Seen,
    links: BTreeMap<String, LinkState>,
    usage: Usage,
    usage_saved: Instant,
    plans: (Plan, Plan),
    /// the kernel may differ from `plans` (a network change happened since they were applied)
    dirty: bool,
    discovered: Option<Instant>,
    last_tick: Option<Instant>,
    last_probe: Option<Instant>,
    probe_round: usize,
    state: State,
    reason: String,
    status_text: String,
    started: u64,
}

fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

impl Service {
    pub fn new(paths: Paths, with_nm: bool) -> Service {
        let usage = Usage::load(&paths.usage());
        Service {
            paths,
            with_nm,
            cfg: Config::default(),
            cfg_stamp: None,
            seen: Seen::default(),
            links: BTreeMap::new(),
            usage,
            usage_saved: Instant::now(),
            plans: (Plan::default(), Plan::default()),
            dirty: true,
            discovered: None,
            last_tick: None,
            last_probe: None,
            probe_round: 0,
            state: State::Waiting,
            reason: String::new(),
            status_text: String::new(),
            started: unix_now(),
        }
    }

    fn load_config(&mut self) {
        let stamp = std::fs::metadata(&self.paths.config).and_then(|m| m.modified()).ok();
        if stamp == self.cfg_stamp && self.discovered.is_some() {
            return;
        }
        self.cfg_stamp = stamp;
        match Config::load(&self.paths.config) {
            Ok(c) => self.cfg = c,
            Err(e) => eprintln!("heimdall-multilink: {e}; keeping the settings I had"),
        }
    }

    /// The links this feature looks after: up, and not set to Off.
    fn managed(&self) -> Vec<&Found> {
        self.seen.links.iter().filter(|l| l.up && self.cfg.link(&l.name).role != Role::Off).collect()
    }

    fn over_cap(&self, name: &str) -> bool {
        let lc = self.cfg.link(name);
        lc.data_cap_mb.is_some_and(|cap| self.usage.used(name, &usage::period_key(lc.period, sys::today())) >= cap * 1_000_000)
    }

    fn probe(&mut self) {
        let timeout = Duration::from_millis(self.cfg.probe_every_ms.saturating_sub(100).clamp(100, 1500));
        let round = self.probe_round;
        self.probe_round += 1;
        let mut checks = Vec::new();
        let mut keys: Vec<(String, bool)> = Vec::new();
        for l in self.managed() {
            for (v6, gw, addrs, targets) in [(false, l.gw4, &l.addrs4, &self.cfg.probe4), (true, l.gw6, &l.addrs6, &self.cfg.probe6)] {
                let (Some(_), Some(src)) = (gw, addrs.first()) else { continue };
                let parsed: Vec<SocketAddr> = targets.iter().filter_map(|t| t.parse().ok()).collect();
                if parsed.is_empty() {
                    continue;
                }
                checks.push(probe::Check { dev: l.name.clone(), source: *src, target: parsed[round % parsed.len()] });
                keys.push((l.name.clone(), v6));
            }
        }
        let results = probe::run(&checks, timeout);
        for ((name, v6), r) in keys.into_iter().zip(results) {
            let s = self.links.entry(name).or_default();
            if v6 {
                s.h6.record(r);
            } else {
                s.h4.record(r);
            }
        }
    }

    /// One family's links with their weights (None: not in the multipath route now).
    fn family_plan(&mut self, v6: bool) -> Vec<LinkPlan> {
        let managed: Vec<Found> = self.managed().into_iter().cloned().collect();
        let usable: Vec<&Found> = managed
            .iter()
            .filter(|l| if v6 { l.gw6.is_some() && !l.addrs6.is_empty() } else { l.gw4.is_some() && !l.addrs4.is_empty() })
            .collect();
        let healthy = |s: &BTreeMap<String, LinkState>, n: &str| s.get(n).is_some_and(|s| if v6 { s.h6.up } else { s.h4.up });
        let primary: Vec<&Found> = usable
            .iter()
            .copied()
            .filter(|l| self.cfg.link(&l.name).role == Role::Use && !self.over_cap(&l.name) && healthy(&self.links, &l.name))
            .collect();
        // no link set to Use works: the backups (and the links past their cap) step in
        let group: Vec<&Found> =
            if primary.is_empty() { usable.iter().copied().filter(|l| healthy(&self.links, &l.name)).collect() } else { primary };
        let inputs: Vec<weights::Input> = group
            .iter()
            .map(|l| {
                let s = self.links.get(&l.name);
                weights::Input {
                    peak: s.map_or(0.0, |s| s.rate.peak),
                    rtt: s.and_then(|s| if v6 { s.h6.rtt } else { s.h4.rtt }),
                    share: self.cfg.link(&l.name).share,
                }
            })
            .collect();
        let new = weights::weights(&weights::shares(&inputs));
        let old: Vec<u8> = group.iter().filter_map(|l| self.links.get(&l.name).and_then(|s| if v6 { s.w6 } else { s.w4 })).collect();
        let keep = old.len() == new.len() && !weights::differ(&old, &new);
        let chosen = if keep { old } else { new };
        for s in self.links.values_mut() {
            if v6 {
                s.w6 = None;
            } else {
                s.w4 = None;
            }
        }
        for (l, w) in group.iter().zip(&chosen) {
            let s = self.links.entry(l.name.clone()).or_default();
            if v6 {
                s.w6 = Some(*w);
            } else {
                s.w4 = Some(*w);
            }
        }
        usable
            .iter()
            .map(|l| LinkPlan {
                dev: l.name.clone(),
                ifindex: l.index,
                gateway: if v6 { l.gw6.flatten() } else { l.gw4.flatten() },
                addrs: if v6 { l.addrs6.clone() } else { l.addrs4.clone() },
                dns: l.dns.iter().filter(|d| d.is_ipv6() == v6).copied().collect(),
                weight: self.links.get(&l.name).and_then(|s| if v6 { s.w6 } else { s.w4 }),
            })
            .collect()
    }

    fn set_state(&mut self, s: State, reason: String) {
        if s != self.state || reason != self.reason {
            let word = match s {
                State::Active => "spreading new connections",
                State::Paused => "paused",
                State::Waiting => "waiting",
            };
            eprintln!("heimdall-multilink: {word}{}{reason}", if reason.is_empty() { "" } else { ": " });
            sys::notify(&format!("STATUS={word}"));
        }
        self.state = s;
        self.reason = reason;
    }

    /// Once a second (and at once after a network change).
    pub fn tick(&mut self) {
        let now = Instant::now();
        let dt = self.last_tick.map_or(Duration::from_secs(1), |t| now - t);
        self.last_tick = Some(now);
        self.load_config();
        if self.dirty || self.discovered.is_none_or(|t| t.elapsed() > Duration::from_secs(30)) {
            match discover(self.with_nm) {
                Ok(s) => self.seen = s,
                Err(e) => eprintln!("heimdall-multilink: {e}"),
            }
            self.discovered = Some(now);
            let names: Vec<String> = self.seen.links.iter().map(|l| l.name.clone()).collect();
            self.links.retain(|n, _| names.contains(n));
        }
        // what each link carried
        let counters = sys::counters();
        let day = sys::today();
        for l in &self.seen.links {
            let Some((_, c)) = counters.iter().find(|(n, _)| *n == l.name) else { continue };
            let carried = self.links.entry(l.name.clone()).or_default().rate.update(*c, dt);
            let lc = self.cfg.link(&l.name);
            if lc.data_cap_mb.is_some() && carried > 0 {
                self.usage.add(&l.name, &usage::period_key(lc.period, day), carried);
            }
        }
        if self.usage_saved.elapsed() > Duration::from_secs(60) {
            self.save_usage();
        }
        let managed = self.managed().len();
        let (want4, want6) = if let Some(v) = self.seen.vpn.clone() {
            self.set_state(State::Paused, format!("a VPN carries everything ({v}): there is nothing to spread"));
            (Plan::default(), Plan::default())
        } else if managed < 2 {
            self.set_state(State::Waiting, "fewer than two connections are on".into());
            (Plan::default(), Plan::default())
        } else {
            if self.last_probe.is_none_or(|t| t.elapsed() >= Duration::from_millis(self.cfg.probe_every_ms)) {
                self.last_probe = Some(Instant::now());
                self.probe();
            }
            self.set_state(State::Active, String::new());
            let l4 = self.family_plan(false);
            let l6 = self.family_plan(true);
            (plan::plan(&l4), plan::plan(&l6))
        };
        if self.dirty || want4 != self.plans.0 || want6 != self.plans.1 {
            self.dirty = false;
            for e in reconcile("-4", &want4).into_iter().chain(reconcile("-6", &want6)) {
                eprintln!("heimdall-multilink: {e}");
            }
            self.plans = (want4, want6);
        }
        self.write_status();
        sys::notify("WATCHDOG=1");
    }

    fn save_usage(&mut self) {
        self.usage_saved = Instant::now();
        if let Err(e) = self.usage.save(&self.paths.usage()) {
            eprintln!("heimdall-multilink: {e}");
        }
    }

    pub fn status_json(&self) -> serde_json::Value {
        let total: f64 = self.seen.links.iter().filter_map(|l| self.links.get(&l.name)).map(|s| s.rate.now).sum();
        let round = |b: f64| ((b / 1000.0).round() * 1000.0) as u64;
        let links: Vec<serde_json::Value> = self
            .seen
            .links
            .iter()
            .map(|l| {
                let lc = self.cfg.link(&l.name);
                let s = self.links.get(&l.name);
                let rate = s.map_or(0.0, |s| s.rate.now);
                let key = usage::period_key(lc.period, sys::today());
                json!({
                    "name": l.name,
                    "role": lc.role.id(),
                    "up": l.up,
                    "ipv4": l.gw4.is_some(),
                    "ipv6": l.gw6.is_some(),
                    "healthy4": s.is_some_and(|s| s.h4.up),
                    "healthy6": s.is_some_and(|s| s.h6.up),
                    "weight4": s.and_then(|s| s.w4),
                    "weight6": s.and_then(|s| s.w6),
                    "rtt_ms": s.and_then(|s| s.h4.rtt.or(s.h6.rtt)).map(|d| d.as_millis() as u64),
                    "rate": round(rate),
                    "peak": round(s.map_or(0.0, |s| s.rate.peak)),
                    "share_now": if total >= 1000.0 { (rate / total * 100.0).round() as u64 } else { 0 },
                    "share_limit": lc.share,
                    "data_cap_mb": lc.data_cap_mb,
                    "period": lc.period.id(),
                    "used_bytes": self.usage.used(&l.name, &key),
                    "over_cap": self.over_cap(&l.name),
                })
            })
            .collect();
        json!({
            "state": match self.state { State::Active => "active", State::Paused => "paused", State::Waiting => "waiting" },
            "reason": self.reason,
            "since": self.started,
            "new_links": self.cfg.new_links.id(),
            "combined_rate": round(total),
            "links": links,
            "probe4": self.cfg.probe4,
            "probe6": self.cfg.probe6,
        })
    }

    fn write_status(&mut self) {
        let text = self.status_json().to_string() + "\n";
        if text != self.status_text {
            if let Err(e) = sys::write_atomic(&self.paths.status(), &text) {
                eprintln!("heimdall-multilink: {e}");
            }
            self.status_text = text;
        }
    }
}

/// The service's whole life: start clean, run until SIGTERM, leave clean.
pub fn run(paths: Paths, with_nm: bool) -> Result<(), String> {
    for d in [&paths.run, &paths.state] {
        std::fs::create_dir_all(d).map_err(|e| format!("{}: {e}", d.display()))?;
    }
    for e in clear_routing() {
        eprintln!("heimdall-multilink: leftovers: {e}");
    }
    let sig = sys::signal_fd().ok_or("signalfd failed")?;
    let nl = sys::netlink_wake().ok_or("the netlink socket could not be made")?;
    sys::sysctls_set(&paths.sysctl_orig())?;
    let mut svc = Service::new(paths, with_nm);
    sys::notify("READY=1");
    let tick = Duration::from_secs(1);
    loop {
        svc.tick();
        let until = Instant::now() + tick;
        loop {
            let left = until.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            let mut fds = [
                libc::pollfd { fd: sig.as_raw_fd(), events: libc::POLLIN, revents: 0 },
                libc::pollfd { fd: nl.as_raw_fd(), events: libc::POLLIN, revents: 0 },
            ];
            // SAFETY: fds is a live array of two pollfd
            let n = unsafe { libc::poll(fds.as_mut_ptr(), 2, left.as_millis().max(1) as libc::c_int) };
            if n < 0 && std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
                return Err("poll failed".into());
            }
            if fds[0].revents != 0 {
                svc.save_usage();
                let paths = std::mem::take(&mut svc.paths);
                for e in restore(&paths) {
                    eprintln!("heimdall-multilink: {e}");
                }
                eprintln!("heimdall-multilink: stopped; the normal routing is back");
                return Ok(());
            }
            if fds[1].revents != 0 {
                sys::drain(&nl);
                svc.dirty = true;
                // a burst of changes (NetworkManager bringing a link up) is looked at once it settles a little
                std::thread::sleep(Duration::from_millis(200));
                sys::drain(&nl);
                break;
            }
        }
    }
}

/// What `status` prints while the service is not running: the links it would look after, with the owner's choices.
pub fn status_when_off(paths: &Paths) -> serde_json::Value {
    let cfg = Config::load(&paths.config).unwrap_or_default();
    let seen = discover(false).unwrap_or_default();
    let links: Vec<serde_json::Value> = seen
        .links
        .iter()
        .map(|l| {
            let lc = cfg.link(&l.name);
            json!({"name": l.name, "role": lc.role.id(), "up": l.up, "ipv4": l.gw4.is_some(), "ipv6": l.gw6.is_some(),
                   "share_limit": lc.share, "data_cap_mb": lc.data_cap_mb, "period": lc.period.id()})
        })
        .collect();
    json!({"state": "off", "reason": "", "new_links": cfg.new_links.id(), "combined_rate": 0, "links": links,
           "probe4": cfg.probe4, "probe6": cfg.probe6})
}

/// The status file, if the service is running.
pub fn status_file(paths: &Paths) -> Option<serde_json::Value> {
    serde_json::from_str(&std::fs::read_to_string(paths.status()).ok()?).ok()
}
