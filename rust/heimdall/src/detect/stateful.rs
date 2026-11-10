//! The detectors that reason across events (Go: burst.go, pressure.go, stats.go, baseline.go, agentbaseline.go, inbound.go,
//! limbo.go, remoteaccess.go).

use crate::event::{Detector, Event, Finding, Severity};
use crate::gojson::{self, FromGo, ObjectWriter, Value};
use crate::gonet;
use crate::gotext::{self, fixed, quote};
use crate::gotime::Time;
use std::collections::{BTreeMap, BTreeSet, HashMap};

const SEC: i64 = 1_000_000_000;

/// Go's `Duration.Seconds()`, computed the same way so the float is the same.
pub fn seconds(d: i64) -> f64 {
    let s = d / SEC;
    let ns = d % SEC;
    s as f64 + ns as f64 / 1e9
}

/// An unusually high rate of new agent sessions: a leaky bucket that drains at threshold/window per second.
pub struct BurstDetector {
    window: i64,
    threshold: f64,
    leak_rate: f64,
    cooldown: i64,
    level: f64,
    last_event: Time,
    last_finding: Time,
}

impl BurstDetector {
    /// window and cooldown in nanoseconds.
    pub fn new(window: i64, threshold: i64, cooldown: i64) -> Self {
        let t = threshold as f64;
        BurstDetector {
            window,
            threshold: t,
            leak_rate: t / seconds(window),
            cooldown,
            level: 0.0,
            last_event: Time::default(),
            last_finding: Time::default(),
        }
    }
}

impl Detector for BurstDetector {
    fn id(&self) -> &'static str {
        "session-burst"
    }
    fn inspect(&mut self, e: &Event) -> Vec<Finding> {
        if e.kind != "session_created" {
            return Vec::new();
        }
        if !self.last_event.is_zero() {
            let elapsed = seconds(e.time.sub(&self.last_event));
            if elapsed > 0.0 {
                self.level -= self.leak_rate * elapsed;
                if self.level < 0.0 {
                    self.level = 0.0;
                }
            }
        }
        self.last_event = e.time;
        self.level += 1.0;
        if self.level < self.threshold {
            return Vec::new();
        }
        if !self.last_finding.is_zero() && e.time.sub(&self.last_finding) < self.cooldown {
            return Vec::new();
        }
        self.last_finding = e.time;
        self.level = 0.0;
        let summary = format!(
            "session creation rate exceeded {} per {} -- unusually high rate for single-operator use",
            self.threshold as i64,
            gotext::duration(self.window)
        );
        vec![Finding::new(self.id(), Severity::Critical, summary, e)]
    }
}

/// Memory or load at or above a threshold: one alert when it starts, quiet until it clears.
pub struct ResourcePressureDetector {
    mem: f64,
    load: f64,
    over_mem: bool,
    over_load: bool,
}

impl ResourcePressureDetector {
    pub fn new(mem_threshold_percent: f64, load_threshold_per_cpu: f64) -> Self {
        ResourcePressureDetector { mem: mem_threshold_percent, load: load_threshold_per_cpu, over_mem: false, over_load: false }
    }
}

impl Detector for ResourcePressureDetector {
    fn id(&self) -> &'static str {
        "resource-pressure"
    }
    fn inspect(&mut self, e: &Event) -> Vec<Finding> {
        if e.kind != "host_telemetry" {
            return Vec::new();
        }
        let mut out = Vec::new();
        if let Some(m) = gotext::parse_float(e.f("mem_percent")) {
            let over = m >= self.mem;
            if over && !self.over_mem {
                out.push(Finding::new(
                    self.id(),
                    Severity::Warning,
                    format!(
                    "host memory usage is {}%, at or above the {}% threshold -- detection reliability may degrade under sustained pressure",
                    fixed(m, 1), fixed(self.mem, 1)),
                    e,
                ));
            }
            self.over_mem = over;
        }
        if let Some(l) = gotext::parse_float(e.f("load_per_cpu")) {
            let over = l >= self.load;
            if over && !self.over_load {
                out.push(Finding::new(
                    self.id(),
                    Severity::Warning,
                    format!("host load average is {} per core, at or above the {} threshold", fixed(l, 2), fixed(self.load, 2)),
                    e,
                ));
            }
            self.over_load = over;
        }
        out
    }
}

/// A running mean and variance (Welford's algorithm).
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct OnlineStats {
    count: i64,
    mean: f64,
    m2: f64,
}

impl OnlineStats {
    pub fn add(&mut self, x: f64) {
        self.count += 1;
        let delta = x - self.mean;
        self.mean += delta / self.count as f64;
        let delta2 = x - self.mean;
        self.m2 += delta * delta2;
    }
    pub fn count(&self) -> i64 {
        self.count
    }
    pub fn mean(&self) -> f64 {
        self.mean
    }
    /// The sample standard deviation; 0 below two samples.
    pub fn std_dev(&self) -> f64 {
        if self.count < 2 {
            return 0.0;
        }
        (self.m2 / (self.count - 1) as f64).sqrt()
    }
    pub fn z_score(&self, x: f64) -> f64 {
        let sd = self.std_dev();
        if sd == 0.0 {
            return 0.0;
        }
        (x - self.mean) / sd
    }

    /// The state file form, `{"count":N,"mean":F,"m2":F}`.
    pub fn write(&self, out: &mut String) {
        let mut w = ObjectWriter::new(out);
        w.raw("count", &self.count.to_string());
        gojson::write_f64(w.key("mean"), self.mean);
        gojson::write_f64(w.key("m2"), self.m2);
        w.end();
    }
}

#[derive(Default)]
struct StatsJson {
    count: i64,
    mean: f64,
    m2: f64,
}
crate::go_struct!(StatsJson { count: "count", mean: "mean", m2: "m2" });

impl FromGo for OnlineStats {
    fn read_into(&mut self, v: &Value, field: &str) -> Result<(), gojson::Error> {
        let mut j = StatsJson::default();
        j.read_into(v, field)?;
        if j.count < 0 || j.mean.is_nan() || j.m2.is_nan() || j.m2 < 0.0 {
            return Err(gojson::Error("stats: damaged".into()));
        }
        *self = OnlineStats { count: j.count, mean: j.mean, m2: j.m2 };
        Ok(())
    }
}

/// The floors below which an outlier is not reported (memory in percent, load per CPU).
pub fn default_baseline_floors() -> BTreeMap<String, f64> {
    BTreeMap::from([("mem_percent".to_string(), 85.0), ("load_per_cpu".to_string(), 1.5)])
}

/// A host_telemetry value far from this host's own learned baseline (z-score), edge-triggered per field.
pub struct BaselineDriftDetector {
    min_samples: i64,
    z: f64,
    stats: BTreeMap<&'static str, OnlineStats>,
    flagged: BTreeMap<&'static str, bool>,
    floors: Option<BTreeMap<String, f64>>,
}

impl BaselineDriftDetector {
    pub fn new(min_samples: i64, z: f64) -> Self {
        BaselineDriftDetector { min_samples, z, stats: BTreeMap::new(), flagged: BTreeMap::new(), floors: None }
    }
    /// As the daemon runs it: upward outliers only, and only above the floors.
    pub fn with_floors(min_samples: i64, z: f64, floors: BTreeMap<String, f64>) -> Self {
        BaselineDriftDetector { floors: Some(floors), ..Self::new(min_samples, z) }
    }
}

impl Detector for BaselineDriftDetector {
    fn id(&self) -> &'static str {
        "baseline-drift"
    }
    fn inspect(&mut self, e: &Event) -> Vec<Finding> {
        if e.kind != "host_telemetry" {
            return Vec::new();
        }
        let mut out = Vec::new();
        for key in ["mem_percent", "load_per_cpu"] {
            let Some(raw) = e.fields.get(key) else { continue };
            let Some(val) = gotext::parse_float(raw) else { continue };
            let stats = self.stats.entry(key).or_default();
            if stats.count() >= self.min_samples {
                let z = stats.z_score(val);
                let mut over = z >= self.z || z <= -self.z;
                if let Some(fl) = &self.floors {
                    over = over && z > 0.0 && val >= fl.get(key).copied().unwrap_or(0.0);
                }
                if over && !self.flagged.get(key).copied().unwrap_or(false) {
                    out.push(Finding::new("baseline-drift", Severity::Info, format!(
                        "{key} is {}, {} standard deviations from this host's own learned baseline (mean {}, stddev {}) -- statistically unusual for this machine, not just over a fixed threshold",
                        fixed(val, 2), fixed(z, 1), fixed(stats.mean(), 2), fixed(stats.std_dev(), 2)), e));
                }
                self.flagged.insert(key, over);
            }
            stats.add(val);
        }
        out
    }
}

/// The agent baseline's state file (Go: agentBaselineState).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct AgentBaselineState {
    pub window: Time,
    pub counts: BTreeMap<String, f64>,
    pub stats: BTreeMap<String, OnlineStats>,
    pub tools: BTreeMap<String, i64>,
    pub calls: i64,
    pub reported: BTreeMap<String, bool>,
}
crate::go_struct!(AgentBaselineState {
    window: "window",
    counts: "counts",
    stats: "stats",
    tools: "tools",
    calls: "calls",
    reported: "reported_tools",
});

impl AgentBaselineState {
    /// As Go's json.Marshal writes it: fields in order, map keys sorted.
    pub fn to_json(&self) -> String {
        let mut out = String::new();
        let mut w = ObjectWriter::new(&mut out);
        w.str("window", &self.window.rfc3339_nano());
        let o = w.key("counts");
        map_json(o, &self.counts, |o, v| gojson::write_f64(o, *v));
        let o = w.key("stats");
        map_json(o, &self.stats, |o, v| v.write(o));
        let o = w.key("tools");
        map_json(o, &self.tools, |o, v| o.push_str(&v.to_string()));
        w.raw("calls", &self.calls.to_string());
        let o = w.key("reported_tools");
        map_json(o, &self.reported, |o, v| o.push_str(if *v { "true" } else { "false" }));
        w.end();
        out
    }
}

fn map_json<T>(o: &mut String, m: &BTreeMap<String, T>, mut val: impl FnMut(&mut String, &T)) {
    o.push('{');
    for (i, (k, v)) in m.iter().enumerate() {
        if i > 0 {
            o.push(',');
        }
        gojson::write_str(o, k);
        o.push(':');
        val(o, v);
    }
    o.push('}');
}

/// How many tool calls must have been seen before a new tool name counts as novel.
const MIN_TOOL_HISTORY: i64 = 200;

/// The AI agent's own learned baseline: sessions and tool calls per 15-minute window, and tools it never used before.
pub struct AgentBaselineDetector {
    pub min_samples: i64,
    pub z: f64,
    pub state_path: String,
    /// Window length in nanoseconds.
    pub window: i64,
    loaded: bool,
    st: AgentBaselineState,
    flagged: BTreeSet<&'static str>,
}

impl AgentBaselineDetector {
    pub fn new(min_samples: i64, z: f64, state_path: &str) -> Self {
        AgentBaselineDetector {
            min_samples,
            z,
            state_path: state_path.to_owned(),
            window: 15 * 60 * SEC,
            loaded: false,
            st: AgentBaselineState::default(),
            flagged: BTreeSet::new(),
        }
    }

    fn load(&mut self) {
        self.loaded = true;
        self.flagged.clear();
        if !self.state_path.is_empty() {
            if let Ok(b) = std::fs::read(&self.state_path) {
                // Go ignores a damaged file (keeping what it read before the damage); a file that does not read is a fresh start
                if let Ok(v) = gojson::parse(&b) {
                    let mut st = AgentBaselineState::default();
                    let _ = st.read_into(&v, "");
                    self.st = st;
                }
            }
        }
    }

    fn save(&self) {
        if self.state_path.is_empty() {
            return;
        }
        let tmp = format!("{}.tmp", self.state_path);
        if crate::state::write_private(&tmp, self.st.to_json().as_bytes()).is_ok() {
            let _ = std::fs::rename(&tmp, &self.state_path);
        }
    }
}

const SIGNALS: [&str; 2] = ["sessions", "tool_calls"];

fn floor(sig: &str) -> f64 {
    match sig {
        "sessions" => 10.0,
        "tool_calls" => 60.0,
        _ => 0.0,
    }
}

impl Detector for AgentBaselineDetector {
    fn id(&self) -> &'static str {
        "agent-baseline"
    }
    fn inspect(&mut self, e: &Event) -> Vec<Finding> {
        if e.source != "agent-session" || (e.kind != "session_created" && e.kind != "message") {
            return Vec::new();
        }
        if !self.loaded {
            self.load();
        }
        let w = if self.window <= 0 { 15 * 60 * SEC } else { self.window };
        let now = if e.time.is_zero() { Time::now() } else { e.time };
        let start = now.truncate(w);
        let mut save = false;
        if start != self.st.window && start.after(&self.st.window) {
            if !self.st.counts.is_empty() {
                for sig in SIGNALS {
                    let v = self.st.counts.get(sig).copied().unwrap_or(0.0);
                    self.st.stats.entry(sig.to_owned()).or_default().add(v);
                }
            }
            self.st.window = start;
            self.st.counts.clear();
            self.flagged.clear();
            save = true;
        }
        let mut out = Vec::new();
        let mut done = false;
        match e.kind.as_str() {
            "session_created" => *self.st.counts.entry("sessions".into()).or_default() += 1.0,
            _ => {
                let tools = e.f("tools");
                if tools.is_empty() {
                    *self.st.counts.entry("messages".into()).or_default() += 1.0; // keeps the window active
                    done = true;
                } else {
                    let names: Vec<&str> = tools.split(',').collect();
                    *self.st.counts.entry("tool_calls".into()).or_default() += names.len() as f64;
                    for n in names {
                        let seen = self.st.tools.get(n).copied().unwrap_or(0);
                        if self.st.calls >= MIN_TOOL_HISTORY && seen == 0 && !self.st.reported.get(n).copied().unwrap_or(false) {
                            self.st.reported.insert(n.to_owned(), true);
                            out.push(Finding::new(
                                self.id(),
                                Severity::Info,
                                format!("the AI agent used a tool it has never used before in {} tool calls: {}", self.st.calls, quote(n)),
                                e,
                            ));
                        }
                        *self.st.tools.entry(n.to_owned()).or_default() += 1;
                        self.st.calls += 1;
                    }
                }
            }
        }
        if !done {
            for sig in SIGNALS {
                let Some(s) = self.st.stats.get(sig) else { continue };
                let v = self.st.counts.get(sig).copied().unwrap_or(0.0);
                if s.count() < self.min_samples || self.flagged.contains(sig) || v < floor(sig) {
                    continue;
                }
                let z = s.z_score(v);
                if z >= self.z {
                    self.flagged.insert(sig);
                    out.push(Finding::new(self.id(), Severity::Info, format!(
                        "the AI agent's {} in this {} window reached {}, {} standard deviations above its own usual (mean {}, stddev {} over {} active windows)",
                        sig.replace('_', " "), gotext::duration(w), fixed(v, 0), fixed(z, 1), fixed(s.mean(), 1), fixed(s.std_dev(), 1), s.count()), e));
                }
            }
        }
        if save {
            self.save();
        }
        out
    }
}

/// The knocks from outside (fwsource's firewall_block and login_failure), one alert per address when they add up.
pub struct InboundDetector {
    pub window: i64,
    pub cooldown: i64,
    pub block_threshold: usize,
    pub scan_ports: usize,
    pub login_threshold: usize,
    pub ephemeral_low: i64,
    pub ephemeral_high: i64,
    seen: HashMap<String, Knocks>,
    last: HashMap<String, Time>,
    pruned: Time,
}

#[derive(Default)]
struct Knocks {
    blocks: Vec<Time>,
    logins: Vec<Time>,
    ports: HashMap<String, Time>,
    users: BTreeSet<String>,
    origin: String,
}

impl InboundDetector {
    /// With the kernel's temporary port range from /proc (or the default 32768-60999).
    pub fn new() -> Self {
        let mut d = Self::with_range(32768, 60999);
        if let Ok(s) = std::fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range") {
            let mut it = s.split_whitespace();
            if let Some(lo) = it.next().and_then(gonet::sscan_int) {
                d.ephemeral_low = lo;
                if let Some(hi) = it.next().and_then(gonet::sscan_int) {
                    d.ephemeral_high = hi;
                }
            }
        }
        d
    }

    pub fn with_range(lo: i64, hi: i64) -> Self {
        InboundDetector {
            window: 10 * 60 * SEC,
            cooldown: 3600 * SEC,
            block_threshold: 20,
            scan_ports: 10,
            login_threshold: 5,
            ephemeral_low: lo,
            ephemeral_high: hi,
            seen: HashMap::new(),
            last: HashMap::new(),
            pruned: Time::default(),
        }
    }

    fn discovery_answer(&self, e: &Event) -> bool {
        if e.f("proto") != "UDP" {
            return false;
        }
        let Some(ip) = gonet::parse_ip(e.f("src")) else { return false };
        if !(gonet::is_private(&ip) || gonet::is_link_local_unicast(&ip)) {
            return false;
        }
        let Some(port) = gonet::sscan_int(e.f("dst_port")) else { return false };
        port >= self.ephemeral_low && port <= self.ephemeral_high
    }
}

impl Default for InboundDetector {
    fn default() -> Self {
        Self::new()
    }
}

fn keep(ts: &mut Vec<Time>, since: &Time) {
    let i = ts.iter().take_while(|t| t.before(since)).count();
    ts.drain(..i);
}

fn first5<I: Iterator<Item = String>>(it: I) -> String {
    let mut v: Vec<String> = it.collect();
    v.sort();
    if v.len() > 5 {
        v.truncate(5);
        v.push("...".into());
    }
    v.join(", ")
}

impl Detector for InboundDetector {
    fn id(&self) -> &'static str {
        "inbound"
    }
    fn inspect(&mut self, e: &Event) -> Vec<Finding> {
        if e.kind != "firewall_block" && e.kind != "login_failure" {
            return Vec::new();
        }
        let src = e.f("src").to_owned();
        if gonet::parse_ip(&src).is_none() {
            return Vec::new();
        }
        let now = e.time;
        let since = now.add(-self.window);
        if now.sub(&self.pruned) > self.window {
            self.seen
                .retain(|_, v| !((v.blocks.last().is_none_or(|t| t.before(&since))) && (v.logins.last().is_none_or(|t| t.before(&since)))));
            self.pruned = now;
        }
        let discovery = e.kind != "login_failure" && self.discovery_answer(e);
        if !self.seen.contains_key(&src) {
            if self.seen.len() >= 10000 {
                return Vec::new();
            }
            self.seen.insert(src.clone(), Knocks::default());
        }
        let k = self.seen.get_mut(&src).expect("just inserted");
        if !e.f("origin").is_empty() {
            k.origin = e.f("origin").to_owned();
        }
        let origin = if k.origin.is_empty() { "origin unknown".to_owned() } else { k.origin.clone() };
        keep(&mut k.blocks, &since);
        keep(&mut k.logins, &since);
        k.ports.retain(|_, t| !t.before(&since));
        if e.kind == "login_failure" {
            k.logins.push(now);
            if k.users.len() < 20 {
                k.users.insert(e.f("user").to_owned());
            }
        } else {
            k.blocks.push(now);
            let p = e.f("dst_port");
            if !p.is_empty() && k.ports.len() < 1000 && !discovery {
                k.ports.insert(p.to_owned(), now);
            }
        }
        if let Some(t) = self.last.get(&src) {
            if now.sub(t) < self.cooldown {
                return Vec::new();
            }
        }
        let mut f = BTreeMap::from([("src".to_string(), src.clone()), ("origin".to_string(), origin.clone())]);
        for (key, v) in &e.fields {
            if key.starts_with("origin_") {
                f.insert(key.clone(), v.clone());
            }
        }
        let win = gotext::duration(self.window);
        let (sev, summary) = if k.logins.len() >= self.login_threshold {
            let cmd = format!("sudo ufw insert 1 deny from {src} comment 'blocked after a Heimdall alert'");
            f.insert("block_command".into(), cmd.clone());
            f.insert("spoofable".into(), "0".into());
            f.insert("attempts".into(), k.logins.len().to_string());
            let names = first5(k.users.iter().map(|u| quote(u)));
            (Severity::Warning, format!(
                "{} failed {} logins in {win} from {src} ({origin}), as {names}. This address completed a connection, so it is real. To block it: {cmd}",
                k.logins.len(), e.f("service")))
        } else if k.ports.len() >= self.scan_ports {
            f.insert("spoofable".into(), "1".into());
            f.insert("ports".into(), k.ports.len().to_string());
            (Severity::Warning, format!(
                "port scan: {src} ({origin}) tried {} different ports in {win}; the firewall stopped every one. These packets never completed a connection, so the address may be forged: blocking it is not needed and could block an innocent one",
                k.ports.len()))
        } else if k.blocks.len() >= self.block_threshold {
            f.insert("spoofable".into(), "1".into());
            f.insert("attempts".into(), k.blocks.len().to_string());
            (
                Severity::Info,
                format!(
                    "the firewall blocked {src} ({origin}) {} times in {win} (port {}); nothing got through",
                    k.blocks.len(),
                    first5(k.ports.keys().cloned())
                ),
            )
        } else {
            return Vec::new();
        };
        self.last.insert(src, now);
        let ev =
            Event { source: e.source.clone(), session_id: String::new(), time: now, kind: e.kind.clone(), text: e.text.clone(), fields: f };
        vec![Finding::new(self.id(), sev, summary, &ev)]
    }
}

/// Limbo's own safety ordering, audited from outside: a guest started with no policy, a policy removed under a running guest;
/// and Limbo's own alarms.
#[derive(Default)]
pub struct LimboGuestDetector {
    policy_up: HashMap<String, bool>,
    running: HashMap<String, bool>,
}

impl Detector for LimboGuestDetector {
    fn id(&self) -> &'static str {
        "limbo-guest"
    }
    fn inspect(&mut self, e: &Event) -> Vec<Finding> {
        if e.source != "limbo" {
            return Vec::new();
        }
        let g = e.f("guest").to_owned();
        let q = quote(&g);
        let id = self.id();
        match e.kind.as_str() {
            "policy.apply" => {
                self.policy_up.insert(g, true);
            }
            "guest.start" => {
                let up = self.policy_up.get(&g).copied().unwrap_or(false);
                self.running.insert(g, true);
                if !up {
                    return vec![Finding::new(
                        id,
                        Severity::Critical,
                        format!("guest {q} started with no firewall policy applied first"),
                        e,
                    )];
                }
            }
            "guest.stop" => {
                self.running.insert(g, false);
            }
            "policy.remove" => {
                let was = self.running.get(&g).copied().unwrap_or(false);
                self.policy_up.insert(g, false);
                if was {
                    return vec![Finding::new(
                        id,
                        Severity::Critical,
                        format!("firewall policy for guest {q} removed while it was still running"),
                        e,
                    )];
                }
            }
            "image.rejected" => {
                return vec![Finding::new(
                    id,
                    Severity::Critical,
                    format!("guest {q} base image failed checksum verification: {}", e.f("reason")),
                    e,
                )]
            }
            "gate.blocked" => {
                return vec![Finding::new(
                    id,
                    Severity::Warning,
                    format!("guest {q} blocked by the Windows license gate: {}", e.f("reason")),
                    e,
                )]
            }
            _ => {}
        }
        Vec::new()
    }
}

/// Remote-access tools and tunnels (rasource's remote_access events, and connections tagged with ra_provider). One alert per
/// provider, signal and interface per cooldown (wall clock, as in Go).
pub struct RemoteAccessDetector {
    pub approved: Option<crate::event::ApprovedFn>,
    /// Nanoseconds.
    pub cooldown: i64,
    last: HashMap<String, Time>,
}

impl RemoteAccessDetector {
    pub fn new(approved: Option<crate::event::ApprovedFn>) -> Self {
        RemoteAccessDetector { approved, cooldown: 3600 * SEC, last: HashMap::new() }
    }
}

impl Detector for RemoteAccessDetector {
    fn id(&self) -> &'static str {
        "remote-access"
    }
    fn inspect(&mut self, e: &Event) -> Vec<Finding> {
        let (provider, kind, signal) = match e.kind.as_str() {
            "remote_access" => (e.f("provider").to_owned(), e.f("ra_kind").to_owned(), e.f("signal").to_owned()),
            "new_connection" => {
                if e.f("ra_provider").is_empty() {
                    return Vec::new();
                }
                (e.f("ra_provider").to_owned(), e.f("ra_kind").to_owned(), format!("connection:{}", e.f("ra_signal")))
            }
            _ => return Vec::new(),
        };
        let key = format!("{provider}|{signal}|{}", e.f("iface"));
        let now = Time::now();
        if let Some(t) = self.last.get(&key) {
            if now.sub(t) < self.cooldown {
                return Vec::new();
            }
        }
        self.last.insert(key, now);
        let id = self.id();
        if provider.is_empty() {
            return vec![Finding::new(id, Severity::Warning, format!("{}: a tunnel no known tool explains", e.text), e)];
        }
        let name = if e.f("provider_name").is_empty() { provider.clone() } else { e.f("provider_name").to_owned() };
        if kind != "c2" && self.approved.as_ref().is_some_and(|a| a(&provider)) {
            return vec![Finding::new(id, Severity::Info, format!("{} ({name}, approved by the owner)", e.text), e)];
        }
        if kind == "c2" {
            return vec![Finding::new(id, Severity::Critical, format!("{}: {name} is a command-and-control implant", e.text), e)];
        }
        if signal.ends_with("gomod-dep") {
            return vec![Finding::new(
                id,
                Severity::Warning,
                format!("{}: the program contains code of {name} (it may open its own {kind})", e.text),
                e,
            )];
        }
        vec![Finding::new(id, Severity::Critical, format!("{}: {name} is a remote-access tool the owner has not approved", e.text), e)]
    }
}
