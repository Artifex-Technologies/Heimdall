//! The translators: detectors that turn one kind of source event into a finding, keeping no state (Go: integrity.go,
//! maintenance.go, network.go, connection.go, package.go, kernel.go, hardening.go, wifi.go, lan.go, limbonet.go).

use crate::event::{Detector, Event, Finding, Severity};
use crate::gotext::quote;

fn one(id: &str, sev: Severity, summary: String, e: &Event) -> Vec<Finding> {
    vec![Finding::new(id, sev, summary, e)]
}

/// Tells whether a package owns a file and the SHA-256 it recorded (pacman's database).
pub trait PackageVerifier: Send {
    /// (package, sha256 or "", owned)
    fn expected(&self, path: &str) -> (String, String, bool);
}

/// Says whether a change to one of the AI agents' behaviour files was approved: "approved", "unsigned" (with why), or ""
/// when it has no say.
pub trait TrustJudge: Send {
    fn judge(&self, path: &str, new_hash: &str, deleted: bool) -> (String, String);
}

/// hostsource's file events, judged against the signed list (trust) and the package database.
#[derive(Default)]
pub struct FileIntegrityDetector {
    pub verify: Option<Box<dyn PackageVerifier>>,
    pub trust: Option<Box<dyn TrustJudge>>,
}

fn verb(kind: &str) -> &'static str {
    match kind {
        "file_created" => "new file",
        "file_deleted" => "deleted",
        _ => "changed",
    }
}

impl Detector for FileIntegrityDetector {
    fn id(&self) -> &'static str {
        "file-integrity"
    }

    fn inspect(&mut self, e: &Event) -> Vec<Finding> {
        let id = self.id();
        let path = e.f("path");
        let kind = e.kind.as_str();
        if let Some(t) = &self.trust {
            if matches!(kind, "file_modified" | "file_created" | "file_deleted") {
                let (verdict, why) = t.judge(path, e.f("new_hash"), kind == "file_deleted");
                match verdict.as_str() {
                    "approved" => {
                        return one(id, Severity::Info, format!("{path}: {}, approved (it matches the signed list)", verb(kind)), e)
                    }
                    "unsigned" => {
                        let mut f = Finding::new(
                            id,
                            Severity::Critical,
                            format!("{path}: {} without approval ({why}); it decides how an AI agent behaves", verb(kind)),
                            e,
                        );
                        f.firm = true;
                        return vec![f];
                    }
                    _ => {}
                }
            }
        }
        match kind {
            "file_created" => {
                if let Some(v) = &self.verify {
                    let (pkg, sha, owned) = v.expected(path);
                    if owned && !sha.is_empty() && sha == e.f("new_hash") {
                        return one(id, Severity::Info, format!("a new file in a watched folder, installed by package {pkg}: {path}"), e);
                    }
                }
                one(id, Severity::Critical, format!("a new file appeared in a watched folder: {path}"), e)
            }
            "file_modified" => {
                if let Some(v) = &self.verify {
                    let (pkg, sha, owned) = v.expected(path);
                    if owned {
                        if !sha.is_empty() && sha == e.f("new_hash") {
                            return one(id, Severity::Info, format!("{path} changed and now matches package {pkg} (a package update)"), e);
                        }
                        if !sha.is_empty() {
                            return one(
                                id,
                                Severity::Critical,
                                format!("{path} differs from what package {pkg} shipped (not a package update)"),
                                e,
                            );
                        }
                    }
                }
                one(id, Severity::Critical, format!("watched file changed unexpectedly: {path}"), e)
            }
            "file_deleted" => one(id, Severity::Critical, format!("watched file was deleted: {path}"), e),
            _ => Vec::new(),
        }
    }
}

/// The opening (warning) and closing (info) of a maintenance window.
#[derive(Default)]
pub struct MaintenanceDetector;

impl Detector for MaintenanceDetector {
    fn id(&self) -> &'static str {
        "maintenance-window"
    }
    fn inspect(&mut self, e: &Event) -> Vec<Finding> {
        match e.kind.as_str() {
            "maintenance_opened" => one(
                self.id(),
                Severity::Warning,
                format!(
                    "maintenance window opened by {}: {} (until {}); routine alerts are softened to info, content checks are unchanged",
                    e.f("actor"),
                    quote(e.f("reason")),
                    e.f("until")
                ),
                e,
            ),
            "maintenance_closed" => one(
                self.id(),
                Severity::Info,
                format!("maintenance window closed ({}, opened by {})", quote(e.f("reason")), e.f("actor")),
                e,
            ),
            _ => Vec::new(),
        }
    }
}

/// An ecosystem port listening or connected off loopback.
#[derive(Default)]
pub struct NetworkExposureDetector;

impl Detector for NetworkExposureDetector {
    fn id(&self) -> &'static str {
        "network-exposure"
    }
    fn inspect(&mut self, e: &Event) -> Vec<Finding> {
        match e.kind.as_str() {
            "non_loopback_bind" => one(
                self.id(),
                Severity::Critical,
                format!(
                    "port {} is listening on {}, not loopback -- violates the ecosystem's loopback-only rule",
                    e.f("port"),
                    e.f("address")
                ),
                e,
            ),
            "non_loopback_peer" => one(
                self.id(),
                Severity::Critical,
                format!("port {} has a connection from {}:{}, not loopback", e.f("local_port"), e.f("remote_addr"), e.f("remote_port")),
                e,
            ),
            _ => Vec::new(),
        }
    }
}

/// The connection watcher's new connections, by rule (Go: connection.go).
#[derive(Default)]
pub struct ConnectionDetector {
    /// The enrolled mesh peer at an address (Heimdall talking to the owner's other computers is expected).
    pub mesh_peer: Option<crate::event::MeshPeerFn>,
}

const ECOSYSTEM_PROCS: &[&str] = &["sarina", "heimdalld", "limbo", "limbod"];

impl Detector for ConnectionDetector {
    fn id(&self) -> &'static str {
        "connection-watch"
    }
    fn inspect(&mut self, e: &Event) -> Vec<Finding> {
        if e.kind != "new_connection" {
            return Vec::new();
        }
        let f = |k| e.f(k);
        let mut dest = format!("{}:{}", f("remote_addr"), f("remote_port"));
        if !f("remote_origin").is_empty() && f("remote_scope") == "public" {
            dest += &format!(" ({})", f("remote_origin"));
        }
        let process = f("process");
        let mut sev = Severity::Info;
        let mut summary = format!("{process} connected to {dest} (new destination for it)");
        let peer = || self.mesh_peer.as_ref().and_then(|m| m(f("remote_addr"))).filter(|n| !n.is_empty());
        if !f("remote_listed").is_empty() {
            sev = Severity::Critical;
            summary = format!(
                "{process} connected to {dest}, an address on threat lists ({}): known malware, botnet or criminal networks. \
                 This was a real, completed connection. Find out why {process} talks to it before anything else; to cut it off: sudo ufw insert 1 deny out to {} comment 'blocked after a Heimdall alert'",
                f("remote_listed"),
                f("remote_addr")
            );
        } else if f("blocked") == "1" {
            sev = Severity::Critical;
            summary = format!(
                "app {} has its network switched off but {process} connected to {dest}: restart the app so the rule applies",
                quote(f("app"))
            );
        } else if let Some(name) = (process == "heimdalld").then(peer).flatten() {
            summary = format!("heimdalld exchanged alerts with the enrolled mesh peer {name} at {dest}");
        } else if ECOSYSTEM_PROCS.contains(&process) {
            sev = Severity::Critical;
            summary = format!("{process} (an ecosystem program) connected off the machine to {dest}: the rule is loopback only");
        } else if process == "ollama" {
            sev = Severity::Warning;
            summary = format!("ollama connected off the machine to {dest} (a model download does this; nothing else should)");
        } else if f("learning") == "1" {
            return Vec::new();
        }
        one(self.id(), sev, summary, e)
    }
}

/// An installed package with a known vulnerability (Arch's security tracker).
#[derive(Default)]
pub struct PackageVulnerabilityDetector;

impl Detector for PackageVulnerabilityDetector {
    fn id(&self) -> &'static str {
        "package-vulnerability"
    }
    fn inspect(&mut self, e: &Event) -> Vec<Finding> {
        if e.kind != "vulnerable_package" {
            return Vec::new();
        }
        let f = |k| e.f(k);
        let sev = match f("severity") {
            "Critical" => Severity::Critical,
            "High" => Severity::Warning,
            _ => Severity::Info,
        };
        let what =
            format!("{} {} has a known {} vulnerability ({} {})", f("package"), f("installed"), f("severity"), f("advisory"), f("cves"));
        let todo = if f("no_fix") == "true" {
            format!("there is no fixed version yet; if you do not need it, removing it closes the hole (sudo pacman -Rs {})", f("package"))
        } else {
            format!(
                "it is fixed in {}: update with sudo pacman -Syu (if that version is not offered yet, the repositories have not caught up; check again tomorrow)",
                f("fixed")
            )
        };
        one(self.id(), sev, format!("{what}: {todo}"), e)
    }
}

/// An installed kernel with known holes a newer kernel fixes.
#[derive(Default)]
pub struct KernelVulnerabilityDetector;

impl Detector for KernelVulnerabilityDetector {
    fn id(&self) -> &'static str {
        "kernel-vulnerability"
    }
    fn inspect(&mut self, e: &Event) -> Vec<Finding> {
        if e.kind != "vulnerable_kernel" {
            return Vec::new();
        }
        let f = |k| e.f(k);
        let running = f("running") == "true";
        let exploited = !f("exploited").is_empty();
        let sev = if running && exploited {
            Severity::Critical
        } else if running || exploited {
            Severity::Warning
        } else {
            Severity::Info
        };
        let which = if running { "the running kernel" } else { "an installed kernel" };
        let mut s = format!(
            "{which} ({}) has {} known hole(s) that newer kernels fix, {} scored high; worst {} ({}): {}.",
            f("kernel"),
            f("count"),
            f("high"),
            f("worst"),
            f("worst_score"),
            f("worst_summary")
        );
        if exploited {
            s += &format!(" Known to be exploited: {}.", f("exploited"));
        }
        if f("same_line") != "0" && !f("same_line").is_empty() {
            s += &format!(
                " {} of them are fixed in {} on its own line: sudo pacman -Syu when that version is offered, then restart into it.",
                f("same_line"),
                f("line_fix")
            );
        }
        if f("same_line") != f("count") {
            s += &format!(" The rest are fixed only in newer kernel lines (from {}): booting the newer kernel closes them.", f("fixed"));
        }
        one(self.id(), sev, s, e)
    }
}

/// A setting that leaves a known hole open, with the fix.
#[derive(Default)]
pub struct HardeningDetector;

impl Detector for HardeningDetector {
    fn id(&self) -> &'static str {
        "hardening"
    }
    fn inspect(&mut self, e: &Event) -> Vec<Finding> {
        if e.kind != "hardening_gap" {
            return Vec::new();
        }
        let sev = if e.f("level") == "warning" { Severity::Warning } else { Severity::Info };
        one(self.id(), sev, format!("{}: {}. Fix: {}", e.f("now"), e.f("why"), e.f("fix")), e)
    }
}

/// heimdall-wifi-check's verdicts.
#[derive(Default)]
pub struct WifiDetector;

impl Detector for WifiDetector {
    fn id(&self) -> &'static str {
        "wifi-safety"
    }
    fn inspect(&mut self, e: &Event) -> Vec<Finding> {
        if e.kind != "wifi_check" {
            return Vec::new();
        }
        let ssid = quote(e.f("ssid"));
        match e.f("verdict") {
            "unsafe" => one(self.id(), Severity::Critical, format!(
                "Wi-Fi {ssid} is not safe: {}. Disconnect, or use a VPN for everything (Proton VPN) and do not sign in to anything without it", e.f("reasons")), e),
            "caution" => one(self.id(), Severity::Warning, format!("Wi-Fi {ssid} needs care: {}. A VPN is a good idea here", e.f("reasons")), e),
            "safe" => one(self.id(), Severity::Info, format!("Wi-Fi {ssid} checked: nothing wrong found"), e),
            _ => Vec::new(),
        }
    }
}

/// The local-network watches: router impersonation, new listeners, new devices on a trusted network.
#[derive(Default)]
pub struct LanDetector;

impl Detector for LanDetector {
    fn id(&self) -> &'static str {
        "lan-watch"
    }
    fn inspect(&mut self, e: &Event) -> Vec<Finding> {
        let f = |k| e.f(k);
        let id = self.id();
        match e.kind.as_str() {
            "router_changed" => one(id, Severity::Critical, format!(
                "on {} the router's hardware address changed from {} to {} while you were connected: someone may be impersonating the router (ARP spoofing). Disconnect, or make sure the VPN is on",
                quote(f("ssid")), f("expected_mac"), f("new_mac")), e),
            "router_impersonated" => one(id, Severity::Critical, format!(
                "on {}, {} answers with the router's hardware address {}: a sign of ARP spoofing. Disconnect, or make sure the VPN is on",
                quote(f("ssid")), f("other_ip"), f("expected_mac")), e),
            "new_lan_device" => {
                let what = if f("name").is_empty() { "a device" } else { f("name") };
                let mut about = Vec::new();
                if !f("vendor").is_empty() {
                    about.push(format!("made by {}", f("vendor")));
                } else if f("private_mac") == "true" {
                    about.push("using a private address (usually a phone, tablet or laptop)".to_string());
                }
                about.push(format!("at {}", f("ip")));
                one(id, Severity::Warning, format!(
                    "a new device joined {}: {what}, {}. If you do not know it, look at it in Settings > Wi-Fi & Network > Devices",
                    quote(f("ssid")), about.join(", ")), e)
            }
            "new_listener" => one(id, Severity::Warning, format!(
                "a program started listening for connections from the network on {}/{}. The firewall blocks it unless a rule allows it; to see which program: sudo ss -tulpn | grep ':{} '",
                f("proto"), f("port"), f("port")), e),
            _ => Vec::new(),
        }
    }
}

fn or_dash(s: &str) -> &str {
    if s.is_empty() {
        "-"
    } else {
        s
    }
}

fn limbo_target(e: &Event) -> String {
    let mut s = format!("{} to {}", or_dash(e.f("proto")), or_dash(e.f("dst")));
    if !e.f("dport").is_empty() {
        s += &format!(" port {}", e.f("dport"));
    }
    if !e.f("count").is_empty() {
        s += &format!(", {} time(s)", e.f("count"));
    }
    s
}

/// Limbo's net.anomaly and net.capped.
#[derive(Default)]
pub struct LimboNetworkDetector;

impl Detector for LimboNetworkDetector {
    fn id(&self) -> &'static str {
        "limbo-network"
    }
    fn inspect(&mut self, e: &Event) -> Vec<Finding> {
        if e.source != "limbo" {
            return Vec::new();
        }
        let g = quote(e.f("guest"));
        let id = self.id();
        match e.kind.as_str() {
            "net.anomaly" => {
                let w = limbo_target(e);
                match e.f("reason") {
                    "host_probe" => one(
                        id,
                        Severity::Critical,
                        format!("guest {g} reached for this computer itself ({w}): a sandboxed program probing its host"),
                        e,
                    ),
                    "lan_probe" => {
                        one(id, Severity::Critical, format!("guest {g} reached for the home network, the router or another guest ({w})"), e)
                    }
                    "scan" => one(
                        id,
                        Severity::Warning,
                        format!("guest {g} was refused many different destinations in a short time ({w}): it looks like a scan"),
                        e,
                    ),
                    "ipv6" => one(
                        id,
                        Severity::Warning,
                        format!("guest {g} tried to send IPv6 off its own link ({w}); it has no IPv6, so this was dropped"),
                        e,
                    ),
                    r => one(
                        id,
                        Severity::Warning,
                        format!("guest {g}: Limbo reported unusual network refusals (reason {}, {w})", quote(r)),
                        e,
                    ),
                }
            }
            "net.capped" => one(
                id,
                Severity::Info,
                format!(
                    "guest {g} used its budget of {} network events; Limbo records no more new destinations for it (anomalies still are)",
                    or_dash(e.f("limit"))
                ),
                e,
            ),
            _ => Vec::new(),
        }
    }
}

fn clip(s: &str, n: usize) -> String {
    if s.chars().count() > n {
        let mut out: String = s.chars().take(n).collect();
        out.push_str("...");
        out
    } else {
        s.to_owned()
    }
}

/// Limbo's exchange.held and exchange.fail. The guest's own path is untrusted and moves from "path" to "guest_path".
#[derive(Default)]
pub struct LimboExchangeDetector;

impl Detector for LimboExchangeDetector {
    fn id(&self) -> &'static str {
        "limbo-exchange"
    }
    fn inspect(&mut self, e: &Event) -> Vec<Finding> {
        if e.source != "limbo" || (e.kind != "exchange.held" && e.kind != "exchange.fail") {
            return Vec::new();
        }
        let g = quote(e.f("guest"));
        let mut ev = e.clone();
        ev.fields = e.fields.iter().map(|(k, v)| (if k == "path" { "guest_path".to_owned() } else { k.clone() }, v.clone())).collect();
        // Go copies the map in random order, so with both "path" and "guest_path" present either may win; "path" is the
        // guest's own and the one Go means, so it wins here
        if let Some(p) = e.fields.get("path") {
            ev.fields.insert("guest_path".into(), p.clone());
        }
        let path = quote(&clip(e.f("path"), 120));
        if e.kind == "exchange.held" {
            return one(
                self.id(),
                Severity::Warning,
                format!(
                "guest {g} tried to hand out a file ClamAV knows as malware ({path}, signature {}); Limbo held it and did not hand it out",
                quote(&clip(e.f("signature"), 80))),
                &ev,
            );
        }
        one(
            self.id(),
            Severity::Info,
            format!("guest {g}: a file could not be scanned, so it stayed in the guest's outbox ({path}: {})", clip(e.f("reason"), 120)),
            &ev,
        )
    }
}
