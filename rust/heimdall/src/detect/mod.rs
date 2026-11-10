//! Every detector, and the list the daemon runs them in (Go: cmd/heimdalld newDetectors; the order is a fixture both
//! languages check, testdata/parity/detector-order.json).

pub mod simple;
pub mod stateful;
pub mod text;

use crate::config::Config;
use crate::event::Detector;
use crate::gojson::{self, FromGo};
use crate::gonet;
use std::sync::Mutex;

pub use simple::*;
pub use stateful::*;
pub use text::*;

/// What the detectors need from the system, so a test can give its own.
#[derive(Default)]
pub struct Deps {
    pub verifier: Option<Box<dyn PackageVerifier>>,
    pub trust: Option<Box<dyn TrustJudge>>,
    pub mesh_peer: Option<crate::event::MeshPeerFn>,
    pub approved: Option<crate::event::ApprovedFn>,
    /// The kernel's temporary port range; None: read it from /proc.
    pub ephemeral: Option<(i64, i64)>,
}

/// The detectors in the daemon's order.
pub fn daemon_detectors(cfg: &Config, deps: Deps) -> Vec<Box<dyn Detector>> {
    let inbound = match deps.ephemeral {
        Some((lo, hi)) => InboundDetector::with_range(lo, hi),
        None => InboundDetector::new(),
    };
    vec![
        Box::new(InjectionDetector::new()),
        Box::new(CredentialDetector::new()),
        Box::new(UnicodeDetector::new()),
        Box::new(EscalationDetector::new()),
        Box::new(BurstDetector::new(cfg.burst_window(), cfg.burst_threshold, cfg.burst_cooldown())),
        Box::new(FileIntegrityDetector { verify: deps.verifier, trust: deps.trust }),
        Box::new(MaintenanceDetector),
        Box::new(ResourcePressureDetector::new(cfg.resource_mem_threshold_percent, cfg.resource_load_threshold_per_cpu)),
        Box::new(NetworkExposureDetector),
        Box::new(ConnectionDetector { mesh_peer: deps.mesh_peer }),
        Box::new(inbound),
        Box::new(PackageVulnerabilityDetector),
        Box::new(KernelVulnerabilityDetector),
        Box::new(HardeningDetector),
        Box::new(WifiDetector),
        Box::new(LanDetector),
        Box::new(BaselineDriftDetector::with_floors(cfg.baseline_min_samples, cfg.baseline_z_threshold, default_baseline_floors())),
        Box::new(AgentBaselineDetector::new(cfg.baseline_min_samples, cfg.baseline_z_threshold, &cfg.agent_baseline_state_path)),
        Box::new(LimboGuestDetector::default()),
        Box::new(LimboNetworkDetector),
        Box::new(LimboExchangeDetector),
        Box::new(RemoteAccessDetector::new(deps.approved)),
    ]
}

// ---- the owner's files the detectors consult (read-only) ----

#[derive(Default, Clone)]
struct Peer {
    name: String,
    fingerprint: String,
    address: String,
}
crate::go_struct!(Peer { name: "name", fingerprint: "fingerprint", address: "address" });

fn valid_peer(p: &Peer) -> bool {
    let n = p.name.as_bytes();
    let name_ok = !n.is_empty()
        && n.len() <= 32
        && (n[0].is_ascii_lowercase() || n[0].is_ascii_digit())
        && n.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-');
    let fp_ok = p.fingerprint.len() == 36
        && p.fingerprint.starts_with("hm1-")
        && p.fingerprint[4..].bytes().all(|c| c.is_ascii_lowercase() || (b'2'..=b'7').contains(&c));
    let Some((host, port)) = gonet::split_host_port(&p.address) else { return false };
    let Some(ip) = gonet::parse_ip(host) else { return false };
    name_ok && fp_ok && !port.is_empty() && port != "0" && !gonet::is_unspecified(&ip) && !gonet::is_multicast(&ip)
}

/// The enrolled mesh peers (Go: mesh.LoadPeers): root's file, writable by nobody else; invalid entries skipped.
fn load_peers(path: &str) -> Vec<Peer> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let Ok(f) = std::fs::OpenOptions::new().read(true).custom_flags(libc_o_nofollow()).open(path) else { return Vec::new() };
    let Ok(md) = f.metadata() else { return Vec::new() };
    let euid = rustix::process::geteuid().as_raw();
    if (md.uid() != 0 && md.uid() != euid) || md.mode() & 0o022 != 0 {
        return Vec::new();
    }
    let Ok(b) = std::io::read_to_string(f) else { return Vec::new() };
    // Go decodes one JSON value from the stream; text after it is not read
    let Ok(v) = gojson::parse_first(b.as_bytes()) else { return Vec::new() };
    let mut ps: Vec<Peer> = Vec::new();
    if ps.read_into(&v, "").is_err() {
        return Vec::new();
    }
    ps.into_iter().filter(valid_peer).collect()
}

fn libc_o_nofollow() -> i32 {
    rustix::fs::OFlags::NOFOLLOW.bits() as i32
}

/// Go's mesh.IsPeerHost: the name of the enrolled peer at an IP address (the file is read on each call, as in Go).
pub fn mesh_peer_at(path: &str, ip: &str) -> Option<String> {
    let want = gonet::parse_ip(ip)?;
    load_peers(path).into_iter().find_map(|p| {
        let (host, _) = gonet::split_host_port(&p.address)?;
        (gonet::parse_ip(host)? == want).then_some(p.name)
    })
}

/// The owner's approved remote-access tools (Go: remoteaccess.Approvals), re-read when the file's time changes.
pub struct Approvals {
    pub path: String,
    cache: Mutex<(i128, std::collections::BTreeSet<String>)>,
}

#[derive(Default)]
struct ApprovalsFile {
    approved: Vec<String>,
}
crate::go_struct!(ApprovalsFile { approved: "approved" });

impl Approvals {
    pub fn new(path: &str) -> Approvals {
        Approvals { path: path.to_owned(), cache: Mutex::new((0, Default::default())) }
    }

    pub fn approved(&self, id: &str) -> bool {
        let mut g = self.cache.lock().unwrap_or_else(|p| p.into_inner());
        let Ok(md) = std::fs::metadata(&self.path) else {
            *g = (0, Default::default());
            return false;
        };
        let mtime = md.modified().ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map_or(0, |d| d.as_nanos() as i128);
        if mtime != g.0 {
            g.0 = mtime;
            g.1.clear();
            if let Ok(b) = std::fs::read(&self.path) {
                if let Ok(f) = gojson::unmarshal(&b, ApprovalsFile::default()) {
                    g.1.extend(f.approved);
                }
            }
        }
        g.1.contains(id)
    }
}
