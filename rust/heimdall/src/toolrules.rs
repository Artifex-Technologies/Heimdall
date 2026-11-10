//! Rules for a computer full of security tools (LykanOS; Go: internal/toolrules). In force only where
//! /etc/heimdall/security-tools exists. The catalog is the Go daemon's own file, compiled in from the same path.

use crate::event::{Finding, Severity};
use crate::gojson::{self, FromGo};
use crate::gotime::Time;
use std::collections::HashMap;

pub const MARKER_PATH: &str = "/etc/heimdall/security-tools";

/// The Go daemon's catalog, the one file both read.
pub const CATALOG: &str = include_str!("../../../internal/toolrules/tool-rules.json");

#[derive(Clone, Debug, Default)]
pub struct Tool {
    pub id: String,
    pub name: String,
    pub packages: Vec<String>,
    pub expects: Vec<String>,
    pub quiet: bool,
    pub offline: bool,
}
crate::go_struct!(Tool { id: "id", name: "name", packages: "packages", expects: "expects", quiet: "quiet", offline: "offline" });

#[derive(Default)]
struct Catalog {
    tools: Vec<Tool>,
}
crate::go_struct!(Catalog { tools: "tools" });

/// The built-in catalog.
pub fn builtin() -> Result<Vec<Tool>, String> {
    let v = gojson::parse(CATALOG.as_bytes()).map_err(|e| format!("toolrules: the built-in catalog does not read: {e}"))?;
    let mut c = Catalog::default();
    c.read_into(&v, "").map_err(|e| format!("toolrules: the built-in catalog does not read: {e}"))?;
    Ok(c.tools)
}

/// Whether this system asks for the rules.
pub fn enabled() -> bool {
    std::path::Path::new(MARKER_PATH).exists()
}

/// Which package installed a file and the SHA-256 it recorded: (package, sha, owned).
pub type Owner = Box<dyn Fn(&str) -> (String, String, bool) + Send>;
/// A file's SHA-256 now.
pub type Hasher = Box<dyn FnMut(&str) -> Option<String> + Send>;

pub struct Policy {
    tools: Vec<Tool>,
    by_package: HashMap<String, usize>,
    owner: Owner,
    hash: Hasher,
    /// How long a quiet tool's further new destinations are only counted (nanoseconds).
    pub quiet: i64,
    pub now: Box<dyn Fn() -> Time + Send>,
    quiet_at: HashMap<String, Time>,
    held: HashMap<String, i64>,
    tampered: HashMap<String, Time>,
}

/// The file hash, kept while a file's size and modification time stay the same (a tool's jar can be hundreds of MB).
pub fn caching_hasher() -> Hasher {
    let mut cache: HashMap<String, (u64, std::time::SystemTime, String)> = HashMap::new();
    Box::new(move |path: &str| {
        let md = std::fs::metadata(path).ok()?;
        let mtime = md.modified().ok()?;
        if let Some((size, t, sum)) = cache.get(path) {
            if *size == md.len() && *t == mtime {
                return Some(sum.clone());
            }
        }
        let sum = crate::state::sha256_file(path).ok()?;
        cache.insert(path.to_owned(), (md.len(), mtime, sum.clone()));
        Some(sum)
    })
}

impl Policy {
    pub fn new(tools: Vec<Tool>, owner: Owner, hash: Hasher) -> Policy {
        let mut by_package = HashMap::new();
        for (i, t) in tools.iter().enumerate() {
            for p in &t.packages {
                by_package.insert(p.clone(), i);
            }
        }
        Policy {
            tools,
            by_package,
            owner,
            hash,
            quiet: 10 * 60 * 1_000_000_000,
            now: Box::new(Time::now),
            quiet_at: HashMap::new(),
            held: HashMap::new(),
            tampered: HashMap::new(),
        }
    }

    /// What becomes of one finding (none, when a quiet tool's destination is only counted).
    pub fn apply(&mut self, mut f: Finding) -> Vec<Finding> {
        if f.detector_id == "tool-rules" {
            return vec![f];
        }
        let prog = if f.event.f("script").is_empty() { f.event.f("exe").to_owned() } else { f.event.f("script").to_owned() };
        if prog.is_empty() {
            return vec![f];
        }
        let (pkg, want, owned) = (self.owner)(&prog);
        let Some(&ti) = self.by_package.get(&pkg).filter(|_| owned) else { return vec![f] };
        let t = self.tools[ti].clone();
        let got = match (self.hash)(&prog) {
            Some(g) if !want.is_empty() => g,
            _ => return vec![f], // nothing to check it against
        };
        if got != want {
            let key = format!("{prog}|{got}");
            let now = (self.now)();
            let report = self.tampered.get(&key).is_none_or(|last| now.sub(last) >= 3600 * 1_000_000_000);
            let ev = f.event.clone();
            let mut out = vec![f];
            if report {
                self.tampered.insert(key, now);
                let mut g = Finding::new(
                    "tool-rules",
                    Severity::Critical,
                    format!(
                        "{}'s program {prog} is not what package {pkg} installed (its SHA-256 differs): a changed security tool, \
                     which an attacker could hide behind. Find out what changed it; reinstall with: sudo pacman -S {pkg}",
                        t.name
                    ),
                    &ev,
                );
                g.firm = true;
                out.push(g);
            }
            return out;
        }
        if !f.event.f("agent").is_empty() {
            if f.severity == Severity::Info {
                f.severity = Severity::Warning;
            }
            f.summary = format!("[{} started {}] {}", f.event.f("agent"), t.name, f.summary);
            return vec![f];
        }
        if t.offline && f.detector_id == "connection-watch" {
            if f.severity == Severity::Info {
                f.severity = Severity::Warning;
            }
            f.summary = format!("{} works offline, yet it made a connection: {}", t.name, f.summary);
            return vec![f];
        }
        if !t.expects.contains(&f.detector_id) || f.severity == Severity::Critical {
            return vec![f];
        }
        if t.quiet && f.detector_id == "connection-watch" {
            let now = (self.now)();
            if let Some(last) = self.quiet_at.get(&t.id) {
                if now.sub(last) < self.quiet {
                    *self.held.entry(t.id.clone()).or_default() += 1;
                    return Vec::new();
                }
            }
            let held = self.held.get(&t.id).copied().unwrap_or(0);
            self.quiet_at.insert(t.id.clone(), now);
            self.held.insert(t.id.clone(), 0);
            let minutes = (self.quiet as f64 / 60e9) as i64;
            let mut more = format!("; its further new destinations are counted, not listed, for {minutes} minutes");
            if held > 0 {
                more = format!("; {held} more new destinations before this one{more}");
            }
            f.summary += &more;
        }
        f.severity = Severity::Info;
        f.summary = format!("[{}, a verified security tool] {}", t.name, f.summary);
        vec![f]
    }
}
