//! Installed packages with a known security vulnerability (Go: internal/pkgaudit): Arch's security tracker (a file
//! heimdall-intel-update downloads) matched against the versions in pacman's local database. Reads two files, reports.

use super::vercmp::{same_upstream, vercmp};
use super::{read_seen, write_seen, AuditError};
use crate::event::{Event, Fields};
use crate::gojson;
use crate::gotext;
use crate::gotime::Time;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::os::unix::ffi::OsStrExt;

/// One entry of the tracker (an "AVG").
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Group {
    pub name: String,
    pub packages: Vec<String>,
    /// Vulnerable (no fix yet), Fixed, Not affected, Unknown, Testing.
    pub status: String,
    pub severity: String,
    pub type_: String,
    pub affected: String,
    pub fixed: String,
    pub issues: Vec<String>,
}

crate::go_struct!(Group {
    name: "name",
    packages: "packages",
    status: "status",
    severity: "severity",
    type_: "type",
    affected: "affected",
    fixed: "fixed",
    issues: "issues",
});

/// One installed package with one known vulnerability.
#[derive(Clone, Debug, PartialEq)]
pub struct Finding {
    pub package: String,
    /// As pacman's database has it (bytes: not checked for UTF-8, as in Go).
    pub installed: Vec<u8>,
    pub group: Group,
    /// The tracker has no fixed version yet.
    pub no_fix: bool,
}

impl Finding {
    /// Identifies a finding for "already reported".
    pub fn key(&self) -> String {
        format!("{}|{}|{}", self.group.name, self.package, gotext::lossy(&self.installed))
    }
}

/// bufio.Scanner's lines: split at '\n', one trailing '\r' dropped, the last line without a newline kept; a line of 64 KiB
/// or more stops the reading (Go's ErrTooLong), keeping what came before.
pub fn scanner_lines(b: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut rest = b;
    while !rest.is_empty() {
        let (line, next) = match rest.iter().position(|&c| c == b'\n') {
            Some(i) => (&rest[..i], &rest[i + 1..]),
            None => (rest, &rest[rest.len()..]),
        };
        if line.len() >= 64 * 1024 {
            break;
        }
        out.push(line.strip_suffix(b"\r").unwrap_or(line));
        rest = next;
    }
    out
}

/// What one package's `desc` file names: (name, version, base).
pub fn parse_desc(b: &[u8]) -> (&[u8], &[u8], &[u8]) {
    let (mut name, mut ver, mut base, mut field): (&[u8], &[u8], &[u8], &[u8]) = (b"", b"", b"", b"");
    for l in scanner_lines(b) {
        if l.starts_with(b"%") && l.ends_with(b"%") {
            field = l;
        } else if l.is_empty() {
            field = b"";
        } else if field == b"%NAME%" {
            name = l;
        } else if field == b"%VERSION%" {
            ver = l;
        } else if field == b"%BASE%" {
            base = l;
        }
    }
    (name, ver, base)
}

/// The folder's entries sorted by name, as Go's os.ReadDir gives them: (name, is a directory, not following links).
pub fn read_dir_sorted(dir: &str) -> std::io::Result<Vec<(Vec<u8>, bool)>> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir)? {
        let e = e?;
        let is_dir = e.file_type().map(|t| t.is_dir()).unwrap_or(false);
        out.push((e.file_name().as_bytes().to_vec(), is_dir));
    }
    out.sort();
    Ok(out)
}

/// pacman's local database: package name to version (and `base:NAME` for a base name the tracker sometimes uses).
pub fn installed(db_dir: &str) -> std::io::Result<BTreeMap<Vec<u8>, Vec<u8>>> {
    let mut out: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
    for (entry, is_dir) in read_dir_sorted(db_dir)? {
        if !is_dir {
            continue;
        }
        let mut p = db_dir.as_bytes().to_vec();
        p.push(b'/');
        p.extend_from_slice(&entry);
        p.extend_from_slice(b"/desc");
        let Ok(mut f) = std::fs::File::open(std::ffi::OsStr::from_bytes(&p)) else { continue };
        let mut b = Vec::new();
        let _ = f.read_to_end(&mut b); // a read error ends the reading there, as Go's scanner does
        let (name, ver, base) = parse_desc(&b);
        if !name.is_empty() && !ver.is_empty() {
            out.insert(name.to_vec(), ver.to_vec());
            if !base.is_empty() && base != name && !out.contains_key(base) {
                let mut k = b"base:".to_vec();
                k.extend_from_slice(base);
                out.insert(k, ver.to_vec());
            }
        }
    }
    Ok(out)
}

/// Reads the tracker's all.json.
pub fn load_tracker(path: &str) -> Result<Vec<Group>, AuditError> {
    let b = std::fs::read(path).map_err(|e| AuditError::io("open", path, &e))?;
    gojson::unmarshal(&b, Vec::<Group>::new())
        .map_err(|e| AuditError::other(format!("the security tracker file is not readable: {e}")))
}

fn rank(sev: &str) -> i32 {
    match gotext::to_lower(sev).as_str() {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

/// Matches the tracker against the installed versions, most severe first, then by package name.
///
/// Go sorts with `sort.Slice`, which is not stable: for findings of equal severity and package name (one package in two
/// advisories) the order of more than 12 findings can differ from this stable sort. The findings are the same.
pub fn check(groups: &[Group], inst: &BTreeMap<Vec<u8>, Vec<u8>>) -> Vec<Finding> {
    let mut out = Vec::new();
    for g in groups {
        let st = gotext::to_lower(&g.status);
        if st == "not affected" || st == "fixed" && g.fixed.is_empty() {
            continue;
        }
        for p in &g.packages {
            let ver = inst.get(p.as_bytes()).or_else(|| inst.get(format!("base:{p}").as_bytes()));
            let Some(ver) = ver else { continue };
            if !g.fixed.is_empty() && vercmp(ver, g.fixed.as_bytes()) < 0 {
                out.push(Finding { package: p.clone(), installed: ver.clone(), group: g.clone(), no_fix: false });
            } else if g.fixed.is_empty() && st == "vulnerable" && !g.affected.is_empty() && same_upstream(ver, g.affected.as_bytes()) {
                // no fix yet: only the very version known to be affected (the tracker keeps stale entries open for years)
                out.push(Finding { package: p.clone(), installed: ver.clone(), group: g.clone(), no_fix: true });
            }
        }
    }
    out.sort_by(|a, b| rank(&b.group.severity).cmp(&rank(&a.group.severity)).then_with(|| a.package.cmp(&b.package)));
    out
}

/// Checks the installed packages against the tracker file and reports each finding once (until the package version
/// changes); the state file is Go's (`package-audit.json`: the keys still open).
pub struct Watcher {
    pub tracker_path: String,
    pub pacman_db: String,
    pub state_path: String,
}

impl Watcher {
    pub fn poll(&self) -> Result<Vec<Event>, AuditError> {
        let groups = load_tracker(&self.tracker_path)?;
        let inst = installed(&self.pacman_db).map_err(|e| AuditError::io("open", &self.pacman_db, &e))?;
        let seen = read_seen(&self.state_path);
        let now = Time::now();
        let mut current = BTreeSet::new();
        let mut events = Vec::new();
        for f in check(&groups, &inst) {
            let key = f.key();
            let new = !seen.contains(&key);
            current.insert(key);
            if !new {
                continue;
            }
            let fix = if f.no_fix { "no fixed version yet".to_string() } else { format!("fixed in {}", f.group.fixed) };
            let installed = gotext::lossy(&f.installed);
            let cves = f.group.issues.join(" ");
            let text = format!(
                "{} {} is installed and has a known {} vulnerability ({}, {}; {})",
                f.package,
                installed,
                gotext::to_lower(&f.group.severity),
                f.group.name,
                cves,
                fix
            );
            let fields = Fields::from([
                ("package".to_string(), f.package.clone()),
                ("installed".to_string(), installed),
                ("fixed".to_string(), f.group.fixed.clone()),
                ("severity".to_string(), f.group.severity.clone()),
                ("advisory".to_string(), f.group.name.clone()),
                ("cves".to_string(), cves),
                ("type".to_string(), f.group.type_.clone()),
                ("no_fix".to_string(), f.no_fix.to_string()),
            ]);
            events.push(Event {
                source: "host-packages".into(),
                time: now,
                kind: "vulnerable_package".into(),
                text,
                fields,
                ..Default::default()
            });
        }
        // remember only what is still open: a package updated and later vulnerable again is reported again
        write_seen(&self.state_path, &current);
        Ok(events)
    }
}
