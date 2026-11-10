//! Installed kernels with known holes a newer kernel fixes (Go: internal/kernelaudit, the daemon's half): the compact list
//! `heimdalld intel-check kernel` makes from osv.dev's Linux records (that one-shot command stays in Go), compared with the
//! kernels in /usr/lib/modules.

use super::{read_seen, write_seen, AuditError};
use crate::event::{Event, Fields};
use crate::gojson;
use crate::gotext;
use crate::gotime::Time;
use std::collections::BTreeSet;
use std::os::unix::ffi::OsStrExt;

/// One affected stretch: introduced <= v < fixed.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Range {
    pub introduced: String,
    pub fixed: String,
}
crate::go_struct!(Range { introduced: "introduced", fixed: "fixed" });

/// One kernel CVE.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Vuln {
    pub id: String,
    pub summary: String,
    /// CVSS 3.x base score; 0 = not scored.
    pub score: f64,
    pub vector: String,
    pub ranges: Vec<Range>,
    /// On CISA's list of vulnerabilities known to be exploited.
    pub exploited: bool,
}
crate::go_struct!(Vuln { id: "id", summary: "summary", score: "score", vector: "vector", ranges: "ranges", exploited: "exploited" });

/// The compact list the daemon reads.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct File {
    pub generated: Time,
    pub source: String,
    pub vulns: Vec<Vuln>,
}
crate::go_struct!(File { generated: "generated", source: "source", vulns: "vulns" });

/// Reads the compact file.
pub fn load(path: &str) -> Result<File, AuditError> {
    let b = std::fs::read(path).map_err(|e| AuditError::io("open", path, &e))?;
    gojson::unmarshal(&b, File::default()).map_err(|e| AuditError::other(e.to_string()))
}

/// A kernel version as numbers (7.3.0-4-cachyos -> [7, 3, 0]), at least three.
pub fn version(s: &str) -> Vec<i64> {
    let s = s.split_once('-').map_or(s, |(a, _)| a);
    let mut out = Vec::new();
    for p in s.split('.') {
        match gotext::atoi(p) {
            Some(n) => out.push(n),
            None => break,
        }
    }
    while out.len() < 3 {
        out.push(0);
    }
    out
}

/// Orders two versions (missing parts are 0).
pub fn compare(a: &[i64], b: &[i64]) -> i32 {
    for i in 0..a.len().max(b.len()) {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        if x != y {
            return if x < y { -1 } else { 1 };
        }
    }
    0
}

/// A kernel's stable line (6.18 for 6.18.55).
pub fn line(v: &[i64]) -> (i64, i64) {
    (v[0], v[1])
}

/// One CVE that affects a kernel and has a fixed version.
#[derive(Clone, Debug, PartialEq)]
pub struct Hole<'a> {
    pub vuln: &'a Vuln,
    pub fixed_in: String,
    /// The fix is on the kernel's own line, so an update of that kernel package closes it.
    pub same_line: bool,
}

/// The fix reached the kernel's own line at or before its version (the records' ranges overlap; this settles it).
fn fixed_on_line(v: &Vuln, k: &[i64]) -> bool {
    v.ranges.iter().any(|r| {
        if r.fixed.is_empty() {
            return false;
        }
        let f = version(&r.fixed);
        line(&f) == line(k) && compare(k, &f) >= 0
    })
}

/// The holes of one kernel that a newer kernel fixes, worst first (exploited ones before the rest), and the version that
/// fixes all of them.
pub fn check<'a>(f: &'a File, kernel: &str) -> (Vec<Hole<'a>>, String) {
    let k = version(kernel);
    let mut holes = Vec::new();
    let mut best: Option<Vec<i64>> = None;
    let mut fix_all = String::new();
    for v in &f.vulns {
        if fixed_on_line(v, &k) {
            continue;
        }
        for r in &v.ranges {
            if r.fixed.is_empty() || compare(&k, &version(&r.introduced)) < 0 || compare(&k, &version(&r.fixed)) >= 0 {
                continue;
            }
            let fx = version(&r.fixed);
            holes.push(Hole { vuln: v, fixed_in: r.fixed.clone(), same_line: line(&fx) == line(&k) });
            if best.as_ref().is_none_or(|b| compare(&fx, b) > 0) {
                best = Some(fx);
                fix_all = r.fixed.clone();
            }
            break;
        }
    }
    // Go: sort.SliceStable
    holes.sort_by(|a, b| {
        b.vuln
            .exploited
            .cmp(&a.vuln.exploited)
            .then_with(|| b.vuln.score.partial_cmp(&a.vuln.score).unwrap_or(std::cmp::Ordering::Equal))
            .then_with(|| b.vuln.id.cmp(&a.vuln.id))
    });
    (holes, fix_all)
}

/// The kernels in a modules folder (/usr/lib/modules): the folders with a kernel image, by name.
pub fn installed(modules_dir: &str) -> Vec<String> {
    let Ok(ents) = super::pkg::read_dir_sorted(modules_dir) else { return Vec::new() };
    let mut out = Vec::new();
    for (name, _) in ents {
        let mut p = modules_dir.as_bytes().to_vec();
        p.push(b'/');
        p.extend_from_slice(&name);
        p.extend_from_slice(b"/vmlinuz");
        if std::fs::metadata(std::ffi::OsStr::from_bytes(&p)).is_ok() {
            out.push(gotext::lossy(&name));
        }
    }
    out
}

/// The running kernel (uname -r).
pub fn running() -> String {
    // SAFETY: uname fills the zeroed struct; release is NUL-terminated within its array.
    unsafe {
        let mut u: libc::utsname = std::mem::zeroed();
        if libc::uname(&mut u) != 0 {
            return String::new();
        }
        let b: Vec<u8> = u.release.iter().take_while(|&&c| c != 0).map(|&c| c as u8).collect();
        gotext::lossy(&b)
    }
}

/// Compares the installed kernels with the list and reports each kernel once (again when what is open changes); the state
/// file is Go's (`kernel-audit.json`).
pub struct Watcher {
    pub list_path: String,
    pub modules_dir: String,
    pub state_path: String,
    /// The running kernel; empty: asked of the system.
    pub running: String,
}

impl Watcher {
    pub fn poll(&self) -> Result<Vec<Event>, AuditError> {
        let f = load(&self.list_path)?;
        let run = if self.running.is_empty() { running() } else { self.running.clone() };
        let seen = read_seen(&self.state_path);
        let mut current = BTreeSet::new();
        let mut events = Vec::new();
        for k in installed(&self.modules_dir) {
            let (holes, fix_all) = check(&f, &k);
            if holes.is_empty() {
                continue;
            }
            let key = format!("{}|{}|{}", k, holes.len(), holes[0].vuln.id);
            let new = !seen.contains(&key);
            current.insert(key);
            if !new {
                continue;
            }
            let (mut ids, mut exploited) = (Vec::new(), Vec::new());
            let (mut scored, mut same_line) = (0, 0);
            let mut line_fix = String::new();
            for h in &holes {
                if ids.len() < 8 {
                    ids.push(h.vuln.id.as_str());
                }
                if h.vuln.score >= 7.0 {
                    scored += 1;
                }
                if h.vuln.exploited {
                    exploited.push(h.vuln.id.as_str());
                }
                if h.same_line {
                    same_line += 1;
                    if line_fix.is_empty() || compare(&version(&h.fixed_in), &version(&line_fix)) > 0 {
                        line_fix = h.fixed_in.clone();
                    }
                }
            }
            let worst = holes[0].vuln;
            let score = gotext::fixed(worst.score, 1);
            let text = format!(
                "kernel {} has {} known hole(s) fixed in {}; worst {} ({}): {}",
                k,
                holes.len(),
                fix_all,
                worst.id,
                score,
                worst.summary
            );
            let fields = Fields::from([
                ("kernel".to_string(), k.clone()),
                ("running".to_string(), (k == run).to_string()),
                ("count".to_string(), holes.len().to_string()),
                ("high".to_string(), scored.to_string()),
                ("fixed".to_string(), fix_all.clone()),
                ("worst".to_string(), worst.id.clone()),
                ("worst_score".to_string(), score),
                ("worst_summary".to_string(), worst.summary.clone()),
                ("cves".to_string(), ids.join(" ")),
                ("exploited".to_string(), exploited.join(" ")),
                ("same_line".to_string(), same_line.to_string()),
                ("line_fix".to_string(), line_fix),
            ]);
            events.push(Event {
                source: "host-kernel".into(),
                time: Time::now(),
                kind: "vulnerable_kernel".into(),
                text,
                fields,
                ..Default::default()
            });
        }
        write_seen(&self.state_path, &current);
        Ok(events)
    }
}

/// CVSS 3.0/3.1 base score from its vector (Go: kernelaudit.CVSS3; used by the compact list's maker, kept here for the
/// fixtures' sake and for a later port of that command).
pub fn cvss3(vector: &str) -> Option<f64> {
    let mut m = std::collections::HashMap::new();
    for part in vector.split('/') {
        if let Some((k, v)) = part.split_once(':') {
            m.insert(k, v);
        }
    }
    let g = |k: &str| m.get(k).copied().unwrap_or("");
    let changed = g("S") == "C";
    let av = match g("AV") {
        "N" => 0.85,
        "A" => 0.62,
        "L" => 0.55,
        "P" => 0.2,
        _ => 0.0,
    };
    let ac = match g("AC") {
        "L" => 0.77,
        "H" => 0.44,
        _ => 0.0,
    };
    let mut pr = match g("PR") {
        "N" => 0.85,
        "L" => 0.62,
        "H" => 0.27,
        _ => 0.0,
    };
    if changed && g("PR") == "L" {
        pr = 0.68;
    } else if changed && g("PR") == "H" {
        pr = 0.5;
    }
    let ui = match g("UI") {
        "N" => 0.85,
        "R" => 0.62,
        _ => 0.0,
    };
    let cia = |k: &str| match g(k) {
        "H" => Some(0.56),
        "L" => Some(0.22),
        "N" => Some(0.0),
        _ => None,
    };
    let (c, i, a) = (cia("C")?, cia("I")?, cia("A")?);
    if av == 0.0 || ac == 0.0 || pr == 0.0 || ui == 0.0 || (g("S") != "U" && g("S") != "C") {
        return None;
    }
    let iss: f64 = 1.0 - (1.0 - c) * (1.0 - i) * (1.0 - a);
    let impact = if changed { 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02).powi(15) } else { 6.42 * iss };
    if impact <= 0.0 {
        return Some(0.0);
    }
    let expl = 8.22 * av * ac * pr * ui;
    if changed {
        return Some(roundup(f64::min(1.08 * (impact + expl), 10.0)));
    }
    Some(roundup(f64::min(impact + expl, 10.0)))
}

fn roundup(x: f64) -> f64 {
    let n = (x * 100000.0).round() as i64;
    if n % 10000 == 0 {
        return n as f64 / 100000.0;
    }
    (n / 10000 + 1) as f64 / 10.0
}
