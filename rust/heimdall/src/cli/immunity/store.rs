//! Immunity's store as root keeps it (Go: internal/immunity: immunity.go, quarantine.go, limbo.go, inventory.go, analyze.go,
//! report.go): the root-only folder with `samples/<sha256>.gz` and the index `immunity.json` (written as Go writes it, the
//! entries as `gostruct` values of the daemon's own `immunity::ENTRY`), ClamAV's signature file, the inventory of programs,
//! holding and releasing files (through safefs), the proofs, the copies of what Limbo held, and the analysis in Limbo.
//!
//! One difference that only shows inside the samples: they are gzip files made by flate2, not by Go's compressor, so the
//! compressed bytes differ while the content (checked against its SHA-256 on every read) is the same, and each program
//! reads the other's. Where Go cannot write a file name in the gzip header (a character above U+00FF), Go writes a broken
//! sample that can never be read back; the port leaves the name out of the header and keeps a good sample.

use super::elf;
use super::scan::ClamAv;
use crate::goerr;
use crate::gostruct::{self, Ty, Val};
use crate::gotime::Time;
use crate::immunity::ENTRY;
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::io::{Read, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{MetadataExt, PermissionsExt};

pub const DEFAULT_SIGNATURES: &str = "/var/lib/clamav/heimdall-immunity.hsb";
pub const MIN_SIZE: usize = 64;
pub const MAX_SIZE: usize = 256 << 20;
pub const LIMBO_HELD_DIR: &str = "/var/lib/limbo/state/exchange-held";
/// The places the inventory looks at.
pub const INVENTORY_ROOTS: &[&str] = &[
    "/usr/local/bin",
    "/usr/local/sbin",
    "/usr/local/lib",
    "/opt",
    "/home/*/.local/bin",
    "/home/*/bin",
    "/home/*/.config/systemd/user",
    "/home/*/.local/share/applications",
];
const NEVER: &[&str] = &["/usr/", "/boot/", "/proc/", "/sys/", "/dev/", "/run/", "/var/lib/pacman/"];
const MIN_AGE: i64 = 24 * 3600 * 1_000_000_000;

pub const SUSPECT: &str = "suspect";
pub const HELD: &str = "held";
pub const IMMUNE: &str = "immune";
pub const REFERENCE: &str = "reference";
pub const RELEASED: &str = "released";

// ---- entries as gostruct values

fn fields(t: &Ty) -> &'static [gostruct::Field] {
    match t {
        Ty::Struct(_, f) => f,
        _ => &[],
    }
}

fn idx(t: &Ty, name: &str) -> usize {
    fields(t).iter().position(|f| f.0 == name).unwrap_or_else(|| panic!("no field {name}"))
}

/// A field of an entry (or of any struct value of `t`).
pub fn get<'a>(t: &Ty, v: &'a Val, name: &str) -> &'a Val {
    match v {
        Val::Struct(vals) => &vals[idx(t, name)],
        _ => panic!("not a struct"),
    }
}

pub fn set(t: &Ty, v: &mut Val, name: &str, x: Val) {
    if let Val::Struct(vals) = v {
        vals[idx(t, name)] = x;
    }
}

pub fn s(v: &Val, name: &str) -> String {
    match get(&ENTRY, v, name) {
        Val::Str(s) => s.clone(),
        Val::Bytes(b) => crate::gotext::lossy(b),
        _ => String::new(),
    }
}

pub fn i(v: &Val, name: &str) -> i64 {
    match get(&ENTRY, v, name) {
        Val::Int(n) => *n,
        Val::Uint(n) => *n as i64,
        _ => 0,
    }
}

pub fn t(v: &Val, name: &str) -> Time {
    match get(&ENTRY, v, name) {
        Val::Time(t) => *t,
        _ => Time::default(),
    }
}

fn now() -> Time {
    Time::now().utc().truncate(1_000_000_000)
}

/// Go's `Entry.Name`: the signature name ClamAV reports.
pub fn sig_name(e: &Val) -> String {
    let sha = s(e, "sha256");
    format!("Heimdall.Immunity.{}.{}", s(e, "kind"), &sha[..sha.len().min(12)])
}

/// Go's `oneLine` (300 bytes; a cut character becomes U+FFFD per byte, as Go writes it).
fn one_line(text: &str) -> String {
    let joined = crate::gotext::fields(text).collect::<Vec<_>>().join(" ");
    let b = joined.as_bytes();
    if b.len() > 300 {
        return crate::gotext::lossy(&b[..300]);
    }
    joined
}

/// Go's `immunity.Kind`.
pub fn kind(head: &[u8]) -> &'static str {
    let p = |x: &[u8]| head.starts_with(x);
    if p(b"\x7fELF") {
        "Elf"
    } else if p(b"MZ") {
        "Pe"
    } else if p(b"#!") {
        "Script"
    } else if p(b"PK\x03\x04") || p(b"\x1f\x8b") || p(b"7z\xbc\xaf") || p(b"Rar!") {
        "Archive"
    } else if p(b"%PDF") || p(b"\xd0\xcf\x11\xe0") {
        "Document"
    } else if head.iter().any(|&c| c == 0 || c < 0x09 || (c > 0x0d && c < 0x20)) {
        "Data"
    } else {
        "Text"
    }
}

/// The group id of `name` from /etc/group (Go's `user.LookupGroup`).
fn group_id(name: &str) -> Option<u32> {
    let g = std::fs::read_to_string("/etc/group").ok()?;
    g.lines().find_map(|l| {
        let f: Vec<&str> = l.split(':').collect();
        (f.len() >= 3 && f[0] == name).then(|| f[2].parse().ok()).flatten()
    })
}

/// Go's `shareWithDaemon`: the mode, and as root the heimdall group.
fn share(path: &str, mode: u32) {
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
    if rustix::process::geteuid().is_root() {
        if let Some(gid) = group_id("heimdall") {
            let _ = std::os::unix::fs::chown(path, Some(0), Some(gid));
        }
    }
}

/// The reference scanner (Go: immunity.ClamAV): ClamAV's signature for a file, "" when it does not know it.
pub fn clamav(path: &str) -> Result<String, String> {
    let c = ClamAv::new();
    if !c.available() {
        return Err("ClamAV is not installed".into());
    }
    match c.scan_file(path.as_bytes()) {
        (_, Some(e)) => Err(e),
        (r, None) => Ok(if r.infected { r.signature } else { String::new() }),
    }
}

/// Go's `os.MkdirTemp("", "heimdall-immunity-")`.
fn mkdir_temp() -> Result<String, String> {
    let base = std::env::var("TMPDIR").ok().filter(|t| !t.is_empty()).unwrap_or_else(|| "/tmp".into());
    for _ in 0..10000 {
        let mut r = [0u8; 4];
        crate::grants::random(&mut r);
        let p = format!("{base}/heimdall-immunity-{}", u32::from_le_bytes(r));
        match std::fs::DirBuilder::new().mode(0o700).create(&p) {
            Ok(()) => return Ok(p),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(goerr::path("mkdirtemp", &format!("{base}/heimdall-immunity-*"), &e)),
        }
    }
    Err("mkdirtemp: too many tries".into())
}
use std::os::unix::fs::DirBuilderExt;

/// Go's `strings.ToValidUTF8(s, "?")`: each run of bytes that are not UTF-8 becomes one "?".
fn to_valid_utf8(b: &[u8]) -> String {
    let mut out = String::new();
    let mut rest = b;
    while !rest.is_empty() {
        match std::str::from_utf8(rest) {
            Ok(s) => {
                out.push_str(s);
                break;
            }
            Err(e) => {
                let good = e.valid_up_to();
                out.push_str(std::str::from_utf8(&rest[..good]).unwrap());
                out.push('?');
                // skip the whole run of bad bytes (Go replaces a run once)
                let mut j = good + e.error_len().unwrap_or(rest.len() - good);
                while j < rest.len() {
                    match std::str::from_utf8(&rest[j..]) {
                        Ok(_) => break,
                        Err(e2) if e2.valid_up_to() > 0 => break,
                        Err(e2) => j += e2.error_len().unwrap_or(rest.len() - j),
                    }
                }
                rest = &rest[j..];
            }
        }
    }
    out
}

/// Go's `math.Log2`.
fn log2(x: f64) -> f64 {
    let (frac, exp) = frexp(x);
    if frac == 0.5 {
        return (exp - 1) as f64;
    }
    frac.ln() * (1.0 / std::f64::consts::LN_2) + exp as f64
}

fn frexp(x: f64) -> (f64, i32) {
    if x == 0.0 || x.is_nan() || x.is_infinite() {
        return (x, 0);
    }
    let bits = x.to_bits();
    let exp = ((bits >> 52) & 0x7ff) as i32 - 1022;
    let frac = f64::from_bits((bits & !(0x7ffu64 << 52)) | (1022u64 << 52));
    (frac, exp)
}

fn entropy(b: &[u8]) -> f64 {
    if b.is_empty() {
        return 0.0;
    }
    let mut n = [0f64; 256];
    for &c in b {
        n[c as usize] += 1.0;
    }
    let mut e = 0.0;
    for c in n {
        if c > 0.0 {
            let p = c / b.len() as f64;
            e -= p * log2(p);
        }
    }
    (e * 100.0).round() / 100.0
}

fn telling() -> &'static regex::Regex {
    static RX: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    RX.get_or_init(|| {
        regex::Regex::new(
            r"(?i)(https?://|ftp://|(?-u:\b)[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(?-u:\b)|/bin/|/tmp/|/dev/|/etc/|\.ssh|passwd|shadow|curl|wget|nc |bash|chmod|base64|crontab|systemctl|sudo|LD_PRELOAD|ptrace|mmap|socket|connect|exec)",
        )
        .unwrap()
    })
}

/// Go's `pickStrings`: printable runs of 6 or more, the telling ones first, at most `max`, each at most 160 bytes.
fn pick_strings(b: &[u8], max: usize) -> Vec<String> {
    let mut all: Vec<String> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut start: Option<usize> = None;
    let mut flush = |start: &mut Option<usize>, end: usize| {
        if let Some(st) = *start {
            if end - st >= 6 {
                let s = &b[st..end.min(st + 160)];
                let s = String::from_utf8(s.to_vec()).unwrap();
                if !seen.contains(&s) && seen.len() < 5000 {
                    seen.insert(s.clone());
                    all.push(s);
                }
            }
        }
        *start = None;
    };
    for (i, &c) in b.iter().enumerate() {
        if (0x20..0x7f).contains(&c) || c == b'\t' {
            if start.is_none() {
                start = Some(i);
            }
        } else {
            flush(&mut start, i);
        }
    }
    flush(&mut start, b.len());
    let rx = telling();
    all.sort_by_key(|s| !rx.is_match(s));
    all.truncate(max);
    all
}

/// Go's `MakeReport`, as the index's `report` value.
pub fn make_report(b: &[u8], kind: &str) -> Val {
    let strs = |v: Vec<String>| Val::Slice(if v.is_empty() { None } else { Some(v.into_iter().map(Val::Str).collect()) });
    let head = if kind == "Text" || kind == "Script" { to_valid_utf8(&b[..b.len().min(2048)]) } else { String::new() };
    let elf_val = if kind == "Elf" {
        match elf::read(b) {
            Some(info) => Val::Ptr(Some(Box::new(Val::Struct(vec![
                Val::Str(info.class.clone()),
                Val::Str(info.machine.clone()),
                Val::Str(info.typ.clone()),
                Val::Str(crate::gotext::lossy(&info.interp)),
                strs(info.needed.iter().map(|n| crate::gotext::lossy(n)).collect()),
                Val::Bool(info.stripped),
                Val::Bool(info.is_static()),
            ])))),
            None => Val::Ptr(None),
        }
    } else {
        Val::Ptr(None)
    };
    Val::Ptr(Some(Box::new(Val::Struct(vec![Val::Float(entropy(b)), Val::Str(head), strs(pick_strings(b, 40)), elf_val]))))
}

// ---- gzip samples

/// Go's gzip header name: Latin-1, or nothing when the name has a character Latin-1 has not.
fn latin1(name: &str) -> Option<Vec<u8>> {
    name.chars().map(|c| if c == '\0' || c as u32 > 0xff { None } else { Some(c as u32 as u8) }).collect()
}

fn gzip(b: &[u8], name: &str) -> Vec<u8> {
    let mut g = flate2::GzBuilder::new().operating_system(255);
    if let Some(n) = latin1(name).filter(|n| !n.is_empty()) {
        g = g.filename(n);
    }
    let mut w = g.write(Vec::new(), flate2::Compression::default());
    let _ = w.write_all(b);
    w.finish().unwrap_or_default()
}

fn gunzip(gz: &[u8]) -> Result<Vec<u8>, String> {
    if gz.is_empty() {
        return Err("EOF".into());
    }
    if gz.len() < 10 {
        return Err("unexpected EOF".into());
    }
    if gz[0] != 0x1f || gz[1] != 0x8b || gz[2] != 8 {
        return Err("gzip: invalid header".into());
    }
    let mut out = Vec::new();
    let mut d = flate2::read::MultiGzDecoder::new(gz).take(MAX_SIZE as u64 + 1);
    match d.read_to_end(&mut out) {
        Ok(_) => Ok(out),
        Err(e) if e.to_string().contains("crc") => Err("gzip: invalid checksum".into()),
        Err(_) => Err("unexpected EOF".into()),
    }
}

// ---- the store

/// The immunity store.
pub struct Store {
    pub dir: String,
    pub signatures: String,
}

impl Store {
    /// The store at its usual place (HEIMDALL_IMMUNITY_DIR and HEIMDALL_IMMUNITY_SIGNATURES for tests).
    pub fn default_store() -> Store {
        let env = |k: &str, d: &str| std::env::var(k).ok().filter(|v| !v.is_empty()).unwrap_or_else(|| d.to_string());
        Store {
            dir: env("HEIMDALL_IMMUNITY_DIR", crate::immunity::DEFAULT_DIR),
            signatures: env("HEIMDALL_IMMUNITY_SIGNATURES", DEFAULT_SIGNATURES),
        }
    }

    fn index(&self) -> String {
        crate::gopath::join(&[&self.dir, "immunity.json"])
    }

    fn sample(&self, sha: &str) -> String {
        crate::gopath::join(&[&self.dir, "samples", &format!("{sha}.gz")])
    }

    /// Go's `Load`: the entries (None: no file).
    pub fn load(&self) -> Result<Option<Vec<Val>>, String> {
        match crate::immunity::load_entries(&self.dir)? {
            Some(Val::Slice(Some(es))) => Ok(Some(es)),
            _ => Ok(None),
        }
    }

    fn entries(&self) -> Result<Vec<Val>, String> {
        Ok(self.load()?.unwrap_or_default())
    }

    /// Go's `save`: newest first, two-space JSON and a newline, readable by the heimdall group.
    fn save(&self, es: &mut [Val]) -> Result<(), String> {
        es.sort_by_key(|e| std::cmp::Reverse(t(e, "added")));
        let body = gostruct::to_json_indented(&crate::immunity::ENTRIES, &Val::Slice(Some(es.to_vec())), "  ").unwrap_or_default();
        crate::gopath::mkdir_all(&self.dir, 0o750)?;
        share(&self.dir, 0o750);
        let tmp = format!("{}.tmp", self.index());
        crate::gopath::write_file(&tmp, format!("{body}\n").as_bytes(), 0o640)?;
        share(&tmp, 0o640);
        crate::gopath::rename(&tmp, &self.index())
    }

    /// Go's `find`: a full fingerprint, or a unique prefix of 8 or more.
    pub fn find(es: &[Val], sha: &str) -> Option<usize> {
        let sha = crate::gotext::to_lower(crate::gotext::trim_space(sha));
        let mut at = None;
        for (n, e) in es.iter().enumerate() {
            let full = s(e, "sha256");
            if full == sha {
                return Some(n);
            }
            if sha.len() >= 8 && full.starts_with(&sha) {
                if at.is_some() {
                    return None;
                }
                at = Some(n);
            }
        }
        at
    }

    /// Go's `KeepAs`: kept as a suspect (or the entry already there).
    pub fn keep_as(&self, path: &str, original: &str, reason: &str, source: &str) -> Result<Val, String> {
        let proc_exe = path
            .strip_prefix("/proc/")
            .and_then(|r| r.strip_suffix("/exe"))
            .is_some_and(|n| !n.is_empty() && n.bytes().all(|c| c.is_ascii_digit()));
        let mut f = if proc_exe {
            std::fs::File::open(path).map_err(|e| goerr::path("open", path, &e))?
        } else {
            crate::safefs::open_no_links(path, rustix::fs::OFlags::RDONLY, 0)?
        };
        let m = f.metadata().map_err(|e| goerr::path("stat", path, &e))?;
        if !m.is_file() {
            return Err(format!("{path}: not a regular file"));
        }
        let mut b = Vec::new();
        (&mut f).take(MAX_SIZE as u64 + 1).read_to_end(&mut b).map_err(|e| goerr::path("read", path, &e))?;
        if b.len() > MAX_SIZE {
            return Err(format!("{path}: larger than {} MiB", MAX_SIZE >> 20));
        }
        if b.len() < MIN_SIZE {
            return Err(format!("{path}: only {} bytes; a fingerprint that small would match harmless files", b.len()));
        }
        let sha = hex_sha(&b);
        let mut es = self.entries()?;
        if let Some(old) = es.iter().find(|e| s(e, "sha256") == sha) {
            return Ok(old.clone());
        }
        let mut e = gostruct::zero(&ENTRY);
        set(&ENTRY, &mut e, "sha256", Val::Str(sha.clone()));
        set(&ENTRY, &mut e, "size", Val::Int(b.len() as i64));
        set(&ENTRY, &mut e, "kind", Val::Str(kind(&b[..b.len().min(512)]).into()));
        set(&ENTRY, &mut e, "original", Val::Str(original.into()));
        set(&ENTRY, &mut e, "reason", Val::Str(one_line(reason)));
        set(&ENTRY, &mut e, "source", Val::Str(source.into()));
        set(&ENTRY, &mut e, "added", Val::Time(now()));
        set(&ENTRY, &mut e, "status", Val::Str(SUSPECT.into()));
        crate::gopath::mkdir_all(&crate::gopath::join(&[&self.dir, "samples"]), 0o700)?;
        crate::gopath::write_file(&self.sample(&sha), &gzip(&b, &crate::gopath::base(original)), 0o400)?;
        es.push(e.clone());
        self.save(&mut es)?;
        Ok(e)
    }

    /// Go's `sampleBytes`: the sample back, checked against its fingerprint.
    pub fn sample_bytes(&self, sha: &str) -> Result<Vec<u8>, String> {
        let p = self.sample(sha);
        let gz = std::fs::read(&p).map_err(|e| crate::gopath::read_err(&p, &e))?;
        let b = gunzip(&gz)?;
        if hex_sha(&b) != sha {
            return Err("the stored sample does not match its fingerprint".into());
        }
        Ok(b)
    }

    /// Go's `Extract`.
    pub fn extract(&self, sha: &str, to: &str) -> Result<(), String> {
        let b = self.sample_bytes(sha)?;
        crate::gopath::write_file(to, &b, 0o600)
    }

    /// The reference's signature for a stored sample (written out to a temporary folder for ClamAV to read).
    fn reference(&self, sha: &str) -> Result<Result<String, String>, String> {
        let tmp = mkdir_temp()?;
        let p = format!("{tmp}/sample");
        let r = self.extract(sha, &p).map(|_| clamav(&p));
        let _ = std::fs::remove_dir_all(&tmp);
        r
    }

    /// Go's `Confirm`.
    pub fn confirm(&self, sha: &str) -> Result<Val, String> {
        let mut es = self.entries()?;
        let Some(n) = Self::find(&es, sha) else {
            return Err(format!("no sample {sha} (heimdalld immunity list)"));
        };
        let sig = self.reference(&s(&es[n], "sha256"))?.map_err(|e| format!("the reference (ClamAV) could not check it: {e}"))?;
        if !sig.is_empty() && !sig.starts_with("Heimdall.Immunity.") {
            set(&ENTRY, &mut es[n], "status", Val::Str(REFERENCE.into()));
            set(&ENTRY, &mut es[n], "clamav", Val::Str(sig));
            set(&ENTRY, &mut es[n], "confirmed", Val::Time(now()));
            let e = es[n].clone();
            self.save(&mut es)?;
            return Ok(e);
        }
        set(&ENTRY, &mut es[n], "status", Val::Str(IMMUNE.into()));
        set(&ENTRY, &mut es[n], "confirmed", Val::Time(now()));
        let e = es[n].clone();
        self.save(&mut es)?;
        self.export()?;
        Ok(e)
    }

    /// Go's `Forget`.
    pub fn forget(&self, sha: &str) -> Result<(), String> {
        let mut es = self.entries()?;
        let Some(n) = Self::find(&es, sha) else { return Err(format!("no sample {sha}")) };
        let full = s(&es[n], "sha256");
        es.remove(n);
        self.save(&mut es)?;
        let _ = std::fs::remove_file(self.sample(&full));
        self.export()
    }

    /// Go's `Export`: ClamAV's .hsb file from the immune entries, or none.
    pub fn export(&self) -> Result<(), String> {
        let es = self.entries()?;
        let mut lines: Vec<String> = es
            .iter()
            .filter(|e| s(e, "status") == IMMUNE)
            .map(|e| format!("{}:{}:{}", s(e, "sha256"), i(e, "size"), sig_name(e)))
            .collect();
        if lines.is_empty() {
            return match std::fs::remove_file(&self.signatures) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(goerr::path("remove", &self.signatures, &e)),
            };
        }
        lines.sort();
        let tmp = format!("{}.tmp", self.signatures);
        crate::gopath::write_file(&tmp, format!("{}\n", lines.join("\n")).as_bytes(), 0o644)?;
        crate::gopath::rename(&tmp, &self.signatures)
    }

    /// Go's `Hold`: kept, asked of ClamAV, and the original moved away.
    pub fn hold(&self, from: &str, original: &str, reason: &str, source: &str) -> Result<Val, String> {
        let abs = crate::gopath::abs(original)?;
        for p in NEVER {
            if abs.starts_with(p) {
                return Err(format!("{abs}: files under {p} are never moved"));
            }
        }
        if let Some(pkg) = owned_by_package(&abs) {
            return Err(format!("{abs} belongs to the package {pkg}: never moved (sudo pacman -Qkk {pkg} checks it)"));
        }
        let info = std::fs::symlink_metadata(&abs).map_err(|e| goerr::path("lstat", &abs, &e))?;
        if !info.is_file() {
            return Err(format!("{abs}: not a regular file"));
        }
        let e = self.keep_as(from, &abs, reason, source)?;
        let sha = s(&e, "sha256");
        let mut es = self.entries()?;
        let n = Self::find(&es, &sha).ok_or("the sample is missing from the index")?;
        let status = s(&es[n], "status");
        if status == HELD || status == IMMUNE || status == REFERENCE {
            if abs != s(&es[n], "original") {
                std::fs::remove_file(&abs).map_err(|er| goerr::path("remove", &abs, &er))?;
                let mut copies = match get(&ENTRY, &es[n], "copies") {
                    Val::Slice(Some(c)) => c.clone(),
                    _ => Vec::new(),
                };
                copies.push(Val::Str(abs.clone()));
                set(&ENTRY, &mut es[n], "copies", Val::Slice(Some(copies)));
            }
            let e = es[n].clone();
            self.save(&mut es)?;
            return Ok(e);
        }
        if status == RELEASED && s(&es[n], "original") == abs {
            return Err(format!("{abs} was judged good and released before: left alone"));
        }
        let e = &mut es[n];
        set(&ENTRY, e, "status", Val::Str(HELD.into()));
        set(&ENTRY, e, "held_at", Val::Time(now()));
        set(&ENTRY, e, "mode", Val::Uint((info.permissions().mode() & 0o777) as u64));
        set(&ENTRY, e, "mtime", Val::Int(crate::safefs::mtime_nanos(&info)));
        set(&ENTRY, e, "original", Val::Str(abs.clone()));
        set(&ENTRY, e, "reason", Val::Str(one_line(reason)));
        set(&ENTRY, e, "source", Val::Str(source.into()));
        set(&ENTRY, e, "uid", Val::Int(info.uid() as i64));
        set(&ENTRY, e, "gid", Val::Int(info.gid() as i64));
        if let Some(seen) = self.inventory().get(abs.as_bytes()) {
            if seen.sha256 == sha {
                set(&ENTRY, e, "seen_since", Val::Time(seen.first_seen));
            }
        }
        let kind = s(e, "kind");
        if let Ok(b) = self.sample_bytes(&sha) {
            set(&ENTRY, &mut es[n], "report", make_report(&b, &kind));
        }
        if let Ok(Ok(sig)) = self.reference(&sha) {
            if !sig.is_empty() && !sig.starts_with("Heimdall.Immunity.") {
                set(&ENTRY, &mut es[n], "status", Val::Str(REFERENCE.into()));
                set(&ENTRY, &mut es[n], "clamav", Val::Str(sig));
                set(&ENTRY, &mut es[n], "confirmed", Val::Time(now()));
            }
        }
        if let Err(er) = std::fs::remove_file(&abs) {
            if er.kind() != std::io::ErrorKind::NotFound {
                return Err(format!("kept, but the original could not be moved: {}", goerr::path("remove", &abs, &er)));
            }
        }
        let e = es[n].clone();
        self.save(&mut es)?;
        Ok(e)
    }

    /// Go's `Release`: put back exactly, as its owner, never over a file there now.
    pub fn release(&self, sha: &str, by: &str) -> Result<Val, String> {
        let mut es = self.entries()?;
        let Some(n) = Self::find(&es, sha) else { return Err(format!("no sample {sha}")) };
        let e = es[n].clone();
        let status = s(&e, "status");
        let original = s(&e, "original");
        if status != HELD && status != SUSPECT {
            return Err(format!("{original} is {status}: only a held file can be released (forget it first if this was a mistake)"));
        }
        if status == HELD {
            let b = self.sample_bytes(&s(&e, "sha256"))?;
            let f = crate::safefs::File { data: b, mode: i(&e, "mode") as u32, mtime: Some(i(&e, "mtime")), exclusive: true };
            let (uid, gid) = (i(&e, "uid") as u32, i(&e, "gid") as u32);
            crate::safefs::put_as(&original, &f, uid, gid)
                .map_err(|er| format!("{original}: {er} (if something is there now, move it away first)"))?;
            if let Val::Slice(Some(copies)) = get(&ENTRY, &e, "copies") {
                for c in copies {
                    if let Val::Str(c) = c {
                        let _ = crate::safefs::put_as(c, &f, uid, gid);
                    }
                }
            }
        }
        set(&ENTRY, &mut es[n], "status", Val::Str(RELEASED.into()));
        set(&ENTRY, &mut es[n], "released", Val::Time(now()));
        set(&ENTRY, &mut es[n], "released_by", Val::Str(by.into()));
        let e = es[n].clone();
        self.save(&mut es)?;
        Ok(e)
    }

    /// Go's `ReleaseIfProven`.
    pub fn release_if_proven(&self, sha: &str, proof: &Proof) -> Result<Val, String> {
        let es = self.entries()?;
        let Some(n) = Self::find(&es, sha) else { return Err(format!("no sample {sha}")) };
        match proof.check(&es[n]) {
            Some(why) => self.release(&s(&es[n], "sha256"), &format!("proof: {why}")),
            None => {
                Err("no proof that it was there before: the owner decides (Settings > Security, or sudo heimdalld immunity release)".into())
            }
        }
    }

    /// Go's `TakeFromLimbo`.
    pub fn take_from_limbo(&self, held_dir: &str, sha: &str) -> Result<Val, String> {
        let sha = crate::gotext::to_lower(crate::gotext::trim_space(sha));
        if sha.len() != 64 || !sha.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)) {
            return Err(format!("{} is not a full SHA-256 (64 hex characters)", crate::gotext::quote(&sha)));
        }
        let path = crate::gopath::join(&[held_dir, &sha]);
        hash_is(&path, &sha)?;
        let e = self.keep_as(&path, &path, "Limbo held it: a guest tried to hand it out and ClamAV knew it", "limbo")?;
        let got = s(&e, "sha256");
        if got != sha {
            return Err(format!("{path} changed while it was read (now {got}): kept as a suspect, check Limbo's folder"));
        }
        if s(&e, "status") != SUSPECT || s(&e, "source") != "limbo" {
            return Ok(e);
        }
        let mut es = self.entries()?;
        let Some(n) = Self::find(&es, &sha) else {
            return Err(format!("sample {sha} missing from the index right after it was kept"));
        };
        let kind = s(&es[n], "kind");
        if let Ok(b) = self.sample_bytes(&sha) {
            set(&ENTRY, &mut es[n], "report", make_report(&b, &kind));
        }
        if let Ok(Ok(sig)) = self.reference(&sha) {
            if !sig.is_empty() && !sig.starts_with("Heimdall.Immunity.") {
                set(&ENTRY, &mut es[n], "status", Val::Str(REFERENCE.into()));
                set(&ENTRY, &mut es[n], "clamav", Val::Str(sig));
                set(&ENTRY, &mut es[n], "confirmed", Val::Time(now()));
            }
        }
        let e = es[n].clone();
        self.save(&mut es)?;
        Ok(e)
    }

    fn inventory_path(&self) -> String {
        crate::gopath::join(&[&self.dir, "inventory.json"])
    }

    /// Go's `Inventory`: the file as far as it reads; keys are the paths.
    pub fn inventory(&self) -> BTreeMap<Vec<u8>, Seen> {
        let mut inv = BTreeMap::new();
        let Ok(b) = std::fs::read(self.inventory_path()) else { return inv };
        let Ok(crate::gojson::Value::Object(m)) = crate::gojson::parse(&b) else { return inv };
        for (k, v) in m {
            let mut val = gostruct::zero(&SEEN);
            let mut cx = gostruct::Ctx { top: "Seen", first: None };
            gostruct::read(&SEEN, &v, &mut val, "", &mut cx);
            inv.insert(k.into_bytes(), Seen::from_val(&val));
        }
        inv
    }

    /// Go's `TakeInventory`: the programs under the roots, with their hashes and first sightings.
    pub fn take_inventory(&self, roots: &[&str]) -> Result<usize, String> {
        let old = self.inventory();
        let now = now();
        let mut inv: BTreeMap<Vec<u8>, Seen> = BTreeMap::new();
        for pattern in roots {
            for root in glob(pattern) {
                walk_inventory(&root, None, &old, now, &mut inv);
            }
        }
        crate::gopath::mkdir_all(&self.dir, 0o750)?;
        share(&self.dir, 0o750);
        let mut out = String::from("{");
        for (n, (k, v)) in inv.iter().enumerate() {
            if n > 0 {
                out.push(',');
            }
            crate::gojson::write_str(&mut out, &crate::gotext::lossy(k));
            out.push(':');
            out.push_str(&gostruct::to_json(&SEEN, &v.to_val()).unwrap_or_default());
        }
        out.push('}');
        let tmp = format!("{}.tmp", self.inventory_path());
        crate::gopath::write_file(&tmp, out.as_bytes(), 0o600)?;
        crate::gopath::rename(&tmp, &self.inventory_path())?;
        Ok(inv.len())
    }

    /// Go's `Analyze`: the sample sent to Limbo, what came back kept with it.
    pub fn analyze(&self, sha: &str, l: &Limbo) -> Result<Val, String> {
        let es = self.entries()?;
        let Some(n) = Self::find(&es, sha) else { return Err(format!("no sample {sha}")) };
        let full = s(&es[n], "sha256");
        let a = l.run(self, &full);
        let mut es = self.entries()?;
        let Some(n) = Self::find(&es, &full) else { return Err("the sample was forgotten during its analysis".into()) };
        set(&ENTRY, &mut es[n], "analysis", Val::Ptr(Some(Box::new(a.clone()))));
        self.save(&mut es)?;
        Ok(a)
    }
}

/// Go's `OwnedByPackage`: the package that owns a path (pacman -Qoq).
pub fn owned_by_package(path: &str) -> Option<String> {
    let out = std::process::Command::new("pacman").args(["-Qoq", path]).stderr(std::process::Stdio::null()).output().ok()?;
    out.status.success().then(|| crate::gotext::trim_space(&crate::gotext::lossy(&out.stdout)).to_string())
}

pub fn hex_sha(b: &[u8]) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(b).iter().map(|x| format!("{x:02x}")).collect()
}

/// Go's `hashIs`.
fn hash_is(path: &str, sha: &str) -> Result<(), String> {
    use sha2::Digest;
    let mut f = crate::safefs::open_no_links(path, rustix::fs::OFlags::RDONLY, 0)?;
    let m = f.metadata().map_err(|e| goerr::path("stat", path, &e))?;
    if !m.is_file() {
        return Err(format!("{path}: not a regular file"));
    }
    let mut h = sha2::Sha256::new();
    let mut n = 0usize;
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let k = (&mut f).take((MAX_SIZE + 1 - n) as u64).read(&mut buf).map_err(|e| goerr::path("read", path, &e))?;
        if k == 0 {
            break;
        }
        h.update(&buf[..k]);
        n += k;
        if n > MAX_SIZE {
            break;
        }
    }
    if n > MAX_SIZE {
        return Err(format!("{path}: larger than {} MiB, not kept", MAX_SIZE >> 20));
    }
    let got: String = h.finalize().iter().map(|x| format!("{x:02x}")).collect();
    if got != sha {
        return Err(format!("{path} does not hash to its name (it hashes to {got}): not taken"));
    }
    Ok(())
}

// ---- proofs

/// The owner's signed list and the behaviour files (Go: proofFuncs), read once.
pub struct Proof {
    signed: Option<crate::trust::Manifest>,
    watch: crate::trust::WatchList,
}

impl Proof {
    pub fn load() -> Proof {
        let ts = crate::trust::Store::new(crate::trust::DEFAULT_DIR);
        Proof { signed: ts.load().ok(), watch: ts.watch() }
    }

    /// Go's `Proof`.
    pub fn check(&self, e: &Val) -> Option<String> {
        if s(e, "status") != HELD {
            return None;
        }
        let (orig, sha) = (s(e, "original"), s(e, "sha256"));
        if self.signed.as_ref().is_some_and(|m| m.matches(&orig, &sha)) {
            return Some("the owner signed exactly this content (trust list)".into());
        }
        if self.watch.watches(&orig) {
            return None;
        }
        let (seen, held) = (t(e, "seen_since"), t(e, "held_at"));
        if !seen.is_zero() && held.sub(&seen) >= MIN_AGE {
            return Some(format!(
                "exactly this file was on the computer since {} (Heimdall's inventory)",
                seen.local().format("2006-01-02 15:04")
            ));
        }
        None
    }
}

// ---- the inventory

static SEEN: Ty = Ty::Struct(
    "immunity.Seen",
    &[
        gostruct::Field("sha256", &Ty::Str, false),
        gostruct::Field("size", &Ty::Int, false),
        gostruct::Field("mtime", &Ty::Int, false),
        gostruct::Field("first_seen", &Ty::Time, false),
        gostruct::Field("last_seen", &Ty::Time, false),
    ],
);

/// One file of the inventory.
#[derive(Clone, Debug)]
pub struct Seen {
    pub sha256: String,
    pub size: i64,
    pub mtime: i64,
    pub first_seen: Time,
    pub last_seen: Time,
}

impl Seen {
    fn from_val(v: &Val) -> Seen {
        let g = |n: &str| get(&SEEN, v, n).clone();
        Seen {
            sha256: match g("sha256") {
                Val::Str(s) => s,
                _ => String::new(),
            },
            size: match g("size") {
                Val::Int(n) => n,
                _ => 0,
            },
            mtime: match g("mtime") {
                Val::Int(n) => n,
                _ => 0,
            },
            first_seen: match g("first_seen") {
                Val::Time(t) => t,
                _ => Time::default(),
            },
            last_seen: match g("last_seen") {
                Val::Time(t) => t,
                _ => Time::default(),
            },
        }
    }
    fn to_val(&self) -> Val {
        Val::Struct(vec![
            Val::Str(self.sha256.clone()),
            Val::Int(self.size),
            Val::Int(self.mtime),
            Val::Time(self.first_seen),
            Val::Time(self.last_seen),
        ])
    }
}

/// Go's `filepath.Glob` for the inventory's patterns (a `*` in a folder name).
pub fn glob(pattern: &str) -> Vec<Vec<u8>> {
    let has_meta = |p: &[u8]| p.iter().any(|c| matches!(c, b'*' | b'?' | b'[' | b'\\'));
    let p = pattern.as_bytes();
    if !has_meta(p) {
        return if std::fs::symlink_metadata(pattern).is_ok() { vec![p.to_vec()] } else { Vec::new() };
    }
    let (dir, file) = match p.iter().rposition(|&c| c == b'/') {
        Some(i) => (&p[..=i], &p[i + 1..]),
        None => (&b""[..], p),
    };
    let dir = match dir {
        b"" => b".".to_vec(),
        b"/" => b"/".to_vec(),
        d => d[..d.len() - 1].to_vec(),
    };
    let dirs = if has_meta(&dir) { glob(&String::from_utf8_lossy(&dir)) } else { vec![dir] };
    let mut out = Vec::new();
    for d in dirs {
        let Ok(m) = std::fs::metadata(OsStr::from_bytes(&d)) else { continue };
        if !m.is_dir() {
            continue;
        }
        let Ok(rd) = std::fs::read_dir(OsStr::from_bytes(&d)) else { continue };
        let mut names: Vec<Vec<u8>> = rd.flatten().map(|e| e.file_name().into_vec()).collect();
        names.sort();
        for n in names {
            if super::gomatch::go_match(file, &n) == Some(true) {
                let mut j = d.clone();
                j.push(b'/');
                j.extend_from_slice(&n);
                out.push(super::scan::clean_bytes(&j));
            }
        }
    }
    out
}

const MAX_INVENTORY_FILES: usize = 50000;
const MAX_INVENTORY_BYTES: u64 = 128 << 20;

fn walk_inventory(p: &[u8], ft: Option<std::fs::FileType>, old: &BTreeMap<Vec<u8>, Seen>, now: Time, inv: &mut BTreeMap<Vec<u8>, Seen>) {
    use sha2::Digest;
    if inv.len() >= MAX_INVENTORY_FILES {
        return;
    }
    let os = OsStr::from_bytes(p);
    let ft = match ft {
        Some(t) => t,
        None => match std::fs::symlink_metadata(os) {
            Ok(m) => m.file_type(),
            Err(_) => return,
        },
    };
    if ft.is_dir() {
        let Ok(rd) = std::fs::read_dir(os) else { return };
        let mut ents: Vec<(Vec<u8>, Option<std::fs::FileType>)> =
            rd.flatten().map(|e| (e.file_name().into_vec(), e.file_type().ok())).collect();
        ents.sort_by(|a, b| a.0.cmp(&b.0));
        for (name, t) in ents {
            let mut c = p.to_vec();
            c.push(b'/');
            c.extend_from_slice(&name);
            walk_inventory(&super::scan::clean_bytes(&c), t, old, now, inv);
        }
        return;
    }
    if !ft.is_file() {
        return;
    }
    let Ok(m) = std::fs::symlink_metadata(os) else { return };
    if m.size() > MAX_INVENTORY_BYTES {
        return;
    }
    let ext = {
        let base = p.rsplit(|&c| c == b'/').next().unwrap_or(p);
        base.iter().rposition(|&c| c == b'.').map(|i| &base[i..]).unwrap_or(b"")
    };
    if m.permissions().mode() & 0o111 == 0 && ext != b".service" && ext != b".timer" && ext != b".desktop" {
        return;
    }
    let mt = crate::safefs::mtime_nanos(&m);
    if let Some(o) = old.get(p) {
        if o.size == m.size() as i64 && o.mtime == mt {
            let mut o = o.clone();
            o.last_seen = now;
            inv.insert(p.to_vec(), o);
            return;
        }
    }
    let Ok(mut f) = std::fs::File::open(os) else { return };
    let mut h = sha2::Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        match f.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => h.update(&buf[..n]),
            Err(_) => return,
        }
    }
    let sum: String = h.finalize().iter().map(|x| format!("{x:02x}")).collect();
    let first = match old.get(p) {
        Some(o) if o.sha256 == sum => o.first_seen,
        _ => now,
    };
    inv.insert(p.to_vec(), Seen { sha256: sum, size: m.size() as i64, mtime: mt, first_seen: first, last_seen: now });
}

// ---- Limbo

/// How an analysis reaches Limbo (Go: immunity.Limbo).
pub struct Limbo {
    pub socket: String,
    pub inbox: String,
    pub profile: String,
    pub command: String,
    pub wait: std::time::Duration,
    pub poll: std::time::Duration,
}

impl Limbo {
    /// Go's `DefaultLimbo`.
    pub fn default_limbo() -> Limbo {
        Limbo {
            socket: "/run/limbo/admin.sock".into(),
            inbox: "/var/lib/limbo/inbox".into(),
            profile: "malware-analysis".into(),
            command: "limbo-decompile triage sample; echo; echo '== functions'; limbo-decompile functions sample".into(),
            wait: std::time::Duration::from_secs(25 * 60),
            poll: std::time::Duration::from_secs(3),
        }
    }

    /// One HTTP request over Limbo's admin socket; Go's error text when it does not answer.
    fn call(&self, method: &str, path: &str, body: Option<&str>) -> Result<(u16, Vec<u8>), String> {
        use std::os::unix::net::UnixStream;
        let verb = format!("{}{}", &method[..1], method[1..].to_ascii_lowercase());
        let wrap = |what: String| format!("{verb} \"http://limbo{path}\": {what}");
        let mut c =
            UnixStream::connect(&self.socket).map_err(|e| wrap(format!("dial unix {}: connect: {}", self.socket, goerr::text(&e))))?;
        let _ = c.set_read_timeout(Some(std::time::Duration::from_secs(30)));
        let _ = c.set_write_timeout(Some(std::time::Duration::from_secs(30)));
        let mut req = format!("{method} {path} HTTP/1.1\r\nHost: limbo\r\nUser-Agent: Go-http-client/1.1\r\nConnection: close\r\n");
        match body {
            Some(b) => req.push_str(&format!("Content-Length: {}\r\nContent-Type: application/json\r\n\r\n{b}", b.len())),
            None => req.push_str("\r\n"),
        }
        c.write_all(req.as_bytes()).map_err(|e| wrap(goerr::text(&e)))?;
        let mut raw = Vec::new();
        let _ = c.read_to_end(&mut raw);
        let r = crate::response::parse_reply(&raw, 1 << 20).ok_or_else(|| wrap("malformed HTTP response".into()))?;
        Ok((r.status, r.body))
    }

    /// Go's `Limbo.run`: what the analysis became (an Analysis value).
    fn run(&self, st: &Store, sha: &str) -> Val {
        let mut a = gostruct::zero(analysis_ty());
        let at = analysis_ty();
        set(at, &mut a, "time", Val::Time(now()));
        set(at, &mut a, "profile", Val::Str(self.profile.clone()));
        let fail = |mut a: Val, status: &str, msg: String| {
            set(at, &mut a, "status", Val::Str(status.into()));
            set(at, &mut a, "error", Val::Str(msg));
            a
        };
        let b = match st.sample_bytes(sha) {
            Ok(b) => b,
            Err(e) => return fail(a, "failed", format!("the sample could not be read: {e}")),
        };
        let name = format!("{sha}.sample");
        let path = crate::gopath::join(&[&self.inbox, &name]);
        if let Err(e) = crate::gopath::write_file(&path, &b, 0o600) {
            return fail(a, "unavailable", format!("Limbo's inbox: {e} (is Limbo installed and running?)"));
        }
        struct Rm(String);
        impl Drop for Rm {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(&self.0);
            }
        }
        let _rm = Rm(path);
        let mut body = String::from("{\"command\":");
        crate::gojson::write_str(&mut body, &self.command);
        body.push_str(",\"profile\":");
        crate::gojson::write_str(&mut body, &self.profile);
        body.push_str(",\"sample\":");
        crate::gojson::write_str(&mut body, &name);
        body.push_str(",\"timeout_seconds\":900}");
        let (status, rb) = match self.call("POST", "/v1/sample-runs", Some(&body)) {
            Ok(r) => r,
            Err(e) => return fail(a, "unavailable", format!("Limbo does not answer: {e}")),
        };
        let started = crate::gojson::parse_first(&rb[..rb.len().min(64 << 10)]).unwrap_or_default();
        let member = |v: &crate::gojson::Value, k: &str| match v {
            crate::gojson::Value::Object(m) => m.iter().rev().find(|(key, _)| key == k).map(|(_, v)| v.clone()),
            _ => None,
        };
        let id = match member(&started, "id") {
            Some(crate::gojson::Value::String(s)) => s,
            _ => String::new(),
        };
        if status != 202 || id.is_empty() {
            let why = match member(&started, "error") {
                None | Some(crate::gojson::Value::Null) => "<nil>".to_string(),
                Some(crate::gojson::Value::String(s)) => s,
                Some(crate::gojson::Value::Bool(b)) => b.to_string(),
                Some(crate::gojson::Value::Number(n)) => crate::gotext::parse_float(&n).map_or(n.clone(), |f| format!("{f}")),
                Some(other) => {
                    let mut o = String::new();
                    crate::gojson::write_value(&mut o, &other);
                    o
                }
            };
            return fail(a, "unavailable", format!("Limbo refused the analysis: {why}"));
        }
        set(at, &mut a, "run_id", Val::Str(id.clone()));
        let deadline = std::time::Instant::now() + self.wait;
        while std::time::Instant::now() < deadline {
            std::thread::sleep(self.poll);
            let Ok((_, rb)) = self.call("GET", &format!("/v1/runs/{id}"), None) else { continue };
            let Ok(v) = crate::gojson::parse_first(&rb[..rb.len().min(1 << 20)]) else { continue };
            let Ok(Some(m)) = crate::gojson::struct_members(&v, &["status", "stdout", "stderr", "error"], "") else { continue };
            let mut f = [String::new(), String::new(), String::new(), String::new()];
            let mut bad = false;
            for (k, x) in m {
                match x {
                    crate::gojson::Value::String(s) => f[k] = s.clone(),
                    crate::gojson::Value::Null => {}
                    _ => bad = true,
                }
            }
            if bad || f[0] == "running" {
                continue;
            }
            let mut out = f[1].clone();
            if !f[2].is_empty() {
                out.push_str("\n== messages\n");
                out.push_str(&f[2]);
            }
            let ob = out.as_bytes();
            let out = if ob.len() > 60 << 10 { format!("{}\n[cut]", to_valid_utf8(&ob[..60 << 10])) } else { out };
            set(at, &mut a, "status", Val::Str(f[0].clone()));
            set(at, &mut a, "output", Val::Str(to_valid_utf8(out.as_bytes())));
            set(at, &mut a, "error", Val::Str(f[3].clone()));
            return a;
        }
        fail(a, "timeout", "the analysis did not finish in time".into())
    }
}

/// The Analysis type (the `analysis` field of an entry).
fn analysis_ty() -> &'static Ty {
    match &fields(&ENTRY)[idx(&ENTRY, "analysis")].1 {
        Ty::Ptr(t) => t,
        _ => unreachable!(),
    }
}

/// The status and output of an analysis value.
pub fn analysis_fields(a: &Val) -> (String, String, String, String) {
    let at = analysis_ty();
    let g = |n: &str| match get(at, a, n) {
        Val::Str(s) => s.clone(),
        _ => String::new(),
    };
    (g("status"), g("run_id"), g("error"), g("output"))
}

/// Go's `QueueAnalysis`: asks the root unit to analyse a held sample.
pub fn queue_analysis(dir: &str, sha: &str) -> Result<(), String> {
    if sha.len() != 64 {
        return Err("a full SHA-256 is needed".into());
    }
    let mut b = String::from("{\"analyze\":");
    crate::gojson::write_str(&mut b, sha);
    b.push('}');
    crate::gopath::write_file(&crate::gopath::join(&[dir, &format!("analyze-{}.json", &sha[..16])]), b.as_bytes(), 0o644)
}
