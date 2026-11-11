//! ClamAV as Heimdall runs it, and `heimdalld scan-files` (Go: internal/scan): clamdscan when a ClamAV daemon's socket is
//! there, else clamscan, found on the PATH as Go's `exec.LookPath` finds them; the files collected as Go's `filepath.WalkDir`
//! walks (links never followed, unreadable folders skipped), the exclusions matched as Go's `filepath.Match`, the remembered
//! files kept in Go's JSON, the scan in batches of 200. Paths are bytes throughout, as Go's strings are.

use super::gomatch::go_match;
use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{MetadataExt, PermissionsExt};

const SOCKETS: &[&str] = &["/run/clamav/clamd.ctl", "/run/clamav/clamd.sock", "/var/run/clamav/clamd.ctl"];

/// Go's `exec.LookPath` for a plain name: the first executable regular file of that name in the PATH.
pub fn look_path(name: &str) -> Option<String> {
    let path = std::env::var("PATH").unwrap_or_default();
    for dir in path.split(':') {
        let dir = if dir.is_empty() { "." } else { dir };
        let p = format!("{dir}/{name}");
        if let Ok(m) = std::fs::metadata(&p) {
            if m.is_file() && m.permissions().mode() & 0o111 != 0 {
                return Some(p);
            }
        }
    }
    None
}

/// The scanner: clamdscan or clamscan, or none.
pub struct ClamAv {
    bin: String,
}

/// One file's result.
#[derive(Clone, Debug, Default)]
pub struct ScanResult {
    pub path: Vec<u8>,
    pub infected: bool,
    pub signature: String,
    pub error: String,
}

impl Default for ClamAv {
    fn default() -> ClamAv {
        ClamAv::new()
    }
}

impl ClamAv {
    /// Go's `scan.NewClamAV`.
    pub fn new() -> ClamAv {
        if let Some(p) = look_path("clamdscan") {
            if SOCKETS.iter().any(|s| std::fs::metadata(s).is_ok()) {
                return ClamAv { bin: p };
            }
        }
        ClamAv { bin: look_path("clamscan").unwrap_or_default() }
    }

    pub fn available(&self) -> bool {
        !self.bin.is_empty()
    }

    fn args(&self) -> Vec<OsString> {
        let mut a: Vec<OsString> = vec!["--no-summary".into()];
        if self.bin.ends_with("clamdscan") {
            a.push("--fdpass".into());
        }
        a.push("--".into());
        a
    }

    /// Go's `ScanFile`: one file; an error when ClamAV failed (exit 1 is "found").
    pub fn scan_file(&self, path: &[u8]) -> (ScanResult, Option<String>) {
        let mut res = ScanResult { path: path.to_vec(), ..Default::default() };
        if !self.available() {
            return (res, Some("scan: ClamAV is not installed".into()));
        }
        let mut args = self.args();
        args.push(OsStr::from_bytes(path).to_os_string());
        let (out, code) = combined(&self.bin, &args);
        parse_output(&mut res, &out);
        if res.infected || res.error.is_empty() && code == Some(0) {
            return (res, None);
        }
        if code == Some(1) {
            return (res, None);
        }
        if res.error.is_empty() {
            res.error = crate::gotext::trim_space(&crate::gotext::lossy(&out)).to_string();
        }
        let e = format!("scan: clamav failed on {}: {}", crate::gotext::lossy(path), res.error);
        (res, Some(e))
    }

    /// Go's `ScanBatch`: many files in one run; a file ClamAV did not mention is "not reported by ClamAV".
    pub fn scan_batch(&self, paths: &[Vec<u8>]) -> Vec<ScanResult> {
        let mut res: Vec<ScanResult> =
            paths.iter().map(|p| ScanResult { path: p.clone(), error: "not reported by ClamAV".into(), ..Default::default() }).collect();
        if !self.available() || paths.is_empty() {
            for r in &mut res {
                r.error = "ClamAV is not installed".into();
            }
            return res;
        }
        let mut index: BTreeMap<&[u8], usize> = BTreeMap::new();
        for (i, p) in paths.iter().enumerate() {
            index.insert(p, i);
        }
        let mut args = self.args();
        args.extend(paths.iter().map(|p| OsStr::from_bytes(p).to_os_string()));
        let (out, _) = combined(&self.bin, &args);
        for line in scanner_lines(&out, 1 << 20) {
            let line = trim_space_bytes(line);
            let Some(i) = rfind(line, b": ") else { continue };
            let Some(&idx) = index.get(&line[..i]) else { continue };
            let verdict = &line[i + 2..];
            if verdict == b"OK" {
                res[idx] = ScanResult { path: paths[idx].clone(), ..Default::default() };
            } else if let Some(sig) = verdict.strip_suffix(b" FOUND") {
                res[idx] =
                    ScanResult { path: paths[idx].clone(), infected: true, signature: crate::gotext::lossy(sig), ..Default::default() };
            } else if verdict.ends_with(b" ERROR") {
                res[idx] = ScanResult { path: paths[idx].clone(), error: crate::gotext::lossy(line), ..Default::default() };
            }
        }
        res
    }
}

/// Go's `CombinedOutput`: both streams into one buffer, and the exit code (None: it did not run or was killed).
fn combined(bin: &str, args: &[OsString]) -> (Vec<u8>, Option<i32>) {
    use std::os::fd::FromRawFd;
    let mut fds = [0i32; 2];
    // SAFETY: pipe2 fills the two descriptors; each is owned by exactly one File below
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return (Vec::new(), None);
    }
    let (rf, wo) = unsafe { (std::fs::File::from_raw_fd(fds[0]), std::fs::File::from_raw_fd(fds[1])) };
    let Ok(we) = wo.try_clone() else { return (Vec::new(), None) };
    let mut rf = rf;
    let child = std::process::Command::new(bin).args(args).stdin(std::process::Stdio::null()).stdout(wo).stderr(we).spawn();
    let Ok(mut child) = child else { return (Vec::new(), None) };
    let mut out = Vec::new();
    let _ = std::io::Read::read_to_end(&mut rf, &mut out);
    let code = child.wait().ok().and_then(|s| s.code());
    (out, code)
}

/// Go's bufio.Scanner lines (CR before LF dropped), stopping at a line longer than `max`.
pub fn scanner_lines(b: &[u8], max: usize) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut start = 0;
    while start < b.len() {
        let end = b[start..].iter().position(|&c| c == b'\n').map_or(b.len(), |i| start + i);
        if end - start > max || (end == b.len() && end - start >= max) {
            break;
        }
        let mut line = &b[start..end];
        if line.ends_with(b"\r") {
            line = &line[..line.len() - 1];
        }
        out.push(line);
        start = end + 1;
    }
    out
}

fn is_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | b'\x0b' | b'\x0c' | b'\r')
}

/// Go's `strings.TrimSpace` for the ASCII spaces (ClamAV's lines carry no others at their ends).
fn trim_space_bytes(b: &[u8]) -> &[u8] {
    let s = b.iter().position(|&c| !is_space(c)).unwrap_or(b.len());
    let e = b.iter().rposition(|&c| !is_space(c)).map_or(s, |i| i + 1);
    &b[s..e.max(s)]
}

fn rfind(h: &[u8], n: &[u8]) -> Option<usize> {
    (0..=h.len().checked_sub(n.len())?).rev().find(|&i| &h[i..i + n.len()] == n)
}

/// Go's `ParseClamOutput`.
fn parse_output(res: &mut ScanResult, out: &[u8]) {
    for line in scanner_lines(out, 64 * 1024) {
        let line = trim_space_bytes(line);
        if line.ends_with(b" FOUND") {
            res.infected = true;
            if let Some(i) = rfind(line, b": ") {
                let v = &line[i + 2..];
                res.signature = crate::gotext::lossy(v.strip_suffix(b" FOUND").unwrap_or(v));
            }
        } else if line.ends_with(b" ERROR") {
            res.error = crate::gotext::lossy(line);
        }
    }
}

/// Go's `scan.Excluder`.
pub struct Excluder {
    pub patterns: Vec<String>,
}

impl Excluder {
    pub fn matches(&self, path: &[u8]) -> bool {
        for p in &self.patterns {
            if p.is_empty() {
                continue;
            }
            if p.contains(['*', '?', '[']) {
                if go_match(p.as_bytes(), path) == Some(true) {
                    return true;
                }
                if go_match(p.as_bytes(), &base_bytes(path)) == Some(true) {
                    return true;
                }
                continue;
            }
            let clean = crate::gopath::clean(p);
            let mut pre = clean.as_bytes().to_vec();
            pre.push(b'/');
            if path == clean.as_bytes() || path.starts_with(&pre) {
                return true;
            }
        }
        false
    }
}

/// Go's `filepath.Base` on bytes.
fn base_bytes(p: &[u8]) -> Vec<u8> {
    if p.is_empty() {
        return b".".to_vec();
    }
    let mut t = p;
    while t.len() > 1 && t.ends_with(b"/") {
        t = &t[..t.len() - 1];
    }
    if t == b"/" {
        return b"/".to_vec();
    }
    match t.iter().rposition(|&c| c == b'/') {
        Some(i) => t[i + 1..].to_vec(),
        None => t.to_vec(),
    }
}

/// The remembered files (Go's `scan.State`).
pub struct State {
    path: String,
    files: BTreeMap<Vec<u8>, (i64, i64)>,
    signatures: String,
}

impl State {
    /// Go's `LoadState`: a missing or unreadable file, or one that is not JSON, is a fresh start; what reads is kept.
    pub fn load(path: &str) -> State {
        let mut st = State { path: path.to_string(), files: BTreeMap::new(), signatures: String::new() };
        if path.is_empty() {
            return st;
        }
        let Ok(b) = std::fs::read(path) else { return st };
        let Ok(v) = crate::gojson::parse(&b) else { return st };
        if let Ok(Some(m)) = crate::gojson::struct_members(&v, &["files", "signatures"], "scan.State") {
            for (i, val) in m {
                match (i, val) {
                    (0, crate::gojson::Value::Object(files)) => {
                        for (k, f) in files {
                            let mut size_mtime = (0i64, 0i64);
                            if let Ok(Some(fm)) = crate::gojson::struct_members(f, &["size", "mtime"], "scan.stamp") {
                                for (j, x) in fm {
                                    if let crate::gojson::Value::Number(n) = x {
                                        if let Some(n) = crate::gotext::atoi(n) {
                                            if j == 0 {
                                                size_mtime.0 = n
                                            } else {
                                                size_mtime.1 = n
                                            }
                                        }
                                    }
                                }
                            }
                            st.files.insert(k.as_bytes().to_vec(), size_mtime);
                        }
                    }
                    (0, crate::gojson::Value::Null) => {}
                    (1, crate::gojson::Value::String(s)) => st.signatures = s.clone(),
                    _ => {}
                }
            }
        }
        st
    }

    /// Go's `UseSignatures`: other signatures mean every file is scanned again.
    pub fn use_signatures(&mut self, sig: &str) {
        if self.signatures != sig {
            self.files.clear();
            self.signatures = sig.to_string();
        }
    }

    fn unchanged(&self, path: &[u8], m: &std::fs::Metadata) -> bool {
        self.files.get(path).is_some_and(|&(s, t)| s == m.size() as i64 && t == crate::safefs::mtime_nanos(m))
    }

    fn record(&mut self, path: &[u8], m: &std::fs::Metadata) {
        self.files.insert(path.to_vec(), (m.size() as i64, crate::safefs::mtime_nanos(m)));
    }

    /// Go's `Save`: compact JSON, the keys in order, 0600 through a temporary file.
    pub fn save(&self) -> Result<(), String> {
        if self.path.is_empty() {
            return Ok(());
        }
        let mut out = String::from("{\"files\":{");
        // Go sorts the keys as the strings Go holds (the raw bytes)
        for (i, (k, (s, t))) in self.files.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            crate::gojson::write_str(&mut out, &crate::gotext::lossy(k));
            out.push_str(&format!(":{{\"size\":{s},\"mtime\":{t}}}"));
        }
        out.push('}');
        if !self.signatures.is_empty() {
            out.push_str(",\"signatures\":");
            crate::gojson::write_str(&mut out, &self.signatures);
        }
        out.push('}');
        let tmp = format!("{}.tmp", self.path);
        crate::gopath::write_file(&tmp, out.as_bytes(), 0o600)?;
        crate::gopath::rename(&tmp, &self.path)
    }
}

/// Go's `FileStamp`: "size:mtime" of a file, "" when it is not there.
pub fn file_stamp(path: &str) -> String {
    match std::fs::metadata(path) {
        Ok(m) => format!("{}:{}", m.size(), crate::safefs::mtime_nanos(&m)),
        Err(_) => String::new(),
    }
}

/// Go's `immunity.RulesStamp`: changes whenever an approved rule is added, changed or removed.
pub fn rules_stamp(dir: &str) -> String {
    use sha2::Digest;
    let mut m: Vec<Vec<u8>> = Vec::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let n = e.file_name().into_vec();
            if n.starts_with(b"heimdall-rule-") && n.ends_with(b".yar") && n.len() >= 18 {
                let mut p = crate::gopath::clean(dir).into_bytes();
                p.push(b'/');
                p.extend_from_slice(&n);
                m.push(p);
            }
        }
    }
    if m.is_empty() {
        return String::new();
    }
    m.sort();
    let mut h = sha2::Sha256::new();
    for p in &m {
        if let Ok(md) = std::fs::metadata(OsStr::from_bytes(p)) {
            h.update(p);
            h.update(format!(" {} {}\n", md.size(), crate::safefs::mtime_nanos(&md)).as_bytes());
        }
    }
    let hex: String = h.finalize().iter().map(|b| format!("{b:02x}")).collect();
    hex[..16].to_string()
}

/// Go's `scan.Collect`: the regular files under the roots, sorted, the excluded, too big and unchanged ones left out.
pub fn collect(roots: &[String], ex: &Excluder, max_bytes: i64, st: &State) -> Vec<Vec<u8>> {
    fn walk(p: &[u8], ft: Option<std::fs::FileType>, ex: &Excluder, max: i64, st: &State, out: &mut Vec<Vec<u8>>) {
        let os = OsStr::from_bytes(p);
        let ft = match ft {
            Some(t) => t,
            None => match std::fs::symlink_metadata(os) {
                Ok(m) => m.file_type(),
                Err(_) => return,
            },
        };
        if ex.matches(p) {
            return;
        }
        if ft.is_dir() {
            let Ok(rd) = std::fs::read_dir(os) else { return };
            let mut ents: Vec<(Vec<u8>, Option<std::fs::FileType>)> =
                rd.flatten().map(|e| (e.file_name().into_vec(), e.file_type().ok())).collect();
            ents.sort_by(|a, b| a.0.cmp(&b.0));
            for (name, t) in ents {
                walk(&join_bytes(p, &name), t, ex, max, st, out);
            }
            return;
        }
        if !ft.is_file() {
            return;
        }
        let Ok(m) = std::fs::symlink_metadata(os) else { return };
        if max > 0 && m.size() as i64 > max {
            return;
        }
        if st.unchanged(p, &m) {
            return;
        }
        out.push(p.to_vec());
    }
    let mut files = Vec::new();
    for r in roots {
        walk(r.as_bytes(), None, ex, max_bytes, st, &mut files);
    }
    files.sort();
    files
}

/// Go's `filepath.Join(dir, name)` on bytes: joined and cleaned.
fn join_bytes(dir: &[u8], name: &[u8]) -> Vec<u8> {
    let mut d = dir.to_vec();
    if !d.is_empty() {
        d.push(b'/');
    }
    d.extend_from_slice(name);
    clean_bytes(&d)
}

/// Go's `filepath.Clean` on bytes.
pub fn clean_bytes(p: &[u8]) -> Vec<u8> {
    if p.is_empty() {
        return b".".to_vec();
    }
    let rooted = p[0] == b'/';
    let mut parts: Vec<&[u8]> = Vec::new();
    for seg in p.split(|&c| c == b'/') {
        match seg {
            b"" | b"." => {}
            b".." => {
                if parts.last().is_some_and(|l| *l != b"..") {
                    parts.pop();
                } else if !rooted {
                    parts.push(b"..");
                }
            }
            s => parts.push(s),
        }
    }
    let joined = parts.join(&b'/');
    match (rooted, joined.is_empty()) {
        (true, _) => [b"/".as_slice(), &joined].concat(),
        (false, true) => b".".to_vec(),
        (false, false) => joined,
    }
}

/// Go's `scan.Run` with ClamAV (a batch scanner): 200 files a run, each clean or infected file remembered.
pub fn run(c: &ClamAv, files: &[Vec<u8>], st: &mut State) -> Vec<ScanResult> {
    let mut out = Vec::new();
    for chunk in files.chunks(200) {
        for r in c.scan_batch(chunk) {
            if r.error.is_empty() {
                if let Ok(m) = std::fs::metadata(OsStr::from_bytes(&r.path)) {
                    st.record(&r.path, &m);
                }
            }
            out.push(r);
        }
    }
    out
}
