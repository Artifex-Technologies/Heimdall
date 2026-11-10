//! "Does pacman own this file, and is it what the package shipped?" from pacman's own database, read-only (Go:
//! internal/pkgverify): /var/lib/pacman/local/<pkg>/{files,mtree}.

use crate::detect::PackageVerifier;
use std::io::{BufRead, BufReader};

pub struct Verifier {
    pub dir: String,
}

impl Verifier {
    pub fn new(dir: &str) -> Verifier {
        Verifier { dir: dir.into() }
    }
}

fn listed(files: &str, rel: &str) -> bool {
    let Ok(f) = std::fs::File::open(files) else { return false };
    BufReader::new(f).split(b'\n').map_while(Result::ok).any(|l| l == rel.as_bytes())
}

/// mtree lines look like "./usr/bin/foo time=... size=... sha256digest=HEX".
fn digest(mtree: &str, rel: &str) -> String {
    let Ok(f) = std::fs::File::open(mtree) else { return String::new() };
    let want = format!("./{rel} ");
    let gz = flate2::read::GzDecoder::new(f);
    for line in BufReader::new(gz).split(b'\n') {
        let Ok(line) = line else { return String::new() };
        if line.len() > 1 << 20 {
            return String::new(); // Go's scanner stops at a line over 1 MiB
        }
        if !line.starts_with(want.as_bytes()) {
            continue;
        }
        let line = crate::gotext::lossy(&line);
        return crate::gotext::fields(&line).find_map(|f| f.strip_prefix("sha256digest=")).unwrap_or("").to_owned();
    }
    String::new()
}

impl Verifier {
    /// (package, recorded SHA-256 or "", owned).
    pub fn expected(&self, path: &str) -> (String, String, bool) {
        if self.dir.is_empty() {
            return (String::new(), String::new(), false);
        }
        let rel = path.strip_prefix('/').unwrap_or(path);
        let Ok(rd) = std::fs::read_dir(&self.dir) else { return (String::new(), String::new(), false) };
        let mut names: Vec<String> = rd
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        for n in names {
            if listed(&format!("{}/{n}/files", self.dir), rel) {
                return (n.clone(), digest(&format!("{}/{n}/mtree", self.dir), rel), true);
            }
        }
        (String::new(), String::new(), false)
    }
}

impl PackageVerifier for Verifier {
    fn expected(&self, path: &str) -> (String, String, bool) {
        Verifier::expected(self, path)
    }
}
