//! `heimdall-fileguard scan`: the one "check this file before I use it" for every place files come in (a font dropped into
//! Settings, what Minos unpacks, a copy from a USB drive). For each file:
//!
//! - its name: a look-alike or hidden-character name is a warning;
//! - what it really is: a program named like a picture, a font, a song or a document is refused, and so is a "font" that
//!   is not one;
//! - the downloads guard's checks (guard.rs): something that contacts a server when opened is a warning;
//! - an archive (ZIP, which Office files are too, tar, compressed): the extraction's dry run in its sandbox, one level deep. A
//!   decompression bomb, a name that escapes the folder or a file named two ways is refused; one too big to check in full,
//!   damaged, or with encrypted parts is a warning;
//! - ClamAV (clamav.rs): known malware is refused; a possibly unwanted program or a heuristic guess is a warning, and so is
//!   "not-fully-scanned" (ClamAV stopped at a limit), said plainly.
//!
//! Exit 0 when nothing is refused, 1 when something is, 2 when a file could not be read (or a usage error).

use crate::clamav::{self, Clam};
use crate::extract::{self, Why};
use crate::{guard, intake, lookalike};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Verdict {
    Ok,
    Warn,
    Refused,
}

impl Verdict {
    pub fn id(self) -> &'static str {
        match self {
            Verdict::Ok => "ok",
            Verdict::Warn => "warn",
            Verdict::Refused => "refused",
        }
    }
}

/// The check of one file.
#[derive(Clone, Debug)]
pub struct Checked {
    pub path: PathBuf,
    pub verdict: Verdict,
    pub reasons: Vec<String>,
    pub clamav: Clam,
    /// The downloads guard's report (for the watcher's notice).
    pub guard: Option<guard::Report>,
    /// The file could not be read.
    pub error: bool,
    pub size: u64,
    /// Bytes an archive unpacks to (as far as the dry run went).
    pub unpacked: u64,
}

impl Checked {
    fn new(path: &Path) -> Checked {
        Checked {
            path: path.to_path_buf(),
            verdict: Verdict::Ok,
            reasons: vec![],
            clamav: Clam::Unavailable(None),
            guard: None,
            error: false,
            size: 0,
            unpacked: 0,
        }
    }

    pub fn raise(&mut self, v: Verdict, reason: impl Into<String>) {
        self.verdict = self.verdict.max(v);
        let r = reason.into();
        if !self.reasons.contains(&r) && self.reasons.len() < 16 {
            self.reasons.push(r);
        }
    }

    pub fn json(&self) -> Value {
        json!({"path": self.path.to_string_lossy(), "verdict": self.verdict.id(), "reasons": self.reasons, "clamav": self.clamav.id()})
    }
}

/// How `scan` runs.
#[derive(Clone, Debug, Default)]
pub struct Settings {
    /// heimdall-fileguard itself, to run an archive's dry run in the sandboxed worker (None: in this process, for tests).
    pub worker: Option<PathBuf>,
    /// Look into archives (the watcher leaves it for after a game).
    pub archives: bool,
}

fn ext(name: &str) -> String {
    match name.rsplit_once('.') {
        Some((stem, e)) if !stem.is_empty() => e.to_ascii_lowercase(),
        _ => String::new(),
    }
}

const FONTS: &[&str] = &["ttf", "otf", "ttc", "otc", "woff", "woff2", "pfb", "pfa"];

/// Extensions of things that are never programs: a program wearing one is pretending.
const DATA: &[&str] = &[
    "ttf", "otf", "ttc", "otc", "woff", "woff2", "png", "jpg", "jpeg", "gif", "webp", "bmp", "tif", "tiff", "heic", "heif", "avif", "ico",
    "svg", "mp3", "flac", "ogg", "opus", "wav", "m4a", "aac", "wma", "mp4", "m4v", "mkv", "webm", "avi", "mov", "wmv", "pdf", "doc",
    "docx", "xls", "xlsx", "ppt", "pptx", "odt", "ods", "odp", "rtf", "epub", "txt", "md", "csv", "json", "xml", "html", "htm",
];
const TEXT: &[&str] = &["txt", "md", "csv", "json", "xml", "html", "htm", "svg"];

/// A program, from its first bytes: ELF, Windows (MZ), Mach-O; a script (#!) counts only for formats that are not text.
fn program(head: &[u8], e: &str) -> Option<&'static str> {
    if head.starts_with(b"\x7FELF") {
        Some("a Linux program")
    } else if head.starts_with(b"MZ") {
        Some("a Windows program")
    } else if [b"\xFE\xED\xFA\xCE", b"\xCE\xFA\xED\xFE", b"\xFE\xED\xFA\xCF", b"\xCF\xFA\xED\xFE"].iter().any(|m| head.starts_with(*m)) {
        Some("a macOS program")
    } else if head.starts_with(b"#!") && !TEXT.contains(&e) {
        Some("a script")
    } else {
        None
    }
}

fn font(head: &[u8], e: &str) -> bool {
    match e {
        "pfb" => head.starts_with(b"\x80\x01"),
        "pfa" => head.starts_with(b"%!PS-AdobeFont") || head.starts_with(b"%!FontType1"),
        _ => [&b"\x00\x01\x00\x00"[..], b"OTTO", b"true", b"typ1", b"ttcf", b"wOFF", b"wOF2"].iter().any(|m| head.starts_with(m)),
    }
}

/// Everything but ClamAV for one file.
pub fn own(path: &Path, s: &Settings) -> Checked {
    let mut c = Checked::new(path);
    let f = match intake::open_archive(path) {
        Ok(f) => f,
        Err(e) => {
            let regular = std::fs::metadata(path).map(|m| m.is_file()).unwrap_or(true);
            c.error = regular;
            c.raise(
                Verdict::Refused,
                if regular { format!("it could not be read: {e}") } else { "it is not a regular file (a folder, device or pipe)".into() },
            );
            return c;
        }
    };
    c.size = f.metadata().map(|m| m.len()).unwrap_or(0);
    let mut head = vec![0u8; c.size.min(8192) as usize];
    if let Err(e) = crate::zip::Source::read_at(&f, 0, &mut head) {
        c.error = true;
        c.raise(Verdict::Refused, format!("it could not be read: {e}"));
        return c;
    }
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let e = ext(&name);
    let lr = lookalike::check(&name);
    if lr.suspicious() {
        c.raise(Verdict::Warn, format!("its name may not be what it seems: {}", lr.words()));
    }
    if DATA.contains(&e.as_str()) {
        if let Some(p) = program(&head, &e) {
            c.raise(Verdict::Refused, format!("it is named like a .{e} file but it is {p}"));
        }
    }
    if FONTS.contains(&e.as_str()) && !font(&head, &e) && !c.reasons.iter().any(|r| r.contains("program") || r.contains("script")) {
        c.raise(Verdict::Refused, format!("it is named like a font (.{e}) but it is not one"));
    }
    match guard::inspect_path(path, &guard::Limits::default()) {
        Ok(r) => {
            for x in r.findings.iter().take(3) {
                let t = x.target.as_deref().map(|t| format!(": {}", lookalike::visible(t))).unwrap_or_default();
                let i = x.inside.as_deref().map(|i| format!(" (inside {})", lookalike::visible(i))).unwrap_or_default();
                c.raise(Verdict::Warn, format!("{}{t}{i}", x.what));
            }
            if r.findings.len() > 3 {
                c.raise(Verdict::Warn, format!("and {} more things that can contact a server", r.findings.len() - 3));
            }
            c.guard = Some(r);
        }
        Err(err) => {
            c.error = true;
            c.raise(Verdict::Refused, format!("it could not be read: {err}"));
            return c;
        }
    }
    if s.archives {
        archive(&mut c, f, &name, s);
    }
    c
}

/// Only the archive's dry run (the watcher's heavy half; the light checks ran when the file arrived).
pub fn archive_only(path: &Path, s: &Settings) -> Checked {
    let mut c = Checked::new(path);
    match intake::open_archive(path) {
        Ok(f) => {
            c.size = f.metadata().map(|m| m.len()).unwrap_or(0);
            let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            archive(&mut c, f, &name, s);
        }
        Err(_) => c.error = true,
    }
    c
}

/// The archive's dry run, and what it means.
fn archive(c: &mut Checked, f: std::fs::File, name: &str, s: &Settings) {
    let Ok(Some(fmt)) = intake::kind_of(&f) else { return };
    let out = match &s.worker {
        Some(exe) => {
            drop(f);
            intake::run_worker(exe, &c.path, None, &[])
        }
        None => intake::engine(f, name, fmt, &extract::Options::default(), &mut extract::Discard),
    };
    c.unpacked = out.unpacked;
    if let Some(r) = &out.refused {
        match r.why {
            Why::Bomb | Why::Escape | Why::Trick => c.raise(Verdict::Refused, r.reason.clone()),
            Why::TooBig => c.raise(Verdict::Warn, format!("it is too big to check in full: {}", r.reason)),
            Why::Unsupported if fmt != extract::Format::Zip => {} // a .gz of something that is not ours to open
            _ => c.raise(Verdict::Warn, format!("Extract would refuse it: {}", r.reason)),
        }
    }
    let enc = out.skipped.iter().filter(|k| k.reason.starts_with("encrypted")).count();
    if enc > 0 {
        c.raise(Verdict::Warn, format!("{enc} encrypted file{} inside could not be checked", if enc == 1 { "" } else { "s" }));
    }
}

/// ClamAV's answers folded into the checks.
pub fn with_clamav(items: &mut [Checked], sc: &clamav::Scanner) {
    let idx: Vec<usize> = (0..items.len()).filter(|&i| !items[i].error).collect();
    let paths: Vec<&Path> = idx.iter().map(|&i| items[i].path.as_path()).collect();
    let answers = clamav::scan(sc, &paths);
    for (k, a) in idx.into_iter().zip(answers) {
        let c = &mut items[k];
        let mut a = a;
        // where ClamAV does not say it stopped at a limit (clamd without AlertExceedsMax), the sizes say it
        if a == Clam::Clean && (c.size > sc.limits.max_file || c.unpacked > sc.limits.max_scan) {
            a = Clam::NotFully("it is bigger than ClamAV's limits".into());
        }
        match &a {
            Clam::Infected(sig) if clamav::confident(sig) => c.raise(Verdict::Refused, format!("ClamAV knows it as malware ({sig})")),
            Clam::Infected(sig) => c.raise(Verdict::Warn, format!("ClamAV warns about it ({sig}): possibly unwanted, not certain malware")),
            Clam::NotFully(why) => c.raise(Verdict::Warn, format!("not fully scanned by ClamAV: {why}")),
            _ => {}
        }
        c.clamav = a;
    }
}

/// The whole check of several files.
pub fn scan(paths: &[PathBuf], s: &Settings, sc: &clamav::Scanner) -> Vec<Checked> {
    let mut items: Vec<Checked> = paths.iter().map(|p| own(p, s)).collect();
    with_clamav(&mut items, sc);
    items
}

/// The exit code: 2 when a file could not be read, 1 when one is refused, else 0.
pub fn code(items: &[Checked]) -> i32 {
    if items.iter().any(|c| c.error) {
        2
    } else if items.iter().any(|c| c.verdict == Verdict::Refused) {
        1
    } else {
        0
    }
}

/// The text form: one line per file, its reasons under it.
pub fn text(c: &Checked) -> String {
    let mut s = format!("{}: {}", lookalike::visible(&c.path.display().to_string()), c.verdict.id());
    for r in &c.reasons {
        s.push_str(&format!("\n  - {r}"));
    }
    let clam = match &c.clamav {
        Clam::Clean => "clean".to_string(),
        Clam::Infected(sig) => format!("found {sig}"),
        Clam::NotFully(why) => format!("not fully scanned ({why})"),
        Clam::Unavailable(None) => "not installed or not running".into(),
        Clam::Unavailable(Some(why)) => why.clone(),
    };
    s.push_str(&format!("\n  ClamAV: {clam}"));
    s
}

#[cfg(test)]
mod tests;
