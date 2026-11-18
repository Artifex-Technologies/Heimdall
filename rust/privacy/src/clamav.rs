//! ClamAV for `heimdall-fileguard scan`: clamdscan when the clamd daemon answers (fast: its signatures stay loaded), else
//! clamscan with explicit limits, else "unavailable". Files are handed over as `/proc/self/fd/N` of descriptors opened here
//! and inherited by ClamAV: what ClamAV scans is the file this program checked (not whatever the name points at a moment
//! later), and every line of its answer names one descriptor, whatever the file is called (a name with ": " or a line break
//! in it cannot confuse the reading).
//!
//! The limits are said explicitly so a decompression bomb is reported, not silently half-scanned: clamscan gets them on its
//! command line (it does not read clamd.conf); clamd has them from /etc/clamav/clamd.conf (Labyrinth OS ships one with
//! the same values). "Heuristics.Limits.Exceeded.*" means ClamAV stopped at a limit: that is "not-fully-scanned" (a warning),
//! never malware, so a big legitimate archive is never quarantined for its size.

use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

/// What ClamAV said about one file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Clam {
    Clean,
    /// Its signature name.
    Infected(String),
    /// ClamAV stopped at a limit or could not read all of it; why, in plain words.
    NotFully(String),
    /// No ClamAV, or it could not run (why, when known).
    Unavailable(Option<String>),
}

impl Clam {
    /// The JSON value: "clean", "infected:SIGNATURE", "not-fully-scanned", "unavailable".
    pub fn id(&self) -> String {
        match self {
            Clam::Clean => "clean".into(),
            Clam::Infected(s) => format!("infected:{s}"),
            Clam::NotFully(_) => "not-fully-scanned".into(),
            Clam::Unavailable(_) => "unavailable".into(),
        }
    }
}

/// The limits in force, for knowing when a file is bigger than ClamAV looks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub max_file: u64,
    pub max_scan: u64,
    /// AlertExceedsMax: ClamAV itself says when it stops at a limit.
    pub alerts: bool,
}

/// The limits clamscan gets here and Labyrinth's clamd.conf sets: a file up to 256 MiB, 512 MiB scanned per file (an
/// archive and everything in it), 12 levels of archives in archives, 10,000 files in one, 2 minutes per file, and an alert
/// whenever one is reached.
pub const OURS: Limits = Limits { max_file: 256 << 20, max_scan: 512 << 20, alerts: true };
const CLAMSCAN_ARGS: &[&str] = &[
    "--no-summary",
    "--max-filesize=256M",
    "--max-scansize=512M",
    "--max-recursion=12",
    "--max-files=10000",
    "--max-scantime=120000",
    "--alert-exceeds-max=yes",
    "--heuristic-alerts=yes",
];

/// clamd's defaults when its config does not say (ClamAV 1.x).
const CLAMD_DEFAULT: Limits = Limits { max_file: 100 << 20, max_scan: 400 << 20, alerts: false };

/// The scanner found on this computer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Scanner {
    pub prog: Option<PathBuf>,
    pub daemon: bool,
    pub limits: Limits,
}

impl Scanner {
    pub fn none() -> Scanner {
        Scanner { prog: None, daemon: false, limits: OURS }
    }
    pub fn name(&self) -> &'static str {
        match (&self.prog, self.daemon) {
            (None, _) => "none",
            (Some(_), true) => "clamdscan",
            (Some(_), false) => "clamscan",
        }
    }
}

fn on_path(prog: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|paths| std::env::split_paths(&paths).map(|d| d.join(prog)).find(|p| p.is_file()))
}

fn size(v: &str) -> Option<u64> {
    let v = v.trim();
    let (num, mult) = match v.chars().last()? {
        'k' | 'K' => (&v[..v.len() - 1], 1u64 << 10),
        'm' | 'M' => (&v[..v.len() - 1], 1 << 20),
        'g' | 'G' => (&v[..v.len() - 1], 1 << 30),
        _ => (v, 1),
    };
    num.trim().parse::<u64>().ok().map(|n| n.saturating_mul(mult))
}

/// clamd.conf: its sockets and limits.
pub fn parse_conf(text: &str) -> (Vec<PathBuf>, Limits) {
    let mut socks = vec![];
    let mut l = CLAMD_DEFAULT;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once(char::is_whitespace) else { continue };
        let v = v.trim();
        match k {
            "LocalSocket" => socks.push(PathBuf::from(v)),
            "MaxFileSize" => l.max_file = size(v).filter(|&n| n > 0).unwrap_or(u64::MAX),
            "MaxScanSize" => l.max_scan = size(v).filter(|&n| n > 0).unwrap_or(u64::MAX),
            "AlertExceedsMax" => l.alerts = matches!(v.to_ascii_lowercase().as_str(), "yes" | "true" | "1"),
            _ => {}
        }
    }
    (socks, l)
}

/// The scanner to use: clamdscan when clamd answers on its socket, else clamscan (when `allow_clamscan`: it loads every
/// signature on each start, a second or more of processor time and about a gigabyte of memory, too heavy for the background
/// guard), else none. `HEIMDALL_CLAMAV=off|clamscan|clamdscan` forces a choice (for tests, and for whoever wants it off).
pub fn find(allow_clamscan: bool) -> Scanner {
    let force = std::env::var("HEIMDALL_CLAMAV").unwrap_or_default();
    if force == "off" {
        return Scanner::none();
    }
    let conf = std::fs::File::open("/etc/clamav/clamd.conf")
        .and_then(|f| {
            let mut s = String::new();
            std::io::Read::read_to_string(&mut std::io::Read::take(f, 1 << 20), &mut s).map(|_| s)
        })
        .unwrap_or_default();
    let (mut socks, dl) = parse_conf(&conf);
    socks.extend(["/run/clamav/clamd.ctl", "/run/clamav/clamd.sock"].map(PathBuf::from));
    let up = force == "clamdscan" || (force.is_empty() && socks.iter().any(|s| std::os::unix::net::UnixStream::connect(s).is_ok()));
    if up {
        if let Some(p) = on_path("clamdscan") {
            return Scanner { prog: Some(p), daemon: true, limits: dl };
        }
    }
    if allow_clamscan || force == "clamscan" {
        if let Some(p) = on_path("clamscan") {
            return Scanner { prog: Some(p), daemon: false, limits: OURS };
        }
    }
    Scanner::none()
}

/// A definite malware signature, not a guess: possibly unwanted programs, heuristics, phishing hints, encrypted files and
/// limits are warnings. The same rule as Labyrinth OS's labyrinth-scan-downloads (packages/tools/src/scan.rs `confident`).
pub fn confident(sig: &str) -> bool {
    let s = sig.to_lowercase();
    !(s.starts_with("pua.")
        || s.starts_with("heuristics.")
        || s.starts_with("win.test.")
        || s.contains("heuristic")
        || s.contains(".phish")
        || s.starts_with("phishing.")
        || s.starts_with("html.phish")
        || s.contains("encrypted")
        || s.contains("exceeds")
        || s.contains("limit"))
}

/// One line of ClamAV's answer about one descriptor.
pub fn verdict(rest: &str) -> Clam {
    let rest = rest.trim();
    if rest == "OK" || rest == "Empty file" {
        return Clam::Clean;
    }
    if let Some(sig) = rest.strip_suffix(" FOUND") {
        let sig = sig.trim();
        if sig.starts_with("Heuristics.Limits.Exceeded") {
            return Clam::NotFully(format!("ClamAV stopped at one of its limits ({sig})"));
        }
        return Clam::Infected(sig.to_string());
    }
    if let Some(e) = rest.strip_suffix(" ERROR") {
        return Clam::NotFully(format!("ClamAV could not scan it ({})", e.trim()));
    }
    Clam::NotFully(format!("ClamAV gave no clear answer ({rest})"))
}

/// Scans files, 200 per ClamAV run; one answer per file, in order.
pub fn scan(sc: &Scanner, files: &[&Path]) -> Vec<Clam> {
    let Some(prog) = &sc.prog else { return files.iter().map(|_| Clam::Unavailable(None)).collect() };
    let mut out = Vec::with_capacity(files.len());
    for chunk in files.chunks(200) {
        out.extend(run(prog, sc.daemon, chunk));
    }
    out
}

fn run(prog: &Path, daemon: bool, files: &[&Path]) -> Vec<Clam> {
    let mut res: Vec<Clam> = files.iter().map(|_| Clam::Unavailable(Some("ClamAV did not answer for it".into()))).collect();
    let mut open: Vec<(usize, std::fs::File)> = vec![];
    for (i, f) in files.iter().enumerate() {
        use std::os::unix::fs::OpenOptionsExt;
        match std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NONBLOCK).open(f) {
            Ok(h) => open.push((i, h)),
            Err(e) => res[i] = Clam::Unavailable(Some(format!("it could not be opened: {e}"))),
        }
    }
    if open.is_empty() {
        return res;
    }
    let fds: Vec<i32> = open.iter().map(|(_, f)| f.as_raw_fd()).collect();
    let mut cmd = Command::new(prog);
    if daemon {
        cmd.args(["--fdpass", "--no-summary"]);
    } else {
        cmd.args(CLAMSCAN_ARGS);
    }
    cmd.arg("--");
    for fd in &fds {
        cmd.arg(format!("/proc/self/fd/{fd}"));
    }
    cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let keep = fds.clone();
    // SAFETY: fcntl only, in the child before exec: the descriptors are passed on
    unsafe {
        std::os::unix::process::CommandExt::pre_exec(&mut cmd, move || {
            for &fd in &keep {
                libc::fcntl(fd, libc::F_SETFD, 0);
            }
            Ok(())
        });
    }
    let child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            let why = format!("ClamAV could not start: {e}");
            for (i, _) in &open {
                res[*i] = Clam::Unavailable(Some(why.clone()));
            }
            return res;
        }
    };
    // a hostile file can keep ClamAV busy: two minutes per file is its own limit, and the whole run stops at 30 minutes
    let limit = Duration::from_secs((120 + 60 * open.len() as u64).min(1800));
    let out = crate::intake::wait_output(child, limit);
    let text = String::from_utf8_lossy(&out.stdout);
    let mut by_fd = std::collections::HashMap::new();
    for (k, (i, _)) in open.iter().enumerate() {
        by_fd.insert(format!("/proc/self/fd/{}", fds[k]), *i);
    }
    for line in text.lines() {
        let Some((name, rest)) = line.split_once(": ") else { continue };
        if let Some(&i) = by_fd.get(name) {
            res[i] = verdict(rest);
        }
    }
    if out.timed_out {
        for (i, _) in &open {
            if matches!(res[*i], Clam::Unavailable(_)) {
                res[*i] = Clam::NotFully("ClamAV took too long".into());
            }
        }
    } else if open.iter().all(|(i, _)| matches!(res[*i], Clam::Unavailable(_))) {
        // nothing answered: ClamAV could not run (no signatures yet, clamd gone...): its first complaint says why
        let err = String::from_utf8_lossy(&out.stderr);
        let why =
            err.lines().map(str::trim).find(|l| !l.is_empty()).map(|l| format!("ClamAV could not run: {}", crate::lookalike::visible(l)));
        for (i, _) in &open {
            res[*i] = Clam::Unavailable(why.clone());
        }
    }
    drop(open);
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn answers_are_read() {
        assert_eq!(verdict("OK"), Clam::Clean);
        assert_eq!(verdict("Empty file"), Clam::Clean);
        assert_eq!(verdict("Eicar-Test-Signature FOUND"), Clam::Infected("Eicar-Test-Signature".into()));
        assert!(matches!(verdict("Heuristics.Limits.Exceeded.MaxScanSize FOUND"), Clam::NotFully(_)));
        assert!(matches!(verdict("Can't open file or directory ERROR"), Clam::NotFully(_)));
        assert_eq!(Clam::Infected("X.Y".into()).id(), "infected:X.Y");
        assert_eq!(Clam::NotFully(String::new()).id(), "not-fully-scanned");
        assert!(confident("Win.Trojan.Agent-1") && confident("Eicar-Test-Signature"));
        assert!(
            !confident("PUA.Win.Packer.Upx")
                && !confident("Heuristics.Encrypted.Zip")
                && !confident("Heuristics.Limits.Exceeded.MaxFileSize")
        );
    }

    #[test]
    fn clamd_conf_is_read() {
        let (s, l) = parse_conf("# c\nLocalSocket /run/clamav/clamd.ctl\nMaxFileSize 256M\nMaxScanSize 1G\nAlertExceedsMax yes\n");
        assert_eq!(s, [PathBuf::from("/run/clamav/clamd.ctl")]);
        assert_eq!(l, Limits { max_file: 256 << 20, max_scan: 1 << 30, alerts: true });
        let (_, d) = parse_conf("");
        assert_eq!(d, CLAMD_DEFAULT);
        assert_eq!(parse_conf("MaxFileSize 0\n").1.max_file, u64::MAX, "0 means no limit");
    }
}
