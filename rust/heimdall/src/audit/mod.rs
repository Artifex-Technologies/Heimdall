//! The long audits (Go: internal/pkgaudit, internal/kernelaudit, internal/hardening, internal/gametime): installed packages
//! against Arch's security tracker, installed kernels against the kernel's own CVE list, and settings that leave a hole
//! open. Each runs at start and then every `package_audit_interval_hours`, and waits while a game runs (Yggdrasil's
//! `yggdrasil-gametime status`).
//!
//! They run on one thread of their own, since reading a tracker of thousands of entries takes a moment the daemon's loop
//! should not wait for; the events go to the loop over a channel, and a byte in a pipe wakes the loop's poll(2) (`AuditSource`).
//! The state files are Go's: a JSON object of the keys still open, each `true`.

pub mod gametime;
pub mod hardening;
pub mod kernel;
pub mod pkg;
pub mod report;
pub mod vercmp;

use crate::sources::{Msg, Source};
use std::collections::{BTreeMap, BTreeSet};
use std::os::fd::{AsFd, BorrowedFd, FromRawFd, OwnedFd};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// An audit that could not run: Go's error text, and whether it was a missing file (Go: os.IsNotExist, not logged).
#[derive(Debug, Clone, PartialEq)]
pub struct AuditError {
    pub msg: String,
    pub not_exist: bool,
}

impl AuditError {
    pub fn io(op: &str, path: &str, e: &std::io::Error) -> Self {
        AuditError { msg: crate::sources::go_path_error(op, path, e), not_exist: e.kind() == std::io::ErrorKind::NotFound }
    }
    pub fn other(msg: String) -> Self {
        AuditError { msg, not_exist: false }
    }
}

impl std::fmt::Display for AuditError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.msg)
    }
}

/// The keys an audit reported and that are still open (Go: `map[string]bool` read with errors ignored: a document that is
/// not JSON is a fresh start, a value of the wrong type is skipped and the rest kept).
pub fn read_seen(path: &str) -> BTreeSet<String> {
    let mut m: BTreeMap<String, bool> = BTreeMap::new();
    if let Ok(b) = std::fs::read(path) {
        if let Ok(v) = crate::gojson::parse(&b) {
            let _ = crate::gojson::FromGo::read_into(&mut m, &v, "");
        }
    }
    m.into_iter().filter(|(_, v)| *v).map(|(k, _)| k).collect()
}

/// Writes the keys still open as Go's `json.Marshal(map[string]bool)` does (sorted, each `true`), atomically, mode 0600.
/// An empty path writes nothing (Go would write a stray `.tmp` in its working folder).
pub fn write_seen(path: &str, keys: &BTreeSet<String>) {
    if path.is_empty() {
        return;
    }
    let mut out = String::from("{");
    for (i, k) in keys.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        crate::gojson::write_str(&mut out, k);
        out.push_str(":true");
    }
    out.push('}');
    let _ = crate::state::write_atomic(path, out.as_bytes(), 0o600);
}

/// The audits the config switches on, and how often.
pub struct Audits {
    pub packages: Option<pkg::Watcher>,
    pub kernel: Option<kernel::Watcher>,
    pub hardening: Option<hardening::Watcher>,
    pub every: Duration,
    pub gate: gametime::Gate,
}

impl Audits {
    pub fn is_empty(&self) -> bool {
        self.packages.is_none() && self.kernel.is_none() && self.hardening.is_none()
    }

    /// One round: each audit after the game-time gate lets it go. False when told to stop while waiting.
    pub fn round(&self, stop: &mpsc::Receiver<()>, send: &mut dyn FnMut(Msg)) -> bool {
        if let Some(w) = &self.packages {
            if !self.gate.wait(stop, "the package audit", send) {
                return false;
            }
            match w.poll() {
                Ok(evs) => evs.into_iter().for_each(|e| send(Msg::Event(e))),
                Err(e) if !e.not_exist => send(Msg::Log(format!("package audit: {e}"))),
                Err(_) => {}
            }
        }
        if let Some(w) = &self.kernel {
            if !self.gate.wait(stop, "the kernel audit", send) {
                return false;
            }
            match w.poll() {
                Ok(evs) => evs.into_iter().for_each(|e| send(Msg::Event(e))),
                Err(e) if !e.not_exist => send(Msg::Log(format!("kernel audit: {e}"))),
                Err(_) => {}
            }
        }
        if let Some(w) = &self.hardening {
            if !self.gate.wait(stop, "the hardening checks", send) {
                return false;
            }
            w.poll().into_iter().for_each(|e| send(Msg::Event(e)));
        }
        true
    }
}

pub(crate) fn pipe() -> std::io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: pipe2 fills the two descriptors, owned from here on.
    unsafe {
        if libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok((OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])))
    }
}

/// The audit thread's end on the daemon's loop: woken by the pipe, it hands on what the thread sent.
pub struct AuditSource {
    rx: mpsc::Receiver<Msg>,
    wake: OwnedFd,
    stop: Option<mpsc::Sender<()>>,
}

impl AuditSource {
    /// Starts the thread: a round at once, then one every `audits.every` after the last ended, until the daemon stops.
    pub fn start(audits: Audits) -> std::io::Result<AuditSource> {
        let (r, w) = pipe()?;
        let (tx, rx) = mpsc::channel::<Msg>();
        let (stop_tx, stop_rx) = mpsc::channel::<()>();
        std::thread::Builder::new().name("audits".into()).spawn(move || {
            let mut send = |m: Msg| {
                if tx.send(m).is_ok() {
                    let _ = rustix::io::write(&w, &[1]); // a full pipe already wakes the loop
                }
            };
            loop {
                if !audits.round(&stop_rx, &mut send) {
                    return;
                }
                // the tracker and the kernel list were a few megabytes while read: hand that back now, not in 6 hours (this
                // thread has a glibc arena of its own; measured: 6.3 MB PSS after a round instead of 16.6 MB with one arena
                // shared with the loop, where the first look at the sessions and the round fragment the same heap)
                // SAFETY: malloc_trim only releases free memory to the kernel.
                unsafe { libc::malloc_trim(0) };
                match stop_rx.recv_timeout(audits.every) {
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                    _ => return,
                }
            }
        })?;
        Ok(AuditSource { rx, wake: r, stop: Some(stop_tx) })
    }
}

impl Source for AuditSource {
    fn name(&self) -> &'static str {
        "audits"
    }
    fn fd(&self) -> Option<BorrowedFd<'_>> {
        Some(self.wake.as_fd())
    }
    fn due(&self) -> Option<Instant> {
        None
    }
    fn ready(&mut self, _now: Instant, out: &mut Vec<Msg>) {
        let mut buf = [0u8; 256];
        while matches!(rustix::io::read(&self.wake, &mut buf), Ok(n) if n > 0) {}
        out.extend(self.rx.try_iter());
    }
    fn run(&mut self, _now: Instant, _out: &mut Vec<Msg>) {}
    fn stop(&mut self, out: &mut Vec<Msg>) {
        // the thread ends at its next wait; an audit in the middle of a read is simply left (the process ends), as in Go
        self.stop.take();
        out.extend(self.rx.try_iter());
    }
}
