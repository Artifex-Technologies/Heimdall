//! The sources: what turns the system into events (Go: internal/sources). The daemon runs them all on one thread: each says
//! when it next wants to look (a poll interval) and which file descriptor the kernel will wake it on (inotify, a journal
//! pipe), and the loop sleeps in one poll(2) until the first of them. Nothing runs while nothing happens.

pub mod agent;
pub mod files;
pub mod fim;
pub mod inotify;
pub mod journal;
pub mod limbo;
pub mod maintenance;
pub mod net;
pub mod telemetry;
pub mod vault;

use crate::event::Event;
use crate::gotime::Time;
use std::os::fd::BorrowedFd;
use std::time::Instant;

/// What a source hands the loop.
#[derive(Debug)]
pub enum Msg {
    /// An event for the engine.
    Event(Event),
    /// An event that Limbo's responder would also observe (shadow mode has none; kept apart so step 3 can add it).
    LimboEvent(Event),
    /// A problem reading a source, with a stable code; it is logged and becomes an `integration` alert.
    Issue(Issue),
    /// A line for the daemon's log only.
    Log(String),
}

/// A problem reading a source (Go: agentsource.Issue).
#[derive(Clone, Debug, PartialEq)]
pub struct Issue {
    pub code: String,
    pub path: String,
    pub detail: String,
    pub remedy: String,
}

impl std::fmt::Display for Issue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}: {} (remedy: {})", self.code, self.path, self.detail, self.remedy)
    }
}

/// A source on the daemon's loop.
pub trait Source {
    fn name(&self) -> &'static str;
    /// The descriptor the kernel wakes this source on, if any.
    fn fd(&self) -> Option<BorrowedFd<'_>> {
        None
    }
    /// When it next wants to run without being woken; None: only when woken.
    fn due(&self) -> Option<Instant>;
    /// Its descriptor is readable.
    fn ready(&mut self, _now: Instant, _out: &mut Vec<Msg>) {}
    /// Its time came.
    fn run(&mut self, now: Instant, out: &mut Vec<Msg>);
    /// The daemon is stopping: write what must be kept.
    fn stop(&mut self, _out: &mut Vec<Msg>) {}
}

/// An I/O error as Go prints it: `open PATH: permission denied` (Go's *PathError with its syscall.Errno text).
pub fn go_path_error(op: &str, path: &str, e: &std::io::Error) -> String {
    format!("{op} {path}: {}", go_errno(e))
}

/// The text Go gives an errno: the C library's message with a lowercase first letter (Go's table is the same messages).
pub fn go_errno(e: &std::io::Error) -> String {
    let s = e.to_string();
    let s = match s.find(" (os error ") {
        Some(i) => &s[..i],
        None => &s,
    };
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_lowercase().collect::<String>() + c.as_str(),
        None => String::new(),
    }
}

/// Go's `filepath.Clean`, lexically.
pub fn clean_path(p: &str) -> String {
    if p.is_empty() {
        return ".".into();
    }
    let rooted = p.starts_with('/');
    let mut parts: Vec<&str> = Vec::new();
    for seg in p.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                if parts.last().is_some_and(|l| *l != "..") {
                    parts.pop();
                } else if !rooted {
                    parts.push("..");
                }
            }
            s => parts.push(s),
        }
    }
    let joined = parts.join("/");
    match (rooted, joined.is_empty()) {
        (true, _) => format!("/{joined}"),
        (false, true) => ".".into(),
        (false, false) => joined,
    }
}

/// A file's modification time with its nanoseconds (Go's `ModTime`).
pub fn mtime(md: &std::fs::Metadata) -> Time {
    use std::os::unix::fs::MetadataExt;
    Time::from_unix(md.mtime(), md.mtime_nsec() as u32)
}

/// Go's `filepath.Glob(dir/*SUFFIX)` for a simple suffix: the matching names in dir, sorted as Go sorts them (by bytes).
pub fn glob_suffix(dir: &str, suffix: &str) -> Vec<String> {
    let Ok(rd) = std::fs::read_dir(dir) else { return Vec::new() };
    let mut names: Vec<Vec<u8>> = rd
        .filter_map(|e| e.ok())
        .map(|e| std::os::unix::ffi::OsStrExt::as_bytes(e.file_name().as_os_str()).to_vec())
        .filter(|n| n.ends_with(suffix.as_bytes()))
        .collect();
    names.sort();
    names.into_iter().map(|n| format!("{dir}/{}", crate::gotext::lossy(&n))).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_like_go() {
        for (i, o) in [
            ("/tmp/sarina-evals/", "/tmp/sarina-evals"),
            ("/a/./b/../c", "/a/c"),
            ("", "."),
            ("a/../..", ".."),
            ("/..", "/"),
            ("//x//y", "/x/y"),
        ] {
            assert_eq!(clean_path(i), o, "{i}");
        }
    }

    #[test]
    fn errors_like_go() {
        let e = std::io::Error::from_raw_os_error(13);
        assert_eq!(go_path_error("open", "/x", &e), "open /x: permission denied");
        assert_eq!(go_errno(&std::io::Error::from_raw_os_error(40)), "too many levels of symbolic links");
    }
}
