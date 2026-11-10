//! The long audits wait while a game runs (Go: internal/gametime; the contract with Yggdrasil is in CLAUDE.md):
//! `yggdrasil-gametime status` exits 0 while a game runs, with "A game is running: REASON." on its first line, and 1 when none
//! does. A missing tool, any other exit, or no answer within 10 s means no game: the audit runs as before. Watching never asks.

use crate::sources::Msg;
use std::io::Read;
use std::os::fd::AsFd;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// Yggdrasil's game-time tool.
pub const COMMAND: &str = "/usr/bin/yggdrasil-gametime";

/// How often a waiting audit asks again.
pub const RETRY: Duration = Duration::from_secs(300);

/// How long the tool may take to answer.
pub const ANSWER_WITHIN: Duration = Duration::from_secs(10);

/// Asks before a long job whether a game runs.
#[derive(Clone, Debug, Default)]
pub struct Gate {
    /// The tool; empty: COMMAND.
    pub path: String,
    /// How often to ask again while a game runs; zero: RETRY.
    pub retry: Duration,
}

/// The tool's reason as Go keeps it: the first line without "A game is running: " and the final dot, every character Go
/// does not print as itself made '?', at most 160 bytes (then "...").
pub fn reason(stdout: &[u8]) -> String {
    let s = crate::gotext::lossy(stdout);
    let first = s.split_once('\n').map_or(s.as_str(), |(a, _)| a);
    let t = crate::gotext::trim_space(first);
    let t = t.strip_prefix("A game is running: ").unwrap_or(t);
    let t = t.strip_suffix('.').unwrap_or(t);
    let r: String = t.chars().map(|c| if crate::gotext::is_print(c) { c } else { '?' }).collect();
    if r.len() > 160 {
        return crate::gotext::byte_prefix(&r, 160) + "...";
    }
    r
}

impl Gate {
    fn tool(&self) -> &str {
        if self.path.is_empty() {
            COMMAND
        } else {
            &self.path
        }
    }

    /// Asks the tool once: true while a game runs, with its reason.
    pub fn playing(&self) -> (bool, String) {
        let path = self.tool();
        if std::fs::metadata(path).is_err() {
            return (false, String::new());
        }
        let child = Command::new(path)
            .arg("status")
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LANG", "C")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn();
        let Ok(mut child) = child else { return (false, String::new()) };
        let deadline = Instant::now() + ANSWER_WITHIN;
        let mut out = Vec::new();
        let mut timed_out = false;
        if let Some(mut so) = child.stdout.take() {
            let mut buf = [0u8; 4096];
            loop {
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    timed_out = true;
                    break;
                }
                let fd = so.as_fd();
                let mut fds = [rustix::event::PollFd::new(&fd, rustix::event::PollFlags::IN)];
                let ts = rustix::event::Timespec { tv_sec: left.as_secs() as i64, tv_nsec: left.subsec_nanos() as i64 };
                match rustix::event::poll(&mut fds, Some(&ts)) {
                    Ok(0) => continue,
                    Ok(_) | Err(rustix::io::Errno::INTR) => {}
                    Err(_) => break,
                }
                match so.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        if out.len() < 1 << 20 {
                            out.extend_from_slice(&buf[..n]);
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted || e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(_) => break,
                }
            }
        }
        if timed_out {
            let _ = child.kill();
            let _ = child.wait();
            return (false, String::new());
        }
        // stdout closed: the tool is ending; wait for it, but not past the deadline
        let status = loop {
            match child.try_wait() {
                Ok(Some(st)) => break Some(st),
                Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(5)),
                _ => {
                    let _ = child.kill();
                    let _ = child.wait();
                    break None;
                }
            }
        };
        match status {
            Some(st) if st.success() => (true, reason(&out)),
            _ => (false, String::new()), // exit 1: no game; anything else: trouble, so run as before
        }
    }

    /// True once no game runs: at once when none does, else after asking again every `retry`. One log line when the job
    /// starts waiting; false when told to stop while waiting.
    pub fn wait(&self, stop: &mpsc::Receiver<()>, job: &str, send: &mut dyn FnMut(Msg)) -> bool {
        let every = if self.retry.is_zero() { RETRY } else { self.retry };
        let mut waiting = false;
        loop {
            let (playing, why) = self.playing();
            if !playing {
                return true;
            }
            if !waiting {
                send(Msg::Log(format!(
                    "{job} waits until the game is over ({why}); asking again every {}",
                    crate::gotext::duration(every.as_nanos() as i64)
                )));
            }
            waiting = true;
            match stop.recv_timeout(every) {
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                _ => return false,
            }
        }
    }
}
