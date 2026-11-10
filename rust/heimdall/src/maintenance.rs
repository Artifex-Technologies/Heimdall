//! The owner's maintenance window (Go: internal/maintenance), read-only here: `heimdalld maintenance on` (Go) writes it.

use crate::gojson::{self, FromGo};
use crate::gotime::Time;
use std::sync::Mutex;

/// The longest a window may stay open: 4 hours, in nanoseconds.
pub const MAX_DURATION: i64 = 4 * 3600 * 1_000_000_000;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Window {
    pub reason: String,
    pub actor: String,
    pub opened: Time,
    pub until: Time,
}
crate::go_struct!(Window { reason: "reason", actor: "actor", opened: "opened", until: "until" });

impl Window {
    /// Whether the window is open at t.
    pub fn active(&self, t: &Time) -> bool {
        !self.until.is_zero() && t.before(&self.until)
    }
}

/// The window in the file (None when there is none or it does not read), capped at MAX_DURATION after it opened.
pub fn read(path: &str) -> Option<Window> {
    let b = std::fs::read(path).ok()?;
    let v = gojson::parse(&b).ok()?;
    let mut w = Window::default();
    w.read_into(&v, "").ok()?;
    if !w.opened.is_zero() && w.until.sub(&w.opened) > MAX_DURATION {
        w.until = w.opened.add(MAX_DURATION);
    }
    Some(w)
}

/// Re-reads the file at most every two seconds, so the engine can ask on every finding.
pub struct Watcher {
    path: String,
    inner: Mutex<(Time, Option<Window>)>,
}

impl Watcher {
    pub fn new(path: &str) -> Watcher {
        Watcher { path: path.to_owned(), inner: Mutex::new((Time::default(), None)) }
    }

    /// The open window, if any.
    pub fn active(&self) -> Option<Window> {
        if self.path.is_empty() {
            return None;
        }
        let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let now = Time::now();
        if now.sub(&g.0) > 2_000_000_000 {
            g.1 = read(&self.path);
            g.0 = now;
        }
        g.1.clone().filter(|w| w.active(&now))
    }
}
