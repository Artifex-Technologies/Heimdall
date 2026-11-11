//! The owner's maintenance window (Go: internal/maintenance). The daemon only reads it; `heimdalld maintenance on|off`
//! (src/cli/maintenance.rs) writes it.

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

// The writing side, for `heimdalld maintenance on|off|status` (Go: Open, Write, Clear, Describe). The daemon only reads.

impl Window {
    /// As Go's `json.Marshal(w)` writes it (no newline after).
    pub fn to_json(&self) -> String {
        let mut out = String::new();
        let mut o = gojson::ObjectWriter::new(&mut out);
        o.str("reason", &self.reason);
        o.str("actor", &self.actor);
        o.str("opened", &self.opened.rfc3339_nano());
        o.str("until", &self.until.rfc3339_nano());
        o.end();
        out
    }
}

/// Go's `Open`: a window of length `d` (capped at four hours) from `now`, in `now`'s offset (a fixed zone; the command
/// moves `until` into the local zone itself, as Go's `time.Now().Add` does).
pub fn open(actor: &str, reason: &str, d: i64, now: Time) -> Result<Window, String> {
    if d <= 0 {
        return Err("maintenance: the duration must be positive".into());
    }
    let d = d.min(MAX_DURATION);
    if reason.is_empty() {
        return Err("maintenance: a reason is required".into());
    }
    Ok(Window { reason: reason.into(), actor: actor.into(), opened: now, until: now.add(d) })
}

/// Go's `Write`: the window through a temporary file (mode 0644) and a rename.
pub fn write(path: &str, w: &Window) -> Result<(), String> {
    let tmp = format!("{path}.tmp");
    crate::gopath::write_file(&tmp, w.to_json().as_bytes(), 0o644)?;
    crate::gopath::rename(&tmp, path)
}

/// Go's `Clear`: the file removed; none there is fine.
pub fn clear(path: &str) -> Result<(), String> {
    match std::fs::remove_file(path) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(crate::goerr::path("remove", path, &e)),
        _ => Ok(()),
    }
}

/// Go's `time.Duration.Round(m)`: halves away from zero, saturating as Go does.
pub fn round_duration(d: i64, m: i64) -> i64 {
    if m <= 0 {
        return d;
    }
    let less_than_half = |x: i64, y: i64| (x as u64).wrapping_add(x as u64) < y as u64;
    let r = d % m;
    if d < 0 {
        let r = -r;
        if less_than_half(r, m) {
            return d + r;
        }
        // Go's int64 arithmetic wraps on the way and only the result is checked
        let d1 = d.wrapping_sub(m).wrapping_add(r);
        return if d1 < d { d1 } else { i64::MIN };
    }
    if less_than_half(r, m) {
        return d - r;
    }
    let d1 = d.wrapping_add(m).wrapping_sub(r);
    if d1 > d {
        d1
    } else {
        i64::MAX
    }
}

/// Go's `Describe`: the one-line status text (`w` None: no window found).
pub fn describe(w: Option<&Window>, now: &Time) -> String {
    match w {
        Some(w) if w.active(now) => format!(
            "maintenance window open: {}, opened by {}, {} left (ends {})",
            crate::gotext::quote(&w.reason),
            w.actor,
            crate::gotext::duration(round_duration(w.until.sub(now), 60_000_000_000)),
            w.until.hhmm()
        ),
        _ => "no maintenance window is open".into(),
    }
}

/// The four-hour bound, as one check (the Kani harness below and tests/cli_admin.rs's properties run it): a window opened
/// for any length from any time ends at most four hours (and at most the length asked) after it opened.
pub fn check_bound(unix_secs: i64, nanos: u32, d: i64, offset: i32) {
    let now = Time::from_unix(unix_secs, nanos % 1_000_000_000).at_offset(offset);
    if let Ok(w) = open("a", "r", d, now) {
        assert!(d > 0);
        let len = w.until.sub(&w.opened);
        assert!(len > 0 && len <= MAX_DURATION && len <= d);
        assert!(w.active(&now));
        assert!(!w.active(&now.add(MAX_DURATION)));
    } else {
        assert!(d <= 0);
    }
}

#[cfg(kani)]
mod proofs {
    /// A maintenance window never lasts more than four hours, whatever length was asked for.
    #[kani::proof]
    fn a_window_never_lasts_more_than_four_hours() {
        let secs: i64 = kani::any();
        kani::assume(secs.unsigned_abs() < 1 << 40);
        super::check_bound(secs, kani::any(), kani::any(), kani::any::<i16>() as i32 * 60);
    }
}
