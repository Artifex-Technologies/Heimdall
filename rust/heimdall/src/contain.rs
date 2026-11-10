//! Containment requests (Go: internal/contain's Trigger): when automatic containment is switched on
//! (`/etc/heimdall/contain.json`, `auto_contain`), a critical finding about the AI agents becomes a request the root unit
//! (`heimdall-contain`, run by the Go binary) carries out: unload the models, stop Sarina and lock her out.
//!
//! - Which findings: an unapproved change to the agents' behaviour files (file-integrity, "decides how an AI agent behaves")
//!   or a session that keeps asking for tools its tier does not allow (permission-escalation from a session). An injection
//!   phrase alone does not: it is often only text she read.
//! - At most one request every ten minutes, none while the lock (`/etc/heimdall/contained`) is there; every alert is passed
//!   on first.
//! - The request is `contain.RequestPath` written whole (a `.tmp` renamed into place), as Go writes it.
//! - In charge only: the shadow daemon never asks (daemon.rs).

use crate::alert::{Alert, Sink};
use crate::gojson;
use crate::gostruct::{self, Field, Ty, Val};
use crate::gotime::Time;

pub const MARKER_PATH: &str = "/etc/heimdall/contained";
pub const REQUEST_PATH: &str = "/var/lib/heimdall/contain-request.json";
pub const CONFIG_PATH: &str = "/etc/heimdall/contain.json";

/// Ten minutes, in nanoseconds.
const EVERY: i64 = 10 * 60 * 1_000_000_000;

/// Whether an alert is the kind that warrants containing the AI (Go: AboutAgents).
pub fn about_agents(a: &Alert) -> bool {
    if a.severity.as_str() != "critical" {
        return false;
    }
    match a.detector_id.as_str() {
        "file-integrity" => a.summary.contains("decides how an AI agent behaves"),
        "permission-escalation" => a.source == "agent-session",
        _ => false,
    }
}

static CONFIG: Ty = Ty::Struct("contain.Config", &[Field("auto_contain", &Ty::Bool, false), Field("auto_emergency", &Ty::Bool, false)]);

/// Whether automatic containment is on (Go: LoadConfig(path).AutoContain): a missing or unreadable file is off; the file is
/// read as Go's json.Unmarshal reads it (a type error elsewhere keeps what was read).
pub fn auto_contain(path: &str) -> bool {
    let Ok(b) = std::fs::read(path) else { return false };
    let (v, _) = gostruct::unmarshal(&CONFIG, &b);
    matches!(gostruct::field(&CONFIG, &v, "auto_contain"), Some(Val::Bool(true)))
}

/// Whether the lock is there (Go: ReadMarker): any file that reads is a lock, even one that is not JSON.
pub fn locked(path: &str) -> bool {
    std::fs::read(path).is_ok()
}

/// Whether a request may be written, given the time since the last one (None: there was none). Go compares the clamped
/// `time.Duration` the same way, so a clock that went back counts as "too soon".
pub fn due(since_last: Option<i64>) -> bool {
    since_last.is_none_or(|d| d >= EVERY)
}

/// The sink (Go: Trigger).
pub struct Trigger {
    pub next: Box<dyn Sink>,
    pub config_path: String,
    pub request_path: String,
    pub marker_path: String,
    pub now: Box<dyn Fn() -> Time + Send>,
    last: Option<Time>,
}

impl Trigger {
    pub fn new(next: Box<dyn Sink>, config_path: &str, request_path: &str, marker_path: &str) -> Trigger {
        Trigger {
            next,
            config_path: config_path.into(),
            request_path: request_path.into(),
            marker_path: marker_path.into(),
            now: Box::new(Time::now),
            last: None,
        }
    }
}

impl Sink for Trigger {
    fn write(&mut self, a: &Alert) -> std::io::Result<()> {
        let r = self.next.write(a);
        if !about_agents(a) || !auto_contain(&self.config_path) || locked(&self.marker_path) {
            return r;
        }
        let now = (self.now)();
        if !due(self.last.map(|l| now.sub(&l))) {
            return r;
        }
        self.last = Some(now);
        // Go: json.Marshal(Request{Time: now.UTC(), Reason: a.Summary, Auto: true})
        let mut b = String::new();
        let mut o = gojson::ObjectWriter::new(&mut b);
        o.str("time", &now.utc().rfc3339_nano());
        o.str("reason", &a.summary);
        o.raw("auto", "true");
        o.end();
        let _ = crate::state::write_atomic(&self.request_path, b.as_bytes(), 0o644);
        r
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    /// Never two requests within ten minutes: whatever the times, a request is due only after the full ten minutes since
    /// the last one (or when there was none).
    #[kani::proof]
    fn never_two_requests_within_ten_minutes() {
        let last: i64 = kani::any();
        let now: i64 = kani::any();
        let since = if kani::any() { Some(now.saturating_sub(last)) } else { None };
        if due(since) {
            if let Some(d) = since {
                assert!(d >= EVERY);
            }
        }
        // and a request is never refused once ten minutes have passed
        if let Some(d) = since {
            if d >= EVERY {
                assert!(due(since));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The Kani claim, over a spread of differences without Kani.
    #[test]
    fn never_two_requests_within_ten_minutes() {
        assert!(due(None));
        for d in [i64::MIN, -1, 0, 1, EVERY - 1, EVERY, EVERY + 1, i64::MAX] {
            assert_eq!(due(Some(d)), d >= EVERY, "{d}");
        }
    }
}
