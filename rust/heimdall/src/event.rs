//! The event/finding model every detector shares (Go: internal/detect/types.go).

use crate::gotime::Time;
use std::collections::BTreeMap;

/// A coarse triage level. Ordered: info < warning < critical.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Warning => "warning",
            Severity::Critical => "critical",
        }
    }

    pub fn parse(s: &str) -> Option<Severity> {
        match s {
            "info" => Some(Severity::Info),
            "warning" => Some(Severity::Warning),
            "critical" => Some(Severity::Critical),
            _ => None,
        }
    }
}

/// Source-specific structured data. Ordered, so everything written from it is the same every time (Go's encoder sorts map
/// keys too).
pub type Fields = BTreeMap<String, String>;

/// One observation fed into the engine.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Event {
    /// The producer, e.g. "agent-session".
    pub source: String,
    /// The Sarina session the event came from, when known.
    pub session_id: String,
    /// When the event was observed. Zero: unknown.
    pub time: Time,
    /// A source-defined category, e.g. "message".
    pub kind: String,
    /// The free text the text detectors look at.
    pub text: String,
    pub fields: Fields,
}

impl Event {
    /// The field's value, "" when absent (a Go map lookup).
    pub fn f(&self, k: &str) -> &str {
        self.fields.get(k).map_or("", String::as_str)
    }
}

/// A detector's verdict that an event deserves attention.
#[derive(Clone, Debug, PartialEq)]
pub struct Finding {
    pub detector_id: String,
    pub severity: Severity,
    pub summary: String,
    pub event: Event,
    /// Never softened by a maintenance window.
    pub firm: bool,
}

impl Finding {
    pub fn new(detector: &str, severity: Severity, summary: String, event: &Event) -> Finding {
        Finding { detector_id: detector.to_owned(), severity, summary, event: event.clone(), firm: false }
    }
}

/// The name of the enrolled mesh peer at an IP address, if any.
pub type MeshPeerFn = Box<dyn Fn(&str) -> Option<String> + Send>;
/// Whether the owner approved a remote-access tool, by its id.
pub type ApprovedFn = Box<dyn Fn(&str) -> bool + Send>;

/// Inspects one event at a time. The engine calls a detector from one thread, in order, so a stateful detector needs no lock.
pub trait Detector: Send {
    fn id(&self) -> &'static str;
    fn inspect(&mut self, e: &Event) -> Vec<Finding>;
}
