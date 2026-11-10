//! Related alerts become incidents (Go: internal/correlate). Each alert names things (an agent session, a Limbo guest, a
//! remote address, a file, a program, a remote-access tool); alerts that share any of them within the window are one incident,
//! and when an incident holds alerts from two or more detectors (at least one a warning), one "incident" alert says so.
//!
//! A sink wrapper: work happens only when an alert is written. Memory is bounded (incidents expire after the window; at most
//! 200 incidents, 64 keys and 50 members each).

use crate::alert::{Alert, Sink};
use crate::event::{Event, Fields, Finding, Severity};
use crate::gojson::{self, ObjectWriter};
use crate::gotime::Time;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

pub const DETECTOR_ID: &str = "incident";
const MAX_INCIDENTS: usize = 200;
const MAX_MEMBERS: usize = 50;
const MAX_KEYS: usize = 64;
/// The default window: 30 minutes.
pub const WINDOW: i64 = 30 * 60 * 1_000_000_000;

/// The alert fields that name a thing worth linking on, and the kind each names.
const KEY_FIELDS: [(&str, &str); 10] = [
    ("guest", "guest"),
    ("remote_addr", "address"),
    ("src", "address"),
    ("other_ip", "address"),
    ("path", "file"),
    ("provider", "tool"),
    ("pid", "process"),
    ("process", "program"),
    ("app", "app"),
    ("request_id", "request"),
];

/// Detectors whose alerts are about Heimdall itself or are already summaries.
fn skipped(d: &str) -> bool {
    matches!(d, DETECTOR_ID | "integration" | "maintenance-window" | "baseline-drift" | "resource-pressure")
}

/// The things an alert names, as "kind:value", sorted.
pub fn keys(a: &Alert) -> Vec<String> {
    let mut ks = Vec::new();
    if !a.session_id.is_empty() {
        ks.push(format!("session:{}", a.session_id));
    }
    for (f, kind) in KEY_FIELDS {
        let v = a.fields.get(f).map(String::as_str).unwrap_or("");
        if v.is_empty() || v == "unknown" || v == "0" || (f == "pid" && v == "-1") {
            continue;
        }
        ks.push(format!("{kind}:{v}"));
    }
    ks.sort();
    ks
}

fn rank(s: &str) -> i32 {
    match s {
        "critical" => 2,
        "warning" => 1,
        _ => 0,
    }
}

/// One alert of an incident, briefly.
#[derive(Clone, Debug, PartialEq)]
pub struct Member {
    pub time: Time,
    pub detector_id: String,
    pub severity: String,
    pub summary: String,
}

/// A group of related alerts.
#[derive(Clone, Debug, PartialEq)]
pub struct Incident {
    pub id: String,
    pub first: Time,
    pub last: Time,
    pub severity: String,
    pub detectors: BTreeMap<String, i64>,
    pub keys: BTreeSet<String>,
    pub alerts: Vec<Member>,
    reported: usize,
    /// A member alert was not practice (Sarina's evals mark theirs practice=1).
    real: bool,
}

impl Incident {
    /// As Go's encoder writes the incident for GET /v1/incidents.
    pub fn to_json(&self, out: &mut String) {
        let mut o = ObjectWriter::new(out);
        o.str("id", &self.id);
        o.str("first", &self.first.rfc3339_nano());
        o.str("last", &self.last.rfc3339_nano());
        o.str("severity", &self.severity);
        let d = o.key("detectors");
        d.push('{');
        for (i, (k, v)) in self.detectors.iter().enumerate() {
            if i > 0 {
                d.push(',');
            }
            gojson::write_str(d, k);
            d.push(':');
            d.push_str(&v.to_string());
        }
        d.push('}');
        let k = o.key("keys");
        k.push('[');
        for (i, x) in self.keys.iter().enumerate() {
            if i > 0 {
                k.push(',');
            }
            gojson::write_str(k, x);
        }
        k.push(']');
        let a = o.key("alerts");
        if self.alerts.is_empty() {
            a.push_str("null");
        } else {
            a.push('[');
            for (i, m) in self.alerts.iter().enumerate() {
                if i > 0 {
                    a.push(',');
                }
                let mut mo = ObjectWriter::new(a);
                mo.str("time", &m.time.rfc3339_nano());
                mo.str("detector_id", &m.detector_id);
                mo.str("severity", &m.severity);
                mo.str("summary", &m.summary);
                mo.end();
            }
            a.push(']');
        }
        o.end();
    }
}

/// The incidents, shared with the API.
#[derive(Default)]
pub struct State {
    incidents: Vec<Incident>,
    seq: u64,
}

impl State {
    /// The live incidents, newest first (GET /v1/incidents).
    pub fn incidents(&self) -> Vec<Incident> {
        self.incidents.iter().rev().cloned().collect()
    }
}

/// Passes every alert on, then links it.
pub struct Correlator {
    next: Box<dyn Sink>,
    pub state: Arc<Mutex<State>>,
    /// Nanoseconds; 0: WINDOW.
    pub window: i64,
    pub now: fn() -> Time,
}

impl Correlator {
    pub fn new(next: Box<dyn Sink>) -> Correlator {
        Correlator { next, state: Arc::new(Mutex::new(State::default())), window: 0, now: Time::now }
    }

    /// Adds the alert to the incident(s) it shares a key with (merging them); returns the incident when it now spans a new
    /// number of detectors (two or more) and holds at least one warning.
    fn link(&self, a: &Alert, keys: &[String]) -> Option<Incident> {
        let mut st = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let now = (self.now)();
        let window = if self.window <= 0 { WINDOW } else { self.window };
        st.incidents.retain(|inc| now.sub(&inc.last) <= window);
        let mut into: Option<usize> = None;
        let mut kept: Vec<Incident> = Vec::with_capacity(st.incidents.len());
        for inc in std::mem::take(&mut st.incidents) {
            let shared = keys.iter().any(|k| inc.keys.contains(k));
            if !shared {
                kept.push(inc);
            } else if let Some(i) = into {
                merge(&mut kept[i], inc); // a second incident shares a key: they are one story
            } else {
                into = Some(kept.len());
                kept.push(inc);
            }
        }
        st.incidents = kept;
        let i = match into {
            Some(i) => i,
            None => {
                st.seq += 1;
                let id = format!("inc-{}", st.seq);
                st.incidents.push(Incident {
                    id,
                    first: now,
                    last: now,
                    severity: String::new(),
                    detectors: BTreeMap::new(),
                    keys: BTreeSet::new(),
                    alerts: Vec::new(),
                    reported: 0,
                    real: false,
                });
                if st.incidents.len() > MAX_INCIDENTS {
                    st.incidents.remove(0);
                }
                st.incidents.len() - 1
            }
        };
        let inc = &mut st.incidents[i];
        inc.last = now;
        for k in keys {
            if inc.keys.len() < MAX_KEYS {
                inc.keys.insert(k.clone());
            }
        }
        *inc.detectors.entry(a.detector_id.clone()).or_insert(0) += 1;
        inc.real = inc.real || a.fields.get("practice").map(String::as_str) != Some("1");
        if rank(a.severity.as_str()) > rank(&inc.severity) || inc.severity.is_empty() {
            inc.severity = a.severity.as_str().to_string();
        }
        inc.alerts.push(Member {
            time: a.time,
            detector_id: a.detector_id.clone(),
            severity: a.severity.as_str().to_string(),
            summary: a.summary.clone(),
        });
        if inc.alerts.len() > MAX_MEMBERS {
            let cut = inc.alerts.len() - MAX_MEMBERS;
            inc.alerts.drain(..cut);
        }
        if inc.detectors.len() >= 2 && inc.detectors.len() > inc.reported && rank(&inc.severity) >= 1 {
            inc.reported = inc.detectors.len();
            return Some(inc.clone());
        }
        None
    }

    fn alert_for(inc: &Incident) -> Alert {
        let dets: Vec<&str> = inc.detectors.keys().map(String::as_str).collect();
        let all: Vec<&str> = inc.keys.iter().map(String::as_str).collect();
        let mut shown: Vec<String> = all.iter().take(6).map(|s| s.to_string()).collect();
        if all.len() > 6 {
            shown.push(format!("and {} more", all.len() - 6));
        }
        let n: i64 = inc.detectors.values().sum();
        let summary = format!("{n} related alerts from {} detectors ({}) share {}", dets.len(), dets.join(", "), shown.join(", "));
        let mut fields = Fields::from([
            ("incident_id".to_string(), inc.id.clone()),
            ("detectors".to_string(), dets.join(",")),
            ("keys".to_string(), all.join(",")),
        ]);
        if !inc.real {
            fields.insert("practice".into(), "1".into()); // every alert in it came from Sarina's evals
        }
        // an incident is reported only at warning or above, so its severity is always a known one
        let sev = Severity::parse(&inc.severity).unwrap_or(Severity::Warning);
        let ev = Event { source: "correlation".into(), kind: "incident".into(), time: inc.last, fields, ..Default::default() };
        Alert::from_finding(&Finding::new(DETECTOR_ID, sev, summary, &ev))
    }
}

fn merge(into: &mut Incident, from: Incident) {
    if from.first.before(&into.first) {
        into.first = from.first;
    }
    for k in from.keys {
        if into.keys.len() < MAX_KEYS {
            into.keys.insert(k);
        }
    }
    for (d, n) in from.detectors {
        *into.detectors.entry(d).or_insert(0) += n;
    }
    into.real = into.real || from.real;
    if rank(&from.severity) > rank(&into.severity) {
        into.severity = from.severity;
    }
    let mut alerts = from.alerts;
    alerts.append(&mut into.alerts);
    // Go: sort.Slice by time (not stable: members raised in the same nanosecond may come in another order past 12)
    alerts.sort_by(|a, b| if a.time.before(&b.time) { std::cmp::Ordering::Less } else if b.time.before(&a.time) { std::cmp::Ordering::Greater } else { std::cmp::Ordering::Equal });
    if alerts.len() > MAX_MEMBERS {
        let cut = alerts.len() - MAX_MEMBERS;
        alerts.drain(..cut);
    }
    into.alerts = alerts;
}

impl Sink for Correlator {
    fn write(&mut self, a: &Alert) -> std::io::Result<()> {
        let r = self.next.write(a);
        if skipped(&a.detector_id) {
            return r;
        }
        let ks = keys(a);
        if ks.is_empty() {
            return r;
        }
        if let Some(inc) = self.link(a, &ks) {
            let _ = self.next.write(&Self::alert_for(&inc));
        }
        r
    }
}
