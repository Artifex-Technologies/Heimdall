//! Governance (Go: internal/governance): Sarina asks before a memory write (`POST /v1/review`), and the text runs through the
//! injection, credential and invisible-character detectors in Heimdall's own process. Any finding is a "deny" with the
//! findings' summaries as reasons; every finding is also an alert. Fails open on Sarina's side when Heimdall is absent,
//! closed on a deny (docs/ARCHITECTURE.md, Phase 4).

use crate::alert::{Alert, Sink};
use crate::detect::text::{CredentialDetector, InjectionDetector, UnicodeDetector};
use crate::event::{Detector, Event};
use crate::gojson::{self, ObjectWriter};
use crate::gotime::Time;

/// A consultation: what kind of write, from which session, the text.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Request {
    pub kind: String,
    pub session_id: String,
    pub text: String,
}
crate::go_struct!(Request { kind: "kind", session_id: "session_id", text: "text" });

/// The answer: "allow", or "deny" with the reasons.
#[derive(Clone, Debug, PartialEq)]
pub struct Verdict {
    pub decision: &'static str,
    pub reasons: Vec<String>,
}

impl Verdict {
    /// As Go's encoder writes it (`reasons` left out when empty).
    pub fn to_json(&self) -> String {
        let mut out = String::new();
        let mut o = ObjectWriter::new(&mut out);
        o.str("decision", self.decision);
        if !self.reasons.is_empty() {
            let r = o.key("reasons");
            r.push('[');
            for (i, x) in self.reasons.iter().enumerate() {
                if i > 0 {
                    r.push(',');
                }
                gojson::write_str(r, x);
            }
            r.push(']');
        }
        o.end();
        out
    }
}

pub struct Reviewer {
    detectors: Vec<Box<dyn Detector>>,
}

impl Default for Reviewer {
    fn default() -> Self {
        Reviewer {
            detectors: vec![Box::new(InjectionDetector::new()), Box::new(CredentialDetector::new()), Box::new(UnicodeDetector::new())],
        }
    }
}

impl Reviewer {
    /// Reviews one request; each finding is written to `sink` as an alert (the audit trail).
    pub fn review(&mut self, req: &Request, sink: Option<&mut dyn Sink>) -> Verdict {
        let ev = Event {
            source: "governance-review".into(),
            session_id: req.session_id.clone(),
            time: Time::now(),
            kind: format!("governance_review:{}", req.kind),
            text: req.text.clone(),
            ..Default::default()
        };
        let mut reasons = Vec::new();
        let mut alerts = Vec::new();
        for d in self.detectors.iter_mut() {
            for f in d.inspect(&ev) {
                reasons.push(f.summary.clone());
                alerts.push(Alert::from_finding(&f));
            }
        }
        if let Some(s) = sink {
            for a in &alerts {
                let _ = s.write(a);
            }
        }
        if reasons.is_empty() {
            Verdict { decision: "allow", reasons }
        } else {
            Verdict { decision: "deny", reasons }
        }
    }
}
