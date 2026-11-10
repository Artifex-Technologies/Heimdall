//! Runs each event through every detector in order, then verification, the tool rules and maintenance softening, and hands
//! the alerts to the sink (Go: internal/engine). One thread owns the engine: sources send their events to it, so every
//! detector sees one event at a time, in the order they arrived, with no locks.

use crate::alert::{Alert, Sink};
use crate::event::{Detector, Event, Finding, Severity};
use crate::maintenance;
use crate::toolrules::Policy;
use crate::verify;

pub struct Engine {
    detectors: Vec<Box<dyn Detector>>,
    sink: Box<dyn Sink>,
    window: Option<maintenance::Watcher>,
    softened: Vec<String>,
    tools: Option<Policy>,
    /// Where a failed write or a detector that panicked is reported (the daemon's log).
    pub log: Box<dyn FnMut(&str) + Send>,
}

impl Engine {
    pub fn new(sink: Box<dyn Sink>, detectors: Vec<Box<dyn Detector>>) -> Engine {
        Engine { detectors, sink, window: None, softened: Vec::new(), tools: None, log: Box::new(|m| eprintln!("heimdalld-rs: {m}")) }
    }

    /// Softens findings of the named detectors to info while a maintenance window is open.
    pub fn set_maintenance(&mut self, w: maintenance::Watcher, detectors: &[String]) {
        self.window = Some(w);
        self.softened = detectors.to_vec();
    }

    /// Puts the security-tool rules in force (after verification, before softening).
    pub fn set_tool_rules(&mut self, p: Policy) {
        self.tools = Some(p);
    }

    pub fn detector_ids(&self) -> Vec<&'static str> {
        self.detectors.iter().map(|d| d.id()).collect()
    }

    /// One event through every detector, in registration order.
    pub fn handle(&mut self, ev: &Event) {
        for i in 0..self.detectors.len() {
            // A detector that panics on some input loses that event, not the daemon (Go would crash the whole process).
            let d = &mut self.detectors[i];
            let found = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| d.inspect(ev)));
            let found = match found {
                Ok(f) => f,
                Err(_) => {
                    let id = self.detectors[i].id();
                    (self.log)(&format!("detector {id} panicked on an event of kind {:?}; the event was skipped for it", ev.kind));
                    continue;
                }
            };
            for f in found {
                let f = verify::apply(f);
                match &mut self.tools {
                    None => self.write(f),
                    Some(p) => {
                        for g in p.apply(f) {
                            self.write(g);
                        }
                    }
                }
            }
        }
    }

    fn write(&mut self, mut f: Finding) {
        if f.severity != Severity::Info && !f.firm && self.softened.contains(&f.detector_id) {
            if let Some(w) = self.window.as_ref().and_then(maintenance::Watcher::active) {
                f.severity = Severity::Info;
                f.summary = format!("[maintenance: {}] {}", w.reason, f.summary);
            }
        }
        let a = Alert::from_finding(&f);
        if let Err(e) = self.sink.write(&a) {
            (self.log)(&format!("alert sink write failed: {e}"));
        }
    }

    /// Writes an alert that did not come from a detector (an integration failure), through the same sink.
    pub fn write_alert(&mut self, a: &Alert) {
        if let Err(e) = self.sink.write(a) {
            (self.log)(&format!("alert sink write failed: {e}"));
        }
    }
}
