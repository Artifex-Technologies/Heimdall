//! The opening and closing of a maintenance window as events, every 5 seconds (Go: cmd/heimdalld watchMaintenance).

use super::{Msg, Source};
use crate::event::{Event, Fields};
use crate::gotime::Time;
use crate::maintenance::{self, Window};
use std::time::{Duration, Instant};

pub struct MaintenanceSource {
    path: String,
    prev: Option<Window>,
    next: Instant,
}

impl MaintenanceSource {
    pub fn new(path: &str) -> MaintenanceSource {
        MaintenanceSource { path: path.into(), prev: None, next: Instant::now() }
    }
}

impl Source for MaintenanceSource {
    fn name(&self) -> &'static str {
        "maintenance"
    }
    fn due(&self) -> Option<Instant> {
        Some(self.next)
    }
    fn run(&mut self, now: Instant, out: &mut Vec<Msg>) {
        self.next = now + Duration::from_secs(5);
        let w = maintenance::read(&self.path);
        let t = Time::now();
        let active = w.as_ref().is_some_and(|w| w.active(&t));
        let ev = |kind: &str, w: &Window, until: bool| {
            let mut f = Fields::from([("actor".to_string(), w.actor.clone()), ("reason".to_string(), w.reason.clone())]);
            if until {
                f.insert("until".into(), w.until.hhmm());
            }
            Event { source: "maintenance".into(), session_id: String::new(), time: t, kind: kind.into(), text: w.reason.clone(), fields: f }
        };
        match (active, &self.prev) {
            (true, prev) if prev.as_ref().is_none_or(|p| w.as_ref().is_some_and(|w| w.opened != p.opened)) => {
                let w = w.expect("active");
                out.push(Msg::Event(ev("maintenance_opened", &w, true)));
                self.prev = Some(w);
            }
            (false, Some(p)) => {
                out.push(Msg::Event(ev("maintenance_closed", p, false)));
                self.prev = None;
            }
            _ => {}
        }
    }
}
