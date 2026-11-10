//! The restrict-only rules of Heimdall's Limbo response, kept small and pure so they can be proved (Kani, below) and
//! property-tested (tests/properties.rs). The responder that calls Limbo is ported in step 3; these are the rules it must
//! follow (Go: internal/response, the re-check before a hold and Client.QuarantineStatus).
//!
//! The owner's decision (2026-10-04): Heimdall may make a Limbo guest more restricted, never less. Limbo enforces it on its
//! side (control.sock has no route to release or lower a hold); here it is enforced again by construction:
//!
//! - the only level Heimdall ever asks for is [`Level::Restrict`] ([`REQUESTED`]); a request has no level field to set;
//! - [`decide`] sends a request only when the guest is held at no level, or at restrict by a hold older than the trigger
//!   (re-asserting it): never when the guest is already held more strictly, so a request can never stand for a lowering;
//! - [`Hold::raise`] is how a hold's level changes: it only ever rises.

use crate::gotime::Time;

/// Limbo's hold levels, in order of strictness.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Level {
    /// Deny-all firewall; the guest keeps running and can be inspected.
    Restrict = 1,
    /// The guest's link is down as well.
    Isolate = 2,
}

impl Level {
    /// Limbo's name for a level; an unknown name is no level (Go: `rank[r.Level] == 0`).
    pub fn parse(s: &str) -> Option<Level> {
        match s {
            "restrict" => Some(Level::Restrict),
            "isolate" => Some(Level::Isolate),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Level::Restrict => "restrict",
            Level::Isolate => "isolate",
        }
    }
}

/// The one level Heimdall asks Limbo for.
pub const REQUESTED: Level = Level::Restrict;

/// A request to hold a guest. It has no level: [`Request::level`] is always [`REQUESTED`].
#[derive(Clone, Debug, PartialEq)]
pub struct Request {
    pub guest: String,
    pub reason: String,
    pub source: String,
}

impl Request {
    pub fn level(&self) -> Level {
        REQUESTED
    }
}

/// One of Limbo's holding records, as `GET /v1/quarantine` lists them.
#[derive(Clone, Debug, PartialEq)]
pub struct Record {
    pub guest: String,
    pub status: String,
    pub level: String,
    pub opened: Time,
}

/// The strongest level among a guest's holding records (open or marked dangerous) and the newest open time at that level
/// (Go: Client.QuarantineStatus).
pub fn strongest(records: &[Record], guest: &str) -> Option<(Level, Time)> {
    let mut best: Option<(Level, Time)> = None;
    for r in records {
        if r.guest != guest || (r.status != "open" && r.status != "dangerous") {
            continue;
        }
        let Some(l) = Level::parse(&r.level) else { continue };
        best = match best {
            None => Some((l, r.opened)),
            Some((bl, bo)) if l > bl || (l == bl && r.opened.after(&bo)) => Some((l, r.opened)),
            keep => keep,
        };
    }
    best
}

/// What to do about a trigger.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Ask Limbo to hold the guest at this level (always [`REQUESTED`]).
    Send(Level),
    /// Nothing to send: the guest is already held at least as strictly, since the trigger.
    Skip(&'static str),
}

/// The re-check before a hold (Go: Responder.alreadyDone, the part that looks at Limbo's records): `current` is the
/// strongest hold Limbo has for the guest (None: none, or unknown), `trigger` the time of the newest trigger.
pub fn decide(current: Option<(Level, Time)>, trigger: Time) -> Decision {
    match current {
        None => Decision::Send(REQUESTED),
        Some((Level::Isolate, _)) => Decision::Skip("Limbo already holds the guest at level isolate"),
        Some((Level::Restrict, opened)) => {
            if !opened.before(&trigger) {
                Decision::Skip("Limbo already holds the guest at level restrict, opened after the trigger")
            } else {
                // a hold older than the trigger may predate the change that triggered it: re-asserting it is the point
                Decision::Send(REQUESTED)
            }
        }
    }
}

/// A hold as Heimdall knows it: its level can only rise.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hold {
    level: Option<Level>,
}

impl Hold {
    pub fn none() -> Hold {
        Hold { level: None }
    }

    pub fn level(&self) -> Option<Level> {
        self.level
    }

    /// The hold after a request at `to`: the stricter of the two, never less than it was.
    pub fn raise(&mut self, to: Level) {
        self.level = Some(match self.level {
            Some(l) if l >= to => l,
            _ => to,
        });
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    fn any_level() -> Option<Level> {
        match kani::any::<u8>() % 3 {
            0 => None,
            1 => Some(Level::Restrict),
            _ => Some(Level::Isolate),
        }
    }

    fn any_time() -> Time {
        Time::from_unix(kani::any::<i32>() as i64, kani::any::<u32>() % 1_000_000_000)
    }

    /// Restrict never loosens: whatever Limbo holds, a request Heimdall sends is at least as strict as it.
    #[kani::proof]
    fn a_request_never_loosens() {
        let current = any_level().map(|l| (l, any_time()));
        if let Decision::Send(l) = decide(current, any_time()) {
            assert!(l == REQUESTED);
            if let Some((c, _)) = current {
                assert!(l >= c);
            }
        }
    }

    /// The level of a hold only rises.
    #[kani::proof]
    fn a_hold_only_rises() {
        let mut h = Hold { level: any_level() };
        let before = h.level();
        let to = if kani::any() { Level::Restrict } else { Level::Isolate };
        h.raise(to);
        let after = h.level().unwrap();
        assert!(after >= to);
        if let Some(b) = before {
            assert!(after >= b);
        }
    }

    /// A request asks for restrict, whatever it was built from.
    #[kani::proof]
    fn requests_are_restrict() {
        let r = Request { guest: String::new(), reason: String::new(), source: String::new() };
        assert!(r.level() == Level::Restrict);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The Kani proofs above, as exhaustive tests over the levels and a spread of times, so they run without Kani too.
    fn levels() -> [Option<Level>; 3] {
        [None, Some(Level::Restrict), Some(Level::Isolate)]
    }

    fn times() -> Vec<Time> {
        [-1_000_000i64, -1, 0, 1, 1_762_000_000, i32::MAX as i64]
            .iter()
            .flat_map(|&s| [Time::from_unix(s, 0), Time::from_unix(s, 999_999_999)])
            .collect()
    }

    #[test]
    fn exhaustive_a_request_never_loosens() {
        for c in levels() {
            for o in times() {
                for t in times() {
                    let cur = c.map(|l| (l, o));
                    if let Decision::Send(l) = decide(cur, t) {
                        assert_eq!(l, REQUESTED);
                        assert!(c.is_none_or(|c| l >= c), "{cur:?} {t:?}");
                    }
                }
            }
        }
    }

    #[test]
    fn exhaustive_a_hold_only_rises() {
        for start in levels() {
            for to in [Level::Restrict, Level::Isolate] {
                let mut h = Hold { level: start };
                h.raise(to);
                let after = h.level().unwrap();
                assert!(after >= to && start.is_none_or(|b| after >= b));
            }
        }
    }

    #[test]
    fn the_recheck_matches_go() {
        let t = Time::from_unix(1000, 0);
        assert_eq!(decide(None, t), Decision::Send(Level::Restrict));
        assert!(matches!(decide(Some((Level::Isolate, Time::from_unix(1, 0))), t), Decision::Skip(_)));
        assert!(matches!(decide(Some((Level::Restrict, t)), t), Decision::Skip(_)), "opened at the trigger counts as after");
        assert_eq!(decide(Some((Level::Restrict, Time::from_unix(999, 0))), t), Decision::Send(Level::Restrict));
    }

    #[test]
    fn strongest_matches_go() {
        let r = |g: &str, st: &str, l: &str, s: i64| Record {
            guest: g.into(),
            status: st.into(),
            level: l.into(),
            opened: Time::from_unix(s, 0),
        };
        let recs = [
            r("a", "open", "restrict", 5),
            r("a", "open", "restrict", 9),
            r("a", "released", "isolate", 20),
            r("b", "open", "isolate", 1),
            r("a", "dangerous", "nonsense", 30),
        ];
        assert_eq!(strongest(&recs, "a"), Some((Level::Restrict, Time::from_unix(9, 0))));
        assert_eq!(strongest(&recs, "b"), Some((Level::Isolate, Time::from_unix(1, 0))));
        assert_eq!(strongest(&recs, "c"), None);
    }
}
