//! The bodies of the fuzz targets (rust/fuzz/fuzz_targets): one per parser of outside data. Each must never panic and must
//! keep its invariants on any input. They live here so the same bodies also run in the ordinary test suite
//! (tests/fuzz_smoke.rs, random and seed inputs) where cargo-fuzz (nightly) is not available.

use crate::alert::Alert;
use crate::config::Config;
use crate::gojson;
use crate::gotext;
use crate::gotime::Time;
use crate::replay;
use crate::rules;

/// JSON as Go reads it: what reads, written back and read again, is the same value.
pub fn json(data: &[u8]) {
    if let Ok(v) = gojson::parse(data) {
        let mut out = String::new();
        gojson::write_value(&mut out, &v);
        let back = gojson::parse(out.as_bytes()).expect("what was written reads back");
        assert_eq!(back, v);
    }
    let _ = gojson::parse_first(data);
}

/// The daemon's config file.
pub fn config(data: &[u8]) {
    if let Ok(c) = Config::parse(data) {
        // the durations never panic, whatever the numbers
        let _ = (c.poll_interval(), c.burst_window(), c.firewall_poll_interval(), c.limbo_poll_interval());
    }
}

/// A text rule file: refused with messages or loaded, never a panic.
pub fn rule_file(data: &[u8]) {
    match rules::load(data) {
        Ok(set) => assert!(!set.rules.is_empty()),
        Err(problems) => assert!(!problems.is_empty()),
    }
}

/// An event line (the replay format, and the shape every source produces): read, then run through every detector.
pub fn event_line(data: &[u8]) {
    let Ok(v) = gojson::parse(data) else { return };
    let Ok(e) = replay::event_from_value(&v) else { return };
    let mut ds = crate::detect::daemon_detectors(
        &Config { agent_baseline_state_path: String::new(), ..Config::default() },
        crate::detect::Deps { ephemeral: Some((32768, 60999)), ..Default::default() },
    );
    for d in ds.iter_mut() {
        for f in d.inspect(&e) {
            let a = Alert::from_finding(&crate::verify::apply(f));
            let line = a.to_json();
            let back = Alert::from_json(line.as_bytes()).expect("an alert line reads back");
            assert_eq!(back.summary, a.summary);
        }
    }
}

/// An alert line written by either daemon (the shadow-mode comparison reads both logs).
pub fn alert_line(data: &[u8]) {
    if let Ok(a) = Alert::from_json(data) {
        let line = a.to_json();
        assert_eq!(Alert::from_json(line.as_bytes()).expect("reads back"), a);
    }
}

/// Text from outside: Go's reading of bytes, the text detectors' helpers and RFC 3339 times.
pub fn text(data: &[u8]) {
    let s = gotext::lossy(data);
    if let Ok(valid) = std::str::from_utf8(data) {
        assert_eq!(s, valid);
    }
    let _ = gotext::quote(&s);
    let r = crate::detect::redact_credentials(&s);
    assert_eq!(crate::detect::redact_credentials(&r), r, "redaction is stable");
    let _ = crate::detect::text::decode_escapes(&s);
    if let Some(t) = Time::parse_rfc3339(&s) {
        assert_eq!(Time::parse_rfc3339(&t.rfc3339_nano()), Some(t));
    }
}
