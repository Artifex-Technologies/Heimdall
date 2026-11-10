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

/// A Sarina session file, as the session watcher reads it; every decoded message then through every detector.
pub fn session_file(data: &[u8]) {
    let Ok((_, cwd, msgs)) = crate::sources::agent::parse_session(data) else { return };
    let _ = crate::sources::clean_path(&cwd);
    for (role, text, tools) in msgs.into_iter().flatten() {
        let mut fields = crate::event::Fields::new();
        fields.insert("role".into(), role);
        fields.insert("tools".into(), tools.join(","));
        let e = crate::event::Event { source: "agent-session".into(), kind: "message".into(), text, fields, ..Default::default() };
        let mut ds = crate::detect::daemon_detectors(
            &Config { agent_baseline_state_path: String::new(), ..Config::default() },
            crate::detect::Deps { ephemeral: Some((32768, 60999)), ..Default::default() },
        );
        for d in ds.iter_mut() {
            let _ = d.inspect(&e);
        }
    }
}

/// One line of Limbo's events.jsonl.
pub fn limbo_line(data: &[u8]) {
    if let Some(e) = crate::sources::limbo::parse_line(data) {
        assert!(!e.f("guest").is_empty() && !e.kind.is_empty());
    }
}

/// A MaxMind DB file (heimdall-intel-update downloads them): opened, then looked up at addresses that walk the tree.
pub fn mmdb(data: &[u8]) {
    let Ok(db) = crate::ipintel::Db::from_bytes(data.to_vec()) else { return };
    for ip in ["203.0.113.9", "1.2.3.4", "2001:db8::1", "::ffff:198.51.100.7", "255.255.255.254"] {
        let _ = db.lookup(&ip.parse().expect("an address"));
    }
    if data.len() >= 4 {
        let ip = std::net::IpAddr::from([data[0], data[1], data[2], data[3]]);
        if let Ok(Some(m)) = db.lookup(&ip) {
            let _ = crate::ipintel::Origin::from_record(&m).text();
        }
    }
}

/// One `journalctl -o json` line, as the firewall watch reads it.
pub fn journal_line(data: &[u8]) {
    let mut p = crate::sources::journal::Parser { origins: None, threats: None };
    let (e, _) = p.entry(data);
    if let Some(e) = e {
        assert!(crate::gonet::parse_ip(e.f("src")).is_some());
    }
    let _ = crate::ipintel::parse_list("fuzz", data);
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

/// Arch's security tracker (all.json) and one pacman `desc` file: read as Go reads them, then matched; pacman's version
/// comparison stays antisymmetric on whatever versions come out.
pub fn tracker(data: &[u8]) {
    use crate::audit::{pkg, vercmp};
    let (name, ver, _) = pkg::parse_desc(data);
    let mut inst = std::collections::BTreeMap::new();
    if !name.is_empty() && !ver.is_empty() {
        inst.insert(name.to_vec(), ver.to_vec());
    }
    if let Ok(groups) = gojson::unmarshal(data, Vec::<pkg::Group>::new()) {
        for f in pkg::check(&groups, &inst) {
            assert!(inst.contains_key(f.package.as_bytes()) || inst.contains_key(format!("base:{}", f.package).as_bytes()));
        }
    }
    let half = data.len() / 2;
    let (a, b) = (&data[..half], &data[half..]);
    assert_eq!(vercmp::vercmp(a, b), -vercmp::vercmp(b, a), "antisymmetric");
    assert_eq!(vercmp::vercmp(a, a), 0);
}

/// The kernel list (`heimdalld intel-check kernel`'s file): read, then checked against a few kernels.
pub fn kernel_list(data: &[u8]) {
    use crate::audit::kernel;
    let _ = kernel::cvss3(&gotext::lossy(data));
    if let Ok(f) = gojson::unmarshal(data, kernel::File::default()) {
        for k in ["6.18.42-1-lts", "0", "", "7.3.0-4-cachyos"] {
            let (holes, fix_all) = kernel::check(&f, k);
            assert_eq!(holes.is_empty(), fix_all.is_empty());
            for h in &holes {
                assert!(kernel::compare(&kernel::version(k), &kernel::version(&h.fixed_in)) < 0, "a hole is fixed later");
            }
        }
    }
}

/// The game-time tool's output: the reason is one short line.
pub fn gametime(data: &[u8]) {
    let r = crate::audit::gametime::reason(data);
    assert!(r.len() <= 160 + 3 * 3 + 3, "{}", r.len());
    assert!(!r.contains('\n'));
}

/// One HTTP request to the API from an account that may not use it: whatever the bytes, nothing but /healthz is ever
/// answered with 200, and no alert is raised.
pub fn http_request(data: &[u8]) {
    use crate::api::{read_request, Access, Api};
    use std::sync::{Arc, Mutex};
    let Ok(r) = read_request(&mut &data[..]) else { return };
    let mut access = Access::new(Vec::new(), Vec::new());
    access.passwd = "/nonexistent".into();
    let raised = Arc::new(Mutex::new(0usize));
    let r2 = raised.clone();
    let api = Api {
        ring: Arc::new(Mutex::new(crate::alert::Ring::new(10))),
        incidents: Arc::default(),
        reviewer: Some(Mutex::new(Default::default())),
        grants: None,
        access: Some(access),
        alerts: Box::new(move |_| *r2.lock().unwrap() += 1),
        files: crate::api::Files {
            audit: Some(Default::default()),
            lan_dir: Some("/nonexistent".into()),
            immunity_dir: Some("/nonexistent".into()),
            rule_drafts: Some("/nonexistent/rule-drafts.json".into()),
        },
    };
    // an account that is neither root nor this process's (nor in the empty lists)
    // SAFETY: getuid has no preconditions.
    let other = unsafe { libc::getuid() }.wrapping_add(4242).max(1);
    let resp = api.handle(&r, Ok(other));
    if r.path != "/healthz" {
        assert_ne!(resp.status, 200, "{} {}", r.method, r.path);
    }
    assert_eq!(*raised.lock().unwrap(), 0);
    let _ = crate::api::query_get(&r.query, "n");
}

/// A reply from sarina-service (the advisory): every status and body becomes Go's code with a remedy, the service's own
/// words bounded, and nothing but a 2xx reads as an answer.
pub fn sarina_reply(data: &[u8]) {
    crate::advisor::fuzz_reply(data);
}
