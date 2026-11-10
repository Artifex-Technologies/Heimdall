//! The containment trigger against the Go fixture (testdata/parity/contain.json): the same alerts, switch files and locks,
//! with the same clock; every step must pass the alert on and leave the same files, the request byte for byte.

use heimdall::alert::{Alert, Sink};
use heimdall::contain::Trigger;
use heimdall::gotime::Time;
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
struct Count(Arc<Mutex<usize>>);
impl Sink for Count {
    fn write(&mut self, _: &Alert) -> std::io::Result<()> {
        *self.0.lock().unwrap() += 1;
        Ok(())
    }
}

fn place(path: &std::path::Path, v: Option<&Value>) {
    let _ = std::fs::remove_dir_all(path);
    let _ = std::fs::remove_file(path);
    match v.and_then(Value::as_str) {
        None => {}
        Some("<dir>") => std::fs::create_dir(path).unwrap(),
        Some(s) => std::fs::write(path, s).unwrap(),
    }
}

#[test]
fn the_trigger_asks_as_go_asks() {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/parity/contain.json");
    let fx: Value = serde_json::from_slice(&std::fs::read(p).expect("go test ./internal/parity -update")).unwrap();
    let base = std::env::temp_dir().join(format!("heimdall-contain-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let (mut cases, mut steps, mut requests) = (0, 0, 0);
    for (i, c) in fx["cases"].as_array().unwrap().iter().enumerate() {
        let name = c["name"].as_str().unwrap();
        let dir = base.join(format!("c{i}"));
        std::fs::create_dir_all(&dir).unwrap();
        let clock = Arc::new(Mutex::new(Time::parse_rfc3339(c["clock"].as_str().unwrap()).unwrap()));
        let count = Count::default();
        let path = |f: &str| dir.join(f).to_string_lossy().into_owned();
        let mut t = Trigger::new(Box::new(count.clone()), &path("contain.json"), &path("contain-request.json"), &path("contained"));
        let c2 = clock.clone();
        t.now = Box::new(move || *c2.lock().unwrap());
        for (k, st) in c["steps"].as_array().unwrap().iter().enumerate() {
            let adv = st.get("advance_seconds").and_then(Value::as_i64).unwrap_or(0);
            {
                let mut now = clock.lock().unwrap();
                *now = now.add(adv * 1_000_000_000);
            }
            place(&dir.join("contain.json"), st.get("config"));
            place(&dir.join("contained"), st.get("marker"));
            *count.0.lock().unwrap() = 0;
            t.write(&Alert::from_json(st["alert"].as_str().unwrap().as_bytes()).unwrap()).unwrap();
            assert_eq!(*count.0.lock().unwrap() as u64, st["passed"].as_u64().unwrap(), "{name}, step {k}: passed on");
            let mut files = BTreeMap::new();
            for e in std::fs::read_dir(&dir).unwrap() {
                let e = e.unwrap();
                let n = e.file_name().to_string_lossy().into_owned();
                let v = if e.file_type().unwrap().is_dir() { "<dir>".to_string() } else { String::from_utf8_lossy(&std::fs::read(e.path()).unwrap()).into_owned() };
                files.insert(n, v);
            }
            let want: BTreeMap<String, String> =
                st["files"].as_object().unwrap().iter().map(|(k, v)| (k.clone(), v.as_str().unwrap().to_string())).collect();
            assert_eq!(files, want, "{name}, step {k}: the files");
            if files.contains_key("contain-request.json") {
                requests += 1;
            }
            let _ = std::fs::remove_file(dir.join("contain-request.json"));
            steps += 1;
        }
        cases += 1;
    }
    let _ = std::fs::remove_dir_all(&base);
    eprintln!("{cases} cases, {steps} steps, {requests} requests");
    assert!(cases >= 37 && steps >= 50 && requests >= 20, "{cases} cases, {steps} steps, {requests} requests");
}

use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig { cases: 300, ..ProptestConfig::default() })]

    /// Over any run of alerts, switch states, locks and clock steps: every alert is passed on; a request is written only for
    /// a critical finding about the agents while switched on and unlocked, never two within ten minutes, and it carries
    /// that alert's summary.
    #[test]
    fn requests_only_for_agent_threats_and_ten_minutes_apart(
        steps in proptest::collection::vec((0usize..6, any::<bool>(), any::<bool>(), 0i64..900), 1..25)
    ) {
        let dir = std::env::temp_dir().join(format!("heimdall-contain-prop-{}-{:?}", std::process::id(), std::thread::current().id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = |f: &str| dir.join(f).to_string_lossy().into_owned();
        let count = Count::default();
        let clock = Arc::new(Mutex::new(Time::parse_rfc3339("2026-11-10T08:00:00Z").unwrap()));
        let mut t = Trigger::new(Box::new(count.clone()), &path("contain.json"), &path("contain-request.json"), &path("contained"));
        let c2 = clock.clone();
        t.now = Box::new(move || *c2.lock().unwrap());
        let kinds = [
            ("file-integrity", "critical", "host-fim", "/x/.sarina/skills/a.md: changed without approval; it decides how an AI agent behaves"),
            ("permission-escalation", "critical", "agent-session", "escalation"),
            ("permission-escalation", "critical", "limbo", "escalation elsewhere"),
            ("injection-phrase", "critical", "agent-session", "ignore previous instructions"),
            ("file-integrity", "warning", "host-fim", "it decides how an AI agent behaves"),
            ("connection-watch", "critical", "host-net", "x"),
        ];
        let mut last: Option<Time> = None;
        for (n, (kind, on, lock, adv)) in steps.iter().enumerate() {
            let now = {
                let mut c = clock.lock().unwrap();
                *c = c.add(adv * 1_000_000_000);
                *c
            };
            std::fs::write(path("contain.json"), if *on { r#"{"auto_contain":true}"# } else { "{}" }).unwrap();
            if *lock { std::fs::write(path("contained"), "x").unwrap(); } else { let _ = std::fs::remove_file(path("contained")); }
            let (det, sev, src, sum) = kinds[*kind];
            let line = format!(r#"{{"time":"2026-11-10T07:00:00Z","detector_id":"{det}","severity":"{sev}","summary":"{sum}","source":"{src}","event_kind":"","event_text":""}}"#);
            t.write(&Alert::from_json(line.as_bytes()).unwrap()).unwrap();
            prop_assert_eq!(*count.0.lock().unwrap(), n + 1);
            let asked = std::fs::read_to_string(path("contain-request.json")).ok();
            let _ = std::fs::remove_file(path("contain-request.json"));
            let threat = *kind < 2 && *on && !*lock;
            if let Some(r) = asked {
                prop_assert!(threat, "asked for {}", det);
                prop_assert!(last.is_none_or(|l| now.sub(&l) >= 600_000_000_000));
                let v: Value = serde_json::from_str(&r).unwrap();
                prop_assert_eq!(v["reason"].as_str().unwrap(), sum);
                prop_assert_eq!(v["auto"].as_bool(), Some(true));
                last = Some(now);
            } else if threat {
                prop_assert!(last.is_some_and(|l| now.sub(&l) < 600_000_000_000), "a due request was not written");
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
