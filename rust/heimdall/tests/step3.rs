//! Step 3 against the Go fixtures: the correlator (testdata/parity/correlate.json): every line it passes on, byte for byte
//! (incident alerts with their raise time set to zero), and GET /v1/incidents' body.

use heimdall::alert::{Alert, Sink};
use heimdall::correlate::{Correlator, DETECTOR_ID};
use heimdall::gotime::Time;
use serde_json::Value;
use std::sync::{Arc, Mutex};

fn fixture(name: &str) -> Value {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/parity").join(name);
    serde_json::from_slice(&std::fs::read(p).expect("go test ./internal/parity -update")).unwrap()
}

#[derive(Clone, Default)]
struct Lines(Arc<Mutex<Vec<String>>>);

impl Sink for Lines {
    fn write(&mut self, a: &Alert) -> std::io::Result<()> {
        let mut a = a.clone();
        if a.detector_id == DETECTOR_ID {
            a.time = Time::default();
        }
        self.0.lock().unwrap().push(a.to_json());
        Ok(())
    }
}

thread_local! {
    static CLOCK: std::cell::Cell<Time> = std::cell::Cell::new(Time::default());
}

fn clock() -> Time {
    CLOCK.with(|c| c.get())
}

#[test]
fn the_correlator_passes_on_and_groups_as_go() {
    let fx = fixture("correlate.json");
    let (mut steps, mut incidents) = (0, 0);
    for sc in fx["scenarios"].as_array().unwrap() {
        let name = sc["name"].as_str().unwrap();
        let mut now = Time::parse_rfc3339(sc["clock"].as_str().unwrap()).unwrap();
        let lines = Lines::default();
        let mut c = Correlator::new(Box::new(lines.clone()));
        c.window = sc.get("window_seconds").and_then(Value::as_i64).unwrap_or(0) * 1_000_000_000;
        c.now = clock;
        for (i, st) in sc["steps"].as_array().unwrap().iter().enumerate() {
            now = now.add(st.get("advance_seconds").and_then(Value::as_i64).unwrap_or(0) * 1_000_000_000);
            CLOCK.with(|k| k.set(now));
            let a = Alert::from_json(st["alert"].as_str().unwrap().as_bytes()).unwrap();
            lines.0.lock().unwrap().clear();
            c.write(&a).unwrap();
            let got = lines.0.lock().unwrap().clone();
            let want: Vec<String> =
                st["out"].as_array().map(|v| v.iter().map(|l| l.as_str().unwrap().to_string()).collect()).unwrap_or_default();
            incidents += want.iter().filter(|l| l.contains("\"detector_id\":\"incident\"")).count();
            assert_eq!(got, want, "{name}, step {i}");
            steps += 1;
        }
        let mut body = String::from("[");
        for (i, inc) in c.state.lock().unwrap().incidents().iter().enumerate() {
            if i > 0 {
                body.push(',');
            }
            inc.to_json(&mut body);
        }
        body.push(']');
        assert_eq!(body, sc["incidents"].as_str().unwrap(), "{name}: incidents");
    }
    assert!(steps > 2000 && incidents > 300, "{steps} steps, {incidents} incident alerts");
}

/// End to end on a real loopback socket (Go: TestRealLoopbackPeerIsIdentified): the test's own account is identified from
/// the kernel's table and let in; a policy that sees only other tables refuses; a non-loopback address is refused at bind.
/// HEI-80: the baseline detector marks each scored minute, and GET /v1/telemetry gives each field's hour (60
/// characters: 1 out of range, 0 within, - none scored); an outlier sets its minute.
#[test]
fn the_telemetry_hour_marks_an_outliers_minute() {
    use heimdall::alert::Ring;
    use heimdall::api::{serve, Access, Api};
    use heimdall::event::Detector;
    use std::io::{Read, Write};
    let minutes: heimdall::anomaly::Shared = Arc::default();
    let mut d = heimdall::detect::stateful::BaselineDriftDetector::new(10, 3.0).with_minutes(Some(minutes.clone()));
    let now = heimdall::gotime::Time::now().unix();
    let at = |secs_ago: i64, mem: &str| {
        let mut e = heimdall::event::Event { kind: "host_telemetry".into(), ..Default::default() };
        e.time = heimdall::gotime::Time::from_unix(now - secs_ago, 0);
        e.fields.insert("mem_percent".into(), mem.into());
        e
    };
    // learning (10 values, two minutes ago and before) marks nothing; then values within range, then an outlier now
    for i in 0..10 {
        d.inspect(&at(600 + i, if i % 2 == 0 { "40" } else { "42" }));
    }
    d.inspect(&at(120, "41"));
    d.inspect(&at(0, "95"));
    let api = Api {
        ring: Arc::new(Mutex::new(Ring::new(10))),
        incidents: Arc::default(),
        reviewer: None,
        grants: None,
        access: Some(Access::new(vec![], vec![])),
        alerts: Box::new(|_| {}),
        files: Default::default(),
        minutes: Some(minutes),
    };
    let addr = serve("127.0.0.1:0", api).unwrap();
    let mut s = std::net::TcpStream::connect(addr).unwrap();
    s.write_all(b"GET /v1/telemetry HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n").unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).unwrap();
    assert!(out.starts_with("HTTP/1.1 200 OK\r\n"), "{out}");
    let body = out.split("\r\n\r\n").nth(1).unwrap();
    let v: Value = serde_json::from_str(body).unwrap();
    assert_eq!(v["minutes"], 60);
    let hour = v["fields"]["mem_percent"].as_str().unwrap();
    assert_eq!(hour.len(), 60);
    assert!(hour.ends_with('1'), "the outlier's minute: {hour}");
    assert_eq!(hour.chars().nth(57), Some('0'), "the value within range two minutes ago: {hour}");
    assert!(hour[..50].chars().all(|c| c == '-'), "nothing scored while learning: {hour}");
}

#[test]
fn a_real_loopback_caller_is_identified_by_the_kernel() {
    use heimdall::alert::Ring;
    use heimdall::api::{serve, Access, Api};
    use std::io::{Read, Write};
    let get = |addr: std::net::SocketAddr, path: &str| {
        let mut s = std::net::TcpStream::connect(addr).unwrap();
        write!(s, "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n", addr.port()).unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).unwrap();
        out
    };
    let mk = |access: Access| Api {
        ring: Arc::new(Mutex::new(Ring::new(10))),
        incidents: Arc::default(),
        reviewer: None,
        grants: None,
        access: Some(access),
        alerts: Box::new(|_| {}),
        files: Default::default(),
        minutes: None,
    };
    let addr = serve("127.0.0.1:0", mk(Access::new(vec![], vec![]))).unwrap();
    let r = get(addr, "/v1/alerts");
    assert!(r.starts_with("HTTP/1.1 200 OK\r\n") && r.ends_with("\r\n\r\n[]\n"), "{r}");
    // tables that do not hold the connection: the caller is unknown, refused (but /healthz is open)
    let mut blind = Access::new(vec![], vec![]);
    blind.proc_tcp = vec!["/nonexistent".into()];
    let addr = serve("127.0.0.1:0", mk(blind)).unwrap();
    assert!(get(addr, "/v1/alerts").starts_with("HTTP/1.1 403 Forbidden\r\n"));
    assert!(get(addr, "/healthz").ends_with("\r\n\r\nok\n"));
    assert!(serve("0.0.0.0:0", mk(Access::new(vec![], vec![]))).unwrap_err().to_string().contains("must be a loopback address"));
}

fn normalise_file(s: &str) -> String {
    let re = regex::Regex::new(r#""(id|time)": "[^"]*""#).unwrap();
    re.replace_all(s, |c: &regex::Captures| if &c[1] == "id" { "\"id\": \"ID\"" } else { "\"time\": \"TIME\"" }.to_string()).into_owned()
}

fn normalise(s: &str, dir: &str) -> String {
    let s = s.replace(dir, "DIR");
    let re = regex::Regex::new(r#""id":"[0-9a-f]{8}"|approve [0-9a-f]{8}|rule test [0-9a-f]{8}|"time":"[^"]*""#).unwrap();
    re.replace_all(&s, |c: &regex::Captures| {
        let m = &c[0];
        if m.starts_with("\"id\"") {
            "\"id\":\"ID\"".to_string()
        } else if m.starts_with("approve") {
            "approve ID".to_string()
        } else if m.starts_with("rule test") {
            "rule test ID".to_string()
        } else {
            "\"time\":\"TIME\"".to_string()
        }
    })
    .into_owned()
}

/// The API (testdata/parity/api.json): the Go server's guards, the caller check (a made-up account database here, a stub
/// there), alerts, review, incidents and requests; each request as raw HTTP through the Rust reader.
#[test]
fn the_api_answers_as_go() {
    use heimdall::alert::Ring;
    use heimdall::api::{read_request, Access, Api};
    let fx = fixture("api.json");
    let dir = std::env::temp_dir().join(format!("heimdall-api-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let d = dir.to_string_lossy().into_owned();
    // 1000 is in wheel, 954 is sarina, 64001 is neither (not 1001: the GitHub runner runs as 1001, and an API always allows its own account)
    std::fs::write(
        format!("{d}/passwd"),
        "root:x:0:0::/root:/bin/sh\nowner:x:1000:1000::/home/o:/bin/sh\nsarina:x:954:954::/:/bin/false\nother:x:64001:64001::/:/bin/sh\n",
    )
    .unwrap();
    std::fs::write(format!("{d}/group"), "wheel:x:998:owner\nowner:x:1000:\nsarina:x:954:\nother:x:64001:\n").unwrap();
    let mut n = 0;
    for (i, c) in fx["cases"].as_array().unwrap().iter().enumerate() {
        let name = c["name"].as_str().unwrap();
        let cd = format!("{d}/c{i}");
        std::fs::create_dir_all(&cd).unwrap();
        let ring = Arc::new(Mutex::new(Ring::new(500)));
        for l in c.get("ring").and_then(Value::as_array).cloned().unwrap_or_default() {
            ring.lock().unwrap().write(&Alert::from_json(l.as_str().unwrap().as_bytes()).unwrap()).unwrap();
        }
        let s = |k: &str| c.get(k).and_then(Value::as_str).unwrap_or("").to_string();
        if !s("requests").is_empty() {
            std::fs::write(format!("{cd}/req.json"), s("requests")).unwrap();
        }
        if !s("decisions").is_empty() {
            std::fs::write(format!("{cd}/grants.json"), s("decisions")).unwrap();
        }
        // the computer the request sees (as Go's case wrote it)
        for (f, spec) in c.get("files").and_then(Value::as_object).cloned().unwrap_or_default() {
            let p = format!("{cd}/{f}");
            std::fs::create_dir_all(std::path::Path::new(&p).parent().unwrap()).unwrap();
            std::fs::write(&p, spec.get("content").and_then(Value::as_str).unwrap_or("")).unwrap();
            let mode = spec.get("mode").and_then(Value::as_u64).unwrap_or(0o644) as u32;
            std::fs::set_permissions(&p, std::os::unix::fs::PermissionsExt::from_mode(mode)).unwrap();
        }
        for (l, target) in c.get("links").and_then(Value::as_object).cloned().unwrap_or_default() {
            std::os::unix::fs::symlink(target.as_str().unwrap(), format!("{cd}/{l}")).unwrap();
        }
        let files = heimdall::api::Files {
            audit: Some(heimdall::audit::report::Computer {
                tracker: format!("{cd}/tracker.json"),
                pacman_db: format!("{cd}/db"),
                kernel_vulns: format!("{cd}/kernel.json"),
                modules: format!("{cd}/modules"),
                running: Some(s("running")),
                hardening_root: format!("{cd}/root"),
            }),
            lan_dir: c.get("lan").and_then(Value::as_bool).unwrap_or(false).then(|| format!("{cd}/lan")),
            immunity_dir: Some(format!("{cd}/immunity")),
            rule_drafts: Some(format!("{cd}/rule-drafts.json")),
            // YARA-X's checker: the case's stand-in (a file yara-check) or none, never the one installed on this computer
            yara_check: format!("{cd}/yara-check"),
        };
        let mut access = Access::new(vec!["sarina".into()], vec!["wheel".into()]);
        access.passwd = format!("{d}/passwd");
        access.group = format!("{d}/group");
        let raised: Arc<Mutex<Vec<String>>> = Arc::default();
        let r2 = raised.clone();
        let api = Api {
            ring,
            incidents: Arc::default(),
            reviewer: c["reviewer"].as_bool().unwrap().then(|| Mutex::new(Default::default())),
            grants: Some(heimdall::grants::Store { requests: format!("{cd}/req.json"), decisions: format!("{cd}/grants.json") }),
            access: Some(access),
            alerts: Box::new(move |a: Alert| r2.lock().unwrap().push(a.detector_id)),
            files,
            minutes: None,
        };
        let mut raw = format!("{} {} HTTP/1.1\r\nHost: {}\r\n", s("method"), s("path"), s("host"));
        for (k, v) in c.get("headers").and_then(Value::as_object).cloned().unwrap_or_default() {
            raw += &format!("{k}: {}\r\n", v.as_str().unwrap());
        }
        raw += &format!("Content-Length: {}\r\n\r\n{}", s("body").len(), s("body"));
        let req = read_request(&mut raw.as_bytes()).unwrap();
        let peer = match c["peer"].as_u64() {
            Some(u) => Ok(u as u32),
            None => Err("not in the table".to_string()),
        };
        let resp = api.handle(&req, peer);
        assert_eq!(resp.status as i64, c["status"].as_i64().unwrap(), "{name}: {}", resp.body);
        let want = c["response"].as_str().unwrap();
        let got = normalise(&resp.body, &cd);
        if c["exact"].as_bool().unwrap() {
            assert_eq!(got, want, "{name}");
        } else {
            let head = |x: &str| x.split(':').next().unwrap_or("").to_string();
            assert_eq!(head(&got), head(want), "{name}: {got} / Go: {want}");
        }
        let want_alerts: Vec<String> = c["alerts"].as_array().unwrap().iter().map(|x| x.as_str().unwrap().to_string()).collect();
        assert_eq!(*raised.lock().unwrap(), want_alerts, "{name}: alerts");
        if s("method") == "POST" && s("path") == "/v1/rules/drafts" {
            let after = std::fs::read_to_string(format!("{cd}/rule-drafts.json")).map(|a| normalise_file(&a)).unwrap_or_default();
            assert_eq!(after, s("after"), "{name}: the drafts file");
        }
        n += 1;
    }
    let _ = std::fs::remove_dir_all(&dir);
    assert!(n >= 125, "{n} cases");
}
