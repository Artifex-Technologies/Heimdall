//! The Go daemon's table tests, exported as JSON fixtures (internal/parity, testdata/parity), run through the Rust port:
//! every alert line must be byte for byte the one Go wrote (with the time each was raised set to zero), and every assertion
//! of the original Go test must hold.

use heimdall::alert::{Alert, Sink};
use heimdall::config::Config;
use heimdall::detect::{self, Deps, PackageVerifier, TrustJudge};
use heimdall::engine::Engine;
use heimdall::gojson::{self, FromGo, Value};
use heimdall::gotime::Time;
use heimdall::{gonet, gotext, maintenance, replay, toolrules};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

fn fixtures() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/parity")
}

fn obj<'a>(v: &'a Value, k: &str) -> Option<&'a Value> {
    match v {
        Value::Object(m) => m.iter().rev().find(|(key, _)| key == k).map(|(_, v)| v),
        _ => None,
    }
}

fn s(v: Option<&Value>) -> String {
    match v {
        Some(Value::String(s)) => s.clone(),
        _ => String::new(),
    }
}

fn arr(v: Option<&Value>) -> &[Value] {
    match v {
        Some(Value::Array(a)) => a,
        _ => &[],
    }
}

fn pairs(v: Option<&Value>) -> BTreeMap<String, (String, String)> {
    let mut out = BTreeMap::new();
    if let Some(Value::Object(m)) = v {
        for (k, p) in m {
            let a = arr(Some(p));
            out.insert(k.clone(), (s(a.first()), s(a.get(1))));
        }
    }
    out
}

struct Packages(BTreeMap<String, (String, String)>);
impl PackageVerifier for Packages {
    fn expected(&self, path: &str) -> (String, String, bool) {
        match self.0.get(path) {
            Some((p, h)) => (p.clone(), h.clone(), true),
            None => (String::new(), String::new(), false),
        }
    }
}

struct Trust(BTreeMap<String, (String, String)>);
impl TrustJudge for Trust {
    fn judge(&self, path: &str, _: &str, _: bool) -> (String, String) {
        self.0.get(path).cloned().unwrap_or_default()
    }
}

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<String>>>);
impl Sink for Capture {
    fn write(&mut self, a: &Alert) -> std::io::Result<()> {
        let mut a = a.clone();
        a.time = Time::default();
        self.0.lock().unwrap().push(a.to_json());
        Ok(())
    }
}

fn deps(d: Option<&Value>) -> Deps {
    let mut out = Deps { ephemeral: Some((32768, 60999)), ..Default::default() };
    let Some(d) = d else { return out };
    if obj(d, "packages").is_some() {
        out.verifier = Some(Box::new(Packages(pairs(obj(d, "packages")))));
    }
    if obj(d, "trust").is_some() {
        out.trust = Some(Box::new(Trust(pairs(obj(d, "trust")))));
    }
    let approved: Vec<String> = arr(obj(d, "approved")).iter().map(|v| s(Some(v))).collect();
    out.approved = Some(Box::new(move |id: &str| approved.iter().any(|a| a == id)));
    let mut peers = BTreeMap::new();
    if let Some(Value::Object(m)) = obj(d, "mesh_peers") {
        for (k, v) in m {
            peers.insert(k.clone(), s(Some(v)));
        }
    }
    out.mesh_peer = Some(Box::new(move |ip: &str| peers.get(ip).cloned()));
    if let Some(Value::Array(e)) = obj(d, "ephemeral") {
        let n = |v: &Value| if let Value::Number(n) = v { n.parse().unwrap() } else { 0 };
        out.ephemeral = Some((n(&e[0]), n(&e[1])));
    }
    out
}

fn substitute(v: &Value, tmp: &str) -> Value {
    match v {
        Value::String(x) => Value::String(x.replace("$TMP", tmp)),
        Value::Array(a) => Value::Array(a.iter().map(|x| substitute(x, tmp)).collect()),
        Value::Object(m) => Value::Object(m.iter().map(|(k, x)| (k.clone(), substitute(x, tmp))).collect()),
        other => other.clone(),
    }
}

/// Runs one scenario; the alert lines of each step.
fn run(sc: &Value, tmp: &std::path::Path) -> Vec<Vec<String>> {
    let tmp_s = tmp.to_str().unwrap();
    let mut cfg = Config { agent_baseline_state_path: String::new(), maintenance_path: String::new(), ..Config::default() };
    if let Some(c) = obj(sc, "config") {
        let mut text = String::new();
        gojson::write_value(&mut text, &substitute(c, tmp_s));
        cfg = gojson::unmarshal(text.as_bytes(), cfg).expect("scenario config");
    }
    if let Some(w) = obj(sc, "maintenance") {
        cfg.maintenance_path = tmp.join("maintenance.json").to_str().unwrap().to_owned();
        let mut text = String::new();
        gojson::write_value(&mut text, w);
        std::fs::write(&cfg.maintenance_path, text).unwrap();
    }
    let clock = Arc::new(Mutex::new(Time::default()));
    let make_policy = |tr: &Value| {
        let owner = pairs(obj(tr, "owner"));
        let mut hash = BTreeMap::new();
        if let Some(Value::Object(m)) = obj(tr, "hash") {
            for (k, v) in m {
                hash.insert(k.clone(), s(Some(v)));
            }
        }
        *clock.lock().unwrap() = Time::parse_rfc3339(&s(obj(tr, "clock"))).unwrap();
        let mut p = toolrules::Policy::new(
            toolrules::builtin().unwrap(),
            Box::new(move |p: &str| match owner.get(p) {
                Some((a, b)) => (a.clone(), b.clone(), true),
                None => (String::new(), String::new(), false),
            }),
            Box::new(move |p: &str| hash.get(p).cloned()),
        );
        let c = clock.clone();
        p.now = Box::new(move || *c.lock().unwrap());
        p
    };
    // the policy keeps its own state across a restart of the detectors, as in Go (one Policy for the run)
    let policy = obj(sc, "tool_rules").map(make_policy);
    let capture = Capture::default();
    let policy = Arc::new(Mutex::new(policy));
    let build = |cfg: &Config| {
        let mut e = Engine::new(Box::new(capture.clone()), detect::daemon_detectors(cfg, deps(obj(sc, "deps"))));
        e.set_maintenance(maintenance::Watcher::new(&cfg.maintenance_path), &cfg.maintenance_soften);
        if let Some(p) = policy.lock().unwrap().take() {
            e.set_tool_rules(p);
        }
        e
    };
    let mut eng = build(&cfg);
    let mut out = Vec::new();
    for st in arr(obj(sc, "steps")) {
        capture.0.lock().unwrap().clear();
        if obj(st, "restart") == Some(&Value::Bool(true)) {
            assert!(obj(sc, "tool_rules").is_none(), "a restart with tool rules is not supported by this runner");
            eng = build(&cfg);
        } else if let Some(Value::Number(n)) = obj(st, "advance_seconds") {
            let mut c = clock.lock().unwrap();
            *c = c.add(n.parse::<i64>().unwrap() * 1_000_000_000);
        } else if let Some(e) = obj(st, "event") {
            eng.handle(&replay::event_from_value(e).expect("event"));
        }
        out.push(capture.0.lock().unwrap().clone());
    }
    out
}

/// The original Go test's assertions for a step.
fn check(st: &Value, lines: &[String]) -> Result<(), String> {
    for x in arr(obj(st, "expect")) {
        let det = s(obj(x, "detector"));
        let want: Vec<String> = arr(obj(x, "severities")).iter().map(|v| s(Some(v))).collect();
        let mut sevs = Vec::new();
        let mut first: Option<BTreeMap<String, String>> = None;
        for l in lines {
            let a = Alert::from_json(l.as_bytes()).map_err(|e| e.to_string())?;
            if a.detector_id != det {
                continue;
            }
            sevs.push(a.severity.as_str().to_string());
            first.get_or_insert(a.fields.clone());
            let has = s(obj(x, "contains"));
            if !has.is_empty() && !a.summary.contains(&has) {
                return Err(format!("{det}: summary {:?} lacks {has:?}", a.summary));
            }
            let lacks = s(obj(x, "lacks"));
            if !lacks.is_empty() && a.summary.contains(&lacks) {
                return Err(format!("{det}: summary {:?} holds {lacks:?}", a.summary));
            }
        }
        if sevs != want {
            return Err(format!("{det}: severities {sevs:?}, want {want:?}"));
        }
        if let Some(Value::Object(f)) = obj(x, "fields") {
            let first = first.unwrap_or_default();
            for (k, v) in f {
                let got = first.get(k).cloned().unwrap_or_default();
                if got != s(Some(v)) {
                    return Err(format!("{det}: field {k} = {got:?}, want {:?}", s(Some(v))));
                }
            }
        }
    }
    Ok(())
}

#[test]
fn the_go_fixtures_give_the_same_alerts() {
    let mut files: Vec<_> = std::fs::read_dir(fixtures()).unwrap().map(|e| e.unwrap().path()).collect();
    files.sort();
    let (mut steps, mut alerts, mut failures) = (0, 0, Vec::new());
    for path in files {
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        // functions, the audits, the correlator, the API, the responder and the commands (cli-*.json) have their own formats
        // and tests (audits.rs,
        // step3.rs, response.rs, contain.rs, trust.rs)
        if matches!(
            name.as_str(),
            "functions.json" | "audits.json" | "correlate.json" | "api.json" | "response.json" | "contain.json" | "trust.json"
        ) || !name.ends_with(".json")
            || name.starts_with("cli-")
        {
            continue;
        }
        let doc = gojson::parse(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(s(obj(&doc, "format")), "heimdall-parity/1", "{name}");
        for sc in arr(obj(&doc, "scenarios")) {
            let sname = s(obj(sc, "name"));
            let tmp = std::env::temp_dir().join(format!("heimdall-parity-{}-{}", std::process::id(), steps));
            std::fs::create_dir_all(&tmp).unwrap();
            let got = run(sc, &tmp);
            let _ = std::fs::remove_dir_all(&tmp);
            let golden = arr(obj(sc, "golden"));
            assert_eq!(golden.len(), got.len(), "{name}: {sname}: steps");
            for (k, (g, want)) in got.iter().zip(golden).enumerate() {
                let want: Vec<String> = arr(Some(want)).iter().map(|v| s(Some(v))).collect();
                if *g != want {
                    failures.push(format!("{name}: {sname}, step {k}:\n  go:   {want:?}\n  rust: {g:?}"));
                }
                if let Err(e) = check(&arr(obj(sc, "steps"))[k], g) {
                    failures.push(format!("{name}: {sname}, step {k}: the Go test's assertion: {e}"));
                }
                alerts += g.len();
            }
            steps += got.len();
        }
    }
    eprintln!("parity: {steps} steps, {alerts} alerts");
    assert!(failures.is_empty(), "{} differences:\n{}", failures.len(), failures.join("\n"));
    assert!(steps > 1500 && alerts > 100, "the fixtures look empty: {steps} steps, {alerts} alerts");
}

fn num(v: Option<&Value>) -> f64 {
    match v {
        Some(Value::Number(n)) => n.parse().unwrap(),
        _ => panic!("not a number: {v:?}"),
    }
}

fn close(a: f64, b: f64) -> bool {
    a == b || (a - b).abs() <= 1e-12 * a.abs().max(b.abs())
}

#[test]
fn the_go_functions_give_the_same_answers() {
    let doc = gojson::parse(&std::fs::read(fixtures().join("functions.json")).unwrap()).unwrap();
    for c in arr(obj(&doc, "redact")) {
        assert_eq!(detect::redact_credentials(&s(obj(c, "in"))), s(obj(c, "out")), "redact {:?}", s(obj(c, "in")));
    }
    for c in arr(obj(&doc, "quote")) {
        assert_eq!(gotext::quote(&s(obj(c, "in"))), s(obj(c, "out")));
    }
    for c in arr(obj(&doc, "duration")) {
        assert_eq!(gotext::duration(num(obj(c, "ns")) as i64), s(obj(c, "out")));
    }
    for c in arr(obj(&doc, "parse_ip")) {
        let ip = gonet::parse_ip(&s(obj(c, "in")));
        let b = |k| obj(c, k) == Some(&Value::Bool(true));
        assert_eq!(ip.is_some(), b("ok"), "parse {:?}", s(obj(c, "in")));
        if let Some(ip) = ip {
            assert_eq!(gonet::is_private(&ip), b("private"), "{ip}");
            assert_eq!(gonet::is_link_local_unicast(&ip), b("link_local"), "{ip}");
        }
    }
    for c in arr(obj(&doc, "stats")) {
        let mut st = detect::OnlineStats::default();
        for v in arr(obj(c, "values")) {
            st.add(num(Some(v)));
        }
        assert_eq!(st.count() as f64, num(obj(c, "count")));
        assert!(close(st.mean(), num(obj(c, "mean"))));
        assert!(close(st.std_dev(), num(obj(c, "stddev"))));
        for z in arr(obj(c, "z")) {
            let p = arr(Some(z));
            assert!(close(st.z_score(num(p.first())), num(p.get(1))));
        }
    }
    let mut n = 0;
    for c in arr(obj(&doc, "explain")) {
        let mut fields = BTreeMap::new();
        if let Some(Value::Object(m)) = obj(c, "fields") {
            for (k, v) in m {
                fields.insert(k.clone(), s(Some(v)));
            }
        }
        let t = heimdall::explain::for_alert(&s(obj(c, "detector")), &s(obj(c, "severity")), &fields);
        let want = obj(c, "text").unwrap();
        assert_eq!(
            (t.what.as_str(), t.serious.as_str(), t.done.as_str(), t.r#do.as_str()),
            (s(obj(want, "what")).as_str(), s(obj(want, "serious")).as_str(), s(obj(want, "done")).as_str(), s(obj(want, "do")).as_str()),
            "explain {:?} {:?} {fields:?}",
            s(obj(c, "detector")),
            s(obj(c, "severity"))
        );
        n += 1;
    }
    assert!(n > 80);
    // where addresses belong: the synthetic IP databases through the mapped reader, and a threat list
    let dir = fixtures();
    let mut res = heimdall::ipintel::Resolver::new(&[
        dir.join("synthetic-country.mmdb").to_string_lossy().into_owned(),
        dir.join("synthetic-asn.mmdb").to_string_lossy().into_owned(),
    ]);
    let list = heimdall::ipintel::parse_list(
        "drop",
        b"# made up\n203.0.113.0/25 ; x\n198.51.100.7\n10.0.0.0/8\n2001:db8::/32\n{\"cidr\":\"192.0.2.128/26\"}\n",
    )
    .unwrap();
    let mut n = 0;
    for c in arr(obj(&doc, "origins")) {
        let ip: std::net::IpAddr = s(obj(c, "ip")).parse().unwrap();
        let o = res.lookup(&ip);
        assert_eq!(o.text(), s(obj(c, "text")), "{ip}");
        let want: BTreeMap<String, String> = match obj(c, "fields") {
            Some(Value::Object(m)) => m.iter().map(|(k, v)| (k.clone(), s(Some(v)))).collect(),
            _ => BTreeMap::new(),
        };
        assert_eq!(o.fields("remote_").into_iter().collect::<BTreeMap<_, _>>(), want, "{ip}");
        assert_eq!(list.contains(&ip), obj(c, "listed") == Some(&Value::Bool(true)), "{ip}");
        n += 1;
    }
    assert!(n > 300);
    // the daemon's detectors, in the Go daemon's order
    let order: Vec<String> = arr(obj(&doc, "detector_order")).iter().map(|v| s(Some(v))).collect();
    let ours: Vec<String> = detect::daemon_detectors(&Config::default(), Deps { ephemeral: Some((1, 2)), ..Default::default() })
        .iter()
        .map(|d| d.id().to_string())
        .collect();
    assert_eq!(ours, order);
    // a reader of the config must accept what Go accepts: the shipped example
    let mut cfg = Config::default();
    cfg.read_into(&gojson::parse(include_bytes!("../../../packaging/arch/config.json.example")).unwrap(), "").unwrap();
}
