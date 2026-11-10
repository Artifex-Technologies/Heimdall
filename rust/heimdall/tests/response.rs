//! The Limbo responder against the Go fixtures (testdata/parity/response.json): the same alerts and Limbo events through
//! the Rust responder and its real client, against the same scripted fake Limbo on a Unix socket; the requests Limbo saw and
//! the alerts passed on or raised must be Go's (sorted within a step, the queue's waits written as W).

use heimdall::alert::{Alert, Sink};
use heimdall::response::{Client, Responder, Settings};
use serde_json::Value;
use std::io::Write;
use std::os::unix::net::UnixListener;
use std::sync::{Arc, Mutex};
use std::time::Duration;

fn fixture(name: &str) -> Value {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/parity").join(name);
    serde_json::from_slice(&std::fs::read(p).expect("go test ./internal/parity -update")).unwrap()
}

/// Go's NormaliseResponse.
fn normalise(s: &str) -> String {
    let time = regex::Regex::new(r#"^\{"time":"[^"]*","#).unwrap();
    let sock = regex::Regex::new(r"unix [^:]*limbo\.sock").unwrap();
    let wait = regex::Regex::new(r#""queue_wait":"[^"]*"|queue wait [0-9.]+[a-zµ]*s|waited [0-9.]+[a-zµ]*s|waited=[0-9.hms]+"#).unwrap();
    let s = time.replace(s, "{").into_owned();
    let s = sock.replace_all(&s, "unix SOCK").into_owned();
    wait.replace_all(&s, |c: &regex::Captures| {
        let m = &c[0];
        if m.starts_with("\"queue_wait\"") {
            "\"queue_wait\":\"W\"".to_string()
        } else if m.starts_with("queue wait") {
            "queue wait W".to_string()
        } else if m.starts_with("waited=") {
            "waited=W".to_string()
        } else {
            "waited W".to_string()
        }
    })
    .into_owned()
}

#[derive(Clone, Default)]
struct Lines(Arc<Mutex<Vec<String>>>);
impl Sink for Lines {
    fn write(&mut self, a: &Alert) -> std::io::Result<()> {
        self.0.lock().unwrap().push(normalise(&a.to_json()));
        Ok(())
    }
}
impl Lines {
    fn take(&self) -> Vec<String> {
        let mut v = std::mem::take(&mut *self.0.lock().unwrap());
        v.sort();
        v
    }
}

fn reply(s: &mut impl Write, code: u16, ctype: &str, body: &str) {
    let text = match code {
        200 => "OK",
        404 => "Not Found",
        409 => "Conflict",
        _ => "Internal Server Error",
    };
    let _ = write!(s, "HTTP/1.1 {code} {text}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
}

/// The fake control socket, scripted as Go's fakeLimbo.
fn fake(sock: &str, l: Value, seen: Arc<Mutex<Vec<String>>>) {
    let ln = UnixListener::bind(sock).unwrap();
    std::thread::spawn(move || {
        for conn in ln.incoming() {
            let Ok(mut s) = conn else { return };
            let (l, seen) = (l.clone(), seen.clone());
            std::thread::spawn(move || {
                let r = heimdall::api::read_request(&mut s).unwrap();
                let body = String::from_utf8_lossy(&r.body).into_owned();
                seen.lock().unwrap().push(normalise(&format!("{} {} {}", r.method, r.path, body)));
                let get = |k: &str| l.get(k).and_then(Value::as_str).unwrap_or("").to_string();
                let num = |k: &str| l.get(k).and_then(Value::as_u64).unwrap_or(0);
                let json = "application/json";
                if r.method == "GET" && r.path.starts_with("/v1/guests/") {
                    match get("exists").as_str() {
                        "yes" => reply(&mut s, 200, json, &format!("{{\"name\":\"{}\",\"exists\":true}}", &r.path[11..])),
                        "no" => reply(&mut s, 404, json, r#"{"exists":false}"#),
                        "odd" => reply(&mut s, 200, json, "{}"),
                        _ => reply(&mut s, 404, "text/plain; charset=utf-8", "404 page not found\n"),
                    }
                } else if r.method == "GET" && r.path == "/v1/quarantine" {
                    match get("list").as_str() {
                        "" => reply(&mut s, 500, json, r#"{"error":"list failed"}"#),
                        list => reply(&mut s, 200, json, list),
                    }
                } else if r.method == "POST" && r.path == "/v1/quarantine" {
                    let guest = serde_json::from_str::<Value>(&body).ok().and_then(|v| v["guest"].as_str().map(String::from)).unwrap_or_default();
                    std::thread::sleep(Duration::from_millis(num("delay_ms")));
                    let mut rep = get("reply");
                    if rep.is_empty() {
                        rep = r#"{"record":{"id":"q-GUEST","guest":"GUEST","level":"restrict"},"created":true,"applied":true}"#.into();
                    }
                    let code = match num("status") {
                        0 => 200,
                        c => c as u16,
                    };
                    reply(&mut s, code, json, &rep.replace("GUEST", &guest));
                } else if r.method == "POST" && r.path.ends_with("/advisory") {
                    let code = match num("advise_code") {
                        0 => 200,
                        c => c as u16,
                    };
                    reply(&mut s, code, json, "{}");
                } else {
                    reply(&mut s, 404, "text/plain; charset=utf-8", "404 page not found\n");
                }
            });
        }
    });
}

#[test]
fn the_responder_asks_limbo_and_reports_as_go() {
    let fx = fixture("response.json");
    let base = std::env::temp_dir().join(format!("heimdall-resp-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let (mut cases, mut steps, mut requests) = (0, 0, 0);
    for (i, c) in fx["cases"].as_array().unwrap().iter().enumerate() {
        let name = c["name"].as_str().unwrap();
        let dir = base.join(format!("c{i}"));
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("limbo.sock").to_string_lossy().into_owned();
        let seen: Arc<Mutex<Vec<String>>> = Arc::default();
        if !c["limbo"].get("down").and_then(Value::as_bool).unwrap_or(false) {
            fake(&sock, c["limbo"].clone(), seen.clone());
        }
        let cfg = &c["config"];
        let ms = |k: &str, d: Duration| cfg.get(k).and_then(Value::as_u64).filter(|n| *n > 0).map_or(d, Duration::from_millis);
        let def = Settings::default();
        let settings = Settings {
            timeout: ms("timeout_ms", def.timeout),
            max_pending: cfg.get("max_pending").and_then(Value::as_u64).filter(|n| *n > 0).map_or(def.max_pending, |n| n as usize),
            delay: ms("delay_ms", def.delay),
            backlog_threshold: cfg.get("backlog_threshold").and_then(Value::as_u64).filter(|n| *n > 0).map_or(def.backlog_threshold, |n| n as usize),
            backlog_interval: ms("backlog_interval_ms", def.backlog_interval),
            tick: ms("tick_ms", def.tick),
        };
        let out = Lines::default();
        let o2 = out.clone();
        let (mut r, h) =
            Responder::new(Box::new(out.clone()), Box::new(Client { socket: sock }), settings, Box::new(move |a| o2.clone().write(&a).unwrap()), Box::new(|_| {}));
        for (k, st) in c["steps"].as_array().unwrap().iter().enumerate() {
            for input in st["inputs"].as_array().unwrap() {
                std::thread::sleep(Duration::from_millis(input.get("pause_ms").and_then(Value::as_u64).unwrap_or(0)));
                if let Some(a) = input.get("alert").and_then(Value::as_str) {
                    r.write(&Alert::from_json(a.as_bytes()).unwrap()).unwrap();
                }
                if let Some(e) = input.get("observe").and_then(Value::as_str) {
                    let v = heimdall::gojson::parse(e.as_bytes()).unwrap();
                    h.observe(&heimdall::replay::event_from_value(&v).unwrap());
                }
            }
            if st.get("shutdown").and_then(Value::as_bool).unwrap_or(false) {
                h.shutdown(Duration::from_millis(st.get("grace_ms").and_then(Value::as_u64).unwrap_or(0)));
            } else {
                h.wait();
            }
            let mut got_req = std::mem::take(&mut *seen.lock().unwrap());
            got_req.sort();
            let want = |k: &str| -> Vec<String> { st[k].as_array().unwrap().iter().map(|x| x.as_str().unwrap().to_string()).collect() };
            let differ = |got: &[String], want: &[String]| {
                let only = |a: &[String], b: &[String]| a.iter().filter(|x| !b.contains(x)).cloned().collect::<Vec<_>>();
                format!("Rust only: {:?}\nGo only: {:?}", only(got, want), only(want, got))
            };
            let w = want("requests");
            assert!(got_req == w, "{name}, step {k}: the requests Limbo saw\n{}", differ(&got_req, &w));
            let (got, w) = (out.take(), want("out"));
            assert!(got == w, "{name}, step {k}: the alerts\n{}", differ(&got, &w));
            requests += got_req.len();
            steps += 1;
        }
        cases += 1;
    }
    let _ = std::fs::remove_dir_all(&base);
    assert!(cases >= 30 && steps >= 32 && requests >= 400, "{cases} cases, {steps} steps, {requests} requests");
}
