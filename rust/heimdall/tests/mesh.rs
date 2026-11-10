//! The mesh against the Go daemon's (internal/mesh, run by rust/gotools/meshnode): a Go node and a Rust node exchange alerts
//! both ways over real loopback mutual TLS 1.3; each reads the other's identity file; keys that are not enrolled are refused
//! both ways; the same raw requests get the same answers and the same alert lines from both listeners.

use heimdall::alert::{Alert, Sink};
use heimdall::mesh::{self, Identity, Node};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

fn repo() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Builds the Go helper once (at nice 15); None when there is no Go toolchain.
fn meshnode(dir: &std::path::Path) -> Option<String> {
    let out = dir.join("meshnode");
    let st = Command::new(repo().join("rust/scripts/nicego.sh"))
        .args(["build", "-o", out.to_str().unwrap(), "./rust/gotools/meshnode"])
        .status()
        .ok()?;
    st.success().then(|| out.to_string_lossy().into_owned())
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn go_id(bin: &str, dir: &str) -> String {
    let o = Command::new(bin).args(["id", dir]).output().unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    String::from_utf8(o.stdout).unwrap().trim().to_string()
}

fn peers_file(path: &str, fp: &str, port: u16) {
    std::fs::write(path, format!(r#"[{{"name":"peer","fingerprint":"{fp}","address":"127.0.0.1:{port}"}}]"#)).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).unwrap();
}

struct Null;
impl Sink for Null {
    fn write(&mut self, _: &Alert) -> std::io::Result<()> {
        Ok(())
    }
}

/// A received alert line with the time it was received dropped.
fn timeless(line: &str) -> String {
    let mut v: serde_json::Value = serde_json::from_str(line).unwrap();
    v.as_object_mut().unwrap().remove("time");
    v.to_string()
}

fn wait_for(what: &str, secs: u64, mut f: impl FnMut() -> bool) {
    let until = Instant::now() + Duration::from_secs(secs);
    while !f() {
        assert!(Instant::now() < until, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

struct GoNode {
    child: Child,
    lines: Arc<Mutex<Vec<String>>>,
}

fn go_node(bin: &str, dir: &str, peers: &str, listen: &str) -> GoNode {
    let mut child = Command::new(bin)
        .args(["run", "--dir", dir, "--peers", peers, "--listen", listen])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut err = BufReader::new(child.stderr.take().unwrap());
    let mut first = String::new();
    err.read_line(&mut first).unwrap();
    assert_eq!(first.trim(), "ready", "the Go node did not start");
    std::thread::spawn(move || for _ in err.lines() {});
    let lines: Arc<Mutex<Vec<String>>> = Arc::default();
    let (l2, out) = (lines.clone(), child.stdout.take().unwrap());
    std::thread::spawn(move || {
        for l in BufReader::new(out).lines().map_while(Result::ok) {
            l2.lock().unwrap().push(l);
        }
    });
    GoNode { child, lines }
}

/// Posts each body with the Go helper as the peer whose key is in `dir`; the statuses (or "error: ...").
fn go_post(bin: &str, dir: &str, fp: &str, addr: &str, extra: &[&str], bodies: &[String], tmp: &std::path::Path) -> Vec<String> {
    let mut files = Vec::new();
    for (i, b) in bodies.iter().enumerate() {
        let f = tmp.join(format!("body{i}"));
        std::fs::write(&f, b).unwrap();
        files.push(f.to_string_lossy().into_owned());
    }
    let o = Command::new(bin).args(["post", "--dir", dir, "--fp", fp, "--addr", addr]).args(extra).args(&files).output().unwrap();
    String::from_utf8(o.stdout).unwrap().lines().map(String::from).collect()
}

fn alert(line: &str) -> Alert {
    Alert::from_json(line.as_bytes()).unwrap()
}

/// The local alerts both nodes send: what is sent and what is not.
fn local_alerts() -> Vec<String> {
    let long = format!("{}é and more", "x".repeat(499));
    let det = format!("{}é-detector", "d".repeat(39));
    vec![
        r#"{"time":"2026-11-10T08:00:00.123456789+05:30","detector_id":"remote-access","severity":"critical","summary":"AnyDesk is installed <&>","source":"host-packages","event_kind":"remote_access","event_text":"secret text","fields":{"tool":"anydesk"}}"#.into(),
        r#"{"time":"2026-11-10T08:00:01Z","detector_id":"connection-watch","severity":"warning","summary":"a program connected out ✓","source":"host-net","event_kind":"connection","event_text":""}"#.into(),
        r#"{"time":"2026-11-10T08:00:02Z","detector_id":"telemetry","severity":"info","summary":"not sent: below warning","source":"host","event_kind":"x","event_text":""}"#.into(),
        r#"{"time":"2026-11-10T08:00:03Z","detector_id":"integration","severity":"critical","summary":"not sent: integration","source":"heimdall","event_kind":"x","event_text":""}"#.into(),
        r#"{"time":"2026-11-10T08:00:04Z","detector_id":"mesh","severity":"critical","summary":"not sent: received from a peer","source":"mesh:x","event_kind":"mesh_alert","event_text":""}"#.into(),
        format!(r#"{{"time":"2026-11-10T08:00:05Z","detector_id":"{det}","severity":"critical","summary":"{long}","source":"{}é","event_kind":"x","event_text":""}}"#, "s".repeat(39)),
        r#"{"time":"0001-01-01T00:00:00Z","detector_id":"file-integrity","severity":"critical","summary":"/etc/x changed","source":"host-fim","event_kind":"file_modified","event_text":""}"#.into(),
    ]
}

#[test]
fn a_go_node_and_a_rust_node_exchange_alerts() {
    let tmp = std::env::temp_dir().join(format!("heimdall-mesh-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();
    let Some(bin) = meshnode(&tmp) else {
        eprintln!("no Go toolchain: the Go side of the mesh test is skipped");
        return;
    };
    let d = |n: &str| tmp.join(n).to_string_lossy().into_owned();

    // identities: Rust reads the key Go wrote, Go reads the key Rust wrote, the fingerprints agree
    let fp_go = go_id(&bin, &d("go"));
    let id_go_in_rust = mesh::load_or_create(&d("go")).unwrap();
    assert_eq!(id_go_in_rust.fingerprint, fp_go);
    assert_eq!(std::fs::read_to_string(tmp.join("go/fingerprint")).unwrap().trim(), fp_go);
    let id_rs: Identity = mesh::load_or_create(&d("rs")).unwrap();
    assert_eq!(go_id(&bin, &d("rs")), id_rs.fingerprint, "Go reads the key Rust made");
    assert_eq!(std::fs::metadata(tmp.join("rs/key.pem")).unwrap().permissions().mode() & 0o777, 0o600);
    assert_eq!(std::fs::read_to_string(tmp.join("rs/fingerprint")).unwrap().trim(), id_rs.fingerprint);
    assert_eq!(mesh::load_or_create(&d("rs")).unwrap().fingerprint, id_rs.fingerprint, "read back, not made again");
    let fp_stranger_go = go_id(&bin, &d("stranger-go"));
    let stranger_rs = mesh::load_or_create(&d("stranger-rs")).unwrap();

    let (pg, pr) = (free_port(), free_port());
    let (addr_go, addr_rs) = (format!("127.0.0.1:{pg}"), format!("127.0.0.1:{pr}"));
    peers_file(&d("peers-go.json"), &id_rs.fingerprint, pr);
    peers_file(&d("peers-rs.json"), &fp_go, pg);

    let mut go = go_node(&bin, &d("go"), &d("peers-go.json"), &addr_go);
    let got: Arc<Mutex<Vec<String>>> = Arc::default();
    let g2 = got.clone();
    let node = Node {
        id: id_rs.clone(),
        peers_path: d("peers-rs.json"),
        listen: addr_rs.clone(),
        min_severity: "warning".into(),
        out: Arc::new(move |a: Alert| g2.lock().unwrap().push(a.to_json())),
        log: Arc::new(|m: &str| eprintln!("{m}")),
    };
    let (mut sink, n) = node.start(Box::new(Null)).map_err(|e| e.0).unwrap();
    assert_eq!(n, 1);

    // both ways, the same local alerts: 4 of the 7 travel
    let stdin = go.child.stdin.as_mut().unwrap();
    for l in local_alerts() {
        sink.write(&alert(&l)).unwrap();
        writeln!(stdin, "{l}").unwrap();
    }
    wait_for("4 alerts in each direction", 20, || got.lock().unwrap().len() >= 4 && go.lines.lock().unwrap().len() >= 4);
    std::thread::sleep(Duration::from_millis(300));
    let rust_got: Vec<String> = got.lock().unwrap().iter().map(|l| timeless(l)).collect();
    let go_got: Vec<String> = go.lines.lock().unwrap().iter().map(|l| timeless(l)).collect();
    assert_eq!(rust_got.len(), 4, "{rust_got:#?}");
    assert_eq!(rust_got, go_got, "the alert lines a Rust and a Go listener write for the same alerts");
    assert!(rust_got[0].contains(r#""summary":"[peer] AnyDesk is installed <&>""#), "{}", rust_got[0]);
    assert!(rust_got[0].contains(r#""remote_time":"2026-11-10T02:30:00Z""#), "{}", rust_got[0]);
    assert!(!rust_got.iter().any(|l| l.contains("secret text") || l.contains("not sent")));
    got.lock().unwrap().clear();
    go.lines.lock().unwrap().clear();

    // refused both ways: a key that is not enrolled, a server whose key is not the enrolled one, no certificate
    let r = go_post(&bin, &d("stranger-go"), &id_rs.fingerprint, &addr_rs, &[], &[r#"{"alerts":[]}"#.into()], &tmp);
    assert!(r[0].starts_with("error:"), "a Go stranger got in: {r:?}");
    let cfg = mesh::client_config(&stranger_rs, &fp_go, &d("peers-rs.json")).unwrap();
    let e = mesh::post(&cfg, &addr_go, "POST", mesh::PATH, br#"{"alerts":[]}"#);
    assert!(e.is_err(), "a Rust stranger got in: {e:?}");
    let r = go_post(&bin, &d("go"), &fp_stranger_go, &addr_rs, &[], &[r#"{"alerts":[]}"#.into()], &tmp);
    assert!(r[0].contains("is not the enrolled"), "the Go client took the wrong server key: {r:?}");
    let cfg = mesh::client_config(&id_rs, &stranger_rs.fingerprint, &d("peers-rs.json")).unwrap();
    let e = mesh::post(&cfg, &addr_go, "POST", mesh::PATH, br#"{"alerts":[]}"#).unwrap_err();
    assert!(e.contains("is not the enrolled"), "the Rust client took the wrong server key: {e}");
    let none = Arc::new(
        rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(mesh_any_server())
            .with_no_client_auth(),
    );
    for a in [&addr_go, &addr_rs] {
        assert!(mesh::post(&none, a, "POST", mesh::PATH, br#"{"alerts":[]}"#).is_err(), "no certificate, yet in at {a}");
    }
    assert!(got.lock().unwrap().is_empty() && go.lines.lock().unwrap().is_empty());

    // the same raw requests to both listeners: the same answers, the same alert lines
    let w = |extra: &str| {
        format!(r#"{{"time":"2026-11-10T09:00:00Z","detector_id":"x","severity":"warning","summary":"s{extra}","source":"y"}}"#)
    };
    let many = |n: usize| format!(r#"{{"alerts":[{}]}}"#, (0..n).map(|i| w(&i.to_string())).collect::<Vec<_>>().join(","));
    let bodies: Vec<String> = vec![
        format!(
            r#"{{"ALERTS":[{},{{"Time":"2026-11-10T09:00:01+01:00","DETECTOR_ID":"k","Severity":"CRITICAL","summary":"case","extra":[1]}}]}} trailing"#,
            w("a")
        ),
        String::new(),
        "not json".into(),
        r#"{"alerts":null}"#.into(),
        "null".into(),
        "[]".into(),
        r#"{"alerts":{}}"#.into(),
        r#"{"alerts":[{"time":"yesterday"}]}"#.into(),
        r#"{"alerts":[{"severity":5}]}"#.into(),
        r#"{"alerts":[{"summary":"no time, \ud800 lone, \u0000 nul"}]}"#.into(),
        many(51),
        format!(r#"{{"alerts":[{}]}}"#, (0..30).map(|_| w(&"z".repeat(2500))).collect::<Vec<_>>().join(",")),
        format!(r#"{{"alerts":[{}]}}   "#, w(&"q".repeat(600))),
        many(50),
        many(50),
        many(50),
    ];
    let to_rust = go_post(&bin, &d("go"), &id_rs.fingerprint, &addr_rs, &[], &bodies, &tmp);
    let to_go = go_post(&bin, &d("rs"), &fp_go, &addr_go, &[], &bodies, &tmp);
    assert_eq!(to_rust, to_go, "the answers of the Rust and the Go listener");
    assert_eq!(to_go[..4], ["204", "400", "400", "204"]);
    assert_eq!(to_go.last().unwrap(), "429", "the rate limit");
    for (path, method) in [("/mesh/v1/other", "POST"), (mesh::PATH, "GET")] {
        let a = go_post(&bin, &d("go"), &id_rs.fingerprint, &addr_rs, &["--path", path, "--method", method], &["{}".into()], &tmp);
        let b = go_post(&bin, &d("rs"), &fp_go, &addr_go, &["--path", path, "--method", method], &["{}".into()], &tmp);
        assert_eq!((a.clone(), b), (vec!["404".to_string()], vec!["404".to_string()]), "{method} {path}");
    }
    wait_for("the same number of lines", 10, || {
        got.lock().unwrap().len() == go.lines.lock().unwrap().len() && !got.lock().unwrap().is_empty()
    });
    let rust_got: Vec<String> = got.lock().unwrap().iter().map(|l| timeless(l)).collect();
    let go_got: Vec<String> = go.lines.lock().unwrap().iter().map(|l| timeless(l)).collect();
    assert_eq!(rust_got, go_got);
    eprintln!("{} answers equal ({:?}), {} received lines equal", to_go.len() + 2, to_go, rust_got.len());

    writeln!(go.child.stdin.as_mut().unwrap(), "quit").unwrap();
    let _ = go.child.wait();
    let _ = std::fs::remove_dir_all(&tmp);
}

/// A server check that takes any key (for the no-certificate client only: the server must refuse it before that matters).
fn mesh_any_server() -> Arc<dyn rustls::client::danger::ServerCertVerifier> {
    #[derive(Debug)]
    struct Any;
    impl rustls::client::danger::ServerCertVerifier for Any {
        fn verify_server_cert(
            &self,
            _: &rustls::pki_types::CertificateDer<'_>,
            _: &[rustls::pki_types::CertificateDer<'_>],
            _: &rustls::pki_types::ServerName<'_>,
            _: &[u8],
            _: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _: &[u8],
            _: &rustls::pki_types::CertificateDer<'_>,
            _: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _: &[u8],
            _: &rustls::pki_types::CertificateDer<'_>,
            _: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            vec![rustls::SignatureScheme::ED25519]
        }
    }
    Arc::new(Any)
}

use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig { cases: 40, ..ProptestConfig::default() })]

    /// Every key made here: its certificate names it (the fingerprint read from the certificate is the key's), it reads
    /// back the same, and a certificate cut anywhere has no fingerprint.
    #[test]
    fn a_certificate_names_its_key(cut in 0usize..400, n in any::<u32>()) {
        let dir = std::env::temp_dir().join(format!("heimdall-mesh-prop-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let id = mesh::load_or_create(dir.to_str().unwrap()).unwrap();
        prop_assert_eq!(mesh::cert_fingerprint(id.certificate()), Some(id.fingerprint.clone()));
        prop_assert_eq!(mesh::load_or_create(dir.to_str().unwrap()).unwrap().fingerprint, id.fingerprint.clone());
        let c = id.certificate();
        if cut < c.len() {
            prop_assert_eq!(mesh::cert_fingerprint(&c[..cut]), None);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Whatever arrives at whatever pace, a peer gets at most 120 alerts in, plus 2 for each second that passed.
    #[test]
    fn a_peer_never_gets_past_the_rate(steps in proptest::collection::vec((0u64..2000, 1usize..60), 1..40)) {
        let t0 = Instant::now();
        let mut b = mesh::Bucket::new(t0);
        let (mut t, mut taken) = (t0, 0usize);
        for (ms, n) in steps {
            t += Duration::from_millis(ms);
            taken += (0..n).filter(|_| b.take(t)).count();
            let allowed = 120.0 + 2.0 * (t - t0).as_secs_f64();
            prop_assert!(taken as f64 <= allowed + 1e-9, "{} > {}", taken, allowed);
        }
    }
}
