//! `heimdalld maintenance`, `grant`, `remote` and `contain` against the Go heimdalld: the same fake system built twice
//! (tests/common), the Go binary run in one and the Rust one in the other; standard output and error, the exit code, the
//! files under /etc/heimdall, /var/lib/heimdall* and /run, and every call to an outside tool compared. Times that come from
//! the clock are replaced by placeholders first. Plus the Go fixtures of the pure parts (testdata/parity/cli-admin.json).

mod common;
use common::*;
use heimdall::gotime::Time;

/// What a run did, with the clock's traces hidden.
fn norm(o: &Out) -> Out {
    Out { code: o.code, stdout: hide_clock(&normalize(&o.stdout)), stderr: hide_clock(&normalize(&o.stderr)) }
}

/// Clock readings ("(ends 20:15)", "until 20:15"), process ids ("process 4321") and random temporary names (".grants-123").
fn hide_clock(s: &str) -> String {
    let mut out = s.to_string();
    for marker in ["(ends ", "until "] {
        let mut from = 0;
        while let Some(i) = out[from..].find(marker) {
            let at = from + i + marker.len();
            let b = out.as_bytes();
            if at + 5 <= b.len() && b[at + 2] == b':' && b[at..at + 2].iter().all(u8::is_ascii_digit) {
                out.replace_range(at..at + 5, "HH:MM");
            }
            from = at;
        }
    }
    for marker in ["process ", ".grants-"] {
        let mut from = 0;
        while let Some(i) = out[from..].find(marker) {
            let at = from + i + marker.len();
            let n = out[at..].bytes().take_while(u8::is_ascii_digit).count();
            if n > 0 {
                out.replace_range(at..at + n, "N");
            }
            from = at;
        }
    }
    out
}

fn fixture() -> serde_json::Value {
    let p = concat!(env!("CARGO_MANIFEST_DIR"), "/../../testdata/parity/cli-admin.json");
    serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap()
}

fn scratch(name: &str) -> String {
    let d = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("cli-admin-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d.to_string_lossy().into_owned()
}

#[test]
fn maintenance_fixture_from_go() {
    use heimdall::maintenance;
    let f = fixture();
    let dir = scratch("maint");
    let s = |v: &serde_json::Value| v.as_str().unwrap().to_string();
    let mut n = 0;
    for c in f["maintenance_describe"].as_array().unwrap() {
        let w = if s(&c["window"]).is_empty() {
            None
        } else {
            std::fs::write(format!("{dir}/m.json"), s(&c["window"])).unwrap();
            maintenance::read(&format!("{dir}/m.json"))
        };
        let now = Time::parse_rfc3339(&s(&c["now"])).unwrap();
        assert_eq!(maintenance::describe(w.as_ref(), &now), s(&c["text"]), "{c}");
        n += 1;
    }
    for c in f["maintenance_open"].as_array().unwrap() {
        let now = Time::parse_rfc3339(&s(&c["now"])).unwrap();
        match maintenance::open(&s(&c["actor"]), &s(&c["reason"]), c["d"].as_i64().unwrap(), now) {
            Ok(w) => {
                maintenance::write(&format!("{dir}/w.json"), &w).unwrap();
                assert_eq!(std::fs::read_to_string(format!("{dir}/w.json")).unwrap(), s(&c["file"]), "{c}");
            }
            Err(e) => assert_eq!(e, s(&c["error"]), "{c}"),
        }
        n += 1;
    }
    for c in f["maintenance_read"].as_array().unwrap() {
        std::fs::write(format!("{dir}/r.json"), s(&c["file"])).unwrap();
        let w = maintenance::read(&format!("{dir}/r.json"));
        assert_eq!(w.is_some(), c["found"].as_bool().unwrap(), "{c}");
        if let Some(w) = w {
            assert_eq!(w.to_json(), s(&c["back"]), "{c}");
        }
        n += 1;
    }
    for c in f["round"].as_array().unwrap() {
        let (d, m, out) = (c["d"].as_i64().unwrap(), c["m"].as_i64().unwrap(), c["out"].as_i64().unwrap());
        assert_eq!(maintenance::round_duration(d, m), out, "{c}");
        n += 1;
    }
    assert!(n > 190, "{n}");
}

/// A named case: how the system is built, the arguments, how it runs.
type Case<'a> = (&'a str, Box<dyn Fn(&Root)>, Vec<&'a str>, &'a Opts);
/// The same, with the text typed on the terminal.
type TtyCase<'a> = (&'a str, Box<dyn Fn(&Root)>, Vec<&'a str>, &'a str, &'a Opts);
/// A fuzz target's name and body.
type Target = (&'static str, fn(&[u8]));

const DIRS: &[&str] = &["/etc/heimdall", "/var/lib/heimdall", "/var/lib/heimdall-evidence", "/var/lib/heimdall-requests", "/run"];

/// Runs both binaries on the same system and compares everything; returns the Go run's output for further checks.
fn same(test: &str, build: impl Fn(&Root), args: &[&str], o: &Opts) -> Option<Out> {
    let ((g, rg), (r, rr)) = both(test, build, args, o)?;
    let (gn, rn) = (norm(&g), norm(&r));
    assert_same(&format!("{test} {args:?}"), &gn, &rn);
    let tree = |root: &Root| {
        root.tree(DIRS).into_iter().map(|(k, v)| (k, hide_clock(&normalize(&v)))).collect::<std::collections::BTreeMap<_, _>>()
    };
    assert_eq!(tree(&rg), tree(&rr), "{test} {args:?}: files differ");
    assert_eq!(rg.calls(), rr.calls(), "{test} {args:?}: outside calls differ");
    Some(gn)
}

fn etc(r: &Root) {
    r.mkdir("/etc/heimdall", 0o755);
}

fn window(r: &Root, from_now_secs: i64, length_secs: i64, offset: i32) {
    let now = Time::now();
    let opened = now.add(from_now_secs * 1_000_000_000).at_offset(offset);
    let until = opened.add(length_secs * 1_000_000_000);
    r.write(
        "/etc/heimdall/maintenance.json",
        format!(
            r#"{{"reason":"kernel \"update\" ü","actor":"owner","opened":"{}","until":"{}"}}"#,
            opened.rfc3339_nano(),
            until.rfc3339_nano()
        ),
    );
}

#[test]
fn maintenance_as_go() {
    let user = Opts::user();
    let root = Opts::default();
    let sudo = Opts::default().env("SUDO_USER", "owner");
    let cases: Vec<Case> = vec![
        ("none", Box::new(|_| {}), vec![], &root),
        ("bogus", Box::new(|_| {}), vec!["bogus"], &root),
        ("status-none", Box::new(etc), vec!["status"], &user),
        ("status-open", Box::new(|r| window(r, -600, 90 * 60 + 610, -5 * 3600)), vec!["status"], &user),
        ("status-utc", Box::new(|r| window(r, -60, 3600 + 70, 0)), vec!["status"], &user),
        ("status-over", Box::new(|r| window(r, -7200, 3600, 3600)), vec!["status"], &user),
        ("status-capped", Box::new(|r| window(r, -60, 10 * 3600, 0)), vec!["status"], &user),
        ("status-future", Box::new(|r| window(r, 3600, 600, 0)), vec!["status"], &user),
        (
            "status-damaged",
            Box::new(|r| {
                r.write("/etc/heimdall/maintenance.json", "{\"until\": 5");
            }),
            vec!["status"],
            &user,
        ),
        (
            "status-wrongtype",
            Box::new(|r| {
                r.write("/etc/heimdall/maintenance.json", "{\"until\": 5}");
            }),
            vec!["status"],
            &user,
        ),
        ("on-user", Box::new(etc), vec!["on", "--for", "15m", "--reason", "x"], &user),
        ("on-nofor", Box::new(etc), vec!["on", "--reason", "x"], &root),
        ("on-noreason", Box::new(etc), vec!["on", "--for", "15m"], &root),
        ("on-negative", Box::new(etc), vec!["on", "--for", "-5m", "--reason", "x"], &root),
        ("on-badfor", Box::new(etc), vec!["on", "--for", "15", "--reason", "x"], &root),
        ("on-unknownflag", Box::new(etc), vec!["on", "--fore", "15m"], &root),
        ("on", Box::new(etc), vec!["on", "--for", "15m", "--reason", "agent installs \"vim\", <git> & ü\u{2028}"], &root),
        ("on-sudo", Box::new(etc), vec!["on", "--for=2h30m", "-reason=x"], &sudo),
        ("on-capped", Box::new(etc), vec!["on", "--for", "10h", "--reason", "x"], &sudo),
        ("on-nodir", Box::new(|_| {}), vec!["on", "--for", "15m", "--reason", "x"], &root),
        ("on-replace", Box::new(|r| window(r, -60, 600, 0)), vec!["on", "--for", "1h", "--reason", "again"], &sudo),
        ("off", Box::new(|r| window(r, -60, 600, 0)), vec!["off"], &sudo),
        ("off-none", Box::new(etc), vec!["off"], &root),
        ("off-user", Box::new(|r| window(r, -60, 600, 0)), vec!["off"], &user),
        (
            "actors-refused",
            Box::new(|r| {
                r.write("/etc/heimdall/config.json", r#"{"maintenance_actors": ["owner"]}"#);
            }),
            vec!["on", "--for", "15m", "--reason", "x"],
            &root,
        ),
        (
            "actors-ok",
            Box::new(|r| {
                r.write("/etc/heimdall/config.json", r#"{"maintenance_actors": ["owner"]}"#);
            }),
            vec!["on", "--for", "15m", "--reason", "x"],
            &sudo,
        ),
        (
            "own-path",
            Box::new(|r| {
                r.write("/tmp/c.json", r#"{"maintenance_path": "/run/m.json"}"#);
            }),
            vec!["on", "--config", "/tmp/c.json", "--for", "1m", "--reason", "x"],
            &root,
        ),
        (
            "config-dir",
            Box::new(|r| {
                r.mkdir("/tmp/cfg", 0o755);
            }),
            vec!["status", "--config", "/tmp/cfg"],
            &user,
        ),
        (
            "config-unreadable",
            Box::new(|r| {
                r.write_mode("/tmp/c.json", "{}", 0o600);
            }),
            vec!["status", "--config", "/tmp/c.json"],
            &user,
        ),
        (
            "config-damaged",
            Box::new(|r| {
                r.write("/tmp/c.json", "{\"maintenance_path\": 5}");
            }),
            vec!["status", "--config", "/tmp/c.json"],
            &user,
        ),
        ("help", Box::new(|_| {}), vec!["status", "-h"], &user),
    ];
    for (name, build, args, o) in &cases {
        let mut full = vec!["maintenance"];
        full.extend(args.iter());
        if same(&format!("maint-{name}"), build, &full, o).is_none() {
            return;
        }
    }
    // the config's errors, as the commands print them
    for (i, cfg) in [
        r#"{"vault_dirs":[1]}"#,
        r#"{"net_ports":["x"]}"#,
        r#"{"net_ports":[1.5]}"#,
        r#"{"poll_interval_seconds":"5"}"#,
        r#"{"poll_interval_seconds":1.5}"#,
        r#"{"fim_paths":"x"}"#,
        r#"{"resource_mem_threshold_percent":"x"}"#,
        r#"{"maintenance_actors":{}}"#,
        r#"{"maintenance_actors":["a",2]}"#,
        r#"{"api_addr":true}"#,
        "true",
        "[1]",
        "{",
        "{\"a\":1,}",
        "",
        r#"{"MAINTENANCE_PATH":"/run/x.json","maintenance_actors":null}"#,
    ]
    .iter()
    .enumerate()
    {
        let build = |r: &Root| {
            r.write("/tmp/c.json", cfg);
        };
        if same(&format!("maint-cfg{i}"), build, &["maintenance", "status", "--config", "/tmp/c.json"], &Opts::user()).is_none() {
            return;
        }
    }
}

#[test]
fn grant_fixture_from_go() {
    use heimdall::cli::grant::{self, Store};
    use heimdall::gostruct::Val;
    let f = fixture();
    let opt = |v: &serde_json::Value| v.as_str().map(str::to_string);
    let mut n = 0;
    for (i, c) in f["grants"].as_array().unwrap().iter().enumerate() {
        let dir = scratch(&format!("grant{i}"));
        let _ = std::fs::remove_file(format!("{dir}/requests.json"));
        let _ = std::fs::remove_file(format!("{dir}/grants.json"));
        let st = Store { requests: format!("{dir}/requests.json"), decisions: format!("{dir}/grants.json") };
        if let Some(r) = opt(&c["requests"]) {
            std::fs::write(&st.requests, r).unwrap();
        }
        if let Some(d) = opt(&c["decisions"]) {
            std::fs::write(&st.decisions, d).unwrap();
        }
        let now = Time::parse_rfc3339(c["now"].as_str().unwrap()).unwrap();
        let by = c["by"].as_str().unwrap();
        let dur = c["dur"].as_i64().unwrap();
        let op: Vec<&str> = c["op"].as_str().unwrap().split(' ').collect();
        let mut result = String::new();
        let r: Result<(), String> = match op[0] {
            "approve" | "deny" => st.decide(op[1], op[0] == "approve", by, dur, now).map(|d| {
                let g = |k: usize| match &d {
                    Val::Struct(v) => match &v[k] {
                        Val::Str(s) => s.clone(),
                        _ => String::new(),
                    },
                    _ => String::new(),
                };
                result = format!("{}: {} {}", g(3), g(1), g(2));
            }),
            "tier" => st.set_tier(op[1].parse().unwrap(), by, now),
            "revoke" => st.revoke(by, now),
            _ => {
                let (d, on, err) = st.load();
                result = grant::status_view(&d, on, now);
                if let Ok(p) = st.pending() {
                    for id in grant::sorted_ids(&p) {
                        result += &format!(" {id}");
                    }
                }
                err.map_or(Ok(()), Err)
            }
        };
        let err = r.err().unwrap_or_default().replace(&dir, "DIR");
        assert_eq!(err, c["error"].as_str().unwrap(), "{c}");
        assert_eq!(result, c["result"].as_str().unwrap(), "{c}");
        assert_eq!(std::fs::read_to_string(&st.requests).ok(), opt(&c["requests_out"]), "{c}");
        assert_eq!(std::fs::read_to_string(&st.decisions).ok(), opt(&c["decisions_out"]), "{c}");
        n += 1;
    }
    let me = std::process::id().to_string();
    for (i, c) in f["guards"].as_array().unwrap().iter().enumerate() {
        let root = scratch(&format!("guard{i}"));
        let _ = std::fs::remove_dir_all(&root);
        for p in c["procs"].as_array().unwrap() {
            let d = format!("{root}/{}", p["pid"].as_str().unwrap().replace("SELF", &me));
            std::fs::create_dir_all(&d).unwrap();
            if let Some(s) = p["status"].as_str() {
                std::fs::write(format!("{d}/status"), s).unwrap();
            }
            if let Some(s) = p["cmdline"].as_str() {
                std::fs::write(format!("{d}/cmdline"), s).unwrap();
            }
            if let Some(e) = p["exe"].as_str().filter(|e| !e.is_empty()) {
                std::os::unix::fs::symlink(e, format!("{d}/exe")).unwrap();
            }
        }
        let got = grant::guard(&root, c["terminal"].as_bool().unwrap()).err().unwrap_or_default();
        assert_eq!(got.replace(&root, "PROC").replace(&me, "SELF"), c["error"].as_str().unwrap(), "{c}");
        n += 1;
    }
    assert!(n > 240, "{n}");
}

/// Runs the command on a terminal (a pseudo-terminal with echo off; the typed `input` waits in it), standard output and error
/// both on it, as `heimdalld grant` needs for a decision. `PTY_PARENT` names the parent process (to stand in for an agent).
const PTY: &str = r#"import os, sys, termios, fcntl
inp = sys.argv[1].encode()
argv = sys.argv[2:]
m, sl = os.openpty()
a = termios.tcgetattr(sl)
a[3] &= ~termios.ECHO
termios.tcsetattr(sl, termios.TCSANOW, a)
pid = os.fork()
if pid == 0:
    os.close(m)
    os.setsid()
    fcntl.ioctl(sl, termios.TIOCSCTTY, 0)
    for fd in (0, 1, 2):
        os.dup2(sl, fd)
    if sl > 2:
        os.close(sl)
    parent = os.environ.get("PTY_PARENT")
    if parent:
        os.execv("/usr/bin/bash", [parent, "-c", '"$@"; exit $?', "x"] + argv)
    os.execv(argv[0], argv)
os.close(sl)
os.write(m, inp)
out = b""
while True:
    try:
        b = os.read(m, 65536)
    except OSError:
        break
    if not b:
        break
    out += b
_, st = os.waitpid(pid, 0)
sys.stdout.buffer.write(out)
sys.exit(os.waitstatus_to_exitcode(st))
"#;

/// Like `same`, with the command on a terminal and `input` typed into it.
fn same_tty(test: &str, build: impl Fn(&Root), args: &[&str], input: &str, o: &Opts) -> Option<Out> {
    let go = go_or_skip(test)?;
    let mut outs = Vec::new();
    for (bin, tag) in [(go, "go"), (rust_bin(), "rs")] {
        let r = Root::new(&format!("{test}-{tag}"));
        build(&r);
        r.write("/tmp/pty.py", PTY);
        let mut o = o.clone();
        o.setup = format!("mount --bind '{}' \"$R/usr/bin/heimdalld\"\n{}", bin.display(), o.setup);
        let mut a = vec!["/tmp/pty.py", input, "/usr/bin/heimdalld"];
        a.extend(args);
        let out = r.run_as("/usr/bin/python3", std::path::Path::new("/usr/bin/python3"), &a, &o);
        outs.push((norm(&out), r));
    }
    let tree = |root: &Root| {
        root.tree(DIRS).into_iter().map(|(k, v)| (k, hide_clock(&normalize(&v)))).collect::<std::collections::BTreeMap<_, _>>()
    };
    let ((g, rg), (r, rr)) = (&outs[0], &outs[1]);
    assert_same(&format!("{test} {args:?} (terminal)"), g, r);
    assert_eq!(tree(rg), tree(rr), "{test} {args:?}: files differ");
    assert_eq!(rg.calls(), rr.calls(), "{test} {args:?}: outside calls differ");
    Some(g.clone())
}

const REQS: &str = r#"[
  {"id": "aa11bb22", "kind": "escalation", "detail": "claude-cli", "reason": "the build \"fails\"; ü", "session_id": "s-1", "uid": 961, "time": "2026-11-09T10:00:00.5Z", "count": 2},
  {"id": "cc33dd44", "kind": "access_tier", "detail": "2", "uid": 961, "time": "2026-11-10T08:30:00+01:00", "count": 1, "extra": true},
  {"ID": "ee55ff66", "Kind": "escalation", "detail": "cloud-tier", "uid": 1000, "time": "2026-11-01T00:00:00Z", "count": 1}
]
"#;

fn decisions(r: &Root) {
    let future = Time::now().add(3 * 3600 * 1_000_000_000).utc().rfc3339_nano();
    r.write(
        "/etc/heimdall/grants.json",
        format!(
            r#"{{"access_tier": 1, "escalations": [{{"request_id": "x1", "tier": "claude-cli", "session_id": "s-9", "until": "{future}", "by": "owner"}}, {{"tier": "old", "until": "2026-01-01T00:00:00Z", "by": "owner"}}, {{"tier": "any", "until": "{future}", "by": "root"}}], "history": [{{"request_id": "x1", "kind": "escalation", "detail": "claude-cli", "status": "approved", "by": "owner", "time": "2026-11-01T00:00:00Z"}}]}}"#
        ),
    );
}

fn requests(r: &Root) {
    r.mkdir("/etc/heimdall", 0o755);
    r.write_mode("/var/lib/heimdall/grant-requests.json", REQS, 0o640);
}

fn both_files(r: &Root) {
    requests(r);
    decisions(r);
}

/// heimdalld's folder, owned by its account (a file root writes there is left to that account).
fn heimdall_owned(o: Opts) -> Opts {
    Opts { setup: "if [ -d \"$R/var/lib/heimdall\" ]; then chown -R 960:960 \"$R/var/lib/heimdall\"; fi\n".into(), ..o }
}

#[test]
fn grant_status_and_refusals_as_go() {
    let user = heimdall_owned(Opts::user());
    let root = heimdall_owned(Opts::default());
    let plain_user = Opts::user();
    let cases: Vec<Case> = vec![
        ("none", Box::new(|_| {}), vec![], &user),
        ("list", Box::new(both_files), vec!["list"], &root),
        ("status-both", Box::new(both_files), vec!["status"], &root),
        ("status-user", Box::new(both_files), vec!["status"], &user),
        ("status-decisions", Box::new(decisions), vec!["status"], &user),
        ("status-requests", Box::new(requests), vec![], &root),
        (
            "status-nulltier",
            Box::new(|r| {
                r.write("/etc/heimdall/grants.json", r#"{"access_tier": null, "escalations": null}"#);
            }),
            vec![],
            &root,
        ),
        (
            "status-damaged",
            Box::new(|r| {
                r.write("/etc/heimdall/grants.json", r#"{"access_tier": "2"}"#);
            }),
            vec![],
            &root,
        ),
        (
            "status-damaged-list",
            Box::new(|r| {
                r.write("/etc/heimdall/grants.json", r#"{"escalations": [1]}"#);
            }),
            vec![],
            &root,
        ),
        (
            "status-damaged-time",
            Box::new(|r| {
                r.write("/etc/heimdall/grants.json", r#"{"escalations": [{"until": 5}]}"#);
            }),
            vec![],
            &root,
        ),
        (
            "status-syntax",
            Box::new(|r| {
                r.write("/etc/heimdall/grants.json", "{");
            }),
            vec![],
            &root,
        ),
        (
            "status-dir",
            Box::new(|r| {
                r.mkdir("/etc/heimdall/grants.json", 0o755);
            }),
            vec![],
            &root,
        ),
        (
            "status-link",
            Box::new(|r| {
                r.write("/tmp/g.json", "{}");
                r.symlink("/tmp/g.json", "/etc/heimdall/grants.json");
            }),
            vec![],
            &root,
        ),
        (
            "status-requests-damaged",
            Box::new(|r| {
                decisions(r);
                r.write("/var/lib/heimdall/grant-requests.json", r#"[{"uid": -1}]"#);
            }),
            vec![],
            &root,
        ),
        (
            "status-requests-hidden",
            Box::new(|r| {
                decisions(r);
                r.write_mode("/var/lib/heimdall/grant-requests.json", REQS, 0o600);
            }),
            vec![],
            &plain_user,
        ),
        (
            "status-requests-empty",
            Box::new(|r| {
                r.write("/var/lib/heimdall/grant-requests.json", "[]");
            }),
            vec![],
            &root,
        ),
        ("approve-user", Box::new(both_files), vec!["approve", "aa11bb22"], &user),
        ("approve-notty", Box::new(both_files), vec!["approve", "aa11bb22"], &root),
        ("bogus-root", Box::new(both_files), vec!["bogus"], &root),
        ("bogus-user", Box::new(both_files), vec!["bogus"], &user),
        ("badfor", Box::new(both_files), vec!["approve", "aa11bb22", "--for", "soon"], &root),
        ("unknownflag", Box::new(both_files), vec!["approve", "--yes", "aa11bb22"], &root),
    ];
    for (name, build, args, o) in &cases {
        let mut full = vec!["grant"];
        full.extend(args.iter());
        if same(&format!("grant-{name}"), build, &full, o).is_none() {
            return;
        }
    }
}

#[test]
fn grant_decisions_on_a_terminal_as_go() {
    let root = heimdall_owned(Opts::default());
    let sudo = heimdall_owned(Opts::default().env("SUDO_USER", "owner"));
    let agent = heimdall_owned(Opts::default().env("SUDO_USER", "sarina"));
    let parent = heimdall_owned(Opts::default().env("PTY_PARENT", "sarina"));
    let cases: Vec<TtyCase> = vec![
        ("approve-esc", Box::new(both_files), vec!["approve", "aa11bb22"], "yes\n", &sudo),
        ("approve-esc-for", Box::new(both_files), vec!["approve", "aa11bb22", "--for", "30m"], " yes \n", &root),
        ("approve-esc-long", Box::new(both_files), vec!["approve", "--for=48h", "aa11bb22"], "yes\n", &root),
        ("approve-no", Box::new(both_files), vec!["approve", "aa11bb22"], "no\n", &root),
        ("approve-eof", Box::new(both_files), vec!["approve", "aa11bb22"], "\x04", &root),
        ("approve-tier", Box::new(both_files), vec!["approve", "cc33dd44"], "yes\n", &sudo),
        ("approve-tier-nodecisions", Box::new(requests), vec!["approve", "cc33dd44"], "yes\n", &sudo),
        ("approve-folded-id", Box::new(requests), vec!["approve", "ee55ff66"], "yes\n", &sudo),
        ("deny", Box::new(both_files), vec!["deny", "aa11bb22"], "", &sudo),
        ("deny-unknown", Box::new(both_files), vec!["deny", "zz"], "", &root),
        ("deny-norequests", Box::new(decisions), vec!["deny", "aa11bb22"], "", &root),
        (
            "approve-damaged",
            Box::new(|r| {
                requests(r);
                r.write("/etc/heimdall/grants.json", "[1]");
            }),
            vec!["approve", "cc33dd44"],
            "yes\n",
            &root,
        ),
        ("tier", Box::new(both_files), vec!["tier", "2"], "", &sudo),
        (
            "tier-new",
            Box::new(|r| {
                r.mkdir("/etc/heimdall", 0o755);
            }),
            vec!["tier", "3"],
            "",
            &root,
        ),
        ("tier-nodir", Box::new(|_| {}), vec!["tier", "3"], "", &root),
        ("tier-out", Box::new(both_files), vec!["tier", "5"], "", &root),
        ("tier-word", Box::new(both_files), vec!["tier", "x"], "", &root),
        ("tier-octal", Box::new(both_files), vec!["tier", "09"], "", &root),
        ("tier-neg", Box::new(both_files), vec!["tier", "-1"], "", &root),
        ("tier-many", Box::new(both_files), vec!["tier", "1", "2"], "", &root),
        ("revoke", Box::new(both_files), vec!["revoke"], "", &sudo),
        (
            "revoke-none",
            Box::new(|r| {
                r.mkdir("/etc/heimdall", 0o755);
            }),
            vec!["revoke"],
            "",
            &root,
        ),
        ("off-yes", Box::new(both_files), vec!["off"], "yes\n", &root),
        ("off-no", Box::new(both_files), vec!["off"], "nope\n", &root),
        ("off-none", Box::new(|_| {}), vec!["off"], "yes\n", &root),
        ("agent-sudo", Box::new(both_files), vec!["tier", "3"], "", &agent),
        ("agent-parent", Box::new(both_files), vec!["tier", "3"], "", &parent),
    ];
    for (name, build, args, input, o) in &cases {
        let mut full = vec!["grant"];
        full.extend(args.iter());
        if same_tty(&format!("grant-{name}"), build, &full, input, o).is_none() {
            return;
        }
    }
}

#[test]
fn remote_as_go() {
    let root = Opts::default();
    let user = Opts::user();
    let approvals = |text: &'static str| {
        move |r: &Root| {
            r.write("/etc/heimdall/remote-access-approved.json", text);
        }
    };
    let cases: Vec<Case> = vec![
        ("list-none", Box::new(|_| {}), vec![], &user),
        ("list", Box::new(approvals(r#"{"approved": ["tailscale", "anydesk", "nope"]}"#)), vec!["list"], &user),
        ("list-damaged", Box::new(approvals(r#"{"approved": ["tailscale", 5]}"#)), vec!["list"], &user),
        ("list-extra", Box::new(approvals(r#"{"approved": ["tailscale"]}"#)), vec!["list", "extra"], &user),
        ("approve-user", Box::new(|_| {}), vec!["approve", "tailscale"], &user),
        ("approve-nodir", Box::new(|_| {}), vec!["approve", "tailscale"], &root),
        ("approve", Box::new(etc), vec!["approve", "tailscale"], &root),
        ("approve-again", Box::new(approvals(r#"{"approved": ["tailscale"]}"#)), vec!["approve", "tailscale"], &root),
        (
            "approve-more",
            Box::new(approvals(r#"{"approved": ["zerotier", "anydesk", "anydesk"], "x": 1}"#)),
            vec!["approve", "tailscale"],
            &root,
        ),
        ("approve-partial", Box::new(approvals(r#"{"approved": ["zerotier", 5, "anydesk"]}"#)), vec!["approve", "tailscale"], &root),
        ("approve-syntax", Box::new(approvals(r#"{"approved": ["zerotier""#)), vec!["approve", "tailscale"], &root),
        ("forget", Box::new(approvals(r#"{"approved": ["tailscale", "anydesk"]}"#)), vec!["forget", "tailscale"], &root),
        ("forget-last", Box::new(approvals(r#"{"approved": ["tailscale"]}"#)), vec!["forget", "tailscale"], &root),
        ("forget-none", Box::new(etc), vec!["forget", "tailscale"], &root),
        ("forget-null", Box::new(approvals(r#"{"approved": null}"#)), vec!["forget", "tailscale"], &root),
        ("unknown-tool", Box::new(etc), vec!["approve", "nope"], &root),
        ("c2", Box::new(etc), vec!["approve", "sliver"], &root),
        ("c2-forget", Box::new(etc), vec!["forget", "sliver"], &root),
        ("bad-args", Box::new(etc), vec!["approve"], &root),
        ("bad-verb", Box::new(etc), vec!["allow", "tailscale"], &root),
        (
            "dir-in-place",
            Box::new(|r| {
                r.mkdir("/etc/heimdall/remote-access-approved.json.tmp", 0o755);
            }),
            vec!["approve", "tailscale"],
            &root,
        ),
    ];
    for (name, build, args, o) in &cases {
        let mut full = vec!["remote"];
        full.extend(args.iter());
        if same(&format!("remote-{name}"), build, &full, o).is_none() {
            return;
        }
    }
}

/// The fuzz targets of these commands on their seeds, cut and changed byte by byte (rust/fuzz/seeds/<target>).
#[test]
fn fuzz_targets_survive_their_seeds() {
    let targets: &[Target] = &[("grant_files", heimdall::cli::grant::fuzz_files)];
    let mut n = 0;
    for (name, f) in targets {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../fuzz/seeds").join(name);
        for e in std::fs::read_dir(&dir).unwrap() {
            let seed = std::fs::read(e.unwrap().path()).unwrap();
            f(&seed);
            for i in 0..seed.len() {
                f(&seed[..i]);
                let mut m = seed.clone();
                m[i] ^= 0x20;
                f(&m);
                n += 2;
            }
        }
    }
    assert!(n > 500, "{n}");
}

mod properties {
    use heimdall::maintenance;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(2000))]

        /// The Kani harness's body (src/maintenance.rs): never longer than four hours.
        #[test]
        fn a_window_never_lasts_more_than_four_hours(secs in -(1i64 << 40)..(1i64 << 40), nanos: u32, d: i64, off in -50_400i32..50_400) {
            maintenance::check_bound(secs, nanos, d, off);
        }

        /// Go's Round against exact arithmetic: the nearest multiple (halves away from zero), or the end of the range.
        #[test]
        fn round_is_the_nearest_multiple(d: i64, m in 1i64..i64::MAX) {
            let out = maintenance::round_duration(d, m) as i128;
            let (d, m) = (d as i128, m as i128);
            let lo = d - d.rem_euclid(m);
            let hi = lo + m;
            let want = if d.rem_euclid(m) == 0 {
                d
            } else if (d - lo) < (hi - d) || ((d - lo) == (hi - d) && d < 0) {
                lo
            } else {
                hi
            };
            prop_assert_eq!(out, want.clamp(i64::MIN as i128, i64::MAX as i128));
        }

        /// Go's Sscan of an int agrees with reading the leading number by hand.
        #[test]
        fn sscan_reads_the_leading_decimal(n: i64, rest in "[ a-z,;]{0,5}") {
            prop_assert_eq!(heimdall::cli::grant::sscan_int(&format!("{n}{rest}")), Some(n));
        }

        /// A tier is only ever set to 0-3, and the decisions file then says so.
        #[test]
        fn a_tier_is_zero_to_three(n in -10i64..10) {
            let dir = std::env::temp_dir().join(format!("heimdall-tier-prop-{}-{n}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            let st = heimdall::cli::grant::Store {
                requests: dir.join("r.json").to_string_lossy().into_owned(),
                decisions: dir.join("g.json").to_string_lossy().into_owned(),
            };
            let _ = std::fs::remove_file(&st.decisions);
            let r = st.set_tier(n, "o", heimdall::gotime::Time::now());
            prop_assert_eq!(r.is_ok(), (0..=3).contains(&n));
            if r.is_ok() {
                let (d, on, _) = st.load();
                prop_assert!(on);
                let want = format!("on=true tier={} ", n);
                prop_assert!(heimdall::cli::grant::status_view(&d, on, heimdall::gotime::Time::now()).starts_with(&want));
            }
        }

        /// Whatever the file holds, a window read back ends at most four hours after it opened.
        #[test]
        fn a_window_read_is_capped(opened in -(1i64 << 35)..(1i64 << 35), len: i64, reason in ".{0,20}") {
            let dir = std::env::temp_dir().join(format!("heimdall-maint-prop-{}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            let p = dir.join("m.json");
            let o = heimdall::gotime::Time::from_unix(opened, 0);
            let w = maintenance::Window { reason, actor: "a".into(), opened: o, until: o.add(len) };
            std::fs::write(&p, w.to_json()).unwrap();
            let r = maintenance::read(p.to_str().unwrap()).unwrap();
            prop_assert!(r.until.sub(&r.opened) <= maintenance::MAX_DURATION);
        }
    }
}
