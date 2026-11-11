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

/// "(ends 20:15)", "until 20:15 " and "first 2026-..." style clock readings.
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
