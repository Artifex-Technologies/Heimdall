//! `heimdalld contain now|emergency|run-request|release` against the Go binary, in fake roots that also have a process and
//! a network namespace of their own: the containment sees and stops only a made-up "sarina" process started in the fake root,
//! talks to no model server, and every systemctl, fuser and nvidia-smi it runs is a fake. Compared: output, exit codes, the
//! lock, the evidence folder (its name and the times in it aside), immunity's store and the tools called.

mod common;
use common::*;
use std::collections::BTreeMap;

fn opts(extra: &str) -> Opts {
    Opts {
        pid: true,
        net: true,
        setup: format!("chown -R 1000:1000 \"$R/home/owner\"\n{extra}"),
        timeout: std::time::Duration::from_secs(150),
        ..Opts::default()
    }
}

/// A made-up Sarina: a copy of sleep named sarina, running in the fake root's own process namespace (waited for: a
/// fixed 0.2 s was too short on a busy CI runner).
const SARINA: &str =
    "cp /usr/bin/sleep \"$R/tmp/sarina\"\ntouch -d '2026-01-02 03:04:05' \"$R/tmp/sarina\"\n(cd \"$R\" && chroot \"$R\" /tmp/sarina 300 </dev/null >/dev/null 2>&1 &)\n\
     for i in $(seq 100); do grep -qsx sarina \"$R\"/proc/[0-9]*/comm && break; sleep 0.1; done\n";

/// The evidence folder: its files and the parts of them that do not change from run to run.
fn evidence(r: &Root) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for (k, v) in r.tree(&["/var/lib/heimdall-evidence"]) {
        // the folder is named by the time
        let parts: Vec<&str> = k.split('/').collect();
        let k = if parts.len() > 4 { format!("/var/lib/heimdall-evidence/T/{}", parts[5..].join("/")) } else { k.clone() };
        let v = if k.ends_with("processes.json")
            || k.contains("/sarina-") && (k.ends_with("/maps") || k.ends_with("/environ") || k.ends_with("open-files"))
        {
            // what ran: compared by command name only (pids, times and maps are the run's own)
            let mut names: Vec<String> = v.lines().filter(|l| l.contains("\"comm\"")).map(|l| l.trim().to_string()).collect();
            names.sort();
            names.join("|")
        } else {
            normalize(&v)
        };
        out.insert(digits(&k), v);
    }
    out
}

/// Numbers (pids, the random part of a temporary folder's name) as one 9.
fn digits(s: &str) -> String {
    let mut out = String::new();
    let mut last_digit = false;
    for c in s.chars() {
        if c.is_ascii_digit() {
            if !last_digit {
                out.push('9');
            }
            last_digit = true;
        } else {
            out.push(c);
            last_digit = false;
        }
    }
    out
}

fn compare(test: &str, build: impl Fn(&Root), args: &[&str], o: &Opts) -> Option<(Out, Out)> {
    let go = go_or_skip(test)?;
    let (rg, rr) = (Root::new(&format!("{test}-go")), Root::new(&format!("{test}-rs")));
    build(&rg);
    build(&rr);
    // both at once: a containment waits a minute before it checks
    let (g, r) = std::thread::scope(|s| {
        let a = s.spawn(|| rg.run(&go, args, o));
        let b = s.spawn(|| rr.run(&rust_bin(), args, o));
        (a.join().unwrap(), b.join().unwrap())
    });
    let n = |o: &Out| Out { code: o.code, stdout: normalize(&o.stdout), stderr: digits(&normalize(&o.stderr)) };
    assert_same(&format!("{test} {args:?}"), &n(&g), &n(&r));
    let state = |r: &Root| {
        r.tree(&["/etc/heimdall", "/var/lib/heimdall", "/var/lib/heimdall-requests", "/home/owner"])
            .into_iter()
            .map(|(k, v)| (k, normalize(&v)))
            .collect::<BTreeMap<_, _>>()
    };
    assert_eq!(state(&rg), state(&rr), "{test} {args:?}: files differ");
    let imm = |r: &Root| {
        r.tree(&["/var/lib/heimdall-immunity"])
            .into_iter()
            .filter(|(k, _)| !k.ends_with(".gz"))
            .map(|(k, v)| (k, normalize(&v)))
            .collect::<BTreeMap<_, _>>()
    };
    assert_eq!(imm(&rg), imm(&rr), "{test} {args:?}: immunity differs");
    assert_eq!(evidence(&rg), evidence(&rr), "{test} {args:?}: evidence differs");
    let calls = |r: &Root| digits(&r.calls());
    assert_eq!(calls(&rg), calls(&rr), "{test} {args:?}: tools called differ");
    Some((g, r))
}

fn trust(r: &Root) {
    r.write("/etc/heimdall/contain.json", r#"{"auto_contain": true, "auto_emergency": false}"#);
}

#[test]
fn contain_usage_root_and_release_as_go() {
    let none = |_: &Root| {};
    for args in [
        &["contain", "now", "--frob"][..],
        &["contain", "emergency"],
        &["contain", "emergency", "--reason", "x"],
        &["contain", "release"],
        &["contain", "run-request"],
    ] {
        compare("contain-basic", none, args, &opts(""));
        compare("contain-user", none, args, &Opts { root: false, ..opts("") });
    }
    // a lock, a held file of the containment proven by the inventory, one not proven
    let locked = |r: &Root| {
        r.write(
            "/etc/heimdall/contained",
            "{\n  \"since\": \"2026-11-01T00:00:00Z\",\n  \"reason\": \"x\",\n  \"level\": \"contained\"\n}\n",
        );
        r.write("/home/owner/a.sh", format!("#!/bin/sh\n{}\n", "a".repeat(80)));
    };
    compare("contain-release", locked, &["contain", "release"], &opts(""));
    // run-request: none, unreadable, empty reason, automatic containment off
    for (req, cfg) in [("{", true), (r#"{"reason":"   "}"#, true), (r#"{"reason":5}"#, true), (r#"{"reason":"a planted skill"}"#, false)] {
        let b = |r: &Root| {
            r.write("/var/lib/heimdall/contain-request.json", req);
            if cfg {
                trust(r);
            }
        };
        compare("contain-req", b, &["contain", "run-request"], &opts(""));
    }
}

#[test]
fn containment_and_emergency_as_go() {
    let b = |r: &Root| {
        trust(r);
        r.write(
            "/var/lib/heimdall/contain-request.json",
            format!(r#"{{"time":"2026-11-10T20:00:00Z","reason":"{}","auto":false}}"#, "ż".repeat(200)),
        );
        r.write("/home/owner/.sarina/sessions/s1.json", r#"{"session_id":"s1","messages":[]}"#);
        r.write("/etc/heimdall/config.json", r#"{"agent_session_dir":"/var/lib/sarina/sessions"}"#);
        r.write("/var/lib/sarina/sessions/s2.json", r#"{"session_id":"s2","messages":[]}"#);
    };
    let (g, _) = compare("contain-run", b, &["contain", "run-request"], &opts(SARINA)).unwrap_or_default();
    if go_bin().is_some() {
        assert!(g.stderr.contains("stopped Sarina: sarina (") && g.stderr.contains("containment held"), "{g:?}");
    }
    compare("contain-emergency", |_| {}, &["contain", "emergency", "--yes", "--reason", "test"], &opts(SARINA));
}
