//! The audits' fixture (testdata/parity/audits.json, written by internal/parity from the Go code): pacman's version
//! comparison, CVSS scores, kernel versions, the package, kernel and hardening watchers over the same file trees step by step
//! (events and the state files byte for byte), and the game-time tool's answers.

use heimdall::audit::{gametime, hardening, kernel, pkg, vercmp};
use heimdall::event::Event;
use serde_json::Value;
use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;

fn fixture() -> Value {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/parity/audits.json");
    serde_json::from_slice(&std::fs::read(p).expect("audits.json (go test ./internal/parity -update)")).unwrap()
}

fn tmp(name: &str) -> String {
    let d = std::env::temp_dir().join(format!("heimdall-audits-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d.to_string_lossy().into_owned()
}

fn write_tree(dir: &str, files: &serde_json::Map<String, Value>) {
    for (name, f) in files {
        let p = format!("{dir}/{name}");
        std::fs::create_dir_all(std::path::Path::new(&p).parent().unwrap()).unwrap();
        std::fs::write(&p, f["content"].as_str().unwrap()).unwrap();
        let mode = f.get("mode").and_then(Value::as_u64).filter(|m| *m != 0).unwrap_or(0o644) as u32;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
    }
}

fn open_up(dir: &str) {
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755));
            if p.is_dir() {
                open_up(&p.to_string_lossy());
            }
        }
    }
}

fn event_json(e: &Event) -> Value {
    let fields: BTreeMap<_, _> = e.fields.iter().map(|(k, v)| (k.clone(), Value::String(v.clone()))).collect();
    serde_json::json!({"source": e.source, "kind": e.kind, "text": e.text, "fields": fields})
}

fn euid() -> u32 {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc_geteuid() }
}
extern "C" {
    #[link_name = "geteuid"]
    fn libc_geteuid() -> u32;
}

/// Runs every scenario of one audit; returns (steps, events) compared.
fn run(kind: &str) -> (usize, usize) {
    let fx = fixture();
    let (mut steps, mut events) = (0, 0);
    for (si, sc) in fx[kind].as_array().unwrap().iter().enumerate() {
        let name = sc["name"].as_str().unwrap();
        if sc.get("non_root").and_then(Value::as_bool) == Some(true) && euid() == 0 {
            continue;
        }
        let dir = tmp(&format!("{kind}-{si}"));
        let state = format!("{dir}/state.json");
        let mut prev = serde_json::Map::new();
        for (i, st) in sc["steps"].as_array().unwrap().iter().enumerate() {
            let tree = format!("{dir}/step{i}");
            let files = st.get("files").and_then(Value::as_object).cloned().unwrap_or_else(|| prev.clone());
            write_tree(&tree, &files);
            prev = files;
            let (evs, err) = match kind {
                "packages" => {
                    let w = pkg::Watcher {
                        tracker_path: format!("{tree}/tracker.json"),
                        pacman_db: format!("{tree}/db"),
                        state_path: state.clone(),
                    };
                    match w.poll() {
                        Ok(e) => (e, None),
                        Err(e) => (Vec::new(), Some(e)),
                    }
                }
                "kernels" => {
                    let w = kernel::Watcher {
                        list_path: format!("{tree}/list.json"),
                        modules_dir: format!("{tree}/modules"),
                        state_path: state.clone(),
                        running: sc.get("running").and_then(Value::as_str).unwrap_or("").into(),
                    };
                    match w.poll() {
                        Ok(e) => (e, None),
                        Err(e) => (Vec::new(), Some(e)),
                    }
                }
                _ => {
                    let w = hardening::Watcher { sys: hardening::System { root: tree.clone() }, state_path: state.clone() };
                    (w.poll(), None)
                }
            };
            open_up(&tree);
            let want_err = st.get("error").and_then(Value::as_str).unwrap_or("");
            let got_err = err.as_ref().map(|e| e.msg.replace(&dir, "$TMP")).unwrap_or_default();
            assert_eq!(got_err.is_empty(), want_err.is_empty(), "{name}, step {i}: error {got_err:?}, Go {want_err:?}");
            if want_err.starts_with("open ") {
                assert_eq!(got_err, want_err, "{name}, step {i}");
            }
            let want_ne = st.get("not_exist").and_then(Value::as_bool).unwrap_or(false);
            assert_eq!(err.as_ref().is_some_and(|e| e.not_exist), want_ne, "{name}, step {i}: not exist");
            let got: Vec<Value> = evs.iter().map(event_json).collect();
            let mut want: Vec<Value> = st["events"].as_array().cloned().unwrap_or_default();
            let mut got = got;
            if kind == "packages" && want.len() > 12 {
                // Go's sort.Slice is not stable past 12 findings: the same findings, perhaps in another order among equals
                let key = |v: &Value| v.to_string();
                got.sort_by_key(key);
                want.sort_by_key(key);
            }
            assert_eq!(got, want, "{name}, step {i}: events");
            let got_state = std::fs::read_to_string(&state).unwrap_or_default();
            assert_eq!(got_state, st["state"].as_str().unwrap(), "{name}, step {i}: state file");
            steps += 1;
            events += want.len();
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
    (steps, events)
}

#[test]
fn the_package_audit_answers_as_go() {
    let (steps, events) = run("packages");
    assert!(steps >= 70 && events >= 500, "{steps} steps, {events} events");
}

#[test]
fn the_kernel_audit_answers_as_go() {
    let (steps, events) = run("kernels");
    assert!(steps >= 40 && events >= 90, "{steps} steps, {events} events");
}

#[test]
fn the_hardening_checks_answer_as_go() {
    let (steps, events) = run("hardening");
    assert!(steps >= 90 && events >= 200, "{steps} steps, {events} events");
}

#[test]
fn vercmp_cvss_and_kernel_versions_answer_as_go() {
    let fx = fixture();
    for c in fx["vercmp"].as_array().unwrap() {
        let (a, b) = (c["a"].as_str().unwrap(), c["b"].as_str().unwrap());
        assert_eq!(vercmp::vercmp(a.as_bytes(), b.as_bytes()) as i64, c["out"].as_i64().unwrap(), "vercmp {a:?} {b:?}");
    }
    for c in fx["cvss"].as_array().unwrap() {
        let v = c["vector"].as_str().unwrap();
        let got = kernel::cvss3(v);
        assert_eq!(got.is_some(), c["ok"].as_bool().unwrap(), "{v}");
        assert_eq!(got.unwrap_or(0.0), c["score"].as_f64().unwrap(), "{v}");
    }
    for c in fx["kernel_version"].as_array().unwrap() {
        let want: Vec<i64> = c["out"].as_array().unwrap().iter().map(|x| x.as_i64().unwrap()).collect();
        assert_eq!(kernel::version(c["in"].as_str().unwrap()), want, "{}", c["in"]);
    }
}

fn base64(s: &str) -> Vec<u8> {
    let val = |c: u8| match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'+' => 62,
        _ => 63,
    };
    let b: Vec<u8> = s.bytes().filter(|&c| c != b'=').collect();
    let mut out = Vec::new();
    for ch in b.chunks(4) {
        let mut n = 0u32;
        for (i, &c) in ch.iter().enumerate() {
            n |= (val(c) as u32) << (18 - 6 * i);
        }
        for i in 0..ch.len() - 1 {
            out.push((n >> (16 - 8 * i)) as u8);
        }
    }
    out
}

#[test]
fn the_game_time_answers_are_read_as_go_reads_them() {
    let fx = fixture();
    let dir = tmp("gametime");
    for (i, c) in fx["gametime"].as_array().unwrap().iter().enumerate() {
        let tool = format!("{dir}/tool{i}");
        std::fs::write(format!("{tool}.out"), base64(c["stdout"].as_str().unwrap_or(""))).unwrap();
        std::fs::write(&tool, format!("#!/bin/sh\ncat \"$0.out\"\nexit {}\n", c["exit"])).unwrap();
        std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o755)).unwrap();
        let g = gametime::Gate { path: tool, retry: std::time::Duration::ZERO };
        let (playing, reason) = g.playing();
        assert_eq!(playing, c["playing"].as_bool().unwrap(), "case {i}");
        assert_eq!(reason, c["reason"].as_str().unwrap(), "case {i}");
    }
    // a missing tool: no game
    let g = gametime::Gate { path: format!("{dir}/none"), retry: std::time::Duration::ZERO };
    assert_eq!(g.playing(), (false, String::new()));
    let _ = std::fs::remove_dir_all(&dir);
}
