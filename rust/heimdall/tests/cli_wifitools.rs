//! The Wi-Fi helpers, the Python programs the package ships and their Rust ports side by side: each scenario builds the
//! same made-up system twice (a fake root, `tests/common`), runs the Python program in one and the port in the other under
//! the helper's own name, and compares standard output and error, the exit code, every file under the folders the helper
//! writes, and every call to an outside tool with its arguments (nmcli, ip, nft, systemctl, ping, notify-send ... are
//! fakes that record and answer as the scenario says). Where the Python stops with a traceback, the port must stop at the
//! same point with the same exception (its class; the files written until then compared as always).
//!
//! Nothing here touches this computer's network or NetworkManager: every tool that could is a fake, and the check runs in
//! network namespaces of its own.

mod common;
use common::*;
use std::path::PathBuf;

fn script(name: &str) -> PathBuf {
    let dir = if name == "heimdall-wifi-check" { "arch" } else { "net" };
    repo().join("packaging").join(dir).join(name)
}

/// A fake tool that records its arguments exactly (one line per call in /.fake-argv: the name, then each argument in
/// brackets), then runs `body`.
fn recorder(r: &Root, name: &str, body: &str) {
    r.tool(name, &format!("{{ printf '%s' \"$(basename \"$0\")\"; for a in \"$@\"; do printf ' [%s]' \"$a\"; done; printf '\\n'; }} >> /.fake-argv\n{body}"));
}

/// A root with the recording files writable by everyone (the helpers run as root, heimdall or the owner).
fn new_root(tag: &str) -> Root {
    let r = Root::new(tag);
    r.write_mode("/.fake-calls", "", 0o666);
    r.write_mode("/.fake-argv", "", 0o666);
    r
}

/// The exception class at the end of a Python traceback, or of the port's "PROG: Class: message" line.
fn exception(stderr: &str, python: bool) -> Option<String> {
    if python {
        if !stderr.contains("Traceback (most recent call last):") {
            return None;
        }
        let last = stderr.lines().rev().find(|l| !l.trim().is_empty())?;
        let class = last.split(':').next()?.trim();
        Some(class.rsplit('.').next().unwrap_or(class).to_string())
    } else {
        let last = stderr.lines().rev().find(|l| !l.trim().is_empty())?;
        let mut p = last.splitn(3, ": ");
        let (prog, class) = (p.next()?, p.next()?);
        (prog.starts_with("heimdall-wifi-") && class.ends_with("Error") || class == "TimeoutExpired").then(|| class.to_string())
    }
}

/// One run of both: the Python helper in one root, the port in the other, at the same time.
pub struct Pair {
    pub py: (Out, Root),
    pub rs: (Out, Root),
}

fn run_pair(test: &str, prog: &str, build: &dyn Fn(&Root), args: &[&str], o: &Opts) -> Pair {
    let rp = new_root(&format!("{test}-py"));
    build(&rp);
    let rr = new_root(&format!("{test}-rs"));
    build(&rr);
    let inside = format!("/usr/bin/{prog}");
    let (op, or) = std::thread::scope(|sc| {
        let a = sc.spawn(|| rp.run_as(&inside, &script(prog), args, o));
        let b = sc.spawn(|| rr.run_as(&inside, &rust_bin(), args, o));
        (a.join().unwrap(), b.join().unwrap())
    });
    Pair { py: (op, rp), rs: (or, rr) }
}

/// What a run left: the outputs (times made placeholders), the tools called, and every file under `dirs`.
fn assert_pair(what: &str, p: &Pair, dirs: &[&str]) {
    let (po, pr) = &p.py;
    let (ro, rr) = &p.rs;
    let pe = exception(&po.stderr, true);
    match &pe {
        Some(class) => {
            assert_eq!(
                Some(class.clone()),
                exception(&ro.stderr, false),
                "{what}: the same exception\nPython: {}\nRust: {}",
                po.stderr,
                ro.stderr
            );
            assert_eq!(normalize(&po.stdout), normalize(&ro.stdout), "{what}: standard output");
        }
        None => {
            assert_eq!(
                normalize(&po.stdout),
                normalize(&ro.stdout),
                "{what}: standard output\nPython stderr: {}\nRust stderr: {}",
                po.stderr,
                ro.stderr
            );
            assert_eq!(normalize(&po.stderr), normalize(&ro.stderr), "{what}: standard error");
        }
    }
    assert_eq!(po.code, ro.code, "{what}: exit codes\nPython: {po:?}\nRust: {ro:?}");
    assert_eq!(pr.read_str("/.fake-argv"), rr.read_str("/.fake-argv"), "{what}: the tools called (arguments)");
    assert_eq!(pr.calls(), rr.calls(), "{what}: the tools called");
    let tree = |r: &Root| -> Vec<(String, String)> { r.tree(dirs).into_iter().map(|(k, v)| (k, normalize(&v))).collect() };
    let (tp, tr) = (tree(pr), tree(rr));
    if tp != tr {
        for (a, b) in tp.iter().zip(tr.iter()) {
            assert_eq!(a, b, "{what}: files (first difference)");
        }
        assert_eq!(tp, tr, "{what}: files");
    }
}

/// Runs a scenario and compares; returns the pair for the scenario's own checks.
fn case(test: &str, prog: &str, build: &dyn Fn(&Root), args: &[&str], o: &Opts, dirs: &[&str]) -> Pair {
    let p = run_pair(test, prog, build, args, o);
    assert_pair(test, &p, dirs);
    p
}

// ---- heimdall-wifi-notify

const NOTIFY: &str = "heimdall-wifi-notify";

fn notify_opts() -> Opts {
    Opts { setup: "chown -R 1000:1000 \"$R/home/owner\"".into(), ..Opts::user() }
}

/// A notify-send that answers nothing and succeeds.
fn notify_root(r: &Root, public: Option<&str>, guard: Option<&str>, seen: Option<&str>) {
    recorder(r, "notify-send", "exit 0\n");
    if let Some(p) = public {
        r.write("/run/heimdall-wifi/last.json", p);
    }
    if let Some(g) = guard {
        r.write("/run/heimdall-wifi-guard/last.json", g);
    }
    if let Some(s) = seen {
        r.write("/home/owner/.local/state/heimdall/wifi-notified.json", s);
    }
}

fn notify_case(name: &str, public: Option<&str>, guard: Option<&str>, seen: Option<&str>, o: &Opts) -> Pair {
    let (p, g, s) = (public.map(str::to_string), guard.map(str::to_string), seen.map(str::to_string));
    case(
        &format!("notify-{name}"),
        NOTIFY,
        &move |r| notify_root(r, p.as_deref(), g.as_deref(), s.as_deref()),
        &[],
        o,
        &["/home/owner", "/run"],
    )
}

#[test]
fn notify_as_python() {
    let o = notify_opts();
    let unsafe_ = r#"{"time": "2026-11-11T10:00:00Z", "ssid": "Cafe <free>", "verdict": "unsafe", "reasons": ["well-known sites resolve to addresses outside their own networks: x", "secure connections are being intercepted", "third", "fourth"]}"#;
    let p = notify_case("unsafe", Some(unsafe_), None, None, &o);
    assert!(p.py.1.read_str("/.fake-argv").contains("[Wi-Fi is not safe: Cafe <free>]"), "{}", p.py.1.read_str("/.fake-argv"));
    // already shown: nothing; then the same network checked again later
    notify_case("unsafe-seen", Some(unsafe_), None, Some(r#"{"last": "2026-11-11T10:00:00Z"}"#), &o);
    notify_case("caution", Some(r#"{"time": "t2", "ssid": "Hotel", "verdict": "caution", "reasons": ["open network"]}"#), None, None, &o);
    let safe = r#"{"time": "t3", "ssid": "Home", "verdict": "safe", "reasons": []}"#;
    notify_case("safe-first", Some(safe), None, None, &o);
    notify_case("safe-again", Some(safe), None, Some(r#"{"8f1dbf2e0fbbd7b5": "safe", "last": "t0"}"#), &o);
    let key = heimdall::cli::wifitools::sha16("Home");
    notify_case("safe-known", Some(safe), None, Some(&format!(r#"{{"{key}": "safe", "last": "t0", "guard": null}}"#)), &o);
    notify_case("safe-known-falsy", Some(safe), None, Some(&format!(r#"{{"{key}": 0, "last": "t0"}}"#)), &o);
    // the guard's events
    for ev in ["dropped", "vpn-up", "no-vpn", "router-changed", "other"] {
        let g = format!(
            r#"{{"time": "2026-11-11T10:05:00Z", "event": "{ev}", "ssid": "Cafe", "message": "The VPN dropped, so the Wi-Fi was disconnected."}}"#
        );
        notify_case(&format!("guard-{ev}"), None, Some(&g), None, &o);
    }
    notify_case("guard-seen", None, Some(r#"{"time": 5, "event": "dropped"}"#), Some(r#"{"guard": 5.0}"#), &o);
    notify_case("guard-no-time", None, Some(r#"{"event": "dropped", "ssid": "x"}"#), None, &o);
    notify_case("guard-and-verdict", Some(unsafe_), Some(r#"{"time": "g1", "event": "vpn-up", "ssid": "Cafe", "message": "m"}"#), None, &o);
    // names and texts chosen by whoever runs the access point
    let odd = [
        ("ctrl", "\"a\\u0000b\\u001bc\\u200bd\\u2028e\\u00adf\\t\""),
        ("long", &format!("\"{}\"", "\u{e9}x".repeat(50))),
        ("emoji", "\"\\ud83d\\ude00 \\u0301 \\ufeff \\ue000\""),
        ("number", "12.50"),
        ("bignum", "123456789012345678901234567890"),
        ("float", "1e300"),
        ("nan", "NaN"),
        ("list", r#"["a", 1, null, true, {"b": [1.5, -0.0]}]"#),
        ("dict", r#"{"it's": "q\"", "k": "\u0007\u00ff\u0100"}"#),
        ("null", "null"),
        ("false", "false"),
        ("empty", r#""""#),
        ("option", r#""--help""#),
    ];
    for (n, ssid) in odd {
        let pubj = format!(r#"{{"time": "t-{n}", "ssid": {ssid}, "verdict": "caution", "reasons": [{ssid}, "two"]}}"#);
        let g = format!(r#"{{"time": "g-{n}", "event": "dropped", "ssid": {ssid}, "message": {ssid}}}"#);
        notify_case(&format!("odd-{n}"), Some(&pubj), Some(&g), None, &o);
    }
    notify_case(
        "long-message",
        None,
        Some(&format!(r#"{{"time": "g", "event": "vpn-up", "message": "{}"}}"#, "\u{1f600}".repeat(400))),
        None,
        &o,
    );
    notify_case("reasons-string", Some(r#"{"time": "t", "ssid": "s", "verdict": "unsafe", "reasons": "abcdef"}"#), None, None, &o);
    notify_case("reasons-dict", Some(r#"{"time": "t", "ssid": "s", "verdict": "unsafe", "reasons": {"r1": 1, "r2": 2}}"#), None, None, &o);
    notify_case("reasons-number", Some(r#"{"time": "t", "ssid": "s", "verdict": "unsafe", "reasons": 7}"#), None, None, &o);
    notify_case("reasons-null", Some(r#"{"time": "t", "ssid": "s", "verdict": "safe", "reasons": null}"#), None, None, &o);
    notify_case("verdict-odd", Some(r#"{"time": [1], "ssid": "s", "verdict": ["unsafe"]}"#), None, Some(r#"{"last": [1.0]}"#), &o);
    notify_case("time-true", Some(r#"{"time": true, "ssid": "s", "verdict": "unsafe"}"#), None, Some(r#"{"last": 1}"#), &o);
    notify_case("time-nan", Some(r#"{"time": NaN, "ssid": "s", "verdict": "unsafe"}"#), None, Some(r#"{"last": NaN}"#), &o);
    notify_case("time-nan-list", Some(r#"{"time": [NaN], "ssid": "s", "verdict": "unsafe"}"#), None, Some(r#"{"last": [NaN]}"#), &o);
    // damaged files
    for (n, bad) in [
        ("not-json", "{\"time\": "),
        ("list", "[1, 2]"),
        ("string", "\"x\""),
        ("bom", "\u{feff}{}"),
        ("latin1", "{\"ssid\": \"caf\u{e9}\"}"),
        ("dup", r#"{"time": "a", "ssid": "x", "verdict": "safe", "time": "b"}"#),
        ("trailing", r#"{"time": "a"} x"#),
        ("deep", &format!("{{\"time\": \"t\", \"ssid\": {}1{}}}", "[".repeat(300), "]".repeat(300))),
    ] {
        notify_case(&format!("bad-public-{n}"), Some(bad), Some(bad), Some(bad), &o);
    }
    let latin1 = |r: &Root| {
        notify_root(r, Some(r#"{"time": "t", "ssid": "x", "verdict": "unsafe"}"#), None, None);
        r.write("/home/owner/.local/state/heimdall/wifi-notified.json", b"{\"last\": \"caf\xe9\"}");
    };
    case("notify-seen-not-utf8", NOTIFY, &latin1, &[], &o, &["/home/owner", "/run"]);
    let folder = |r: &Root| {
        notify_root(r, None, None, None);
        r.mkdir("/run/heimdall-wifi/last.json", 0o755);
    };
    case("notify-public-folder", NOTIFY, &folder, &[], &o, &["/home/owner", "/run"]);
    // where the state goes
    let xdg = Opts { env: vec![("XDG_STATE_HOME".into(), "/home/owner/xdg/".into())], ..notify_opts() };
    notify_case("xdg", Some(unsafe_), None, None, &xdg);
    let empty_xdg = Opts { env: vec![("XDG_STATE_HOME".into(), String::new())], ..notify_opts() };
    notify_case("xdg-empty", Some(unsafe_), None, None, &empty_xdg);
    let home_slash = Opts { env: vec![("HOME".into(), "/home/owner//".into())], ..notify_opts() };
    notify_case("home-slashes", Some(unsafe_), None, None, &home_slash);
    let not_writable = Opts { env: vec![("XDG_STATE_HOME".into(), "/run/heimdall-wifi/last.json".into())], ..notify_opts() };
    notify_case("state-unwritable", Some(unsafe_), Some(r#"{"time": "g", "event": "vpn-up"}"#), None, &not_writable);
    // no notify-send at all: Python stops with FileNotFoundError, before anything is remembered
    let no_tool = Opts { env: vec![("PATH".into(), "/opt/py".into())], ..notify_opts() };
    let without = |r: &Root| {
        notify_root(r, Some(unsafe_), None, None);
        r.symlink("/usr/bin/python3", "/opt/py/python3");
    };
    case("notify-no-notify-send", NOTIFY, &without, &[], &no_tool, &["/home/owner", "/run"]);
    // a notify-send that prints and fails: its output passes through, its failure is ignored
    let loud = |r: &Root| {
        notify_root(r, Some(unsafe_), Some(r#"{"time": "g", "event": "dropped"}"#), None);
        recorder(r, "notify-send", "echo shown; echo oops >&2; exit 3\n");
    };
    case("notify-send-fails", NOTIFY, &loud, &["--any", "argument"], &o, &["/home/owner", "/run"]);
}

#[test]
fn notify_send_that_hangs_is_killed_after_ten_seconds() {
    let hang = |r: &Root| {
        notify_root(r, Some(r#"{"time": "t", "ssid": "s", "verdict": "unsafe"}"#), None, None);
        recorder(r, "notify-send", "exec sleep 30\n");
    };
    let o = Opts { pid: true, timeout: std::time::Duration::from_secs(40), ..notify_opts() };
    let p = case("notify-hang", NOTIFY, &hang, &[], &o, &["/home/owner", "/run"]);
    assert_eq!(exception(&p.rs.0.stderr, false).as_deref(), Some("TimeoutExpired"));
}
