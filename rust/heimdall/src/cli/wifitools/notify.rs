//! `heimdall-wifi-notify` (packaging/net/heimdall-wifi-notify): shows Heimdall's verdict on the Wi-Fi network just joined
//! (/run/heimdall-wifi/last.json, written by heimdall-wifi-check) and the Wi-Fi guard's events (/run/heimdall-wifi-guard/
//! last.json) as desktop notifications. Unsafe and needs-care networks always get one; a safe network only the first time it
//! is checked. Started by the user's heimdall-wifi-notify.path when either file changes; arguments are ignored.

use super::py::{self, Dict, Load, PyErr, PyResult, Val};
use std::ffi::OsString;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

const PUB: &str = "/run/heimdall-wifi/last.json";
const GUARD: &str = "/run/heimdall-wifi-guard/last.json";

/// `os.path.expanduser("~")` without the trailing slashes: $HOME, else the account's home folder; None when neither is
/// known (Python then keeps "~/.local/state" as it is).
fn home() -> Option<Vec<u8>> {
    let h = match std::env::var_os("HOME") {
        Some(h) => h.into_vec(),
        None => {
            let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
            let mut buf = vec![0 as libc::c_char; 16384];
            let mut res: *mut libc::passwd = std::ptr::null_mut();
            let rc = unsafe { libc::getpwuid_r(libc::getuid(), &mut pw, buf.as_mut_ptr(), buf.len(), &mut res) };
            if rc != 0 || res.is_null() || pw.pw_dir.is_null() {
                return None;
            }
            unsafe { std::ffi::CStr::from_ptr(pw.pw_dir) }.to_bytes().to_vec()
        }
    };
    let mut h = h;
    while h.last() == Some(&b'/') {
        h.pop();
    }
    Some(h)
}

/// `os.path.join(a, b)` for a relative b.
fn join(a: &[u8], b: &str) -> Vec<u8> {
    let mut out = a.to_vec();
    if !out.is_empty() && out.last() != Some(&b'/') {
        out.push(b'/');
    }
    out.extend_from_slice(b.as_bytes());
    out
}

/// Where the notifications already shown are remembered: $XDG_STATE_HOME/heimdall/wifi-notified.json, else
/// ~/.local/state/heimdall/wifi-notified.json.
pub fn seen_path() -> PathBuf {
    let base = match std::env::var_os("XDG_STATE_HOME") {
        Some(x) if !x.is_empty() => x.into_vec(),
        _ => match home() {
            Some(h) => {
                let mut v = h;
                v.extend_from_slice(b"/.local/state");
                if v.is_empty() {
                    b"/".to_vec()
                } else {
                    v
                }
            }
            None => b"~/.local/state".to_vec(),
        },
    };
    PathBuf::from(OsString::from_vec(join(&join(&base, "heimdall"), "wifi-notified.json")))
}

/// `json.load` of a file the program expects a dict in: None where Python's `except (OSError, ValueError)` (or, since
/// 2026-11-11, the check that it is a dict) gives up.
fn read_dict(p: &Path) -> PyResult<Option<Dict>> {
    match py::load_file(p) {
        Load::Ok(Val::Dict(d)) => Ok(Some(d)),
        Load::Recursion => Err(PyErr::new("RecursionError", "maximum recursion depth exceeded")),
        _ => Ok(None),
    }
}

fn notify_send(args: &[String]) -> PyResult<()> {
    let mut argv = py::argv(&["notify-send", "-a", "Heimdall"]);
    argv.extend_from_slice(args);
    py::run(&py::Run { argv: &argv, env: None, input: None, capture: false, timeout: Some(Duration::from_secs(10)) })?;
    Ok(())
}

/// The name shown: printable characters only, at most `n`, or `fallback`.
fn name(v: &Val, n: usize, fallback: &str) -> String {
    let s = py::printable_prefix(&py::str_of(v), n);
    if s.is_empty() {
        fallback.to_string()
    } else {
        s
    }
}

/// The Wi-Fi guard's events: the VPN came on, or the Wi-Fi was dropped because the VPN could not protect it.
fn guard(seen: &mut Dict) -> PyResult<()> {
    let Some(g) = read_dict(Path::new(GUARD))? else { return Ok(()) };
    let time = g.get("time").cloned().unwrap_or(Val::None);
    if py::eq(seen.get("guard").unwrap_or(&Val::None), &time) {
        return Ok(());
    }
    seen.set("guard", time);
    let ssid = name(g.get("ssid").unwrap_or(&py::s("")), 64, "Wi-Fi");
    let msg = py::prefix(&py::str_of(g.get("message").unwrap_or(&py::s(""))), 300);
    let ev = g.get("event").cloned().unwrap_or(Val::None);
    let is = |w: &str| py::eq(&ev, &py::s(w));
    if is("dropped") {
        notify_send(&py::argv(&[
            "-u",
            "critical",
            "-i",
            "network-wireless-disconnected",
            "--",
            &format!("Disconnected from {ssid}"),
            &msg,
        ]))?;
    } else if is("vpn-up") || is("no-vpn") || is("router-changed") {
        notify_send(&py::argv(&["-u", "normal", "-i", "network-vpn", "--", &format!("Wi-Fi: {ssid}"), &msg]))?;
    }
    Ok(())
}

fn write_seen(path: &Path, seen: &Dict) -> PyResult<()> {
    py::makedirs(Path::new(std::ffi::OsStr::from_bytes(py::dirname_bytes(path.as_os_str().as_bytes()))))?;
    py::write_text(path, &py::dumps(&Val::Dict(seen.clone()), None))
}

fn notify() -> PyResult<()> {
    let seen_p = seen_path();
    let mut seen = read_dict(&seen_p)?.unwrap_or_default();
    guard(&mut seen)?;
    write_seen(&seen_p, &seen)?;
    let Some(r) = read_dict(Path::new(PUB))? else { return Ok(()) };
    let mut seen = read_dict(&seen_p)?.unwrap_or_default();
    let time = r.get("time").cloned().unwrap_or(Val::None);
    if py::eq(seen.get("last").unwrap_or(&Val::None), &time) {
        return Ok(()); // already shown
    }
    let ssid = name(r.get("ssid").unwrap_or(&py::s("")), 64, "this network");
    let key = crate::cli::wifitools::sha16(&ssid);
    let verdict = r.get("verdict").cloned().unwrap_or(Val::None);
    let reasons: Vec<String> = r.get("reasons").cloned().unwrap_or(Val::List(Vec::new())).iter()?.iter().map(py::str_of).collect();
    let reasons = reasons[..reasons.len().min(3)].join(" ");
    let is = |w: &str| py::eq(&verdict, &py::s(w));
    let args = if is("unsafe") {
        Some(py::argv(&[
            "-u",
            "critical",
            "-i",
            "network-wireless-disconnected",
            "--",
            &format!("Wi-Fi is not safe: {ssid}"),
            &format!("{reasons}\nDisconnect, or turn on a VPN before you do anything else."),
        ]))
    } else if is("caution") {
        Some(py::argv(&[
            "-u",
            "normal",
            "-i",
            "network-wireless",
            "--",
            &format!("Be careful on {ssid}"),
            &format!("{reasons}\nA VPN is a good idea here."),
        ]))
    } else if is("safe") && !seen.get(&key).is_some_and(Val::truthy) {
        Some(py::argv(&[
            "-u",
            "low",
            "-i",
            "network-wireless",
            "--",
            &format!("Wi-Fi checked: {ssid}"),
            "Heimdall found nothing wrong with this network.",
        ]))
    } else {
        None
    };
    if let Some(a) = args {
        // "--": the network's name is chosen by whoever runs the access point; it must never be read as an option
        notify_send(&a)?;
    }
    seen.set(&key, verdict);
    seen.set("last", time);
    write_seen(&seen_p, &seen)
}

/// The program: exit 0, or 1 where the Python stops with a traceback.
pub fn main(_args: &[String]) -> i32 {
    match notify() {
        Ok(()) => 0,
        Err(e) => py::traceback("heimdall-wifi-notify", &e),
    }
}
