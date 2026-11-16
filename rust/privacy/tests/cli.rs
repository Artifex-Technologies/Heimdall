//! The two commands as Minos, Settings and a person run them: arguments, output, exit codes. Each runs in a made-up home.

use heimdall_privacy::samples;
use std::path::{Path, PathBuf};
use std::process::Command;

fn home(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("heimdall-privacy-cli-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(d.join(".config")).unwrap();
    d
}

fn cmd(bin: &str, home: &Path) -> Command {
    let mut c = Command::new(bin);
    c.env("HOME", home).env("XDG_CONFIG_HOME", home.join(".config")).env("XDG_RUNTIME_DIR", home);
    c
}

#[test]
fn strip_command() {
    let h = home("strip");
    let input = h.join("photo.jpg");
    std::fs::write(&input, samples::jpeg()).unwrap();
    let bin = env!("CARGO_BIN_EXE_heimdall-strip");
    let o = cmd(bin, &h).arg("--can").arg(&input).output().unwrap();
    assert!(o.status.success());
    assert_eq!(String::from_utf8_lossy(&o.stdout).trim(), "jpeg");
    std::fs::write(h.join("notes.txt"), b"hello").unwrap();
    assert_eq!(cmd(bin, &h).arg("--can").arg(h.join("notes.txt")).status().unwrap().code(), Some(1));
    // --check writes nothing
    let o = cmd(bin, &h).args(["--check", "--json"]).arg(&input).output().unwrap();
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert!(v["wrote"].is_null() && v["removed"].as_array().unwrap().iter().any(|x| x == "GPS position (EXIF)"));
    // the Minos form: --json IN OUT
    let out = h.join("photo (clean).jpg");
    let o = cmd(bin, &h).arg("--json").arg(&input).arg(&out).output().unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(v["wrote"], out.display().to_string());
    assert!(out.exists());
    // never over a file: exit 1 and the message last
    let o = cmd(bin, &h).arg("--json").arg(&input).arg(&out).output().unwrap();
    assert_eq!(o.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&o.stderr).lines().last().unwrap().starts_with("heimdall-strip: "));
    // the text form names the copy last; nothing hidden: no copy
    let o = cmd(bin, &h).arg(&input).output().unwrap();
    let text = String::from_utf8_lossy(&o.stdout);
    assert!(text.lines().last().unwrap().starts_with("wrote ") && text.contains("photo (clean 2).jpg"), "{text}");
    let o = cmd(bin, &h).arg(&out).output().unwrap();
    assert_eq!(String::from_utf8_lossy(&o.stdout).trim(), "nothing hidden found; no copy made");
    assert_eq!(cmd(bin, &h).status().unwrap().code(), Some(2));
    assert_eq!(cmd(bin, &h).args(["a", "b", "c"]).status().unwrap().code(), Some(2));
    let _ = std::fs::remove_dir_all(&h);
}

#[test]
fn fileguard_command() {
    let h = home("guard");
    let bin = env!("CARGO_BIN_EXE_heimdall-fileguard");
    let bad = h.join("invoice.pdf");
    std::fs::write(&bad, samples::pdf(true)).unwrap();
    let good = h.join("letter.pdf");
    std::fs::write(&good, samples::pdf(false)).unwrap();
    assert_eq!(cmd(bin, &h).arg("check").arg(&good).status().unwrap().code(), Some(0));
    let o = cmd(bin, &h).arg("check").arg(&good).arg(&bad).output().unwrap();
    assert_eq!(o.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&o.stdout).contains("tracker.example.net"));
    let o = cmd(bin, &h).args(["check", "--json"]).arg(&bad).output().unwrap();
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(v["kind"], "pdf");
    assert_eq!(v["found"], true);
    assert_eq!(cmd(bin, &h).arg("check").arg(h.join("missing")).status().unwrap().code(), Some(2));
    // status: the Downloads folder of the made-up home, switched on until privacy.json says otherwise
    std::fs::create_dir_all(h.join("Downloads")).unwrap();
    let o = cmd(bin, &h).args(["status", "--json"]).output().unwrap();
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(v["enabled"], true);
    assert_eq!(v["running"], false);
    assert_eq!(v["folders"][0], std::fs::canonicalize(h.join("Downloads")).unwrap().display().to_string());
    std::fs::create_dir_all(h.join(".config/heimdall")).unwrap();
    std::fs::write(h.join(".config/heimdall/privacy.json"), br#"{"downloads_guard": false}"#).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&cmd(bin, &h).args(["status", "--json"]).output().unwrap().stdout).unwrap();
    assert_eq!(v["enabled"], false);
    assert_eq!(cmd(bin, &h).arg("nonsense").status().unwrap().code(), Some(2));
    let _ = std::fs::remove_dir_all(&h);
}

/// The service end to end in a made-up home, with a stand-in notify-send first on PATH (it writes down what it was asked to
/// show and answers Dismiss): a finished download gets a notice, a partial one does not, and the switch in privacy.json is
/// followed while it runs.
#[test]
fn fileguard_watch_notices_a_finished_download() {
    use std::os::unix::fs::PermissionsExt;
    let h = home("watch");
    let stubs = h.join("stubs");
    std::fs::create_dir_all(&stubs).unwrap();
    let log = h.join("notices.log");
    let stub = stubs.join("notify-send");
    std::fs::write(
        &stub,
        format!(
            "#!/bin/sh\nfor a in \"$@\"; do printf '%s\\n' \"$a\"; done >> '{}'\necho '--' >> '{}'\necho dismiss\n",
            log.display(),
            log.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
    let dl = h.join("Downloads");
    std::fs::create_dir_all(&dl).unwrap();
    let mut child = cmd(env!("CARGO_BIN_EXE_heimdall-fileguard"), &h)
        .arg("watch")
        .env("PATH", format!("{}:/usr/bin:/bin", stubs.display()))
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let wait_for = |what: &str, secs: u64| {
        let end = std::time::Instant::now() + std::time::Duration::from_secs(secs);
        while std::time::Instant::now() < end {
            if std::fs::read_to_string(&log).unwrap_or_default().contains(what) {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        false
    };
    std::thread::sleep(std::time::Duration::from_millis(500));
    // a browser's download: written as .part, then renamed
    std::fs::write(dl.join("invoice.pdf.part"), samples::pdf(true)).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(1500));
    assert!(!wait_for("invoice", 1), "a partial file is not checked");
    std::fs::rename(dl.join("invoice.pdf.part"), dl.join("invoice.pdf")).unwrap();
    assert!(wait_for("invoice.pdf: It opens a web address", 10), "{}", std::fs::read_to_string(&log).unwrap_or_default());
    let text = std::fs::read_to_string(&log).unwrap();
    assert!(
        text.contains("This file tries to contact a server when opened.")
            && text.contains("details=Show details")
            && text.contains("show=Show in Minos")
    );
    // switched off in Settings: the next file gets no notice
    std::fs::create_dir_all(h.join(".config/heimdall")).unwrap();
    std::fs::write(h.join(".config/heimdall/privacy.json"), br#"{"downloads_guard": false}"#).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(1500));
    std::fs::write(dl.join("second.pdf"), samples::pdf(true)).unwrap();
    assert!(!wait_for("second.pdf", 4), "the switch is off");
    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&h);
}
