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
    // a made-up account too, so the watcher never looks at this computer's /run/media/$USER
    c.env("HOME", home).env("XDG_CONFIG_HOME", home.join(".config")).env("XDG_RUNTIME_DIR", home).env("USER", "heimdall-test-nobody");
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

// ---- safe file intake: scan and extract ----

/// A small ZIP writer for the commands' tests (the library's own hostile builders are in src/extract/tests.rs).
fn zip_of(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut w = heimdall_privacy::zip::Writer::new(Vec::new());
    for (n, b) in files {
        w.file(n.as_bytes(), b, false).unwrap();
    }
    w.finish().unwrap()
}

fn eicar() -> Vec<u8> {
    [&b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$"[..], b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"].concat()
}

/// A clamscan stand-in first on PATH: EICAR (put together at run time) is Eicar-Test-Signature, anything else OK.
fn clam_stub(h: &Path) -> String {
    use std::os::unix::fs::PermissionsExt;
    let stubs = h.join("stubs");
    std::fs::create_dir_all(&stubs).unwrap();
    let p = stubs.join("clamscan");
    std::fs::write(
        &p,
        "#!/bin/sh\nseen=\nfor a in \"$@\"; do\n  [ -n \"$seen\" ] || { [ \"$a\" = -- ] && seen=1; continue; }\n  if grep -q EICAR-STANDARD \"$a\"; then echo \"$a: Eicar-Test-Signature FOUND\"; else echo \"$a: OK\"; fi\ndone\n",
    )
    .unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    format!("{}:/usr/bin:/bin", stubs.display())
}

fn json_of(o: &std::process::Output) -> serde_json::Value {
    serde_json::from_slice(&o.stdout).unwrap_or_else(|e| panic!("{e}: {}", String::from_utf8_lossy(&o.stdout)))
}

#[test]
fn scan_command_contract() {
    let h = home("scan");
    let path = clam_stub(&h);
    let bin = env!("CARGO_BIN_EXE_heimdall-fileguard");
    let font = h.join("Inter.ttf");
    std::fs::write(&font, b"\x00\x01\x00\x00font").unwrap();
    let virus = h.join("eicar.txt");
    std::fs::write(&virus, eicar()).unwrap();
    let run = |args: &[&Path]| {
        cmd(bin, &h).env("PATH", &path).env("HEIMDALL_CLAMAV", "clamscan").arg("scan").arg("--json").args(args).output().unwrap()
    };
    let o = run(&[&font]);
    assert_eq!(o.status.code(), Some(0));
    let v = json_of(&o);
    // the keys a Yggdrasil helper builds against: exactly these
    let f = &v["files"][0];
    let mut keys: Vec<&String> = f.as_object().unwrap().keys().collect();
    keys.sort();
    assert_eq!(keys, ["clamav", "path", "reasons", "verdict"]);
    assert_eq!(v.as_object().unwrap().keys().collect::<Vec<_>>(), ["files"]);
    assert_eq!((f["verdict"].as_str(), f["clamav"].as_str()), (Some("ok"), Some("clean")));
    assert_eq!(f["path"], font.display().to_string());
    let o = run(&[&font, &virus]);
    assert_eq!(o.status.code(), Some(1));
    let v = json_of(&o);
    assert_eq!(v["files"][1]["verdict"], "refused");
    assert_eq!(v["files"][1]["clamav"], "infected:Eicar-Test-Signature");
    let o = run(&[&font, &h.join("missing")]);
    assert_eq!(o.status.code(), Some(2));
    assert_eq!(json_of(&o)["files"][1]["verdict"], "refused");
    // ClamAV switched off: "unavailable", the rest unchanged
    let o = cmd(bin, &h).env("HEIMDALL_CLAMAV", "off").args(["scan", "--json"]).arg(&font).output().unwrap();
    assert_eq!(json_of(&o)["files"][0]["clamav"], "unavailable");
    // the text form, and the usage error
    let o = cmd(bin, &h).env("PATH", &path).env("HEIMDALL_CLAMAV", "clamscan").arg("scan").arg(&virus).output().unwrap();
    let text = String::from_utf8_lossy(&o.stdout);
    assert!(text.contains(": refused") && text.contains("ClamAV: found Eicar-Test-Signature"), "{text}");
    assert_eq!(cmd(bin, &h).arg("scan").status().unwrap().code(), Some(2));
    // an archive's dry run goes through the sandboxed worker
    let bomb = h.join("bomb.zip");
    std::fs::write(&bomb, zip_of(&[("zeros.bin", &vec![0u8; 16 << 20])])).unwrap();
    let o = run(&[&bomb]);
    assert_eq!(o.status.code(), Some(1), "{}", String::from_utf8_lossy(&o.stderr));
    assert!(json_of(&o)["files"][0]["reasons"][0].as_str().unwrap().contains("decompression bomb"));
    let _ = std::fs::remove_dir_all(&h);
}

#[test]
fn extract_command_contract() {
    use std::os::unix::fs::PermissionsExt;
    let h = home("extract");
    let path = clam_stub(&h);
    let bin = env!("CARGO_BIN_EXE_heimdall-fileguard");
    let run = |args: &[&std::ffi::OsStr]| {
        cmd(bin, &h).env("PATH", &path).env("HEIMDALL_CLAMAV", "clamscan").arg("extract").args(args).output().unwrap()
    };
    // the fonts page: only fonts are kept, each checked
    let fonts = h.join("fonts.zip");
    std::fs::write(
        &fonts,
        zip_of(&[("Inter/Inter.ttf", b"\x00\x01\x00\x00font"), ("Inter/OFL.txt", b"licence"), ("Inter/Inter.woff2", b"wOF2data")]),
    )
    .unwrap();
    let out = h.join("out");
    let o = run(&["--json".as_ref(), "--only".as_ref(), "ttf,otf,ttc,woff2".as_ref(), fonts.as_os_str(), out.as_os_str()]);
    assert_eq!(o.status.code(), Some(0), "{}", String::from_utf8_lossy(&o.stderr));
    let v = json_of(&o);
    let mut keys: Vec<&String> = v.as_object().unwrap().keys().collect();
    keys.sort();
    assert_eq!(keys, ["files", "refused", "skipped"]);
    assert!(v["refused"].is_null());
    let f = &v["files"][0];
    let mut fk: Vec<&String> = f.as_object().unwrap().keys().collect();
    fk.sort();
    assert_eq!(fk, ["clamav", "name", "path", "reasons", "size", "verdict"]);
    assert_eq!(f["name"], "Inter/Inter.ttf");
    assert_eq!(f["path"], std::fs::canonicalize(&out).unwrap().join("Inter/Inter.ttf").display().to_string());
    assert_eq!((f["size"].as_u64(), f["verdict"].as_str(), f["clamav"].as_str()), (Some(8), Some("ok"), Some("clean")));
    assert_eq!(v["files"].as_array().unwrap().len(), 2);
    assert_eq!(v["skipped"][0]["name"], "Inter/OFL.txt");
    assert_eq!(std::fs::metadata(&out).unwrap().permissions().mode() & 0o777, 0o700);
    assert!(out.join("Inter/Inter.woff2").is_file() && !out.join("Inter/OFL.txt").exists());
    // OUTDIR must be new
    let o = run(&["--json".as_ref(), fonts.as_os_str(), out.as_os_str()]);
    assert_eq!(o.status.code(), Some(2));
    assert!(json_of(&o)["refused"].as_str().unwrap().contains("already exists"));
    // a bomb, a zip slip, a program dressed as a font, malware inside: refused, nothing left behind
    let cases: Vec<(&str, Vec<u8>, &str)> = vec![
        ("bomb.zip", zip_of(&[("zeros.bin", &vec![0u8; 16 << 20])]), "decompression bomb"),
        ("slip.zip", zip_of(&[("../../evil.txt", b"x")]), "zip slip"),
        ("font.zip", zip_of(&[("Nice.ttf", b"\x7FELF\x02\x01\x01")]), "Nice.ttf: it is named like a .ttf file but it is a Linux program"),
        ("virus.zip", zip_of(&[("readme.txt", &eicar())]), "readme.txt: ClamAV knows it as malware (Eicar-Test-Signature)"),
    ];
    for (name, bytes, want) in cases {
        let a = h.join(name);
        std::fs::write(&a, bytes).unwrap();
        let o2 = h.join(format!("out-{name}"));
        let o = run(&["--json".as_ref(), a.as_os_str(), o2.as_os_str()]);
        assert_eq!(o.status.code(), Some(1), "{name}: {}", String::from_utf8_lossy(&o.stdout));
        let v = json_of(&o);
        assert!(v["refused"].as_str().unwrap().contains(want), "{name}: {v}");
        assert!(!o2.exists(), "{name}: everything written was removed");
        assert!(!h.join("evil.txt").exists());
    }
    // a tar.gz, in text form
    let mut tar = vec![0u8; 512];
    tar[..5].copy_from_slice(b"a.txt");
    tar[100..107].copy_from_slice(b"0000644");
    tar[124..135].copy_from_slice(b"00000000002");
    tar[156] = b'0';
    tar[257..263].copy_from_slice(b"ustar\0");
    tar[148..156].copy_from_slice(b"        ");
    let sum: u32 = tar.iter().map(|&b| b as u32).sum();
    tar[148..155].copy_from_slice(format!("{sum:06o}\0").as_bytes());
    tar.extend_from_slice(b"hi");
    tar.resize(512 * 4, 0);
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    std::io::Write::write_all(&mut gz, &tar).unwrap();
    let tgz = h.join("a.tar.gz");
    std::fs::write(&tgz, gz.finish().unwrap()).unwrap();
    let o = run(&[tgz.as_os_str(), h.join("out-tgz").as_os_str()]);
    assert_eq!(o.status.code(), Some(0), "{}", String::from_utf8_lossy(&o.stdout));
    assert_eq!(std::fs::read(h.join("out-tgz/a.txt")).unwrap(), b"hi");
    assert!(String::from_utf8_lossy(&o.stdout).contains("extracted 1 file"));
    assert_eq!(cmd(bin, &h).args(["extract", "only-one-arg"]).status().unwrap().code(), Some(2));
    let _ = std::fs::remove_dir_all(&h);
}

/// Files that come from elsewhere into the person's own folders (a copy from a drive) are checked too; the folders switch
/// is followed.
#[test]
fn fileguard_watch_checks_the_persons_folders() {
    use std::os::unix::fs::PermissionsExt;
    let h = home("watch-folders");
    let stubs = h.join("stubs");
    std::fs::create_dir_all(&stubs).unwrap();
    let log = h.join("notices.log");
    let stub = stubs.join("notify-send");
    std::fs::write(&stub, format!("#!/bin/sh\nfor a in \"$@\"; do printf '%s\\n' \"$a\"; done >> '{}'\necho dismiss\n", log.display()))
        .unwrap();
    std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
    let docs = h.join("Documents");
    let dl = h.join("Downloads");
    std::fs::create_dir_all(&docs).unwrap();
    std::fs::create_dir_all(&dl).unwrap();
    let bin = env!("CARGO_BIN_EXE_heimdall-fileguard");
    let v: serde_json::Value = serde_json::from_slice(&cmd(bin, &h).args(["status", "--json"]).output().unwrap().stdout).unwrap();
    assert!(v["folders"].as_array().unwrap().iter().any(|f| f.as_str().unwrap().ends_with("/Documents")));
    // stopped however the test ends (a failed assertion included)
    struct Stop(std::process::Child);
    impl Drop for Stop {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let _child = Stop(
        cmd(bin, &h)
            .arg("watch")
            .env("PATH", format!("{}:/usr/bin:/bin", stubs.display()))
            .env("HEIMDALL_GAMETIME", h.join("no-such-tool"))
            .env("HEIMDALL_CLAMAV", "off")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap(),
    );
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
    // a "font" that is a program, copied into Documents: refused at once by the light checks
    std::fs::write(docs.join("Nice.ttf"), b"\x7FELF\x02\x01\x01rest").unwrap();
    assert!(wait_for("This file is not safe to use.", 10), "{}", std::fs::read_to_string(&log).unwrap_or_default());
    assert!(wait_for("Nice.ttf: it is named like a .ttf file but it is a Linux program", 1));
    // a ZIP bomb in Downloads: the heavy check (no game running) refuses it
    std::fs::write(dl.join("bomb.zip"), zip_of(&[("zeros.bin", &vec![0u8; 16 << 20])])).unwrap();
    assert!(
        wait_for("bomb.zip: a file inside unpacks to more than 100 times", 15),
        "{}",
        std::fs::read_to_string(&log).unwrap_or_default()
    );
    // the folders switch off: Documents is no longer watched (Downloads still is)
    std::fs::create_dir_all(h.join(".config/heimdall")).unwrap();
    std::fs::write(h.join(".config/heimdall/privacy.json"), br#"{"folders_guard": false}"#).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(1500));
    std::fs::write(docs.join("Second.ttf"), b"\x7FELF\x02\x01\x01rest").unwrap();
    assert!(!wait_for("Second.ttf", 4), "Documents is not watched now");
    let v: serde_json::Value = serde_json::from_slice(&cmd(bin, &h).args(["status", "--json"]).output().unwrap().stdout).unwrap();
    assert!(!v["folders"].as_array().unwrap().iter().any(|f| f.as_str().unwrap().ends_with("/Documents")));
    let _ = std::fs::remove_dir_all(&h);
}
