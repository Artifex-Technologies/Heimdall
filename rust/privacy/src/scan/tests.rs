//! The verdicts of `scan`, with a stand-in for ClamAV (a script that answers from the file's content; the only "virus" is
//! the EICAR test string, put together here at run time).

use super::*;
use crate::extract::tests::{build, Raw};

fn dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("heimdall-scan-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

pub fn eicar() -> Vec<u8> {
    [&b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$"[..], b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"].concat()
}

/// A clamscan stand-in: EICAR is Eicar-Test-Signature, "BIGBIG" stops at a limit, "PUAPUA" is a possibly unwanted program,
/// anything else is OK. It writes its arguments to `log`.
pub fn fake_clamscan(d: &Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let p = d.join("clamscan");
    let script = format!(
        r#"#!/bin/sh
echo "$@" >> '{log}'
seen=
for a in "$@"; do
  [ -n "$seen" ] || {{ [ "$a" = -- ] && seen=1; continue; }}
  if grep -q 'EICAR-STANDARD-ANTIVIRUS-TEST-FILE' "$a"; then echo "$a: Eicar-Test-Signature FOUND"
  elif grep -q BIGBIG "$a"; then echo "$a: Heuristics.Limits.Exceeded.MaxScanSize FOUND"
  elif grep -q PUAPUA "$a"; then echo "$a: PUA.Win.Tool.Example FOUND"
  else echo "$a: OK"; fi
done
exit 0
"#,
        log = d.join("clamscan.log").display()
    );
    std::fs::write(&p, script).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    p
}

fn local() -> Settings {
    Settings { worker: None, archives: true }
}

#[test]
fn what_a_file_really_is() {
    let d = dir("kinds");
    let w = |n: &str, b: &[u8]| {
        let p = d.join(n);
        std::fs::write(&p, b).unwrap();
        p
    };
    let font = w("Inter.ttf", b"\x00\x01\x00\x00\x00\x10rest of a font");
    let elf_font = w("Evil.ttf", b"\x7FELF\x02\x01\x01rest");
    let not_font = w("Fake.otf", b"<html>not a font</html>");
    let pe_png = w("photo.png", b"MZ\x90\x00rest");
    let script_txt = w("notes.txt", b"#!/bin/sh\necho hi\n");
    let script_mp3 = w("song.mp3", b"#!/bin/sh\nrm -rf ~\n");
    let lookalike = w("Viv\u{0430}ldi.txt", b"hello"); // a Cyrillic a
    let items: Vec<Checked> =
        [&font, &elf_font, &not_font, &pe_png, &script_txt, &script_mp3, &lookalike].iter().map(|p| own(p, &local())).collect();
    let v: Vec<Verdict> = items.iter().map(|c| c.verdict).collect();
    assert_eq!(
        v,
        [Verdict::Ok, Verdict::Refused, Verdict::Refused, Verdict::Refused, Verdict::Ok, Verdict::Refused, Verdict::Warn],
        "{items:#?}"
    );
    assert!(items[1].reasons[0].contains("named like a .ttf file but it is a Linux program"), "{:?}", items[1].reasons);
    assert_eq!(items[1].reasons.len(), 1, "a program named like a font is not also 'not a font'");
    assert!(items[2].reasons[0].contains("not one"));
    assert!(items[6].reasons[0].starts_with("its name may not be what it seems"));
    assert_eq!(code(&items), 1);
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn archives_are_judged_by_their_dry_run() {
    let d = dir("archives");
    let bomb = d.join("bomb.zip");
    std::fs::write(&bomb, build(&[Raw::file("zeros.bin", &vec![0u8; 16 << 20])])).unwrap();
    let slip = d.join("slip.zip");
    std::fs::write(&slip, build(&[Raw::stored("../x.txt", b"x")])).unwrap();
    // more files than the limit at an ordinary ratio: too big to check in full, a warning
    let many: Vec<Raw> = (0..10_001).map(|i| Raw::stored(&format!("f{i}"), b"")).collect();
    let big = d.join("many.zip");
    std::fs::write(&big, build(&many)).unwrap();
    let enc = d.join("enc.zip");
    std::fs::write(&enc, build(&[Raw { flags: 1, ..Raw::stored("secret.txt", b"xxxx") }, Raw::stored("ok.txt", b"ok")])).unwrap();
    let fine = d.join("fonts.zip");
    std::fs::write(&fine, build(&[Raw::file("a.ttf", b"\x00\x01\x00\x00font")])).unwrap();
    let c = |p: &Path| own(p, &local());
    let b = c(&bomb);
    assert_eq!(b.verdict, Verdict::Refused, "{b:?}");
    assert!(b.reasons[0].contains("decompression bomb"));
    assert!(b.unpacked < 4 << 20, "the dry run stopped early");
    assert_eq!(c(&slip).verdict, Verdict::Refused);
    let m = c(&big);
    assert_eq!(m.verdict, Verdict::Warn, "{m:?}");
    assert!(m.reasons[0].starts_with("it is too big to check in full"));
    let e = c(&enc);
    assert_eq!(e.verdict, Verdict::Warn);
    assert_eq!(e.reasons, ["1 encrypted file inside could not be checked"]);
    assert_eq!(c(&fine).verdict, Verdict::Ok);
    // the light half the watcher runs first does not look inside
    assert_eq!(own(&bomb, &Settings { worker: None, archives: false }).verdict, Verdict::Ok);
    assert_eq!(archive_only(&bomb, &local()).verdict, Verdict::Refused);
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn unreadable_files_are_errors() {
    let d = dir("missing");
    let items = scan(&[d.join("missing.ttf")], &local(), &clamav::Scanner::none());
    assert!(items[0].error && items[0].verdict == Verdict::Refused);
    assert_eq!(code(&items), 2);
    let items = scan(std::slice::from_ref(&d), &local(), &clamav::Scanner::none());
    assert!(!items[0].error && items[0].reasons[0].contains("not a regular file"));
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn clamav_answers_become_verdicts() {
    let d = dir("clam");
    let prog = fake_clamscan(&d);
    let w = |n: &str, b: &[u8]| {
        let p = d.join(n);
        std::fs::write(&p, b).unwrap();
        p
    };
    let files = vec![
        w("clean.txt", b"hello"),
        w("eicar.com.txt", &eicar()),
        w("big.zip.txt", b"BIGBIG"),
        w("tool.txt", b"PUAPUA"),
        // a name ClamAV's answer cannot confuse: ": " and a line break in it
        w("odd: name\nEicar-Test-Signature FOUND.txt", b"hello"),
    ];
    let sc = clamav::Scanner { prog: Some(prog), daemon: false, limits: clamav::OURS };
    let items = scan(&files, &local(), &sc);
    let got: Vec<(Verdict, String)> = items.iter().map(|c| (c.verdict, c.clamav.id())).collect();
    assert_eq!(
        got,
        [
            (Verdict::Ok, "clean".to_string()),
            (Verdict::Refused, "infected:Eicar-Test-Signature".into()),
            (Verdict::Warn, "not-fully-scanned".into()),
            (Verdict::Warn, "infected:PUA.Win.Tool.Example".into()),
            (Verdict::Warn, "clean".into()), // warned for its name (a line break), clean for ClamAV
        ]
    );
    assert!(items[2].reasons[0].starts_with("not fully scanned by ClamAV"));
    let log = std::fs::read_to_string(d.join("clamscan.log")).unwrap();
    assert!(log.contains("--alert-exceeds-max=yes") && log.contains("--max-scansize=512M") && log.contains("/proc/self/fd/"), "{log}");
    // a file bigger than ClamAV looks at, where ClamAV itself does not say so (clamd without AlertExceedsMax)
    let quiet = clamav::Scanner { limits: clamav::Limits { max_file: 3, max_scan: 1 << 20, alerts: false }, ..sc.clone() };
    let items = scan(&files[..1], &local(), &quiet);
    assert_eq!(items[0].clamav.id(), "not-fully-scanned");
    assert_eq!(items[0].verdict, Verdict::Warn);
    // no ClamAV: said, and nothing else changes
    let items = scan(&files[..1], &local(), &clamav::Scanner::none());
    assert_eq!((items[0].verdict, items[0].clamav.id()), (Verdict::Ok, "unavailable".into()));
    let _ = std::fs::remove_dir_all(&d);
}
