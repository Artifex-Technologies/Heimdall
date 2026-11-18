//! heimdall-fileguard: the downloads guard (docs/PRIVACY_PACK.md).
//!
//!   heimdall-fileguard check [--json] FILE...   does each file contact a server when opened? exit 0 no, 1 yes, 2 error
//!   heimdall-fileguard watch                    the user service: watch the download folders, a notice per such file
//!   heimdall-fileguard folders                  the folders `watch` watches
//!   heimdall-fileguard status --json            {"enabled":bool,"running":bool,"folders":[...]}
//!   heimdall-fileguard scan [--json] FILE...    check a file before using it: the guard's checks, archives, ClamAV
//!   heimdall-fileguard extract [--json] [--only EXT,EXT] ARCHIVE OUTDIR   unpack safely into a new folder
//!
//! It never changes, moves or deletes a file it checks; `extract` writes only into the new folder it makes (and removes that
//! folder again when it refuses the archive).

use heimdall_privacy::{clamav, guard, intake, lookalike, prefs, scan, watch};
use serde_json::json;
use std::path::Path;

const HELP: &str = "heimdall-fileguard: does a downloaded file contact a server when it is opened?

  heimdall-fileguard check [--json] FILE...   check files (exit 0: nothing found, 1: found, 2: a file could not be read)
  heimdall-fileguard watch                    watch the download folders (the user service heimdall-fileguard.service)
  heimdall-fileguard folders                  list the folders it watches
  heimdall-fileguard status --json            whether it is switched on and running, and its folders
  heimdall-fileguard scan [--json] FILE...    check files before using them (names, what they really are, the guard's
                                              checks, archives, ClamAV); exit 0: nothing refused, 1: refused, 2: unreadable
  heimdall-fileguard scan-drive FOLDER        scan a drive's files and show the result in a notice
  heimdall-fileguard extract [--json] [--only EXT,EXT] ARCHIVE OUTDIR
                                              unpack ZIP, tar, tar.gz/.xz/.zst/.bz2 safely into OUTDIR (made new), each
                                              file then checked like scan; exit 0: done, 1: refused, 2: usage or reading

It never changes a file it checks. Switch the guard off in Settings > Security > Privacy > Check downloads.";

fn finding_json(f: &guard::Finding) -> serde_json::Value {
    json!({"sure": f.sure, "what": f.what, "target": f.target, "inside": f.inside})
}

fn check(args: &[String]) -> i32 {
    let as_json = args.iter().any(|a| a == "--json");
    let files: Vec<&String> = args.iter().filter(|a| *a != "--json").collect();
    if files.is_empty() {
        eprintln!("{HELP}");
        return 2;
    }
    let mut rc = 0;
    for f in files {
        let p = Path::new(f);
        match guard::inspect_path(p, &guard::Limits::default()) {
            Ok(r) => {
                if r.found() && rc == 0 {
                    rc = 1;
                }
                let name = lookalike::visible(f);
                if as_json {
                    let lr = lookalike::check(&p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default());
                    let v = json!({
                        "path": f, "kind": r.kind.id(), "found": r.found(), "complete": r.complete, "notes": r.notes,
                        "findings": r.findings.iter().map(finding_json).collect::<Vec<_>>(),
                        "name_warning": if lr.suspicious() { Some(lr.words()) } else { None },
                    });
                    println!("{v}");
                } else if r.found() {
                    println!("{name}: {} ({})", r.title(), r.kind.words());
                    for x in &r.findings {
                        let t = x.target.as_deref().map(|t| format!(": {}", lookalike::visible(t))).unwrap_or_default();
                        let i = x.inside.as_deref().map(|i| format!(" [inside {}]", lookalike::visible(i))).unwrap_or_default();
                        println!("  - {}{t}{i}", x.what);
                    }
                    if !r.complete {
                        println!("  (not checked in full: {})", r.notes.join("; "));
                    }
                } else {
                    let more = if r.complete { String::new() } else { format!(" (not checked in full: {})", r.notes.join("; ")) };
                    println!("{name}: nothing found{more}");
                }
            }
            Err(e) => {
                eprintln!("heimdall-fileguard: {}: {e}", lookalike::visible(f));
                rc = 2;
            }
        }
    }
    rc
}

fn me() -> std::path::PathBuf {
    std::env::current_exe().unwrap_or_else(|_| "/usr/bin/heimdall-fileguard".into())
}

fn scan_cmd(args: &[String]) -> i32 {
    let as_json = args.iter().any(|a| a == "--json");
    let files: Vec<std::path::PathBuf> = args.iter().filter(|a| *a != "--json").map(std::path::PathBuf::from).collect();
    if files.is_empty() {
        eprintln!("{HELP}");
        return 2;
    }
    let items = scan::scan(&files, &scan::Settings { worker: Some(me()), archives: true }, &clamav::find(true));
    if as_json {
        println!("{}", json!({"files": items.iter().map(scan::Checked::json).collect::<Vec<_>>()}));
    } else {
        for c in &items {
            println!("{}", scan::text(c));
        }
    }
    scan::code(&items)
}

fn extract_cmd(args: &[String]) -> i32 {
    let mut as_json = false;
    let mut only = vec![];
    let mut rest = vec![];
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--json" => as_json = true,
            "--only" if i + 1 < args.len() => {
                only = intake::split_only(&args[i + 1]);
                i += 1;
            }
            "--" => {
                rest.extend(args[i + 1..].iter().cloned());
                break;
            }
            a if a.starts_with("--only=") => only = intake::split_only(&a[7..]),
            _ => rest.push(args[i].clone()),
        }
        i += 1;
    }
    if rest.len() != 2 {
        eprintln!("{HELP}");
        return 2;
    }
    let r = intake::extract_command(&me(), Path::new(&rest[0]), Path::new(&rest[1]), &only, &clamav::find(true));
    if as_json {
        println!("{}", r.json());
    } else {
        for (w, p, c) in &r.files {
            let mut line = format!("{} -> {}: {}", w.name, lookalike::visible(&p.display().to_string()), c.verdict.id());
            for x in &c.reasons {
                line.push_str(&format!("\n  - {x}"));
            }
            println!("{line}");
        }
        for s in &r.skipped {
            println!("skipped {}: {}", s.name, s.reason);
        }
        match &r.refused {
            Some(why) => println!("refused: {why} (nothing was kept)"),
            None => println!("extracted {} file{}", r.files.len(), if r.files.len() == 1 { "" } else { "s" }),
        }
    }
    r.code()
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let rc = match args.first().map(String::as_str) {
        Some("check") => check(&args[1..]),
        Some("scan") => scan_cmd(&args[1..]),
        Some("scan-drive") if args.len() == 2 => watch::scan_drive(Path::new(&args[1])),
        Some("extract") => extract_cmd(&args[1..]),
        Some("extract-worker") => intake::worker_main(&args[1..]),
        Some("watch") => watch::run(),
        Some("folders") => {
            for f in watch::folders() {
                println!("{}", f.display());
            }
            0
        }
        Some("status") if args.get(1).map(String::as_str) == Some("--json") => {
            let p = prefs::Prefs::load();
            let folders: Vec<String> = watch::folders().iter().map(|f| f.display().to_string()).collect();
            println!("{}", json!({"enabled": p.downloads_guard, "running": watch::running(), "folders": folders}));
            0
        }
        Some("-h" | "--help" | "help") => {
            println!("{HELP}");
            0
        }
        _ => {
            eprintln!("{HELP}");
            2
        }
    };
    std::process::exit(rc);
}
