//! heimdall-fileguard: the downloads guard (docs/PRIVACY_PACK.md).
//!
//!   heimdall-fileguard check [--json] FILE...   does each file contact a server when opened? exit 0 no, 1 yes, 2 error
//!   heimdall-fileguard watch                    the user service: watch the download folders, a notice per such file
//!   heimdall-fileguard folders                  the folders `watch` watches
//!   heimdall-fileguard status --json            {"enabled":bool,"running":bool,"folders":[...]}
//!
//! It only reads files; it never changes, moves or deletes one.

use heimdall_privacy::{guard, lookalike, prefs, watch};
use serde_json::json;
use std::path::Path;

const HELP: &str = "heimdall-fileguard: does a downloaded file contact a server when it is opened?

  heimdall-fileguard check [--json] FILE...   check files (exit 0: nothing found, 1: found, 2: a file could not be read)
  heimdall-fileguard watch                    watch the download folders (the user service heimdall-fileguard.service)
  heimdall-fileguard folders                  list the folders it watches
  heimdall-fileguard status --json            whether it is switched on and running, and its folders

It never changes a file. Switch it off in Settings > Security > Privacy > Check downloads.";

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

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let rc = match args.first().map(String::as_str) {
        Some("check") => check(&args[1..]),
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
