//! `heimdalld contain status|now|emergency|evidence|release|run-request` (Go: cmd/heimdalld/contain.go, internal/contain):
//! stop a compromised AI agent (docs/CONTAIN.md).
//!
//! Ported: `status`, `evidence`, the usage. Not yet (they hand over to the Go binary): `now`, `emergency`, `run-request` and
//! `release`, which hold suspicious files in immunity's store and put released ones back (immunity's port).

use crate::contain;

const USAGE: &str = "heimdalld contain: stop a compromised AI agent (see docs/CONTAIN.md)
  heimdalld contain status                    is Sarina contained, and what may Heimdall do by itself
  heimdalld contain now [--reason R] [--escalate]
                                              unload the models, stop Sarina and lock her out (root); --escalate: the
                                              emergency step follows when that did not hold after a minute
  heimdalld contain emergency --yes           the last resort (root): restore the approved files, kill everything on the
                                              graphics card (games and the desktop too), reset the card, restart
  heimdalld contain evidence                  the saved evidence folders (root): what ran, connections, logs, sessions,
                                              copies of the unapproved files; saved before anything is stopped
  heimdalld contain release                   restore the approved files and lift the lock (root)
";

/// The lock's path: Go's, or HEIMDALL_CONTAIN_MARKER (Go's tests use it; it also skips the root check there).
fn marker() -> String {
    match std::env::var("HEIMDALL_CONTAIN_MARKER") {
        Ok(p) if !p.is_empty() => p,
        _ => contain::MARKER_PATH.into(),
    }
}

fn on_off(b: bool) -> String {
    if b {
        "on".into()
    } else {
        format!("off ({})", contain::CONFIG_PATH)
    }
}

pub fn main(args: &[String]) -> Option<i32> {
    let Some(sub) = args.first() else {
        eprint!("{USAGE}");
        return Some(2);
    };
    match sub.as_str() {
        "evidence" => {
            // the saved collections, newest first (root: they are root-only)
            use std::io::Write;
            use std::os::unix::ffi::OsStrExt;
            // names as bytes: Go prints a name that is not UTF-8 as it is
            let mut names: Vec<Vec<u8>> = match std::fs::read_dir(contain::EVIDENCE_DIR)
                .and_then(|rd| rd.map(|e| e.map(|e| e.file_name().as_bytes().to_vec())).collect::<Result<Vec<_>, _>>())
            {
                Ok(n) => n,
                Err(_) => {
                    println!("no evidence saved (or not readable without sudo)");
                    return Some(0);
                }
            };
            names.sort();
            let mut out = Vec::new();
            for n in names.iter().rev() {
                out.extend_from_slice(contain::EVIDENCE_DIR.as_bytes());
                out.push(b'/');
                out.extend_from_slice(n);
                out.push(b'\n');
            }
            let _ = std::io::stdout().write_all(&out);
            Some(0)
        }
        "status" => {
            let m = contain::read_marker(&marker());
            let (auto, emergency) = contain::load_config(contain::CONFIG_PATH);
            let mut out = match &m {
                None => "Sarina: not contained\n".to_string(),
                Some(m) => format!("Sarina: {} since {}\nreason: {}\n", m.level, m.since.local().format("2006-01-02 15:04"), m.reason),
            };
            out += &format!("automatic containment: {}\nautomatic emergency: {}\n", on_off(auto), on_off(emergency));
            print!("{out}");
            Some(if m.is_some() { 1 } else { 0 })
        }
        "now" | "emergency" | "run-request" | "release" => None,
        _ => {
            eprint!("{USAGE}");
            Some(2)
        }
    }
}
