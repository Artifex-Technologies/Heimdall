//! heimdall-strip: Remove hidden info (docs/PRIVACY_PACK.md). A copy of a file without its hidden information, beside it as
//! "name (clean).ext"; the original is never changed and no file is ever replaced.
//!
//!   heimdall-strip [--json] IN [OUT]   write the copy; prints what was removed, then "wrote OUT" (or one JSON line)
//!   heimdall-strip --check [--json] IN what would be removed; writes nothing
//!   heimdall-strip --can IN            exit 0 and print the kind when it can clean IN, 1 when not
//!
//! Exit codes: 0 done (also when nothing hidden was found: then no copy is made), 1 failed, 2 usage.

use heimdall_privacy::strip;
use serde_json::json;
use std::path::Path;

const HELP: &str = "heimdall-strip: save a copy of a file without its hidden information (place, device, author, dates...)

  heimdall-strip [--json] IN [OUT]     write the copy (default OUT: \"IN (clean).ext\" beside it; never over a file)
  heimdall-strip --check [--json] IN   only say what would be removed
  heimdall-strip --can IN              exit 0 (and print the kind) when IN can be cleaned, 1 when not

Pictures (JPEG, PNG, WebP, HEIC/AVIF, TIFF), PDF, Office and OpenDocument files, ZIP archives, MP3, FLAC and WAV are cleaned
by its own code; videos and other sound files (MP4, MOV, M4A, MKV, WebM, Ogg, Opus, AVI) with ffmpeg, streams copied as they are.";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let as_json = args.iter().any(|a| a == "--json");
    let check = args.iter().any(|a| a == "--check");
    let can = args.iter().any(|a| a == "--can");
    if args.iter().any(|a| a == "-h" || a == "--help") {
        println!("{HELP}");
        std::process::exit(0);
    }
    let paths: Vec<&String> = args.iter().filter(|a| !matches!(a.as_str(), "--json" | "--check" | "--can")).collect();
    if paths.is_empty() || paths.len() > 2 || paths.iter().any(|p| p.starts_with("--")) || ((can || check) && paths.len() != 1) {
        eprintln!("{HELP}");
        std::process::exit(2);
    }
    let input = Path::new(paths[0]);
    if can {
        match strip::kind_of_path(input) {
            Ok(Some(k)) => {
                println!("{}", k.id());
                std::process::exit(0)
            }
            _ => std::process::exit(1),
        }
    }
    let out = paths.get(1).map(|p| Path::new(p.as_str()));
    match strip::run(input, out, check) {
        Ok(o) => {
            if as_json {
                println!("{}", json!({"wrote": o.wrote.as_ref().map(|p| p.display().to_string()), "removed": o.removed, "kind": o.kind}));
            } else {
                for r in &o.removed {
                    println!("removed: {r}");
                }
                match &o.wrote {
                    Some(p) => println!("wrote {}", p.display()),
                    None if check => {
                        println!("{}", if o.removed.is_empty() { "nothing hidden found" } else { "(nothing written: --check)" })
                    }
                    None => println!("nothing hidden found; no copy made"),
                }
            }
        }
        Err(e) => {
            eprintln!("heimdall-strip: {e}");
            std::process::exit(1);
        }
    }
}
