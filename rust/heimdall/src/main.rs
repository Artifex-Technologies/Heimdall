//! heimdalld-rs: Heimdall's always-on daemon in Rust. Until the switch it runs beside the Go heimdalld in shadow mode.

use heimdall::{config::Config, replay, rules};
use std::process::ExitCode;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn usage() {
    eprint!(
        "heimdalld-rs -- Heimdall's daemon in Rust (shadow mode until the switch)

Usage:
  heimdalld-rs run --shadow --config PATH
                                    The daemon beside the Go one: real sources, its own alert log, no responses
                                    (docs/RUST_SHADOW.md). Refuses any state or log path in /var/lib/heimdall/.
  heimdalld-rs replay --config PATH [--approvals PATH] < events.jsonl > alerts.jsonl
                                    Run event lines through the detectors (the parity and differential tests use it).
  heimdalld-rs rules check [FILE]   Check a text rule file (default: the built-in rules); every problem is printed.
  heimdalld-rs version
"
    );
}

fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned()
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    // the built-in rules are checked before anything else: the daemon does not run with a refused rule
    if let Err(problems) = rules::check_builtin() {
        eprintln!("heimdalld-rs: the built-in text rules are refused:");
        for p in problems {
            eprintln!("  {p}");
        }
        return ExitCode::from(2);
    }
    match args.get(1).map(String::as_str) {
        Some("run") => {
            let cfg = match Config::load(&flag(&args, "--config").unwrap_or_default()) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("heimdalld-rs: {e}");
                    return ExitCode::from(2);
                }
            };
            ExitCode::from(heimdall::daemon::run(cfg, args.iter().any(|a| a == "--shadow")) as u8)
        }
        Some("replay") => {
            let cfg = match Config::load(&flag(&args, "--config").unwrap_or_default()) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("heimdalld-rs: {e}");
                    return ExitCode::from(2);
                }
            };
            let approvals = flag(&args, "--approvals").unwrap_or_else(|| "/etc/heimdall/remote-access-approved.json".into());
            let stdin = std::io::stdin().lock();
            match replay::run(&cfg, &approvals, stdin, std::io::stdout()) {
                Ok(_) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("heimdalld-rs: {e}");
                    ExitCode::from(2)
                }
            }
        }
        Some("rules") if args.get(2).map(String::as_str) == Some("check") => {
            let (name, b) = match args.get(3) {
                Some(p) => match std::fs::read(p) {
                    Ok(b) => (p.clone(), b),
                    Err(e) => {
                        eprintln!("heimdalld-rs: {p}: {e}");
                        return ExitCode::from(2);
                    }
                },
                None => ("the built-in rules".to_string(), rules::BUILTIN.as_bytes().to_vec()),
            };
            match rules::load(&b) {
                Ok(set) => {
                    println!("{name}: {} rules, all checked", set.rules.len());
                    ExitCode::SUCCESS
                }
                Err(problems) => {
                    eprintln!("{name}: refused:");
                    for p in problems {
                        eprintln!("  {p}");
                    }
                    ExitCode::from(1)
                }
            }
        }
        Some("version") => {
            println!("heimdalld-rs {VERSION}");
            ExitCode::SUCCESS
        }
        Some("-h" | "--help" | "help") => {
            usage();
            ExitCode::SUCCESS
        }
        _ => {
            usage();
            ExitCode::from(2)
        }
    }
}
