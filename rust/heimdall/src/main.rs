//! heimdalld-rs: Heimdall's always-on daemon in Rust, and the one-shot commands ported from the Go heimdalld (src/cli). Until
//! the switch it runs beside the Go heimdalld in shadow mode.

use heimdall::{config::Config, replay, rules};
use std::process::ExitCode;

fn usage() {
    eprint!("{}{}", heimdall::cli::USAGE, heimdall::cli::RUST_USAGE);
}

/// The Go heimdalld kept for the commands not ported yet, after the switch (HEIMDALL_GO for tests).
fn go_binary() -> String {
    std::env::var("HEIMDALL_GO").unwrap_or_else(|_| "/usr/lib/heimdall/heimdalld-go".into())
}

fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned()
}

fn main() -> ExitCode {
    // an argument that is not UTF-8 is read with U+FFFD where it breaks (std::env::args would stop the program; the Wi-Fi
    // helpers' Python reads any bytes)
    let args: Vec<String> = std::env::args_os().map(|a| a.to_string_lossy().into_owned()).collect();
    // started by a helper's name (a link to this program, after the switch): that helper
    let name = args.first().map(|a| a.rsplit('/').next().unwrap_or(a).to_string()).unwrap_or_default();
    if name.starts_with("heimdall-") {
        return match heimdall::cli::tool(&name, &args[1..]) {
            Some(code) => ExitCode::from(code as u8),
            None => {
                eprintln!("heimdalld: {name} is not part of this program");
                ExitCode::from(2)
            }
        };
    }
    // the built-in rules are checked before anything that runs the detectors: the daemon does not run with a refused rule
    let detecting = matches!(args.get(1).map(String::as_str), Some("run" | "replay" | "scan"));
    if detecting {
        if let Err(problems) = rules::check_builtin() {
            eprintln!("heimdalld-rs: the built-in text rules are refused:");
            for p in problems {
                eprintln!("  {p}");
            }
            return ExitCode::from(2);
        }
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
        Some("-h" | "--help" | "help") => {
            usage();
            ExitCode::SUCCESS
        }
        Some(cmd) => {
            // the one-shot commands ported to Rust (src/cli), with the Go heimdalld's arguments, output and exit codes
            if let Some(code) = heimdall::cli::dispatch(cmd, &args[2..]) {
                return ExitCode::from(code as u8);
            }
            // a command not ported yet goes to the Go heimdalld kept beside (after the switch), with the same arguments
            if std::path::Path::new(&go_binary()).exists() {
                use std::os::unix::process::CommandExt;
                let e = std::process::Command::new(go_binary()).args(&args[1..]).exec();
                eprintln!("heimdalld: {}: {e}", go_binary());
                return ExitCode::from(2);
            }
            eprint!("heimdalld: unknown command {}\n\n", heimdall::gotext::quote(cmd));
            usage();
            ExitCode::from(2)
        }
        None => {
            usage();
            ExitCode::from(2)
        }
    }
}
