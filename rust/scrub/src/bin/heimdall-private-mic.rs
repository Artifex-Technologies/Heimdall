//! heimdall-private-mic: the private microphone's switch, for the owner and for Settings.
//!
//!     heimdall-private-mic status [--json]   {"enforce":true,"node":true}
//!     heimdall-private-mic on | off          every app records the private microphone, or the owner's own choice again
//!
//! "enforce" is WirePlumber's setting heimdall.private-mic.enforce (default on; saved, so it stays after a restart);
//! "node" is whether PipeWire has the "Microphone (private)" node (it appears once the package is installed and the
//! session restarted). Both run `wpctl` / `pw-cli` with their arguments one by one; nothing else is touched.

use std::process::{Command, ExitCode, Stdio};

const KEY: &str = "heimdall.private-mic.enforce";
const NODE: &str = "heimdall.private-mic";

fn run(prog: &str, args: &[&str]) -> Option<(bool, String)> {
    let out = Command::new(prog).args(args).stdin(Stdio::null()).stderr(Stdio::null()).output().ok()?;
    Some((out.status.success(), String::from_utf8_lossy(&out.stdout).into_owned()))
}

/// `wpctl settings KEY` prints `Value: true` (and maybe the saved value); a missing key (WirePlumber without our
/// script) counts as the default, on.
fn enforce_from(text: &str) -> bool {
    for line in text.lines() {
        // "Value: false (Saved: false)"
        if let Some(v) = line.trim().strip_prefix("Value:") {
            return v.split_whitespace().next() != Some("false");
        }
    }
    true
}

/// `pw-cli ls Node` lists every node with its properties; ours is the one named heimdall.private-mic exactly.
fn node_from(text: &str) -> bool {
    text.lines().any(|l| l.trim().strip_prefix("node.name = ").is_some_and(|v| v.trim_matches('"') == NODE))
}

fn status() -> (bool, bool) {
    let enforce = run("wpctl", &["settings", KEY]).map(|(_, o)| enforce_from(&o)).unwrap_or(true);
    let node = run("pw-cli", &["ls", "Node"]).is_some_and(|(ok, o)| ok && node_from(&o));
    (enforce, node)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let a: Vec<&str> = args.iter().map(String::as_str).collect();
    match a.as_slice() {
        ["status", "--json"] => {
            let (e, n) = status();
            println!("{{\"enforce\":{e},\"node\":{n}}}");
            ExitCode::SUCCESS
        }
        ["status"] | [] => {
            let (e, n) = status();
            println!(
                "private microphone: {}{}",
                if e { "on (every app records the scrubbed microphone)" } else { "off (apps record the microphone as it is)" },
                if n { "" } else { "; its node is not there yet (install heimdall, then log out and in)" }
            );
            ExitCode::SUCCESS
        }
        [v @ ("on" | "off")] => {
            let val = if *v == "on" { "true" } else { "false" };
            // the value now (WirePlumber's script acts on it at once), then saved so it stays after a restart
            let set = run("wpctl", &["settings", KEY, val]);
            let saved = match set {
                Some((true, _)) => run("wpctl", &["settings", "--save", KEY]),
                other => other,
            };
            match saved {
                Some((true, _)) => ExitCode::SUCCESS,
                Some((false, _)) => {
                    eprintln!(
                        "heimdall-private-mic: WirePlumber did not take the setting (is heimdall installed and the session restarted?)"
                    );
                    ExitCode::from(1)
                }
                None => {
                    eprintln!("heimdall-private-mic: wpctl could not be started");
                    ExitCode::from(1)
                }
            }
        }
        ["--help" | "-h"] => {
            println!("usage: heimdall-private-mic status [--json] | on | off");
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!("usage: heimdall-private-mic status [--json] | on | off");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_wpctl_and_pw_cli_output() {
        assert!(enforce_from("Value: true\n"));
        assert!(!enforce_from("Value: false (Saved: false)\n"));
        assert!(enforce_from("Value: true (Saved: true)\n"));
        assert!(enforce_from(""));
        let ls = "\tid 30, type PipeWire:Interface:Node/3\n \t\tnode.name = \"heimdall.private-mic\"\n";
        assert!(node_from(ls));
        assert!(!node_from(" \t\tnode.name = \"heimdall.private-mic.capture\"\n"));
    }
}
