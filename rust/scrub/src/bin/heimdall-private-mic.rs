//! heimdall-private-mic: the private microphone's switches, for the owner and for Settings.
//!
//!     heimdall-private-mic status [--json]   {"enforce":true,"node":true,"lykanos":false,"sarina_raw":false}
//!     heimdall-private-mic on | off          every app records the private microphone, or the owner's own choice again
//!     heimdall-private-mic sarina-raw on|off LykanOS only: Sarina's voice input records the real microphone (off by default)
//!     heimdall-private-mic os-setup [--remove] [--root DIR]
//!                                            (root, run by the package's pacman hook) the LykanOS-only part on or off
//!
//! "enforce" is WirePlumber's setting heimdall.private-mic.enforce (default on, saved, so it stays after a restart); "node"
//! is whether PipeWire has the "Microphone (private)" node; "lykanos" is /etc/os-release saying ID=lykanos; "sarina_raw" is
//! the LykanOS-only setting heimdall.private-mic.sarina-raw. That setting exists only where os-setup linked its WirePlumber
//! fragment (LykanOS), and WirePlumber's script honours it only with that fragment's marker, so on Labyrinth OS it is not
//! there to switch. wpctl and pw-cli are run with their arguments one by one; nothing else is touched.

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};

const KEY: &str = "heimdall.private-mic.enforce";
const SARINA_KEY: &str = "heimdall.private-mic.sarina-raw";
const NODE: &str = "heimdall.private-mic";
/// The LykanOS-only WirePlumber fragment (in the package) and where os-setup links it.
const LYKANOS_FRAGMENT: &str = "usr/share/heimdall-private-mic/lykanos.conf";
const LYKANOS_LINK: &str = "etc/wireplumber/wireplumber.conf.d/61-heimdall-private-mic-lykanos.conf";

fn run(prog: &str, args: &[&str]) -> Option<(bool, String)> {
    let out = Command::new(prog).args(args).stdin(Stdio::null()).stderr(Stdio::null()).output().ok()?;
    Some((out.status.success(), String::from_utf8_lossy(&out.stdout).into_owned()))
}

/// `wpctl settings KEY` prints `Value: true (Saved: true)`; `None` when the key is unknown or wpctl failed.
fn setting_from(text: &str) -> Option<bool> {
    for line in text.lines() {
        if let Some(v) = line.trim().strip_prefix("Value:") {
            return match v.split_whitespace().next() {
                Some("false") => Some(false),
                Some("true") => Some(true),
                _ => None,
            };
        }
    }
    None
}

fn setting(key: &str) -> Option<bool> {
    run("wpctl", &["settings", key]).and_then(|(ok, o)| if ok { setting_from(&o) } else { None })
}

/// `pw-cli ls Node` lists every node with its properties; ours is the one named heimdall.private-mic exactly.
fn node_from(text: &str) -> bool {
    text.lines().any(|l| l.trim().strip_prefix("node.name = ").is_some_and(|v| v.trim_matches('"') == NODE))
}

/// The ID= line of an os-release file is lykanos (quoted or not).
fn is_lykanos(os_release: &str) -> bool {
    os_release.lines().any(|l| l.trim().strip_prefix("ID=").is_some_and(|v| v.trim().trim_matches('"').trim_matches('\'') == "lykanos"))
}

fn lykanos(root: &Path) -> bool {
    ["etc/os-release", "usr/lib/os-release"].iter().find_map(|p| std::fs::read_to_string(root.join(p)).ok()).is_some_and(|t| is_lykanos(&t))
}

struct Status {
    enforce: bool,
    node: bool,
    lykanos: bool,
    sarina_raw: bool,
}

fn status() -> Status {
    let lyk = lykanos(Path::new("/"));
    Status {
        // a missing key (WirePlumber without the script yet) counts as the default, on
        enforce: setting(KEY).unwrap_or(true),
        node: run("pw-cli", &["ls", "Node"]).is_some_and(|(ok, o)| ok && node_from(&o)),
        lykanos: lyk,
        sarina_raw: lyk && setting(SARINA_KEY).unwrap_or(false),
    }
}

/// Set a WirePlumber setting now (the script acts on it at once), then save it so it stays after a restart.
fn set(key: &str, on: bool) -> ExitCode {
    let val = if on { "true" } else { "false" };
    let r = match run("wpctl", &["settings", key, val]) {
        Some((true, _)) => run("wpctl", &["settings", "--save", key]),
        other => other,
    };
    match r {
        Some((true, _)) => ExitCode::SUCCESS,
        Some((false, _)) => {
            eprintln!("heimdall-private-mic: WirePlumber did not take the setting (is the package installed and the session restarted?)");
            ExitCode::from(1)
        }
        None => {
            eprintln!("heimdall-private-mic: wpctl could not be started");
            ExitCode::from(1)
        }
    }
}

/// Link (LykanOS) or remove (elsewhere, or `remove`) the LykanOS-only fragment under `root`. Only ever touches its own
/// link: a file of the owner's at that path is left alone.
fn os_setup(root: &Path, remove: bool) -> Result<&'static str, String> {
    let link = root.join(LYKANOS_LINK);
    let target = PathBuf::from("/").join(LYKANOS_FRAGMENT);
    let ours = std::fs::read_link(&link).is_ok_and(|t| t == target);
    let present = link.symlink_metadata().is_ok();
    if remove || !lykanos(root) {
        if ours {
            std::fs::remove_file(&link).map_err(|e| format!("{}: {e}", link.display()))?;
            return Ok("removed the LykanOS-only part");
        }
        return Ok("nothing to do");
    }
    if ours {
        return Ok("the LykanOS-only part is on");
    }
    if present {
        return Err(format!("{} exists and is not ours: left alone", link.display()));
    }
    if let Some(dir) = link.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    std::os::unix::fs::symlink(&target, &link).map_err(|e| format!("{}: {e}", link.display()))?;
    Ok("switched on the LykanOS-only part (Sarina's real-microphone setting, off)")
}

const USAGE: &str = "usage: heimdall-private-mic status [--json] | on | off | sarina-raw on|off | os-setup [--remove] [--root DIR]";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let a: Vec<&str> = args.iter().map(String::as_str).collect();
    match a.as_slice() {
        ["status", "--json"] => {
            let s = status();
            println!("{{\"enforce\":{},\"node\":{},\"lykanos\":{},\"sarina_raw\":{}}}", s.enforce, s.node, s.lykanos, s.sarina_raw);
            ExitCode::SUCCESS
        }
        ["status"] | [] => {
            let s = status();
            println!(
                "private microphone: {}{}",
                if s.enforce { "on (every app records the scrubbed microphone)" } else { "off (apps record the microphone as it is)" },
                if s.node { "" } else { "; its node is not there yet (install heimdall-private-mic, then log out and in)" }
            );
            if s.lykanos {
                println!(
                    "Sarina's voice input: {}",
                    if s.sarina_raw { "the real microphone (only her voice input)" } else { "the private microphone, like every app" }
                );
            }
            ExitCode::SUCCESS
        }
        [v @ ("on" | "off")] => set(KEY, *v == "on"),
        ["sarina-raw", v @ ("on" | "off")] => {
            if !lykanos(Path::new("/")) {
                eprintln!(
                    "heimdall-private-mic: this setting exists only on LykanOS; here Sarina records the private microphone like every app"
                );
                return ExitCode::from(1);
            }
            set(SARINA_KEY, *v == "on")
        }
        ["os-setup", rest @ ..] => {
            let mut root = PathBuf::from("/");
            let mut remove = false;
            let mut it = rest.iter();
            while let Some(x) = it.next() {
                match *x {
                    "--remove" => remove = true,
                    "--root" => match it.next() {
                        Some(r) => root = PathBuf::from(r),
                        None => {
                            eprintln!("{USAGE}");
                            return ExitCode::from(2);
                        }
                    },
                    _ => {
                        eprintln!("{USAGE}");
                        return ExitCode::from(2);
                    }
                }
            }
            match os_setup(&root, remove) {
                Ok(m) => {
                    println!("heimdall-private-mic: {m}");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("heimdall-private-mic: {e}");
                    ExitCode::from(1)
                }
            }
        }
        ["--help" | "-h"] => {
            println!("{USAGE}");
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_wpctl_and_pw_cli_output() {
        assert_eq!(setting_from("Value: true\n"), Some(true));
        assert_eq!(setting_from("Value: false (Saved: false)\n"), Some(false));
        assert_eq!(setting_from("Value: true (Saved: true)\n"), Some(true));
        assert_eq!(setting_from(""), None);
        let ls = "\tid 30, type PipeWire:Interface:Node/3\n \t\tnode.name = \"heimdall.private-mic\"\n";
        assert!(node_from(ls));
        assert!(!node_from(" \t\tnode.name = \"heimdall.private-mic.capture\"\n"));
    }

    #[test]
    fn knows_lykanos_by_its_id_only() {
        assert!(is_lykanos("NAME=\"LykanOS\"\nID=lykanos\nID_LIKE=arch\n"));
        assert!(is_lykanos("ID=\"lykanos\"\n"));
        assert!(!is_lykanos("NAME=\"Labyrinth OS\"\nID=labyrinth\nID_LIKE=\"arch lykanos\"\n"));
        assert!(!is_lykanos("ID=arch\n"));
    }

    #[test]
    fn os_setup_links_only_on_lykanos_and_only_its_own_link() {
        let root = std::env::temp_dir().join(format!("hpm-os-setup-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("etc")).unwrap();
        let link = root.join(LYKANOS_LINK);
        std::fs::write(root.join("etc/os-release"), "ID=labyrinth\n").unwrap();
        assert_eq!(os_setup(&root, false).unwrap(), "nothing to do");
        assert!(link.symlink_metadata().is_err());
        std::fs::write(root.join("etc/os-release"), "ID=lykanos\n").unwrap();
        os_setup(&root, false).unwrap();
        assert_eq!(std::fs::read_link(&link).unwrap(), Path::new("/").join(LYKANOS_FRAGMENT));
        assert_eq!(os_setup(&root, false).unwrap(), "the LykanOS-only part is on");
        os_setup(&root, true).unwrap();
        assert!(link.symlink_metadata().is_err());
        // a file of the owner's at that path is never replaced or removed
        std::fs::write(&link, "mine").unwrap();
        assert!(os_setup(&root, false).is_err());
        os_setup(&root, true).unwrap();
        assert_eq!(std::fs::read_to_string(&link).unwrap(), "mine");
        let _ = std::fs::remove_dir_all(&root);
    }
}
