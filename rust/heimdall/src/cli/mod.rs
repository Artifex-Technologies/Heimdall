//! The one-shot commands (everything but `run`), ported from cmd/heimdalld: the same arguments, output, files and exit codes
//! as the Go heimdalld, proved command by command against the Go binary in fake roots (`tests/common`, docs/RUST_CLI.md).
//!
//! `dispatch` answers None for a command not ported yet; `main` then hands it to the Go binary kept beside
//! (/usr/lib/heimdall/heimdalld-go) with the same arguments, so nothing stops working while the port goes on.

pub mod goflag;
pub mod golog;
pub mod tabwriter;

pub mod contain;
pub mod grant;
pub mod immunity;
pub mod intel;
pub mod lan;
pub mod maintenance;
pub mod mesh;
pub mod remote;
pub mod scan;
pub mod trust;
pub mod wifihealth;
pub mod wifitools;

/// Go's `const version` in cmd/heimdalld.
pub const VERSION: &str = "0.1.0";

/// Runs the one-shot command `cmd` with the words after it; None when it is not ported (the caller hands it to Go).
pub fn dispatch(cmd: &str, args: &[String]) -> Option<i32> {
    match cmd {
        "scan" => scan::main(args),
        "scan-files" => immunity::scan_files(args),
        "maintenance" => maintenance::main(args),
        "trust" => trust::main(args),
        "immunity" => immunity::main(args),
        "kernel-check" => intel::kernel_check(args),
        "contain" => contain::main(args),
        "mesh" => mesh::main(args),
        "grant" => grant::main(args),
        "origin" => intel::origin(args),
        "intel-check" => intel::intel_check(args),
        "ipdb-check" => intel::ipdb_check(args),
        "wifi-health" => wifihealth::main(args),
        "lan" => lan::main(args),
        "remote" => remote::main(args),
        crate::safefs::CHILD_COMMAND => Some(match crate::safefs::child(args) {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("{e}");
                1
            }
        }),
        "version" => {
            println!("heimdalld {VERSION}");
            Some(0)
        }
        _ => None,
    }
}

/// The helpers that become links to this program at the switch (packaging/install.sh), chosen by the name it was started
/// as; None for any other name.
pub fn tool(name: &str, args: &[String]) -> Option<i32> {
    match name {
        "heimdall-intel-update" => intel::update_tool(args),
        "heimdall-wifi-check" => wifitools::wifi_check(args),
        "heimdall-wifi-guard" => wifitools::wifi_guard(args),
        "heimdall-wifi-notify" => wifitools::wifi_notify(args),
        _ => None,
    }
}

/// Go's usage text (cmd/heimdalld's `usage`), printed to standard error.
pub const USAGE: &str = r#"heimdalld -- Heimdall agent-behavior monitor

Usage:
  heimdalld run  --config PATH      Run the monitoring daemon in the foreground.
  heimdalld scan --config PATH      Scan once, print findings, exit non-zero on any.
  heimdalld maintenance on --for 2h --reason "why" [--config PATH]
                                    Open a maintenance window (root; at most 4h): routine alerts become info while it is open.
  heimdalld maintenance off|status [--config PATH]
  heimdalld origin [--config PATH] IP...
                                    Where addresses belong (country, network), from the offline IP database.
  heimdalld ipdb-check FILE...      Check downloaded IP database files (heimdall-intel-update runs this before using one).
  heimdalld intel-check list|tracker FILE | kernel ARCHIVE OUT [EXPLOITED]
                                    Check a downloaded threat list or security tracker file before it is used.
  heimdalld scan-files [--state FILE] [--exclude PATTERN]... [--max-mb N] PATH...
                                    Scan files for malware with ClamAV (must be installed). Prints one line per finding; exit 1 if
                                    anything was found, 2 if ClamAV is missing or a file could not be scanned. Runs as the calling
                                    user; with --state, unchanged files are skipped next time.
  heimdalld trust init|status|mode|sign|forget|restore|verify|watch ...
                                    The signed list of files that decide how the AI agents behave (heimdalld trust for details).
  heimdalld immunity add|suspect|confirm|list|forget|check ...
                                    Malware learned beyond ClamAV: fingerprints ClamAV loads, so every scan catches copies.
  heimdalld kernel-check [--all]   Known holes in each installed kernel that a newer kernel fixes (offline, from the kernel's CVE list).
  heimdalld contain status|now|emergency|release
                                    Stop a compromised AI agent: unload the models, stop and lock Sarina; the last resort clears
                                    the graphics card and restarts (heimdalld contain for details).
  heimdalld mesh id|init|list|enroll|forget
                                    Share alerts with Heimdall on your other computers (owner-enrolled keys, off by default).
  heimdalld grant status|approve|deny|tier|revoke|off
                                    The one gate for an AI agent asking for more: hand-offs to other models, access tiers.
  heimdalld wifi-health [--speed] [--json]
                                    Why the Wi-Fi is slow: signal, a crowded channel, other devices, or a problem past the router
                                    (about 10 seconds; --speed adds a speed test).
  heimdalld lan scan|list [--dir DIR]
                                    The devices on a trusted home network: maker, name, first and last seen (heimdall-lan-scan
                                    runs the scan every 5 minutes; it does nothing on a network you have not trusted).
  heimdalld version                 Print the version and exit.

See README.md and docs/ARCHITECTURE.md for configuration and design.
"#;

/// The commands only the Rust heimdalld has, listed after Go's usage.
pub const RUST_USAGE: &str = r#"
Only in the Rust heimdalld:
  heimdalld run --shadow --config PATH
                                    The daemon beside the Go one: real sources, its own alert log, no responses
                                    (docs/RUST_SHADOW.md). Refuses any state or log path in /var/lib/heimdall/.
  heimdalld replay --config PATH [--approvals PATH] < events.jsonl > alerts.jsonl
                                    Run event lines through the detectors (the parity and differential tests use it).
  heimdalld rules check [FILE]     Check a text rule file (default: the built-in rules); every problem is printed.
"#;

#[cfg(test)]
mod tests {
    #[test]
    fn usage_is_gos() {
        // cmd/heimdalld/main.go's usage text, word for word (TestRustUsageIsGos keeps the Go side honest)
        let go = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../cmd/heimdalld/main.go")).unwrap();
        let start = go.find("fmt.Fprint(os.Stderr, `").unwrap() + "fmt.Fprint(os.Stderr, `".len();
        let end = start + go[start..].find('`').unwrap();
        assert_eq!(&go[start..end], super::USAGE);
    }
}
