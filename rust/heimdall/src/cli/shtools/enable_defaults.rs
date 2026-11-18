//! `heimdall-enable-defaults`, ported from the shell script (packaging/net/heimdall-enable-defaults): switch on what
//! Heimdall needs, once, when the package is first installed (a pacman hook runs it; it also works offline, in an
//! installer's chroot). Upgrades never run it again, so whatever the owner switched off stays off.
//!
//! An operating system that ships Heimdall but leaves it off at first (LykanOS, until Heimdall has its rules for the security
//! tools there) puts an empty /etc/heimdall/defaults-off in its image: then nothing is switched on, and
//! `heimdall-enable-defaults --force` (as root) switches it all on later.

use super::coreutils::{say, warn};
use std::process::{Command, Stdio};

pub const UNITS: [&str; 8] = [
    "heimdall.service",
    "heimdall-intel-update.timer",
    "heimdall-dns-blocklist.timer",
    "heimdall-contain.path",
    "heimdall-requests.path",
    "heimdall-inventory.timer",
    "heimdall-sarina-access.path",
    "heimdall-lan-scan.timer",
];

/// `systemctl ARGS >/dev/null 2>&1`: whether it succeeded.
fn quiet(prog: &str, args: &[&str]) -> bool {
    Command::new(prog).args(args).stdin(Stdio::inherit()).stdout(Stdio::null()).stderr(Stdio::null()).status().is_ok_and(|s| s.success())
}

pub fn main(args: &[String]) -> i32 {
    if std::path::Path::new("/etc/heimdall/defaults-off").exists() && args.first().map(String::as_str) != Some("--force") {
        say("heimdall: /etc/heimdall/defaults-off is there, so nothing was switched on (heimdall-enable-defaults --force does it)");
        return 0;
    }
    for u in UNITS {
        if !quiet("systemctl", &["enable", u]) {
            warn(&format!("heimdall: could not enable {u}"));
        }
    }
    // on a running system (Agora, an OS's first login) they start now too, not only at the next start; an installer's
    // chroot only enables them (systemd-detect-virt's own errors on standard error, as in the script)
    let running = std::path::Path::new("/run/systemd/system").is_dir();
    if running {
        let chroot = Command::new("systemd-detect-virt")
            .args(["--chroot", "--quiet"])
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .is_ok_and(|s| s.success());
        if !chroot {
            for u in UNITS {
                if !quiet("systemctl", &["start", u]) {
                    warn(&format!("heimdall: could not start {u}"));
                }
            }
        }
    }
    if !quiet("systemctl", &["--global", "enable", "heimdall-wifi-notify.path"]) {
        warn("heimdall: could not enable heimdall-wifi-notify.path");
    }
    0
}
