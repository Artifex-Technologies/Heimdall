//! Settings that leave a known kind of hole open when closing it costs nothing a user would notice (Go: internal/hardening).
//! Each gap with why it matters and the exact fix; nothing is changed. Reads /dev, /sys and /proc only.

use super::{read_seen, write_seen};
use crate::event::{Event, Fields};
use crate::gotext;
use crate::gotime::Time;
use std::collections::BTreeSet;
use std::os::unix::fs::PermissionsExt;

/// One setting that could be safer.
#[derive(Clone, Debug, PartialEq)]
pub struct Gap {
    pub id: String,
    pub now: String,
    pub why: String,
    pub fix: String,
    /// "warning" or "info".
    pub level: String,
}

/// Where the checks read (a temporary tree in the tests; "" is the real system).
pub struct System {
    pub root: String,
}

const SYSCTL_FILE: &str = "/etc/sysctl.d/60-heimdall-hardening.conf";

fn sysctl_fix(name: &str, want: &str) -> String {
    format!("echo '{name} = {want}' | sudo tee -a {SYSCTL_FILE} && sudo sysctl -w {name}={want}")
}

fn sysctl_path(name: &str) -> String {
    format!("/proc/sys/{}", name.replace('.', "/"))
}

impl System {
    fn path(&self, p: &str) -> String {
        format!("{}{p}", self.root.trim_end_matches('/'))
    }

    fn read_raw(&self, p: &str) -> std::io::Result<Vec<u8>> {
        std::fs::read(self.path(p))
    }

    fn read(&self, p: &str) -> Option<String> {
        self.read_raw(p).ok().map(|b| gotext::trim_space(&gotext::lossy(&b)).to_string())
    }

    /// p exists but could not be read (permission), as opposed to missing.
    fn unreadable(&self, p: &str) -> bool {
        matches!(self.read_raw(p), Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied)
    }

    /// The gaps found now, in Go's order.
    pub fn check(&self) -> Vec<Gap> {
        let mut gaps = Vec::new();
        if let Ok(m) = std::fs::metadata(self.path("/dev/kvm")) {
            let perm = m.permissions().mode() & 0o777;
            if perm & 0o006 != 0 {
                gaps.push(Gap {
                    id: "kvm-world-writable".into(),
                    now: format!("/dev/kvm is {perm:04o} (every account)"),
                    level: "warning".into(),
                    why: "any program can use the kernel's virtual machine code; bugs there (Januscape, CVE-2026-53359) turn that into root. Only the kvm group needs it".into(),
                    fix: "printf 'KERNEL==\"kvm\", GROUP=\"kvm\", MODE=\"0660\"\\n' | sudo tee /etc/udev/rules.d/65-kvm.rules && sudo usermod -aG kvm $USER && sudo udevadm control --reload && sudo udevadm trigger -s misc (sign out and in again so the new group applies; virtual machines keep working)".into(),
                });
            }
        }
        for module in ["kvm_intel", "kvm_amd"] {
            if let Some(v) = self.read(&format!("/sys/module/{module}/parameters/nested")) {
                if v == "Y" || v == "1" {
                    gaps.push(Gap {
                        id: "kvm-nested".into(),
                        now: format!("{module} nested={v}"),
                        level: "info".into(),
                        why: "a guest can run its own hypervisor on this one, the path most KVM escapes (Januscape among them) need; only VMs inside VMs use it".into(),
                        fix: format!("echo 'options {module} nested=0' | sudo tee /etc/modprobe.d/60-heimdall-nested.conf (applies at the next restart; undo by deleting the file)"),
                    });
                }
            }
        }
        // (name, the safe value, lower is stricter, why)
        let sysctls: [(&str, &str, bool, &str); 5] = [
            ("dev.tty.ldisc_autoload", "0", true, "any user can make the kernel load old serial-line modules, a recurring source of root exploits; nothing on a desktop needs it"),
            ("kernel.kptr_restrict", "1", false, "kernel addresses are not hidden from programs without the syslog right in every case, and a known address helps an exploit aim; 1 hides them from those programs, root still sees them"),
            ("fs.protected_fifos", "2", false, "programs can be tricked into writing to a planted pipe in shared folders like /tmp"),
            ("fs.protected_regular", "2", false, "programs can be tricked into writing to a planted file in shared folders like /tmp"),
            ("net.core.bpf_jit_harden", "2", false, "the kernel's BPF compiler output can be used to smuggle exploit code; hardening it costs a little speed only for BPF"),
        ];
        for (name, want, lower_is_stricter, why) in sysctls {
            let p = sysctl_path(name);
            let now = self.read(&p);
            if now.is_none() && self.unreadable(&p) {
                // root-only settings (bpf_jit_harden): not knowing is not the same as no gap
                gaps.push(Gap {
                    id: format!("sysctl-{name}"),
                    now: format!("{name}: Heimdall may not read it"),
                    why: format!("could not be checked: {why}"),
                    fix: format!("sudo sysctl {name}   (if it is not {want}: {})", sysctl_fix(name, want)),
                    level: "info".into(),
                });
                continue;
            }
            let Some(now) = now else { continue };
            // byte order, as Go compares the strings (single digits: text order is number order)
            if (lower_is_stricter && now.as_str() <= want) || (!lower_is_stricter && now.as_str() >= want) {
                continue;
            }
            gaps.push(Gap {
                id: format!("sysctl-{name}"),
                now: format!("{name} = {now}"),
                why: why.to_string(),
                fix: sysctl_fix(name, want),
                level: "info".into(),
            });
        }
        gaps
    }
}

/// Reports each gap once (again when it comes back after being closed); the state file is Go's (`hardening.json`).
pub struct Watcher {
    pub sys: System,
    pub state_path: String,
}

impl Watcher {
    pub fn poll(&self) -> Vec<Event> {
        let seen = read_seen(&self.state_path);
        let mut current = BTreeSet::new();
        let mut events = Vec::new();
        for g in self.sys.check() {
            let key = format!("{}|{}", g.id, g.now);
            let new = !seen.contains(&key);
            current.insert(key);
            if !new {
                continue;
            }
            events.push(Event {
                source: "host-hardening".into(),
                time: Time::now(),
                kind: "hardening_gap".into(),
                text: format!("{}: {}", g.now, g.why),
                fields: Fields::from([
                    ("check".to_string(), g.id),
                    ("now".to_string(), g.now),
                    ("why".to_string(), g.why),
                    ("fix".to_string(), g.fix),
                    ("level".to_string(), g.level),
                ]),
                ..Default::default()
            });
        }
        write_seen(&self.state_path, &current);
        events
    }
}
