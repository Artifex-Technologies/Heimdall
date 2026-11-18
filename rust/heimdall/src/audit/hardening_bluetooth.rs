//! The Bluetooth address privacy check (Go: internal/hardening/bluetooth.go): does BlueZ use changing addresses? Without
//! Privacy in /etc/bluetooth/main.conf, Bluetooth Low Energy announces and connects with this computer's fixed address; with
//! it, the kernel uses a resolvable private address that changes every 15 minutes. Read-only and offline: the bluetoothd
//! program file, the start links, /sys/class/bluetooth and main.conf, read as GLib reads it for BlueZ (`key_file`).

use super::{Gap, System};

const BLUEZ_CONF: &str = "/etc/bluetooth/main.conf";

/// The Privacy values BlueZ turns address privacy on for (src/main.c, parse_privacy), compared exactly.
const PRIVACY_ON: [&[u8]; 5] = [b"network", b"on", b"device", b"limited-network", b"limited-device"];

/// g_ascii_isspace.
fn glib_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

fn trim_left(b: &[u8]) -> &[u8] {
    let n = b.iter().take_while(|c| glib_space(**c)).count();
    &b[n..]
}

fn trim_right(b: &[u8]) -> &[u8] {
    let n = b.iter().rev().take_while(|c| glib_space(**c)).count();
    &b[..b.len() - n]
}

/// GLib's key file reading (Go `keyFile`): the raw value of `key` in `group` (the last one wins), whether it is there, and the
/// first line (from 1) that makes GLib refuse the whole file (0: none). Bytes, as Go's strings.
fn key_file<'a>(text: &'a [u8], group: &[u8], key: &[u8]) -> (&'a [u8], bool, usize) {
    let (mut cur, mut started): (&[u8], bool) = (b"", false);
    let (mut val, mut found): (&[u8], bool) = (b"", false);
    for (i, line) in text.split(|c| *c == b'\n').enumerate() {
        let line = trim_left(line.strip_suffix(b"\r").unwrap_or(line));
        match line.first() {
            None | Some(b'#') => {}
            Some(b'[') => {
                let Some(end) = line.iter().position(|c| *c == b']') else { return (b"", false, i + 1) };
                if !trim_left(&line[end + 1..]).is_empty() {
                    return (b"", false, i + 1);
                }
                (cur, started) = (&line[1..end], true);
            }
            Some(_) => {
                let eq = line.iter().position(|c| *c == b'=');
                let Some(eq) = eq.filter(|e| *e > 0 && started) else { return (b"", false, i + 1) };
                if cur == group && trim_right(&line[..eq]) == key {
                    (val, found) = (trim_left(&line[eq + 1..]), true);
                }
            }
        }
    }
    (val, found, 0)
}

/// g_key_file_get_string's unescaping (Go `keyFileString`): \s \n \t \r \\; any other escape, or one cut off: None.
fn key_file_string(v: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(v.len());
    let mut it = v.iter();
    while let Some(&c) = it.next() {
        if c != b'\\' {
            out.push(c);
            continue;
        }
        out.push(match it.next()? {
            b's' => b' ',
            b'n' => b'\n',
            b't' => b'\t',
            b'r' => b'\r',
            b'\\' => b'\\',
            _ => return None,
        });
    }
    Some(out)
}

const BLUETOOTH_FIX: &str = "put 'Privacy = device' on a line of its own under [General] in /etc/bluetooth/main.conf (add a [General] line first if there is none), then sudo systemctl restart bluetooth. A device paired before may need pairing again";

impl System {
    /// Whether the kernel has a Bluetooth adapter now (an "hciN" entry; "hciN:M" are its connections).
    fn bt_adapter(&self) -> bool {
        use std::os::unix::ffi::OsStrExt;
        let Ok(rd) = std::fs::read_dir(self.path("/sys/class/bluetooth")) else { return false };
        rd.flatten().any(|e| {
            let n = e.file_name();
            n.as_bytes().starts_with(b"hci") && !n.as_bytes().contains(&b':')
        })
    }

    /// The Bluetooth address privacy check, in Go's order.
    pub(super) fn bluetooth_gaps(&self) -> Vec<Gap> {
        let daemons =
            ["/usr/lib/bluetooth/bluetoothd", "/usr/libexec/bluetooth/bluetoothd", "/usr/libexec/bluetoothd", "/usr/sbin/bluetoothd"];
        if self.first_file(&daemons).is_empty() {
            return Vec::new();
        }
        let (mut state, mut level) = ("BlueZ is installed but Bluetooth does not start at boot".to_string(), "info");
        let u = self.starts_at_boot(&["bluetooth.service", "bluetooth"]);
        if !u.is_empty() {
            state = format!("Bluetooth starts at boot ({u}), no adapter now");
            if self.bt_adapter() {
                (state, level) = (format!("Bluetooth starts at boot ({u}) with an adapter"), "warning");
            }
        }
        let read = self.read_raw(BLUEZ_CONF);
        if matches!(&read, Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied) {
            if level != "warning" {
                return Vec::new();
            }
            return vec![Gap {
                id: "bluetooth-settings-unread".into(),
                now: format!("{state}; Heimdall may not read {BLUEZ_CONF}"),
                level: "info".into(),
                why: "could not be checked whether Bluetooth uses changing addresses; with a fixed one, anything nearby can record it and follow this computer from place to place".into(),
                fix: format!("sudo grep -n Privacy {BLUEZ_CONF} (no 'Privacy = device' under [General] means a fixed address: {BLUETOOTH_FIX})"),
                cve: String::new(),
            }];
        }
        let text = read.as_deref().unwrap_or_default();
        let (val, found, bad) = key_file(text, b"General", b"Privacy");
        let now = if read.is_err() {
            format!("{state}: {BLUEZ_CONF} is missing, so Privacy is off (BlueZ's default)")
        } else if bad > 0 {
            format!("{state}: line {bad} of {BLUEZ_CONF} is one BlueZ cannot read, so it uses none of the file and Privacy is off")
        } else if !found {
            format!("{state}: Privacy is not set under [General] in {BLUEZ_CONF}, so it is off (BlueZ's default)")
        } else {
            match key_file_string(val) {
                Some(v) if PRIVACY_ON.contains(&v.as_slice()) => return Vec::new(),
                Some(v) if v == b"off" => format!("{state}: Privacy = off in {BLUEZ_CONF}"),
                _ => format!("{state}: Privacy in {BLUEZ_CONF} is not a value BlueZ knows (off, network, on, device, limited-network, limited-device), so it is off"),
            }
        };
        vec![Gap {
            id: "bluetooth-privacy-off".into(),
            now,
            level: level.into(),
            why: "Bluetooth Low Energy announces and connects with this computer's fixed address, which anything nearby can record to follow it from place to place; with Privacy on, the address changes every 15 minutes and only paired devices recognise it (classic Bluetooth keeps the fixed one while discoverable)".into(),
            fix: BLUETOOTH_FIX.into(),
            cve: String::new(),
        }]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A few of Go's TestKeyFileReadsAsGLib cases (the parity fixtures carry all of them).
    #[test]
    fn key_files_as_glib() {
        let get = |t: &str| {
            let (v, found, bad) = key_file(t.as_bytes(), b"General", b"Privacy");
            if !found || bad > 0 {
                return None;
            }
            key_file_string(v).map(|v| String::from_utf8(v).unwrap())
        };
        assert_eq!(get("[General]\nPrivacy = device   \n").as_deref(), Some("device   "));
        assert_eq!(get("[General]\r\nPrivacy = device\r\n").as_deref(), Some("device"));
        assert_eq!(get("[General]\nPrivacy = device\n[Policy]\n[General]\nPrivacy = off\n").as_deref(), Some("off"));
        assert_eq!(get("[General]\nbroken line\nPrivacy = device\n"), None);
        assert_eq!(get("Privacy = device\n[General]\n"), None);
        assert_eq!(get("[General]\nPrivacy = de\\svice\n").as_deref(), Some("de vice"));
        assert_eq!(get("[General]\nPrivacy = dev\\x\n"), None);
        assert_eq!(get("[General]x\nPrivacy = device\n"), None);
    }
}
