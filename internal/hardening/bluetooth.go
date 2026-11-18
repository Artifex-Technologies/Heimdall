package hardening

// The Bluetooth address privacy check (R19 of the 2026-11 reference plan): does BlueZ use changing addresses? Without Privacy in
// /etc/bluetooth/main.conf, Bluetooth Low Energy announces and connects with this computer's fixed address, which anything
// nearby can record to follow it from place to place. With it on, the kernel uses a resolvable private address that changes
// every 15 minutes and only paired devices recognise. Read-only and offline: the bluetoothd program file, the start links,
// /sys/class/bluetooth and main.conf, read the way GLib reads it for BlueZ (keyFile). Classic Bluetooth (BR/EDR) has no such
// mode: it keeps the fixed address while this computer is discoverable or connecting, whatever Privacy says.

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

const bluezConf = "/etc/bluetooth/main.conf"

// bluezPrivacyOn are the Privacy values BlueZ turns address privacy on for (src/main.c, parse_privacy). It compares them
// exactly; "off", no value, any other value and a value GLib cannot read leave it off.
var bluezPrivacyOn = map[string]bool{"network": true, "on": true, "device": true, "limited-network": true, "limited-device": true}

// glibSpace is g_ascii_isspace.
const glibSpace = " \t\n\v\f\r"

// keyFile reads text as GLib's key files (BlueZ's main.conf) are read: the raw value of key in group (the last one wins; a
// group given twice is one group), whether the key is there, and the first line (from 1) that makes GLib refuse the whole
// file, 0 for none. Checked against GLib itself: a line is left-trimmed and its "\r" before "\n" dropped; empty and "#" lines
// are comments; "[name]" with only spaces after it is a group; "key = value" has the spaces around "=" removed but not those
// at the end of the value; anything else, or a key before the first group, is an error, and BlueZ then uses none of the file.
func keyFile(text, group, key string) (val string, found bool, bad int) {
	cur, started := "", false
	for i, line := range strings.Split(text, "\n") {
		line = strings.TrimLeft(strings.TrimSuffix(line, "\r"), glibSpace)
		switch {
		case line == "" || line[0] == '#':
		case line[0] == '[':
			end := strings.IndexByte(line, ']')
			if end < 0 || strings.TrimLeft(line[end+1:], glibSpace) != "" {
				return "", false, i + 1
			}
			cur, started = line[1:end], true
		default:
			eq := strings.IndexByte(line, '=')
			if eq <= 0 || !started {
				return "", false, i + 1
			}
			if cur == group && strings.TrimRight(line[:eq], glibSpace) == key {
				val, found = strings.TrimLeft(line[eq+1:], glibSpace), true
			}
		}
	}
	return val, found, 0
}

// keyFileString is g_key_file_get_string's unescaping: \s \n \t \r \\; any other escape, or one cut off, makes the value
// unreadable (ok false), which BlueZ takes as no value.
func keyFileString(v string) (string, bool) {
	var b strings.Builder
	for i := 0; i < len(v); i++ {
		if v[i] != '\\' {
			b.WriteByte(v[i])
			continue
		}
		i++
		if i == len(v) {
			return "", false
		}
		switch v[i] {
		case 's':
			b.WriteByte(' ')
		case 'n':
			b.WriteByte('\n')
		case 't':
			b.WriteByte('\t')
		case 'r':
			b.WriteByte('\r')
		case '\\':
			b.WriteByte('\\')
		default:
			return "", false
		}
	}
	return b.String(), true
}

// btAdapter reports whether the kernel has a Bluetooth adapter now (an "hciN" entry; "hciN:M" are its connections).
func (s System) btAdapter() bool {
	entries, _ := os.ReadDir(filepath.Join(s.Root, "/sys/class/bluetooth"))
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "hci") && !strings.Contains(e.Name(), ":") {
			return true
		}
	}
	return false
}

const bluetoothFix = "put 'Privacy = device' on a line of its own under [General] in " + bluezConf + " (add a [General] line first if there is none), then sudo systemctl restart bluetooth. A device paired before may need pairing again"

// bluetoothGaps is the Bluetooth address privacy check (see the top of this file).
func (s System) bluetoothGaps() []Gap {
	if s.firstFile("/usr/lib/bluetooth/bluetoothd", "/usr/libexec/bluetooth/bluetoothd", "/usr/libexec/bluetoothd", "/usr/sbin/bluetoothd") == "" {
		return nil
	}
	state, level := "BlueZ is installed but Bluetooth does not start at boot", "info"
	if u := s.startsAtBoot("bluetooth.service", "bluetooth"); u != "" {
		state = "Bluetooth starts at boot (" + u + "), no adapter now"
		if s.btAdapter() {
			state, level = "Bluetooth starts at boot ("+u+") with an adapter", "warning"
		}
	}
	b, err := os.ReadFile(filepath.Join(s.Root, bluezConf))
	if err != nil && errors.Is(err, fs.ErrPermission) {
		if level != "warning" {
			return nil
		}
		return []Gap{{ID: "bluetooth-settings-unread", Now: state + "; Heimdall may not read " + bluezConf, Level: "info",
			Why: "could not be checked whether Bluetooth uses changing addresses; with a fixed one, anything nearby can record it and follow this computer from place to place",
			Fix: "sudo grep -n Privacy " + bluezConf + " (no 'Privacy = device' under [General] means a fixed address: " + bluetoothFix + ")"}}
	}
	var now string
	val, found, bad := keyFile(string(b), "General", "Privacy")
	switch {
	case err != nil:
		now = state + ": " + bluezConf + " is missing, so Privacy is off (BlueZ's default)"
	case bad > 0:
		now = fmt.Sprintf("%s: line %d of %s is one BlueZ cannot read, so it uses none of the file and Privacy is off", state, bad, bluezConf)
	case !found:
		now = state + ": Privacy is not set under [General] in " + bluezConf + ", so it is off (BlueZ's default)"
	default:
		v, ok := keyFileString(val)
		switch {
		case ok && bluezPrivacyOn[v]:
			return nil
		case ok && v == "off":
			now = state + ": Privacy = off in " + bluezConf
		default:
			now = state + ": Privacy in " + bluezConf + " is not a value BlueZ knows (off, network, on, device, limited-network, limited-device), so it is off"
		}
	}
	return []Gap{{ID: "bluetooth-privacy-off", Now: now, Level: level,
		Why: "Bluetooth Low Energy announces and connects with this computer's fixed address, which anything nearby can record to follow it from place to place; with Privacy on, the address changes every 15 minutes and only paired devices recognise it (classic Bluetooth keeps the fixed one while discoverable)",
		Fix: bluetoothFix}}
}
