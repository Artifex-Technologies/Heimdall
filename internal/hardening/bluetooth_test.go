package hardening

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestKeyFileReadsAsGLib: each case's answer is what GLib's GKeyFile gave for the same text (g_key_file_load_from_data, then
// g_key_file_get_string for General/Privacy), checked once by hand with GLib 2.90.
func TestKeyFileReadsAsGLib(t *testing.T) {
	for _, c := range []struct {
		text string
		val  string // GLib's string; "-" when there is none (no key, a load error or an unreadable value)
	}{
		{"[General]\nPrivacy = device\n", "device"},
		{"[General]\nPrivacy = device   \n", "device   "},
		{"[General]\nPrivacy=device\t\n", "device\t"},
		{"[General]\n  Privacy = device\n", "device"},
		{"[General]\nPrivacy = device # x\n", "device # x"},
		{"[General]\nPrivacy = off\nPrivacy = device\n", "device"},
		{"[General]\nPrivacy = device\n[Policy]\n[General]\nPrivacy = off\n", "off"},
		{"[General]\n  # c\nPrivacy = device\n", "device"},
		{"[General]\nbroken line\nPrivacy = device\n", "-"},
		{"Privacy = device\n[General]\n", "-"},
		{"[General] \nPrivacy = device\n", "device"},
		{"[ General ]\nPrivacy = device\n", "-"},
		{"[General]\nprivacy = device\n", "-"},
		{"[General]\nPrivacy  \t= device\n", "device"},
		{"[General]\r\nPrivacy = device\r\n", "device"},
		{"[General]\n=x\nPrivacy = device\n", "-"},
		{"[General]x\nPrivacy = device\n", "-"},
		{"[General]\nPrivacy = \"device\"\n", "\"device\""},
		{"[General]\nPrivacy = dev\\x\n", "-"},
		{"[General]\nPrivacy = de\\svice\n", "de vice"},
		{"[General]\nPrivacy[de] = off\nPrivacy = device\n", "device"},
		{"[General]\nPrivacy = device\n[General]\n", "device"},
		{"\ufeff[General]\nPrivacy = device\n", "-"},
		{"[General]\nPri vacy = device\n", "-"},
		{"[Gen]eral]\nPrivacy = device\n", "-"},
		{"[General\nPrivacy = device\n", "-"},
		{"[General]\nPrivacy\n", "-"},
	} {
		got := "-"
		if v, found, bad := keyFile(c.text, "General", "Privacy"); found && bad == 0 {
			if s, ok := keyFileString(v); ok {
				got = s
			}
		}
		if got != c.val {
			t.Errorf("%q: %q, GLib %q", c.text, got, c.val)
		}
	}
}

func TestBluetoothGaps(t *testing.T) {
	const bluetoothd = "usr/lib/bluetooth/bluetoothd"
	boot := "etc/systemd/system/bluetooth.target.wants/bluetooth.service"
	base := map[string]string{bluetoothd: "x", boot: "", "sys/class/bluetooth/hci0": "", "etc/bluetooth/main.conf": "[General]\n#Privacy = off\n"}
	with := func(k, v string) map[string]string {
		m := map[string]string{}
		for a, b := range base {
			m[a] = b
		}
		if v == "-" {
			delete(m, k)
		} else {
			m[k] = v
		}
		return m
	}
	for _, c := range []struct {
		name  string
		files map[string]string
		want  string // id:level
		now   string // in Now
	}{
		{"no BlueZ", with(bluetoothd, "-"), "", ""},
		{"Arch's own main.conf", base, "bluetooth-privacy-off:warning", "Privacy is not set under [General]"},
		{"device", with("etc/bluetooth/main.conf", "[General]\nPrivacy = device\n"), "", ""},
		{"network, on, limited", with("etc/bluetooth/main.conf", "[General]\nPrivacy=limited-network\n"), "", ""},
		{"off", with("etc/bluetooth/main.conf", "[General]\nPrivacy = off\n"), "bluetooth-privacy-off:warning", "Privacy = off in"},
		{"a value BlueZ does not know", with("etc/bluetooth/main.conf", "[General]\nPrivacy = Device\n"), "bluetooth-privacy-off:warning", "not a value BlueZ knows"},
		{"a comment after it", with("etc/bluetooth/main.conf", "[General]\nPrivacy = device # on\n"), "bluetooth-privacy-off:warning", "not a value BlueZ knows"},
		{"in another group", with("etc/bluetooth/main.conf", "[General]\n[Policy]\nPrivacy = device\n"), "bluetooth-privacy-off:warning", "not set"},
		{"a line GLib refuses", with("etc/bluetooth/main.conf", "[General]\nPrivacy = device\noops\n"), "bluetooth-privacy-off:warning", "line 3 of"},
		{"no main.conf", with("etc/bluetooth/main.conf", "-"), "bluetooth-privacy-off:warning", "is missing"},
		{"no adapter now", with("sys/class/bluetooth/hci0", "-"), "bluetooth-privacy-off:info", "no adapter now"},
		{"only a connection entry", with("sys/class/bluetooth/hci0", "-"), "bluetooth-privacy-off:info", "no adapter now"},
		{"not started at boot", with(boot, "-"), "bluetooth-privacy-off:info", "does not start at boot"},
		{"OpenRC", with("etc/runlevels/default/bluetooth", ""), "bluetooth-privacy-off:warning", "(bluetooth)"},
		{"Debian's path", with(bluetoothd, "-"), "bluetooth-privacy-off:warning", "Privacy = off in"},
	} {
		files := c.files
		if c.name == "only a connection entry" {
			files["sys/class/bluetooth/hci0:12"] = ""
		}
		if c.name == "OpenRC" {
			delete(files, boot)
		}
		if c.name == "Debian's path" {
			files["usr/libexec/bluetooth/bluetoothd"] = "x"
			files["etc/bluetooth/main.conf"] = "[General]\nPrivacy = off\n"
		}
		var got []string
		for _, g := range (System{Root: tree(t, files)}).bluetoothGaps() {
			got = append(got, g.ID+":"+g.Level)
			if !strings.Contains(g.Now, c.now) || g.Why == "" || !strings.Contains(g.Fix, "Privacy = device") || g.CVE != "" {
				t.Errorf("%s: %+v", c.name, g)
			}
		}
		if strings.Join(got, " ") != c.want {
			t.Errorf("%s: %v, want %s", c.name, got, c.want)
		}
	}
}

func TestBluetoothSettingsUnread(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a file of mode 0200")
	}
	root := tree(t, map[string]string{"usr/lib/bluetooth/bluetoothd": "x", "etc/runlevels/default/bluetooth": "", "sys/class/bluetooth/hci0": "",
		"etc/bluetooth/main.conf": "[General]\n"})
	os.Chmod(filepath.Join(root, "etc/bluetooth/main.conf"), 0o200)
	g := System{Root: root}.bluetoothGaps()
	if len(g) != 1 || g[0].ID != "bluetooth-settings-unread" || g[0].Level != "info" {
		t.Fatalf("%+v", g)
	}
	os.Remove(filepath.Join(root, "sys/class/bluetooth/hci0")) // not a warning: not reported unread either
	if g := (System{Root: root}).bluetoothGaps(); len(g) != 0 {
		t.Fatalf("%+v", g)
	}
}
