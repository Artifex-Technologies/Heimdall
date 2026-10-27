package rasource

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Artifex-Technologies/Heimdall/internal/remoteaccess"
)

func TestPackageNames(t *testing.T) {
	for in, want := range map[string]string{"tailscale-1.104.2-1": "tailscale", "zerotier-one-1.14.2-2": "zerotier-one", "x": "", "ALPM_DB_VERSION": ""} {
		if got := PackageName(in); got != want {
			t.Errorf("%s: %q, want %q", in, got, want)
		}
	}
}

func touch(t *testing.T, p string) {
	t.Helper()
	os.MkdirAll(filepath.Dir(p), 0o755)
	os.WriteFile(p, nil, 0o644)
}

func TestInstalledToolsAndNewTunnelsAreReported(t *testing.T) {
	d := t.TempDir()
	w := New(remoteaccess.Builtin())
	w.PacmanDir, w.NetDir = filepath.Join(d, "local"), filepath.Join(d, "net")
	os.MkdirAll(filepath.Join(w.PacmanDir, "bash-5.2-1"), 0o755)
	os.MkdirAll(filepath.Join(w.PacmanDir, "tailscale-1.104.2-1"), 0o755)
	touch(t, filepath.Join(w.NetDir, "lo", "uevent"))
	touch(t, filepath.Join(w.NetDir, "wg-home", "tun_flags")) // a tunnel already there at start: the computer's own
	ev := w.Poll()
	if len(ev) != 1 || ev[0].Fields["provider"] != "tailscale" || ev[0].Fields["signal"] != "package" {
		t.Fatalf("first poll: %+v", ev)
	}
	if len(w.Poll()) != 0 {
		t.Fatal("nothing changed: nothing to report")
	}
	os.MkdirAll(filepath.Join(w.PacmanDir, "ngrok-3.19-1"), 0o755)
	later := time.Now().Add(2 * time.Second)
	os.Chtimes(w.PacmanDir, later, later)
	touch(t, filepath.Join(w.NetDir, "zt5u4nvqrn", "uevent"))
	os.MkdirAll(filepath.Join(w.NetDir, "wg0"), 0o755)
	os.WriteFile(filepath.Join(w.NetDir, "wg0", "uevent"), []byte("DEVTYPE=wireguard\nINTERFACE=wg0\n"), 0o644)
	got := map[string]string{}
	for _, e := range w.Poll() {
		got[e.Fields["signal"]+":"+e.Fields["package"]+e.Fields["iface"]] = e.Fields["provider"]
	}
	if got["package:ngrok"] != "ngrok" || got["iface:zt5u4nvqrn"] != "zerotier" || len(got) != 3 {
		t.Fatalf("second poll: %v", got)
	}
	if _, ok := got["tunnel:wg0"]; !ok {
		t.Fatalf("a new WireGuard interface: %v", got)
	}
}
