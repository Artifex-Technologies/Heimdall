package hardening

import (
	"os"
	"path/filepath"
	"testing"
)

func put(t *testing.T, root, p, v string, mode os.FileMode) {
	full := filepath.Join(root, p)
	os.MkdirAll(filepath.Dir(full), 0o755)
	if err := os.WriteFile(full, []byte(v+"\n"), mode); err != nil {
		t.Fatal(err)
	}
	os.Chmod(full, mode)
}

func TestGapsAreFoundOnceWithTheirFix(t *testing.T) {
	root := t.TempDir()
	put(t, root, "/dev/kvm", "", 0o666)
	put(t, root, "/sys/module/kvm_intel/parameters/nested", "Y", 0o644)
	put(t, root, "/proc/sys/dev/tty/ldisc_autoload", "1", 0o644)
	put(t, root, "/proc/sys/kernel/kptr_restrict", "2", 0o644) // already stricter
	w := &Watcher{Sys: System{Root: root}, StatePath: filepath.Join(root, "state")}
	ev := w.Poll()
	got := map[string]string{}
	for _, e := range ev {
		got[e.Fields["check"]] = e.Fields["level"]
	}
	if got["kvm-world-writable"] != "warning" || got["kvm-nested"] != "info" || got["sysctl-dev.tty.ldisc_autoload"] != "info" || len(got) != 3 {
		t.Fatal(got)
	}
	if len(w.Poll()) != 0 {
		t.Fatal("once")
	}
	os.Chmod(filepath.Join(root, "/dev/kvm"), 0o660)
	if gaps := (System{Root: root}).Check(); len(gaps) != 2 {
		t.Fatal("closed when fixed", gaps)
	}
}
