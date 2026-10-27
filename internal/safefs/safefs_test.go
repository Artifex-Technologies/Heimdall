package safefs

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOpenNoLinksRefusesALinkAnywhereOnThePath(t *testing.T) {
	d := t.TempDir()
	real := filepath.Join(d, "real")
	os.MkdirAll(real, 0o755)
	os.WriteFile(filepath.Join(real, "f"), []byte("x"), 0o644)
	os.Symlink(real, filepath.Join(d, "link"))
	os.Symlink(filepath.Join(real, "f"), filepath.Join(d, "flink"))
	if f, err := OpenNoLinks(filepath.Join(real, "f"), os.O_RDONLY, 0); err != nil {
		t.Fatal(err)
	} else {
		f.Close()
	}
	for _, p := range []string{filepath.Join(d, "link", "f"), filepath.Join(d, "flink")} {
		if f, err := OpenNoLinks(p, os.O_RDONLY, 0); err == nil {
			f.Close()
			t.Fatalf("%s opened through a link", p)
		}
	}
}

func TestExclusiveWriteNeverReplacesAFileOrALink(t *testing.T) {
	d := t.TempDir()
	victim := filepath.Join(d, "victim")
	os.WriteFile(victim, []byte("keep"), 0o644)
	os.Symlink(victim, filepath.Join(d, "planted"))
	for _, p := range []string{victim, filepath.Join(d, "planted")} {
		if err := write(p, File{Data: []byte("evil"), Mode: 0o644, Exclusive: true}); err == nil {
			t.Fatalf("%s was written over", p)
		}
	}
	if b, _ := os.ReadFile(victim); string(b) != "keep" {
		t.Fatalf("victim changed: %q", b)
	}
	if err := write(filepath.Join(d, "new", "file"), File{Data: []byte("ok"), Mode: 0o600, Exclusive: true}); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(filepath.Join(d, "new", "file")); fi == nil || fi.Mode().Perm() != 0o600 {
		t.Fatal("mode not kept")
	}
}

func TestOwnerOfAndRootOnly(t *testing.T) {
	d := t.TempDir()
	uid, _, err := OwnerOf(filepath.Join(d, "not", "yet", "there"))
	if err != nil || uid != uint32(os.Getuid()) {
		t.Fatalf("owner of the closest existing folder: %d %v", uid, err)
	}
	os.Symlink("/etc", filepath.Join(d, "etc"))
	if _, _, err := OwnerOf(filepath.Join(d, "etc", "x")); err == nil {
		t.Fatal("a link on the way was not refused")
	}
	if os.Getuid() != 0 {
		if RootOnly(d) == nil {
			t.Fatal("a user's folder passed as root-only")
		}
	}
	if err := RootOnly("/usr/share"); err != nil {
		t.Fatal(err)
	}
}

func TestWriteAsRefusesToRestartATestBinary(t *testing.T) {
	if err := WriteAs(filepath.Join(t.TempDir(), "f"), File{Data: []byte("x"), Mode: 0o644}, 1, 1); err == nil {
		t.Fatal("a test binary was started again")
	}
}
