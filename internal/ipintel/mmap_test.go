package ipintel

import (
	"bytes"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"
	"time"
)

// Open maps the file; every answer must be the one the in-memory reader gives.
func TestOpenMapsTheFileAndAnswersAsFromBytes(t *testing.T) {
	raw := testDB(t)
	path := filepath.Join(t.TempDir(), "lite.mmdb")
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	mapped, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if !mapped.mapped {
		t.Fatal("Open read the file into memory instead of mapping it")
	}
	mem, err := FromBytes(raw)
	if err != nil {
		t.Fatal(err)
	}
	if mapped.Type != mem.Type || mapped.BuildEpoch != mem.BuildEpoch || mapped.v4Start != mem.v4Start {
		t.Errorf("metadata differs: %+v vs %+v", mapped, mem)
	}
	for _, ip := range []string{"203.0.113.77", "198.51.100.5", "198.51.100.200", "2001:db8::1", "8.8.8.8", "::1"} {
		a, errA := mapped.Lookup(net.ParseIP(ip))
		b, errB := mem.Lookup(net.ParseIP(ip))
		if FromRecord(a) != FromRecord(b) || (errA == nil) != (errB == nil) {
			t.Errorf("%s: mapped %v %v, in memory %v %v", ip, a, errA, b, errB)
		}
	}
}

// A damaged file is refused with the same errors as before, and an empty one (which cannot be mapped) too.
func TestOpenRefusesDamagedFiles(t *testing.T) {
	good := testDB(t)
	dir := t.TempDir()
	for name, b := range map[string][]byte{
		"empty":     nil,
		"no marker": bytes.Repeat([]byte{1}, 100),
		"truncated": good[:40],
	} {
		p := filepath.Join(dir, strings.ReplaceAll(name, " ", "-"))
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
		_, wantErr := FromBytes(b)
		_, err := Open(p)
		if err == nil || wantErr == nil || err.Error() != wantErr.Error() {
			t.Errorf("%s: Open said %v, FromBytes %v", name, err, wantErr)
		}
	}
	if _, err := Open(filepath.Join(dir, "missing.mmdb")); !os.IsNotExist(err) {
		t.Errorf("missing file: %v", err)
	}
}

// A file cut short in place while mapped makes the kernel fault on the pages past its end. That must be an error from the
// lookup, not the end of heimdalld.
func TestAFileCutShortUnderTheMappingIsAnErrorNotACrash(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lite.mmdb")
	if err := os.WriteFile(path, testDB(t), 0o644); err != nil {
		t.Fatal(err)
	}
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(path, 0); err != nil {
		t.Fatal(err)
	}
	m, err := db.Lookup(net.ParseIP("203.0.113.77"))
	if !errors.Is(err, errCutShort) || m != nil {
		t.Fatalf("lookup in a file cut short: %v %v", m, err)
	}
	// and the goroutine's fault setting is back to what it was
	if debug.SetPanicOnFault(false) {
		t.Error("the lookup left panic-on-fault switched on")
	}
}

// A replaced file (the monthly update renames a new one over it) is opened again, and the old mapping is released once
// nothing uses it.
func TestTheOldMappingIsReleasedAfterAReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "lite.mmdb")
	if err := os.WriteFile(path, testDB(t), 0o644); err != nil {
		t.Fatal(err)
	}
	r := NewResolver(path)
	if o := r.Lookup(net.ParseIP("203.0.113.9")); o.ASN != "AS64500" {
		t.Fatalf("first file: %+v", o)
	}
	mapped := func(suffix string) bool {
		b, _ := os.ReadFile("/proc/self/maps")
		return strings.Contains(string(b), path+suffix+"\n")
	}
	if !mapped("") {
		t.Fatal("the file is not mapped")
	}
	tmp := filepath.Join(dir, "new.mmdb")
	if err := os.WriteFile(tmp, testDB(t), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(time.Hour)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatal(err)
	}
	r.check = time.Time{} // as if a minute had passed
	if o := r.Lookup(net.ParseIP("203.0.113.9")); o.ASN != "AS64500" {
		t.Fatalf("after the update: %+v", o)
	}
	for i := 0; i < 100 && mapped(" (deleted)"); i++ {
		runtime.GC()
		time.Sleep(10 * time.Millisecond)
	}
	if mapped(" (deleted)") {
		t.Error("the replaced file is still mapped")
	}
	if !mapped("") {
		t.Error("the new file is not mapped")
	}
	runtime.KeepAlive(r)
}
