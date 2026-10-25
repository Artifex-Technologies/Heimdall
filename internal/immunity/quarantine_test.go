package immunity

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func init() { OwnedByPackage = func(string) (string, bool) { return "", false } }

func TestHoldAsksTheReferenceAtOnceAndMovesTheOriginal(t *testing.T) {
	s := store(t)
	known := filepath.Join(t.TempDir(), "eicar.com")
	os.WriteFile(known, []byte(strings.Repeat("EICAR-STANDARD-ANTIVIRUS-TEST-FILE ", 3)), 0o644)
	e, err := s.Hold(known, known, "test", "owner", func(string) (string, error) { return "Eicar-Test-Signature", nil })
	if err != nil || e.Status != Reference || e.ClamAV != "Eicar-Test-Signature" {
		t.Fatal(e, err)
	}
	if _, err := os.Stat(known); !os.IsNotExist(err) {
		t.Fatal("known malware is moved without asking anyone")
	}
	unknown := sample(t, planted)
	e, err = s.Hold(unknown, unknown, "planted skill", "containment", func(string) (string, error) { return "", nil })
	if err != nil || e.Status != Held || e.Report == nil || !strings.Contains(e.Report.Head, "Ignore your rules") {
		t.Fatal(e, err)
	}
	if _, err := os.Stat(unknown); !os.IsNotExist(err) {
		t.Fatal("held: moved away")
	}
	// the owner says it is good: back exactly as it was
	os.Chmod(filepath.Dir(unknown), 0o755)
	r, err := s.Release(e.SHA256, "owner")
	if err != nil || r.Status != Released {
		t.Fatal(r, err)
	}
	if b, _ := os.ReadFile(unknown); string(b) != planted {
		t.Fatal("restored")
	}
	if _, err := s.Hold(unknown, unknown, "again", "containment", nil); err == nil {
		t.Fatal("a file judged good is not held again")
	}
}

func TestNeverMovesSystemFiles(t *testing.T) {
	if _, err := store(t).Hold("/usr/bin/ls", "/usr/bin/ls", "x", "owner", nil); err == nil {
		t.Fatal("/usr is never moved")
	}
}

func TestProof(t *testing.T) {
	now := time.Now()
	held := Entry{Status: Held, Original: "/home/u/.local/bin/tool", SHA256: "aa", HeldAt: now}
	if _, ok := Proof(held, nil, nil); ok {
		t.Fatal("no record: no proof")
	}
	held.SeenSince = now.Add(-2 * time.Hour)
	if _, ok := Proof(held, nil, nil); ok {
		t.Fatal("seen only just before: no proof")
	}
	held.SeenSince = now.Add(-72 * time.Hour)
	if why, ok := Proof(held, nil, nil); !ok || !strings.Contains(why, "inventory") {
		t.Fatal("seen for days: proof")
	}
	behaviour := func(string) bool { return true }
	if _, ok := Proof(held, nil, behaviour); ok {
		t.Fatal("an AI behaviour file needs the owner's signature, however long it was there")
	}
	signed := func(p, sha string) bool { return p == held.Original && sha == "aa" }
	if why, ok := Proof(held, signed, behaviour); !ok || !strings.Contains(why, "signed") {
		t.Fatal("signed: proof")
	}
}

func TestInventorySeesProgramsAndRemembersSince(t *testing.T) {
	s := store(t)
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "tool"), []byte("#!/bin/sh\necho hi\n"), 0o755)
	os.WriteFile(filepath.Join(root, "notes.txt"), []byte("not a program"), 0o644)
	if n, err := s.TakeInventory([]string{root}); err != nil || n != 1 {
		t.Fatal(n, err)
	}
	first := s.Inventory()[filepath.Join(root, "tool")].FirstSeen
	s.TakeInventory([]string{root})
	if s.Inventory()[filepath.Join(root, "tool")].FirstSeen != first {
		t.Fatal("unchanged: first sighting kept")
	}
}
