package scan

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fake struct{}

func (fake) Name() string    { return "fake" }
func (fake) Available() bool { return true }
func (fake) ScanFile(_ context.Context, p string) (Result, error) {
	raw, err := os.ReadFile(p)
	if err != nil {
		return Result{Path: p}, err
	}
	if strings.Contains(string(raw), "EVIL") {
		return Result{Path: p, Infected: true, Signature: "Test.Evil"}, nil
	}
	return Result{Path: p}, nil
}

func write(t *testing.T, dir, name, body string) string {
	p := filepath.Join(dir, name)
	os.MkdirAll(filepath.Dir(p), 0o755)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestParseClamOutput(t *testing.T) {
	r := ParseClamOutput("/a", "/a: Eicar-Signature FOUND\n")
	if !r.Infected || r.Signature != "Eicar-Signature" {
		t.Fatalf("%+v", r)
	}
	if r := ParseClamOutput("/a", "/a: OK\n"); r.Infected || r.Error != "" {
		t.Fatalf("%+v", r)
	}
	if r := ParseClamOutput("/a", "/a: Can't open file ERROR\n"); r.Error == "" {
		t.Fatalf("%+v", r)
	}
}

func TestExcluder(t *testing.T) {
	e := Excluder{Patterns: []string{"/home/u/Games", "*.iso", "/x/file.bin", ""}}
	for p, want := range map[string]bool{
		"/home/u/Games":              true,
		"/home/u/Games/a/b":          true,
		"/home/u/GamesExtra/a":       false, // a prefix of the name is not the folder
		"/home/u/Downloads/disk.iso": true,
		"/x/file.bin":                true,
		"/x/file.bin2":               false,
		"/home/u/Downloads/a.txt":    false,
	} {
		if got := e.Match(p); got != want {
			t.Errorf("%s: got %v want %v", p, got, want)
		}
	}
}

func TestCollectRunAndState(t *testing.T) {
	dir := t.TempDir()
	good := write(t, dir, "docs/a.txt", "hello")
	bad := write(t, dir, "docs/b.txt", "xx EVIL xx")
	write(t, dir, "games/c.txt", "EVIL but excluded")
	write(t, dir, "big.bin", strings.Repeat("z", 5000))
	statePath := filepath.Join(t.TempDir(), "state.json")
	st := LoadState(statePath)
	opts := Options{Exclude: Excluder{Patterns: []string{filepath.Join(dir, "games")}}, MaxBytes: 1000, State: st}

	files, err := Collect([]string{dir}, opts)
	if err != nil || len(files) != 2 || files[0] != good || files[1] != bad {
		t.Fatalf("collect: %v %v", err, files)
	}
	res := Run(context.Background(), fake{}, files, st)
	if len(res) != 2 || res[0].Infected || !res[1].Infected || res[1].Signature != "Test.Evil" {
		t.Fatalf("results: %+v", res)
	}
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}

	// a second run, from the saved state: nothing changed, so nothing to scan
	again, _ := Collect([]string{dir}, Options{Exclude: opts.Exclude, MaxBytes: 1000, State: LoadState(statePath)})
	if len(again) != 0 {
		t.Fatalf("unchanged files were scanned again: %v", again)
	}
	// a changed file is scanned again
	write(t, dir, "docs/a.txt", "hello, changed")
	again, _ = Collect([]string{dir}, Options{Exclude: opts.Exclude, MaxBytes: 1000, State: LoadState(statePath)})
	if len(again) != 1 || again[0] != good {
		t.Fatalf("changed file: %v", again)
	}
}

func TestUnavailableScannerReportsAnError(t *testing.T) {
	c := &ClamAV{}
	if c.Available() {
		t.Fatal("no binary means unavailable")
	}
	if _, err := c.ScanFile(context.Background(), "/x"); err == nil {
		t.Fatal("expected an error")
	}
}

func TestClamAVWithAStandInProgram(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "clamscan")
	os.WriteFile(script, []byte(`#!/bin/sh
for last; do :; done
case "$last" in
  *bad*) echo "$last: Test.Virus FOUND"; exit 1 ;;
  *broken*) echo "$last: Can't open file ERROR"; exit 2 ;;
  *) echo "$last: OK"; exit 0 ;;
esac
`), 0o755)
	c := &ClamAV{bin: script}
	if r, err := c.ScanFile(context.Background(), "/x/fine.txt"); err != nil || r.Infected {
		t.Fatalf("clean: %+v %v", r, err)
	}
	if r, err := c.ScanFile(context.Background(), "/x/bad.exe"); err != nil || !r.Infected || r.Signature != "Test.Virus" {
		t.Fatalf("found: %+v %v", r, err)
	}
	if _, err := c.ScanFile(context.Background(), "/x/broken.bin"); err == nil {
		t.Fatal("an unreadable file must be an error, not a clean result")
	}
}
