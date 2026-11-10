package parity

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The Limbo responder's fixture (testdata/parity/response.json); rust/heimdall/tests/response.rs runs it. The queue's
// timing decides a few lines (late and backlog alerts, shutdown), so without -update this checks the Go assertions and
// that the file has the same cases, not every byte.
func TestResponseFixtureMatchesTheGoDaemon(t *testing.T) {
	f, err := AllResponse(t.TempDir)
	if err != nil {
		t.Fatal(err)
	}
	find := func(name string) ResponseCase {
		for _, c := range f.Cases {
			if c.Name == name {
				return c
			}
		}
		t.Fatalf("no case %q", name)
		return ResponseCase{}
	}
	count := func(l []string, s string) (n int) {
		for _, x := range l {
			if strings.Contains(x, s) {
				n++
			}
		}
		return n
	}
	if c := find("triggers and non-triggers"); count(c.Steps[0].Requests, "POST /v1/quarantine {") != 6 {
		t.Errorf("triggers: %v", c.Steps[0].Requests)
	}
	if c := find("stopped while waiting: skipped"); count(c.Steps[0].Out, `"error_code":"quarantine_skipped"`) != 1 {
		t.Errorf("skip: %v", c.Steps[0].Out)
	}
	if c := find("Limbo is down"); count(c.Steps[0].Out, "limbo_unreachable") != 1 {
		t.Errorf("down: %v", c.Steps[0].Out)
	}
	if c := find("Limbo hangs"); count(c.Steps[0].Out, "limbo_quarantine_timeout") != 1 {
		t.Errorf("hangs: %v", c.Steps[0].Out)
	}
	path := filepath.Join(dir(t), "response.json")
	if *update {
		b, err := json.MarshalIndent(f, "", " ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run go test ./internal/parity -update)", err)
	}
	var have ResponseCases
	if err := json.Unmarshal(b, &have); err != nil {
		t.Fatal(err)
	}
	if len(have.Cases) != len(f.Cases) {
		t.Fatal("response.json is out of date: run go test ./internal/parity -update and review the diff")
	}
	for i := range f.Cases {
		if have.Cases[i].Name != f.Cases[i].Name || len(have.Cases[i].Steps) != len(f.Cases[i].Steps) {
			t.Errorf("response.json is out of date at %q: run go test ./internal/parity -update", f.Cases[i].Name)
		}
	}
}
