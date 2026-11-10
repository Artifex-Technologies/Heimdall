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
	if c := find("sarina: an opinion attached to a new hold"); count(c.Steps[0].Requests, `"source":"sarina"`) != 1 || len(c.Steps[0].Sarina) != 3 {
		t.Errorf("advisory: %v %v", c.Steps[0].Requests, c.Steps[0].Sarina)
	}
	if c := find("sarina: tools nonzero"); count(c.Steps[0].Sarina, "/chat") != 0 || count(c.Steps[0].Sarina, "DELETE") != 1 {
		t.Errorf("tools: the evidence must not be sent, the session must be closed: %v", c.Steps[0].Sarina)
	}
	if c := find("sarina: busy: a third advisory is skipped"); count(c.Steps[0].Out, `"error_code":"sarina_busy"`) != 1 {
		t.Errorf("busy: %v", c.Steps[0].Out)
	}
	if c := find("sarina: a slow model times out, the chat is not repeated"); count(c.Steps[0].Sarina, "/chat") != 1 || count(c.Steps[0].Out, "sarina_timeout") != 1 {
		t.Errorf("timeout: %v", c.Steps[0].Sarina)
	}
	if c := find("sarina: a backlog note"); count(c.Steps[0].Out, "quarantine_backlog_advisory") != 1 {
		t.Errorf("backlog note: %v", c.Steps[0].Out)
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
