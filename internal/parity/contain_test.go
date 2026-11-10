package parity

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// The containment trigger's fixture (testdata/parity/contain.json); rust/heimdall/tests/contain.rs runs it.
func TestContainFixtureMatchesTheGoDaemon(t *testing.T) {
	f, err := AllContain(t.TempDir)
	if err != nil {
		t.Fatal(err)
	}
	asked := func(c ContainCase) (n int) {
		for _, st := range c.Steps {
			if _, ok := st.Files["contain-request.json"]; ok {
				n++
			}
		}
		return n
	}
	want := map[string]int{
		"off by default, not about the agents, then asked": 1, "an escalation from a session": 1, "an injection phrase alone": 0,
		"ten minutes": 3, "a lock": 1, "an unreadable lock is still a lock": 1, "a folder in the lock's place is no lock": 2,
		"config {\"auto_contain\": false}": 0, "config {\"AUTO_Contain\": true}": 1,
	}
	for _, c := range f.Cases {
		if n, ok := want[c.Name]; ok && asked(c) != n {
			t.Errorf("%s: %d requests, want %d", c.Name, asked(c), n)
		}
		for _, st := range c.Steps {
			if st.Passed != 1 {
				t.Errorf("%s: every alert is passed on", c.Name)
			}
			if r, ok := st.Files["contain-request.json"]; ok && (!strings.Contains(r, `"auto":true`) || sortedNames(st.Files)[0] == "") {
				t.Errorf("%s: %s", c.Name, r)
			}
		}
	}
	path := filepath.Join(dir(t), "contain.json")
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
	var have, w ContainCases
	if err := json.Unmarshal(b, &have); err != nil {
		t.Fatal(err)
	}
	j, _ := json.Marshal(f)
	_ = json.Unmarshal(j, &w)
	if !reflect.DeepEqual(have, w) {
		t.Error("contain.json is out of date: run go test ./internal/parity -update and review the diff")
	}
}
