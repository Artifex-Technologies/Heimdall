package parity

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// The API's fixture (testdata/parity/api.json); rust/heimdall/tests/step3.rs runs it.
func TestAPIFixtureMatchesTheGoDaemon(t *testing.T) {
	f, err := AllAPI(t.TempDir)
	if err != nil {
		t.Fatal(err)
	}
	// the Go tests' own assertions
	want := map[string]int{"guard: host attacker.example:8930": 403, "guard: host 127.0.0.1:8930": 200, "access: unidentified": 403,
		"access: another account": 403, "access: health is open to all": 200, "review: GET": 405, "review: missing text": 400,
		"review: malformed": 400, "review: without reviewer": 503, "review: oversized": 400, "requests: unknown kind": 400,
		"requests: escalation": 200}
	for _, c := range f.Cases {
		if w, ok := want[c.Name]; ok && c.Status != w {
			t.Errorf("%s: %d, want %d", c.Name, c.Status, w)
		}
		if c.Name == "review: injection" && (!strings.Contains(c.Response, `"deny"`) || len(c.Alerts) == 0) {
			t.Errorf("%s: %s %v", c.Name, c.Response, c.Alerts)
		}
		if c.Name == "requests: escalation" && (len(c.Alerts) != 1 || c.Alerts[0] != "grant-request") {
			t.Errorf("%s: %v", c.Name, c.Alerts)
		}
	}
	path := filepath.Join(dir(t), "api.json")
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
	var have, w APICases
	if err := json.Unmarshal(b, &have); err != nil {
		t.Fatal(err)
	}
	x, _ := json.Marshal(f)
	_ = json.Unmarshal(x, &w)
	if !reflect.DeepEqual(have, w) {
		t.Error("api.json is out of date: run go test ./internal/parity -update and review the diff")
	}
}
