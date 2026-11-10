package parity

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// The trust store's fixture (testdata/parity/trust.json); rust/heimdall/tests/trust.rs runs it. Go's own signer makes a
// new key each time, so -update writes new cases; without it, every stored case is read again by the Go code and must
// give the stored answers.
func TestTrustFixtureMatchesTheGoDaemon(t *testing.T) {
	path := filepath.Join(dir(t), "trust.json")
	if *update {
		f, err := AllTrust(t.TempDir)
		if err != nil {
			t.Fatal(err)
		}
		approved, unsigned := 0, 0
		for _, c := range f.Cases {
			for _, a := range c.Asks {
				switch a.Verdict {
				case "approved":
					approved++
				case "unsigned":
					unsigned++
				}
			}
		}
		if f.Cases[0].Load.Error != "" || approved < 20 || unsigned < 40 {
			t.Fatalf("load %q, %d approved, %d unsigned", f.Cases[0].Load.Error, approved, unsigned)
		}
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
	var have TrustCases
	if err := json.Unmarshal(b, &have); err != nil {
		t.Fatal(err)
	}
	for _, c := range have.Cases {
		in := c
		in.Asks = append([]TrustAsk{}, c.Asks...)
		for i := range in.Asks {
			in.Asks[i].Verdict, in.Asks[i].Why = "", ""
		}
		got, err := RunTrust(in, t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, c) {
			t.Errorf("trust.json is out of date at %q: run go test ./internal/parity -update and review the diff", c.Name)
		}
	}
}
