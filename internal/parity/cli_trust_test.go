package parity

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// The owner's side of trust (testdata/parity/cli-trust.json): nothing in it is random, so without -update the file must
// be exactly what the Go code writes now. rust/heimdall/tests/cli_trust.rs runs it.
func TestCLITrustFixtureMatchesTheGoCommand(t *testing.T) {
	f, err := AllCLITrust(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.MarshalIndent(f, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	b = append(b, '\n')
	path := filepath.Join(dir(t), "cli-trust.json")
	if *update {
		if err := os.WriteFile(path, b, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	have, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run go test ./internal/parity -update)", err)
	}
	if !bytes.Equal(have, b) {
		t.Error("cli-trust.json is out of date: run go test ./internal/parity -update and review the diff")
	}
}
