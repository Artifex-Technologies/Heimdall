package parity

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// The admin commands' fixture (testdata/parity/cli-admin.json); rust/heimdall/tests/cli_admin.rs runs it.
func TestCLIAdminFixtureMatchesTheGoCommands(t *testing.T) {
	f, err := AllCLIAdmin(t.TempDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Describe) < 50 || len(f.Open) < 40 || len(f.Round) < 50 {
		t.Fatalf("too few cases: %d %d %d", len(f.Describe), len(f.Open), len(f.Round))
	}
	path := filepath.Join(dir(t), "cli-admin.json")
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
	var have, want CLIAdmin
	if err := json.Unmarshal(b, &have); err != nil {
		t.Fatal(err)
	}
	j, _ := json.Marshal(f)
	_ = json.Unmarshal(j, &want)
	if !reflect.DeepEqual(have, want) {
		t.Error("cli-admin.json is out of date: run go test ./internal/parity -update and review the diff")
	}
}
