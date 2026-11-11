package parity

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// The Wi-Fi check's fixture (testdata/parity/cli-wifi.json); rust/heimdall/tests/cli_wifi.rs runs it. The cases come from a
// fixed seed, so without -update the file must be exactly what the Go code writes today.
func TestWifiFixtureMatchesTheGoCode(t *testing.T) {
	path := filepath.Join(dir(t), "cli-wifi.json")
	f := AllWifi()
	verdicts := map[string]int{}
	for _, c := range f.Reports {
		var r struct{ Verdict string }
		if err := json.Unmarshal([]byte(c.JSON), &r); err != nil {
			t.Fatalf("report JSON: %v", err)
		}
		verdicts[r.Verdict]++
	}
	if verdicts["good"] < 20 || verdicts["warn"] < 20 || verdicts["bad"] < 20 {
		t.Fatalf("too few of each verdict: %v", verdicts)
	}
	b, err := json.MarshalIndent(f, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	b = append(b, '\n')
	if *update {
		if err := os.WriteFile(path, b, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	old, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run go test ./internal/parity -update)", err)
	}
	if !bytes.Equal(old, b) {
		t.Error("cli-wifi.json is out of date: run go test ./internal/parity -update and review the diff")
	}
}
