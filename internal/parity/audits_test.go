package parity

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// The correlator's fixture (testdata/parity/correlate.json), checked like the others; rust/heimdall/tests/step3.rs runs it.
func TestCorrelationFixtureMatchesTheGoDaemon(t *testing.T) {
	f, err := AllCorrelations()
	if err != nil {
		t.Fatal(err)
	}
	// the Go tests' own assertions
	count := func(c CorrelationCase) (n int) {
		for _, s := range c.Steps {
			for _, l := range s.Out {
				if strings.Contains(l, `"detector_id":"incident"`) {
					n++
				}
			}
		}
		return n
	}
	if count(f.Scenarios[0]) != 2 || count(f.Scenarios[1]) != 0 || count(f.Scenarios[3]) != 2 || count(f.Scenarios[4]) != 1 {
		t.Fatalf("incident alerts: %d %d %d %d", count(f.Scenarios[0]), count(f.Scenarios[1]), count(f.Scenarios[3]), count(f.Scenarios[4]))
	}
	if !strings.Contains(f.Scenarios[2].Incidents, `"detectors":{"connection-watch":1,"limbo-guest":1,"remote-access":1}`) {
		t.Fatalf("bridging: %s", f.Scenarios[2].Incidents)
	}
	path := filepath.Join(dir(t), "correlate.json")
	if *update {
		b, err := json.Marshal(f)
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
	var have, want Correlations
	if err := json.Unmarshal(b, &have); err != nil {
		t.Fatal(err)
	}
	w, _ := json.Marshal(f)
	_ = json.Unmarshal(w, &want)
	if !reflect.DeepEqual(have, want) {
		t.Error("correlate.json is out of date: run go test ./internal/parity -update and review the diff")
	}
}

// The audits' fixture (testdata/parity/audits.json): written with -update, otherwise it must hold what the Go code says.
// The Rust port's test (rust/heimdall/tests/audits.rs) runs the same file.
func TestAuditFixtureMatchesTheGoDaemon(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads every file, so the unreadable-setting case cannot be shown")
	}
	a, err := AllAudits(t.TempDir)
	if err != nil {
		t.Fatal(err)
	}
	// the Go tests' own assertions, on the watchers' answers
	if ev := a.Packages[0].Steps[0].Events; len(ev) != 3 || ev[0].Fields["package"] != "php" || ev[1].Fields["no_fix"] != "true" || ev[2].Fields["advisory"] != "AVG-5" {
		t.Fatalf("TestInstalledPackagesAreMatchedWithPacmanVersions: %+v", ev)
	}
	if st := a.Packages[1].Steps; len(st[0].Events) != 1 || len(st[1].Events) != 0 || len(st[2].Events) != 0 || len(st[3].Events) != 1 {
		t.Fatalf("TestEachFindingIsReportedOnceUntilTheVersionChanges: %+v", st)
	}
	if ev := a.Kernels[1].Steps[0].Events; len(ev) != 1 || ev[0].Fields["same_line"] != "400" || ev[0].Fields["exploited"] != "CVE-2026-00003" || len(a.Kernels[1].Steps[1].Events) != 0 {
		t.Fatalf("TestCompactAndWatch: %+v", ev)
	}
	if st := a.Hardening[0].Steps; len(st[0].Events) != 3 || len(st[1].Events) != 0 {
		t.Fatalf("TestGapsAreFoundOnceWithTheirFix: %+v", st)
	}
	if ev := a.Hardening[1].Steps[0].Events; len(ev) != 1 || ev[0].Fields["check"] != "sysctl-net.core.bpf_jit_harden" {
		t.Fatalf("TestAnUnreadableSettingIsReportedAsUnchecked: %+v", ev)
	}
	path := filepath.Join(dir(t), "audits.json")
	if *update {
		b, err := json.Marshal(a)
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
	var have, want Audits
	if err := json.Unmarshal(b, &have); err != nil {
		t.Fatal(err)
	}
	w, _ := json.Marshal(a)
	_ = json.Unmarshal(w, &want)
	if !reflect.DeepEqual(have, want) {
		t.Error("audits.json is out of date: run go test ./internal/parity -update and review the diff")
	}
}
