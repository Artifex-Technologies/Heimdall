package main

import (
	"reflect"
	"testing"

	"github.com/Artifex-Technologies/Heimdall/internal/config"
	"github.com/Artifex-Technologies/Heimdall/internal/parity"
)

// The parity fixtures (internal/parity) run the daemon's detectors with stand-ins for the system; this keeps their list,
// and with it the Rust port's (testdata/parity/functions.json "detector_order"), the daemon's own, in the same order.
func TestParityDetectorsAreTheDaemons(t *testing.T) {
	ids := func(n int, id func(int) string) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = id(i)
		}
		return out
	}
	cfg := config.Default()
	cfg.AgentBaselineStatePath = ""
	daemon := newDetectors(cfg)
	ours := parity.Detectors(cfg, parity.Deps{})
	got := ids(len(daemon), func(i int) string { return daemon[i].ID() })
	want := ids(len(ours), func(i int) string { return ours[i].ID() })
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("cmd/heimdalld newDetectors %v\ninternal/parity Detectors %v", got, want)
	}
}
