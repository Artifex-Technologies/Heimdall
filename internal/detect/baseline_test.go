package detect

import (
	"fmt"
	"testing"
)

func telemetryEvent(memPercent, loadPerCPU float64) Event {
	return Event{
		Kind: "host_telemetry",
		Fields: map[string]string{
			"mem_percent":  fmt.Sprintf("%.2f", memPercent),
			"load_per_cpu": fmt.Sprintf("%.2f", loadPerCPU),
		},
	}
}

// warmBaseline feeds n samples cycling through a small, consistent spread
// around center (e.g. center=50 -> 50.0, 50.1, 50.2, 50.3, 50.4, 50.0, ...)
// so the resulting baseline has a small, deterministic, nonzero stddev
// without relying on randomness.
func warmBaseline(d *BaselineDriftDetector, n int, center float64) {
	for i := 0; i < n; i++ {
		v := center + 0.1*float64(i%5)
		d.Inspect(telemetryEvent(v, 0.30))
	}
}

func TestBaselineDriftDetectorIgnoresOtherEventKinds(t *testing.T) {
	d := NewBaselineDriftDetector(5, 3.0)
	got := d.Inspect(Event{Kind: "message", Text: "irrelevant"})
	if len(got) != 0 {
		t.Fatalf("expected no findings for a non-telemetry event, got %+v", got)
	}
}

func TestBaselineDriftDetectorRequiresMinSamplesBeforeJudging(t *testing.T) {
	d := NewBaselineDriftDetector(10, 3.0)
	// Wild swings during warm-up must never fire -- there's no baseline
	// yet to compare against.
	for _, v := range []float64{10, 90, 5, 99, 1, 100, 20, 80, 30} { // 9 samples, minSamples=10
		if got := d.Inspect(telemetryEvent(v, 0.3)); len(got) != 0 {
			t.Fatalf("expected no findings before minSamples is reached, got %+v", got)
		}
	}
}

func TestBaselineDriftDetectorFlagsAndClearsAnOutlier(t *testing.T) {
	d := NewBaselineDriftDetector(20, 3.0)
	warmBaseline(d, 20, 50.0) // baseline settles around mean ~50, small spread

	first := d.Inspect(telemetryEvent(95.0, 0.30))
	if len(first) != 1 {
		t.Fatalf("expected exactly one finding on the first outlier, got %+v", first)
	}
	if first[0].DetectorID != "baseline-drift" || first[0].Severity != SeverityWarning {
		t.Fatalf("unexpected finding shape: %+v", first[0])
	}

	// Immediately repeating the same outlier should not re-fire -- still
	// flagged, same convention as ResourcePressureDetector.
	second := d.Inspect(telemetryEvent(95.0, 0.30))
	if len(second) != 0 {
		t.Fatalf("expected no repeat finding while still flagged, got %+v", second)
	}

	// Back to a normal value: clears silently (no finding either way).
	cleared := d.Inspect(telemetryEvent(50.2, 0.30))
	if len(cleared) != 0 {
		t.Fatalf("expected no finding when clearing, got %+v", cleared)
	}

	// A fresh crossing after clearing should fire again.
	third := d.Inspect(telemetryEvent(95.0, 0.30))
	if len(third) != 1 {
		t.Fatalf("expected exactly one finding on the second, fresh crossing, got %+v", third)
	}
}

func TestBaselineDriftDetectorTracksFieldsIndependently(t *testing.T) {
	d := NewBaselineDriftDetector(20, 3.0)
	for i := 0; i < 20; i++ {
		// mem_percent stays flat-ish around 50; load_per_cpu around 0.3.
		v := 50.0 + 0.1*float64(i%5)
		l := 0.30 + 0.01*float64(i%5)
		d.Inspect(Event{Kind: "host_telemetry", Fields: map[string]string{
			"mem_percent":  fmt.Sprintf("%.2f", v),
			"load_per_cpu": fmt.Sprintf("%.2f", l),
		}})
	}

	// Spike only load_per_cpu; mem_percent stays normal in the same event.
	got := d.Inspect(Event{Kind: "host_telemetry", Fields: map[string]string{
		"mem_percent":  "50.10",
		"load_per_cpu": "9.00",
	}})
	if len(got) != 1 {
		t.Fatalf("expected exactly one finding (load_per_cpu only), got %+v", got)
	}
	if got[0].Event.Fields["load_per_cpu"] != "9.00" {
		t.Fatalf("expected the finding to carry the offending event, got %+v", got[0])
	}
}
