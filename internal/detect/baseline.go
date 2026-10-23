package detect

import (
	"fmt"
	"strconv"
)

// baselineFields are the host_telemetry Fields this detector tracks a
// running baseline for. Both already exist for Phase 2's
// resource-pressure detector; this adds a second, complementary judgment
// on the same numbers rather than a new source.
var baselineFields = []string{"mem_percent", "load_per_cpu"}

// BaselineDriftDetector flags a host_telemetry value that is a genuine
// statistical outlier against this specific host's own learned normal
// range, rather than a fixed percentage anyone had to pick in advance --
// complementary to resource-pressure's fixed threshold, not a
// replacement: a host that idles at 85% memory has a different "unusual"
// than one that idles at 20%, and only a learned baseline can tell them
// apart. This is the transferable idea behind TALON's known-vs-novel
// splice-junction classification (see docs/REFERENCES.md), applied
// honestly as streaming statistics rather than a real ML model.
//
// Edge-triggered per field, same pattern as ResourcePressureDetector: one
// alert when a value crosses the z-score threshold, silence while it
// stays there, one alert again on the next new crossing.
//
// Known limitation, not fixed for this first slice: every sample folds
// into the same baseline whether or not it was flagged, so a sustained
// shift eventually becomes the new "normal" rather than staying flagged
// forever. Acceptable for a v1 -- a baseline that never adapts would
// eventually alert on every reboot's warm-up period, every season's usage
// pattern change, forever.
type BaselineDriftDetector struct {
	minSamples int
	zThreshold float64

	stats   map[string]*OnlineStats
	flagged map[string]bool

	// floors, when set, make the detector report only upward outliers at or above a level a person would care about: a machine that idles at
	// 0.02 load and briefly shows 0.3 is 'statistically unusual' but not worth an alert.
	floors map[string]float64
}

// DefaultBaselineFloors are the levels below which an outlier is not reported (memory in percent, load per CPU).
var DefaultBaselineFloors = map[string]float64{"mem_percent": 85, "load_per_cpu": 1.5}

// NewBaselineDriftDetectorWithFloors is the detector as the daemon runs it: upward outliers only, and only above the floors.
func NewBaselineDriftDetectorWithFloors(minSamples int, zThreshold float64, floors map[string]float64) *BaselineDriftDetector {
	d := NewBaselineDriftDetector(minSamples, zThreshold)
	d.floors = floors
	return d
}

// NewBaselineDriftDetector requires minSamples observations of a field
// before judging it at all (an empty baseline has no meaningful spread to
// compare against), and flags a value whose z-score's absolute value
// reaches zThreshold (3.0 is the conventional "three-sigma" starting
// point).
func NewBaselineDriftDetector(minSamples int, zThreshold float64) *BaselineDriftDetector {
	return &BaselineDriftDetector{
		minSamples: minSamples,
		zThreshold: zThreshold,
		stats:      make(map[string]*OnlineStats),
		flagged:    make(map[string]bool),
	}
}

func (d *BaselineDriftDetector) ID() string { return "baseline-drift" }

func (d *BaselineDriftDetector) Inspect(e Event) []Finding {
	if e.Kind != "host_telemetry" {
		return nil
	}

	var findings []Finding
	for _, key := range baselineFields {
		raw, ok := e.Fields[key]
		if !ok {
			continue
		}
		val, err := strconv.ParseFloat(raw, 64)
		if err != nil {
			continue
		}

		stats, known := d.stats[key]
		if !known {
			stats = &OnlineStats{}
			d.stats[key] = stats
		}

		// Judge against history *before* folding this sample in, so a
		// single spike can't inflate its own baseline and excuse itself.
		if stats.Count() >= d.minSamples {
			z := stats.ZScore(val)
			over := z >= d.zThreshold || z <= -d.zThreshold
			if d.floors != nil {
				over = over && z > 0 && val >= d.floors[key]
			}
			if over && !d.flagged[key] {
				findings = append(findings, Finding{
					DetectorID: d.ID(),
					// a statistical oddity of this machine's own load or memory, not a security finding: it is recorded (and shown at the
					// "everything" alert level), but it does not interrupt anyone
					Severity: SeverityInfo,
					Summary: fmt.Sprintf(
						"%s is %.2f, %.1f standard deviations from this host's own learned baseline (mean %.2f, stddev %.2f) -- statistically unusual for this machine, not just over a fixed threshold",
						key, val, z, stats.Mean(), stats.StdDev(),
					),
					Event: e,
				})
			}
			d.flagged[key] = over
		}

		stats.Add(val)
	}
	return findings
}
