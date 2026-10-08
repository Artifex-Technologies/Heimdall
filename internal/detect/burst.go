package detect

import (
	"fmt"
	"time"
)

// BurstDetector flags an unusually high rate of new agent sessions -- a
// single compromised or runaway automation hammering the agent looks very
// different from normal single-operator use, even before any individual
// session content looks suspicious. It only inspects Events of Kind
// "session_created" (one per session file agentsource first observes), so
// it is silent on the per-message Events the other detectors use.
//
// Implemented as a leaky bucket, the same rate-limiting primitive
// CrowdSec's own "leaky" bucket type uses: a level that increments by one
// per event and drains continuously at threshold/window per second. This
// replaced an earlier version that kept every session_created timestamp in
// a slice and re-pruned it on every event (O(n) work and O(n) memory per
// call); a leaky bucket is two float64/time.Time fields and O(1) work
// regardless of how long the detector has been running.
type BurstDetector struct {
	window    time.Duration
	threshold float64
	leakRate  float64 // level units drained per second
	cooldown  time.Duration

	level         float64
	lastEvent     time.Time
	lastFindingAt time.Time
}

// NewBurstDetector reports a finding when threshold session_created Events
// arrive faster than the bucket can drain them over window, then holds off
// firing again until cooldown has passed -- CrowdSec's own bucket model
// has no equivalent to cooldown (a fresh bucket starts immediately and can
// overflow again right away), but re-alerting on every single session
// during a sustained burst is alert fatigue Heimdall's single-operator use
// case doesn't need.
func NewBurstDetector(window time.Duration, threshold int, cooldown time.Duration) *BurstDetector {
	t := float64(threshold)
	return &BurstDetector{
		window:    window,
		threshold: t,
		leakRate:  t / window.Seconds(),
		cooldown:  cooldown,
	}
}

func (d *BurstDetector) ID() string { return "session-burst" }

func (d *BurstDetector) Inspect(e Event) []Finding {
	if e.Kind != "session_created" {
		return nil
	}

	if !d.lastEvent.IsZero() {
		elapsed := e.Time.Sub(d.lastEvent).Seconds()
		if elapsed > 0 {
			d.level -= d.leakRate * elapsed
			if d.level < 0 {
				d.level = 0
			}
		}
	}
	d.lastEvent = e.Time
	d.level++

	if d.level < d.threshold {
		return nil
	}
	if !d.lastFindingAt.IsZero() && e.Time.Sub(d.lastFindingAt) < d.cooldown {
		return nil
	}
	d.lastFindingAt = e.Time
	d.level = 0 // matches CrowdSec: an overflowed bucket resets rather than latching full

	return []Finding{{
		DetectorID: d.ID(),
		Severity:   SeverityCritical,
		Summary:    fmt.Sprintf("session creation rate exceeded %d per %s -- unusually high rate for single-operator use", int(d.threshold), d.window),
		Event:      e,
	}}
}
