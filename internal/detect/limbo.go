package detect

import "fmt"

// LimboGuestDetector audits Limbo's own safety ordering from outside its
// process. Limbo promises that a guest's firewall table is loaded before the
// guest starts and outlives it; Limbo enforcing that on itself is necessary,
// but a bug, a crash handler, or a hand-run `virsh start` that skips it would
// only be visible to something that watched the whole sequence. That is the
// point of this detector, the same reasoning as Phase 4's out-of-process review:
// the thing being checked cannot be the only thing checking.
//
// It also translates Limbo's own alarm events (image rejection, license gate)
// into Findings, thinly, like FileIntegrityDetector.
//
// State is keyed by guest and only ever touched for Events with Source
// "limbo", which come from a single goroutine, so no locking is needed even
// though other sources deliver Events to the same engine concurrently.
type LimboGuestDetector struct {
	policyUp map[string]bool
	running  map[string]bool
}

func NewLimboGuestDetector() *LimboGuestDetector {
	return &LimboGuestDetector{policyUp: map[string]bool{}, running: map[string]bool{}}
}

func (d *LimboGuestDetector) ID() string { return "limbo-guest" }

func (d *LimboGuestDetector) Inspect(e Event) []Finding {
	if e.Source != "limbo" {
		return nil
	}
	g := e.Fields["guest"]
	finding := func(sev Severity, format string, a ...any) []Finding {
		return []Finding{{DetectorID: d.ID(), Severity: sev, Summary: fmt.Sprintf(format, a...), Event: e}}
	}

	switch e.Kind {
	case "policy.apply":
		d.policyUp[g] = true
	case "guest.start":
		d.running[g] = true
		if !d.policyUp[g] {
			// Could also mean Heimdall began watching mid-sequence and never saw
			// the apply; with a persisted offset that gap should not occur, and
			// a guest running unfiltered is worth a false alarm.
			return finding(SeverityCritical, "guest %q started with no firewall policy applied first", g)
		}
	case "guest.stop":
		d.running[g] = false
	case "policy.remove":
		wasRunning := d.running[g]
		d.policyUp[g] = false
		if wasRunning {
			return finding(SeverityCritical, "firewall policy for guest %q removed while it was still running", g)
		}
	case "image.rejected":
		return finding(SeverityCritical, "guest %q base image failed checksum verification: %s", g, e.Fields["reason"])
	case "gate.blocked":
		return finding(SeverityWarning, "guest %q blocked by the Windows license gate: %s", g, e.Fields["reason"])
	}
	return nil
}
