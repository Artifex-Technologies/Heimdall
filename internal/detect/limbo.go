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
	// sample is the immunity store's status of a SHA-256 ("" when it keeps no such sample): a Wine run of a file whose
	// content Heimdall holds as malware is a finding (HEI-10). Nil: Wine runs are not looked up.
	sample func(sha256 string) string
}

func NewLimboGuestDetector() *LimboGuestDetector {
	return &LimboGuestDetector{policyUp: map[string]bool{}, running: map[string]bool{}}
}

// WithSamples looks up the program of each Wine run (limbo wine's wine.start, which names the file's SHA-256) in the
// immunity store.
func (d *LimboGuestDetector) WithSamples(status func(sha256 string) string) *LimboGuestDetector {
	d.sample = status
	return d
}

// sampleWords says what the immunity store's status means; "" for a status that is no finding (released: judged good).
func sampleWords(status string) (Severity, string) {
	switch status {
	case "held":
		return SeverityCritical, "a sample Heimdall holds (waiting for your judgement)"
	case "immune":
		return SeverityCritical, "malware Heimdall holds (ClamAV does not know it; Heimdall has its fingerprint)"
	case "reference":
		return SeverityCritical, "malware Heimdall holds (ClamAV knows it)"
	case "suspect":
		return SeverityWarning, "a file you kept as a suspect"
	}
	return "", ""
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
		if g == "" {
			// Limbo's own check of its images (the weekly one): no guest, the image's path and when it was checked
			return finding(SeverityCritical, "base image %q failed checksum verification in Limbo's %s: %s", e.Fields["path"], orDefault(e.Fields["during"], "check"), e.Fields["reason"])
		}
		return finding(SeverityCritical, "guest %q base image failed checksum verification: %s", g, e.Fields["reason"])
	case "gate.blocked":
		return finding(SeverityWarning, "guest %q blocked by the Windows license gate: %s", g, e.Fields["reason"])
	case "wine.start":
		// limbo wine runs as the person, in bubblewrap: Wine is no security boundary, and there is no guest to restrict
		sha := e.Fields["sha256"]
		if d.sample == nil || len(sha) != 64 {
			return nil
		}
		if sev, what := sampleWords(d.sample(sha)); sev != "" {
			return finding(sev, "limbo wine started %q in the prefix %q: its content is %s (SHA-256 %s)", e.Fields["program"], e.Fields["prefix"], what, sha)
		}
	}
	return nil
}

// orDefault is v, or def when v is empty.
func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
