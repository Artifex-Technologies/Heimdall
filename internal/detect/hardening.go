package detect

// HardeningDetector turns "hardening_gap" events (a setting that leaves a known kind of hole open, where closing it costs nothing
// noticeable) into findings with the fix in the summary: a warning or info; critical only for a hole known to be open (level
// "critical": the SSHole build of sshd, internal/hardening/ssh.go). Nothing is changed by itself.
type HardeningDetector struct{}

func NewHardeningDetector() *HardeningDetector { return &HardeningDetector{} }

func (d *HardeningDetector) ID() string { return "hardening" }

func (d *HardeningDetector) Inspect(e Event) []Finding {
	if e.Kind != "hardening_gap" {
		return nil
	}
	sev := SeverityInfo
	switch e.Fields["level"] {
	case "warning":
		sev = SeverityWarning
	case "critical":
		sev = SeverityCritical
	}
	return []Finding{{DetectorID: d.ID(), Severity: sev, Event: e,
		Summary: e.Fields["now"] + ": " + e.Fields["why"] + ". Fix: " + e.Fields["fix"]}}
}
