package detect

import "fmt"

// KernelVulnerabilityDetector turns "vulnerable_kernel" events (an installed kernel with known holes a newer kernel fixes, from the
// kernel's own CVE records) into findings. Critical only for a hole known to be exploited in the wild (CISA's list) in the running
// kernel: the kernel's CVE team files a CVE for nearly every fix and the scores others add are generous, so a high score alone is a
// warning (running kernel) or info (another installed kernel). The summary says what an update closes now and what needs a newer
// kernel line.
type KernelVulnerabilityDetector struct{}

func NewKernelVulnerabilityDetector() *KernelVulnerabilityDetector {
	return &KernelVulnerabilityDetector{}
}

func (d *KernelVulnerabilityDetector) ID() string { return "kernel-vulnerability" }

func (d *KernelVulnerabilityDetector) Inspect(e Event) []Finding {
	if e.Kind != "vulnerable_kernel" {
		return nil
	}
	f := e.Fields
	running := f["running"] == "true"
	sev := SeverityInfo
	switch {
	case running && f["exploited"] != "":
		sev = SeverityCritical
	case running || f["exploited"] != "":
		sev = SeverityWarning
	}
	which := "an installed kernel"
	if running {
		which = "the running kernel"
	}
	s := fmt.Sprintf("%s (%s) has %s known hole(s) that newer kernels fix, %s scored high; worst %s (%s): %s.", which, f["kernel"], f["count"], f["high"], f["worst"], f["worst_score"], f["worst_summary"])
	if f["exploited"] != "" {
		s += " Known to be exploited: " + f["exploited"] + "."
	}
	if f["same_line"] != "0" && f["same_line"] != "" {
		s += fmt.Sprintf(" %s of them are fixed in %s on its own line: sudo pacman -Syu when that version is offered, then restart into it.", f["same_line"], f["line_fix"])
	}
	if f["same_line"] != f["count"] {
		s += " The rest are fixed only in newer kernel lines (from " + f["fixed"] + "): booting the newer kernel closes them."
	}
	return []Finding{{DetectorID: d.ID(), Severity: sev, Event: e, Summary: s}}
}
