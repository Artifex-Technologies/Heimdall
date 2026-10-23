package detect

import "fmt"

// PackageVulnerabilityDetector turns "vulnerable_package" events (an installed package with a known vulnerability, from Arch's
// security tracker) into findings: critical for a critical one, warning for high, info for the rest. The summary says how to fix it.
type PackageVulnerabilityDetector struct{}

func NewPackageVulnerabilityDetector() *PackageVulnerabilityDetector {
	return &PackageVulnerabilityDetector{}
}

func (d *PackageVulnerabilityDetector) ID() string { return "package-vulnerability" }

func (d *PackageVulnerabilityDetector) Inspect(e Event) []Finding {
	if e.Kind != "vulnerable_package" {
		return nil
	}
	f := e.Fields
	sev := SeverityInfo
	switch f["severity"] {
	case "Critical":
		sev = SeverityCritical
	case "High":
		sev = SeverityWarning
	}
	what := fmt.Sprintf("%s %s has a known %s vulnerability (%s %s)", f["package"], f["installed"], f["severity"], f["advisory"], f["cves"])
	var todo string
	if f["no_fix"] == "true" {
		todo = "there is no fixed version yet; if you do not need it, removing it closes the hole (sudo pacman -Rs " + f["package"] + ")"
	} else {
		todo = "it is fixed in " + f["fixed"] + ": update with sudo pacman -Syu (if that version is not offered yet, the repositories have not caught up; check again tomorrow)"
	}
	return []Finding{{DetectorID: d.ID(), Severity: sev, Summary: what + ": " + todo, Event: e}}
}
