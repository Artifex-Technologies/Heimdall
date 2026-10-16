package detect

import "fmt"

// MaintenanceDetector records the opening and closing of a maintenance window (internal/maintenance). Opening one is a
// warning, not info: the owner should always be able to see that the usual alerts are being softened, by whom and why.
type MaintenanceDetector struct{}

func NewMaintenanceDetector() *MaintenanceDetector { return &MaintenanceDetector{} }

func (d *MaintenanceDetector) ID() string { return "maintenance-window" }

func (d *MaintenanceDetector) Inspect(e Event) []Finding {
	switch e.Kind {
	case "maintenance_opened":
		return []Finding{{DetectorID: d.ID(), Severity: SeverityWarning,
			Summary: fmt.Sprintf("maintenance window opened by %s: %q (until %s); routine alerts are softened to info, content checks are unchanged",
				e.Fields["actor"], e.Fields["reason"], e.Fields["until"]), Event: e}}
	case "maintenance_closed":
		return []Finding{{DetectorID: d.ID(), Severity: SeverityInfo,
			Summary: fmt.Sprintf("maintenance window closed (%q, opened by %s)", e.Fields["reason"], e.Fields["actor"]), Event: e}}
	}
	return nil
}
