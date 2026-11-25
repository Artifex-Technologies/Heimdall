package detect

import (
	"fmt"
	"strconv"
)

// ResourcePressureDetector flags the host running under enough memory or
// load pressure that Heimdall's own detection loop -- and Sarina's -- may
// start missing polls or lagging. It is edge-triggered rather than
// re-alerting on every host_telemetry Event while pressure stays high: a
// sustained condition should alert once when it starts and stay quiet
// until it clears, not flood the alert log once per poll interval for as
// long as the host stays busy.
// Hysteresis (HEI-53, Netdata's alarms): an alarm raised at its threshold clears only well under it, so a value hovering
// at the threshold gives one alert, not one at every crossing.
const (
	memClearMargin  = 5.0 // percentage points under the memory threshold
	loadClearFactor = 0.8 // of the load threshold
)

type ResourcePressureDetector struct {
	memThresholdPercent float64
	loadThresholdPerCPU float64

	overMem  bool
	overLoad bool
}

func NewResourcePressureDetector(memThresholdPercent, loadThresholdPerCPU float64) *ResourcePressureDetector {
	return &ResourcePressureDetector{
		memThresholdPercent: memThresholdPercent,
		loadThresholdPerCPU: loadThresholdPerCPU,
	}
}

func (d *ResourcePressureDetector) ID() string { return "resource-pressure" }

func (d *ResourcePressureDetector) Inspect(e Event) []Finding {
	if e.Kind != "host_telemetry" {
		return nil
	}
	var findings []Finding

	if memPercent, err := strconv.ParseFloat(e.Fields["mem_percent"], 64); err == nil {
		over := memPercent >= d.memThresholdPercent
		if over && !d.overMem {
			findings = append(findings, Finding{
				DetectorID: d.ID(),
				Severity:   SeverityWarning,
				Summary: fmt.Sprintf(
					"host memory usage is %.1f%%, at or above the %.1f%% threshold -- detection reliability may degrade under sustained pressure",
					memPercent, d.memThresholdPercent,
				),
				Event: e,
			})
		}
		d.overMem = over || (d.overMem && memPercent >= d.memThresholdPercent-memClearMargin)
	}

	if loadPerCPU, err := strconv.ParseFloat(e.Fields["load_per_cpu"], 64); err == nil {
		over := loadPerCPU >= d.loadThresholdPerCPU
		if over && !d.overLoad {
			findings = append(findings, Finding{
				DetectorID: d.ID(),
				Severity:   SeverityWarning,
				Summary: fmt.Sprintf(
					"host load average is %.2f per core, at or above the %.2f threshold",
					loadPerCPU, d.loadThresholdPerCPU,
				),
				Event: e,
			})
		}
		d.overLoad = over || (d.overLoad && loadPerCPU >= d.loadThresholdPerCPU*loadClearFactor)
	}

	return findings
}
