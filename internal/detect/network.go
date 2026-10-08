package detect

import "fmt"

// NetworkExposureDetector translates netsource's non_loopback_bind/
// non_loopback_peer Events into Findings. Like FileIntegrityDetector, it's
// a thin, unconditional translator -- the state-transition bookkeeping
// (has this violation already been reported, is it still ongoing) lives
// in netsource.PortWatcher, not here, the same split Phase 2's FIM source
// uses.
type NetworkExposureDetector struct{}

func NewNetworkExposureDetector() *NetworkExposureDetector { return &NetworkExposureDetector{} }

func (d *NetworkExposureDetector) ID() string { return "network-exposure" }

func (d *NetworkExposureDetector) Inspect(e Event) []Finding {
	switch e.Kind {
	case "non_loopback_bind":
		return []Finding{{
			DetectorID: d.ID(),
			Severity:   SeverityCritical,
			Summary: fmt.Sprintf(
				"port %s is listening on %s, not loopback -- violates the ecosystem's loopback-only rule",
				e.Fields["port"], e.Fields["address"],
			),
			Event: e,
		}}
	case "non_loopback_peer":
		return []Finding{{
			DetectorID: d.ID(),
			Severity:   SeverityCritical,
			Summary: fmt.Sprintf(
				"port %s has a connection from %s:%s, not loopback",
				e.Fields["local_port"], e.Fields["remote_addr"], e.Fields["remote_port"],
			),
			Event: e,
		}}
	default:
		return nil
	}
}
