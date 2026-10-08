// Package detect defines the event/finding model shared by every detector,
// and the detector interface itself. A detector is a pure function over a
// stream of Events; it holds only the state it needs to reason across
// events (e.g. a rate counter), never I/O.
package detect

import "time"

// Severity is a coarse triage level. Detectors pick one; sinks and the
// status API may filter or color by it, but nothing branches behavior on it.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityCritical Severity = "critical"
)

// Event is one observation fed into the detection engine. The initial
// source (internal/sources/agentsource) produces one Event per message
// inside a Sarina session file; later sources (host FIM, network flow)
// produce Events shaped the same way so detectors that only care about
// Kind/Text/Fields don't need to know which source an Event came from.
type Event struct {
	// Source names the producer, e.g. "agent-session".
	Source string
	// SessionID is the originating Sarina session id, when known.
	SessionID string
	// Time is when the event was observed (not necessarily produced).
	Time time.Time
	// Kind is a source-defined category, e.g. "message", "permission_denial".
	Kind string
	// Text is the free-text payload detectors pattern-match against.
	Text string
	// Fields carries source-specific structured data (e.g. a parsed count)
	// that a specific detector may use without every detector needing to
	// understand the source's schema.
	Fields map[string]string
}

// Finding is a detector's verdict that an Event (or a short run of them)
// deserves attention.
type Finding struct {
	DetectorID string
	Severity   Severity
	Summary    string
	Event      Event
}

// Detector inspects one Event at a time and optionally emits Findings.
// Implementations that need to reason across events (bursts, sequences)
// keep that state on the receiver; the engine guarantees single-threaded,
// in-order delivery of Events to each Detector so no locking is needed.
type Detector interface {
	// ID names the detector for Finding.DetectorID and log output.
	ID() string
	// Inspect processes one Event and returns zero or more Findings.
	Inspect(e Event) []Finding
}
