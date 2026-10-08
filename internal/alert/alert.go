// Package alert turns detect.Findings into durable, queryable records: a
// timestamped Alert, and Sinks that persist or surface them (stdout,
// a JSONL file, an in-memory ring buffer for the status API).
package alert

import (
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/Artifex-Technologies/Heimdall/internal/detect"
)

// Alert is a Finding plus the wall-clock time Heimdall raised it. Findings
// don't carry their own timestamp -- the underlying Event does, and that's
// "when the observation happened," not "when Heimdall noticed."
type Alert struct {
	Time       time.Time       `json:"time"`
	DetectorID string          `json:"detector_id"`
	Severity   detect.Severity `json:"severity"`
	Summary    string          `json:"summary"`
	Source     string          `json:"source"`
	SessionID  string          `json:"session_id,omitempty"`
	EventKind  string          `json:"event_kind"`
	EventText  string          `json:"event_text"`
	// Fields carries the event's structured data (e.g. the "guest" a Limbo
	// event is about), so a responder can act on it without parsing EventText.
	// Additive: existing consumers that ignore it are unaffected.
	Fields map[string]string `json:"fields,omitempty"`
}

func FromFinding(f detect.Finding) Alert {
	return Alert{
		Time:       time.Now().UTC(),
		DetectorID: f.DetectorID,
		Severity:   f.Severity,
		Summary:    f.Summary,
		Source:     f.Event.Source,
		SessionID:  f.Event.SessionID,
		EventKind:  f.Event.Kind,
		EventText:  f.Event.Text,
		Fields:     f.Event.Fields,
	}
}

// Sink receives every Alert the engine raises. Implementations must be
// safe to call from a single goroutine at a time (the engine never calls
// concurrently) but may be read concurrently (Ring is).
type Sink interface {
	Write(Alert) error
}

// WriterSink appends one JSON object per line to an io.Writer -- stdout in
// the foreground, or a rotated log file.
type WriterSink struct {
	w  io.Writer
	mu sync.Mutex
}

func NewWriterSink(w io.Writer) *WriterSink { return &WriterSink{w: w} }

func (s *WriterSink) Write(a Alert) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	enc := json.NewEncoder(s.w)
	return enc.Encode(a)
}

// Ring keeps the last N alerts in memory for the status API to serve
// without touching disk. Safe for concurrent reads (Recent) while the
// engine goroutine writes.
type Ring struct {
	mu   sync.Mutex
	buf  []Alert
	next int
	size int
	full bool
}

func NewRing(size int) *Ring {
	if size < 1 {
		size = 1
	}
	return &Ring{buf: make([]Alert, size), size: size}
}

func (r *Ring) Write(a Alert) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buf[r.next] = a
	r.next = (r.next + 1) % r.size
	if r.next == 0 {
		r.full = true
	}
	return nil
}

// Recent returns up to n most-recent alerts, newest first.
func (r *Ring) Recent(n int) []Alert {
	r.mu.Lock()
	defer r.mu.Unlock()

	count := r.next
	if r.full {
		count = r.size
	}
	if n <= 0 || n > count {
		n = count
	}

	out := make([]Alert, 0, n)
	idx := r.next
	for i := 0; i < n; i++ {
		idx--
		if idx < 0 {
			idx = r.size - 1
		}
		out = append(out, r.buf[idx])
	}
	return out
}

// MultiSink fans one Alert out to several Sinks, continuing past a failed
// write so one broken sink (e.g. a full disk) doesn't silence the others.
type MultiSink struct {
	sinks []Sink
}

func NewMultiSink(sinks ...Sink) *MultiSink { return &MultiSink{sinks: sinks} }

func (m *MultiSink) Write(a Alert) error {
	var firstErr error
	for _, s := range m.sinks {
		if err := s.Write(a); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("sink write failed: %w", err)
		}
	}
	return firstErr
}

// IntegrationDetector is the DetectorID of alerts that report a failure of
// Heimdall's own integration with another component (Sarina, her session files),
// not something found in monitored data. They share the alert stream so one
// place shows both "something is wrong with the agent" and "Heimdall cannot see
// or consult the agent".
const IntegrationDetector = "integration"

// Integration builds a structured integration-failure alert. code is a stable
// machine-readable identifier (see docs/INTEGRATION-FAILURES.md), summary says
// what happened, and remedy is a one-line next step for a person or for Sarina.
func Integration(code, summary, remedy string, fields map[string]string) Alert {
	f := map[string]string{"error_code": code, "remedy": remedy}
	for k, v := range fields {
		f[k] = v
	}
	return Alert{
		Time:       time.Now().UTC(),
		DetectorID: IntegrationDetector,
		Severity:   detect.SeverityWarning,
		Summary:    code + ": " + summary + " (remedy: " + remedy + ")",
		Source:     "sentry",
		EventKind:  "integration_error",
		Fields:     f,
	}
}
