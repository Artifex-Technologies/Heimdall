// Package engine wires a stream of detect.Events through every configured
// detect.Detector and hands resulting Findings to an alert.Sink. It is the
// one place that knows about both packages -- sources produce Events,
// detectors and sinks don't know about each other.
package engine

import (
	"log"

	"github.com/Artifex-Technologies/Heimdall/internal/alert"
	"github.com/Artifex-Technologies/Heimdall/internal/detect"
	"github.com/Artifex-Technologies/Heimdall/internal/maintenance"
	"github.com/Artifex-Technologies/Heimdall/internal/verify"
)

type Engine struct {
	detectors []detect.Detector
	sink      alert.Sink
	logger    *log.Logger

	// While a maintenance window is open, findings from these detectors (routine administration noise) are written as
	// info, with the window's reason in the summary. Content detectors are never in the list.
	window   WindowSource
	softened map[string]bool
}

// WindowSource tells whether a maintenance window is open.
type WindowSource interface {
	Active() (maintenance.Window, bool)
}

// SetMaintenance turns on softening for the named detectors while the window is open.
func (e *Engine) SetMaintenance(w WindowSource, detectors []string) {
	e.window = w
	e.softened = make(map[string]bool, len(detectors))
	for _, d := range detectors {
		e.softened[d] = true
	}
}

func New(sink alert.Sink, logger *log.Logger, detectors ...detect.Detector) *Engine {
	return &Engine{detectors: detectors, sink: sink, logger: logger}
}

// Handle runs one Event through every detector in registration order and
// writes any resulting Findings to the sink. Detectors run in-process and
// in order deliberately -- a stateful detector (BurstDetector) depends on
// seeing every Event exactly once, so Handle must never be called
// concurrently for Events from the same source.
func (e *Engine) Handle(ev detect.Event) {
	for _, d := range e.detectors {
		for _, f := range d.Inspect(ev) {
			f = verify.Apply(f)
			if e.window != nil && e.softened[f.DetectorID] && f.Severity != detect.SeverityInfo {
				if w, ok := e.window.Active(); ok {
					f.Severity = detect.SeverityInfo
					f.Summary = "[maintenance: " + w.Reason + "] " + f.Summary
				}
			}
			a := alert.FromFinding(f)
			if err := e.sink.Write(a); err != nil && e.logger != nil {
				e.logger.Printf("heimdalld: alert sink write failed: %v", err)
			}
		}
	}
}
