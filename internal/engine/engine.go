// Package engine wires a stream of detect.Events through every configured
// detect.Detector and hands resulting Findings to an alert.Sink. It is the
// one place that knows about both packages -- sources produce Events,
// detectors and sinks don't know about each other.
package engine

import (
	"log"

	"github.com/Artifex-Technologies/Heimdall/internal/alert"
	"github.com/Artifex-Technologies/Heimdall/internal/detect"
)

type Engine struct {
	detectors []detect.Detector
	sink      alert.Sink
	logger    *log.Logger
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
			a := alert.FromFinding(f)
			if err := e.sink.Write(a); err != nil && e.logger != nil {
				e.logger.Printf("heimdalld: alert sink write failed: %v", err)
			}
		}
	}
}
