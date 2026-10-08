// Package governance is Phase 4: an out-of-process second opinion Sarina
// (or any sibling repo) can consult before persisting or acting on text it
// produced itself. It runs Heimdall's own, independently-maintained copy of
// the injection-phrase, credential-shape, and invisible-Unicode checks --
// the same three Sarina's own sarina/memory_security.py already applies
// in-process to curated-memory writes. The point of running them again
// here, in a separate OS process, is that a compromised or sufficiently
// manipulated agent session could in principle disable or bypass its own
// in-process check; it cannot reach into Heimdall's process to do the same.
//
// This is the one place in the codebase that both influences a caller's
// behavior (the caller may act on "deny") and writes to the alert log as
// a side effect of doing so -- see docs/ARCHITECTURE.md's Phase 4 section
// for why that's a deliberate, narrow exception to the rest of this
// project's read-only-toward-Sarina posture, not a precedent for more.
package governance

import (
	"time"

	"github.com/Artifex-Technologies/Heimdall/internal/alert"
	"github.com/Artifex-Technologies/Heimdall/internal/detect"
)

// Request mirrors what a caller sends: text about to be persisted or
// acted on, tagged with what kind of action it's part of (free-form,
// logged as-is -- e.g. "memory_proposal", "escalation") and, when known,
// which session produced it.
type Request struct {
	Kind      string `json:"kind"`
	SessionID string `json:"session_id"`
	Text      string `json:"text"`
}

// Verdict is Heimdall's answer. Decision is "allow" or "deny"; Reasons is
// populated only on deny, one entry per Finding that fired.
type Verdict struct {
	Decision string   `json:"decision"`
	Reasons  []string `json:"reasons,omitempty"`
}

const (
	DecisionAllow = "allow"
	DecisionDeny  = "deny"
)

// Reviewer runs a Request through the same three content detectors Phase
// 1 already applies to Sarina session text, so this package adds no new
// detection logic of its own -- only a new way to invoke the existing
// detectors synchronously, before the fact, instead of after it.
type Reviewer struct {
	detectors []detect.Detector
	sink      alert.Sink
}

// NewReviewer records every review -- allowed or denied -- to sink, so a
// governance consultation leaves the same audit trail any other detection
// does and shows up in /v1/alerts and alert_log_path like anything else.
func NewReviewer(sink alert.Sink) *Reviewer {
	return &Reviewer{
		detectors: []detect.Detector{
			detect.NewInjectionDetector(),
			detect.NewCredentialDetector(),
			detect.NewUnicodeDetector(),
		},
		sink: sink,
	}
}

func (r *Reviewer) Review(req Request) Verdict {
	ev := detect.Event{
		Source:    "governance-review",
		SessionID: req.SessionID,
		Time:      time.Now(),
		Kind:      "governance_review:" + req.Kind,
		Text:      req.Text,
	}

	var reasons []string
	for _, d := range r.detectors {
		for _, f := range d.Inspect(ev) {
			reasons = append(reasons, f.Summary)
			if r.sink != nil {
				_ = r.sink.Write(alert.FromFinding(f))
			}
		}
	}

	if len(reasons) > 0 {
		return Verdict{Decision: DecisionDeny, Reasons: reasons}
	}
	return Verdict{Decision: DecisionAllow}
}
