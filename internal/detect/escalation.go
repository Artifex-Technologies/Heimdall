package detect

import (
	"fmt"
	"regexp"
	"strconv"
)

// permissionDenialPattern matches the "Permission denials: N" line Sarina's
// slash-command dispatch writes into a session's message log (see
// agent_slash_commands.py). It is the one signal a session transcript
// already carries about the agent being refused a tool it asked for.
var permissionDenialPattern = regexp.MustCompile(`Permission denials:\s*(\d+)`)

// EscalationDetector flags session text reporting one or more permission
// denials -- the agent asked for a tool or action its current permission
// tier does not allow. A single denial is expected background noise; the
// detector still reports it at warning level so a human/dashboard can
// notice a pattern the burst detector alone would miss (repeated denials
// spread across many separate sessions rather than one).
type EscalationDetector struct{}

func NewEscalationDetector() *EscalationDetector { return &EscalationDetector{} }

func (d *EscalationDetector) ID() string { return "permission-escalation" }

func (d *EscalationDetector) Inspect(e Event) []Finding {
	match := permissionDenialPattern.FindStringSubmatch(e.Text)
	if match == nil {
		return nil
	}
	count, err := strconv.Atoi(match[1])
	if err != nil || count == 0 {
		return nil
	}
	severity := SeverityWarning
	if count >= 3 {
		severity = SeverityCritical
	}
	return []Finding{{
		DetectorID: d.ID(),
		Severity:   severity,
		Summary:    fmt.Sprintf("session reported %d permission denial(s) -- the agent asked for a tool its current tier does not allow", count),
		Event:      e,
	}}
}
