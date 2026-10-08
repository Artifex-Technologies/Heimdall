package detect

import "regexp"

// injectionPatterns mirrors the phrase list in Sarina's
// sarina/memory_security.py (scan_memory_text): phrasing that indicates an
// instruction trying to override the agent rather than ordinary task text.
// Kept in sync deliberately -- if Sarina's list changes, update this one and
// say so in the commit message, per the two repos' shared conventions.
var injectionPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)ignore (all|any|the)?\s*(previous|prior|above)\s*instructions`),
	regexp.MustCompile(`(?i)disregard (all|any|the)?\s*(previous|prior|above)`),
	regexp.MustCompile(`(?i)you are now\b`),
	regexp.MustCompile(`(?i)new (system )?instructions?\s*:`),
	regexp.MustCompile(`(?i)act as if\b`),
	regexp.MustCompile(`(?i)override (your|the|all) instructions`),
	regexp.MustCompile(`(?i)do not (tell|inform|notify) the user`),
	regexp.MustCompile(`(?i)without (informing|telling|notifying) the user`),
	regexp.MustCompile(`(?i)system prompt\s*:`),
}

// InjectionDetector flags Event text that reads as an attempt to redirect
// the agent's instructions -- a prompt-injection or memory-poisoning
// attempt riding in on tool output, a file read, or a session message.
type InjectionDetector struct{}

func NewInjectionDetector() *InjectionDetector { return &InjectionDetector{} }

func (d *InjectionDetector) ID() string { return "injection-phrase" }

func (d *InjectionDetector) Inspect(e Event) []Finding {
	for _, pattern := range injectionPatterns {
		if match := pattern.FindString(e.Text); match != "" {
			return []Finding{{
				DetectorID: d.ID(),
				Severity:   SeverityCritical,
				Summary:    "text reads as an instruction override rather than task content (\"" + match + "\")",
				Event:      e,
			}}
		}
	}
	return nil
}
