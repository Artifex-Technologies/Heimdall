// Package verify checks each finding once more before it becomes an alert, separately from the detector that raised it and
// trying to disprove it (the idea of cloudflare/security-audit-skill's validation phase; no code taken). It answers with one
// of three verdicts:
//
//	confirmed         the check found what makes the finding real (a completed connection, a value with a real secret's shape)
//	needs_validation  the finding may be real, and the exact fact that is still open is named (a forgeable address, text the
//	                  person typed themselves)
//	rejected          the check disproved it (a documentation example key, a placeholder); the alert is kept but drops to
//	                  info and says why, so nothing is silently hidden
//
// A verdict never raises a severity. Findings no check covers carry no verdict.
package verify

import (
	"math"
	"regexp"
	"strings"

	"github.com/Artifex-Technologies/Heimdall/internal/detect"
)

type Verdict string

const (
	Confirmed       Verdict = "confirmed"
	NeedsValidation Verdict = "needs_validation"
	Rejected        Verdict = "rejected"
)

// Check gives a verdict for the findings it knows about (ok false: not its kind).
type Check func(f detect.Finding) (v Verdict, reason string, ok bool)

// Checks are the verifier's rules, by detector.
var Checks = map[string]Check{
	"credential-shape":  credential,
	"inbound":           inbound,
	"injection-phrase":  typedByPerson,
	"invisible-unicode": typedByPerson,
}

// Apply returns the finding with its verdict in the fields ("verdict", "verdict_reason"); a rejected one becomes info and
// its summary starts with the reason.
func Apply(f detect.Finding) detect.Finding {
	c, ok := Checks[f.DetectorID]
	if !ok {
		return f
	}
	v, reason, ok := c(f)
	if !ok {
		return f
	}
	fields := make(map[string]string, len(f.Event.Fields)+2)
	for k, x := range f.Event.Fields {
		fields[k] = x
	}
	fields["verdict"], fields["verdict_reason"] = string(v), reason
	f.Event.Fields = fields
	if v == Rejected {
		f.Severity = detect.SeverityInfo
		f.Summary = "[rejected: " + reason + "] " + f.Summary
	}
	return f
}

// Documentation and sample values that have a secret's shape but are published as examples, and placeholders.
var (
	knownExamples = []string{"AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "AKIAI44QH8DHBEXAMPLE"}
	placeholderRx = regexp.MustCompile(`(?i)(example|dummy|placeholder|redacted|changeme|your[_-]?(api|secret|key|token|password)|<[^>]*>|\$\{[^}]*\}|\$[A-Z_]{3,}|\*{4,}|x{6,}|\.\.\.)`)
	valueRx       = regexp.MustCompile(`[:=]\s*['"]?(\S+)$`)
)

// credential: every match is checked; a single real-looking one confirms the finding.
func credential(f detect.Finding) (Verdict, string, bool) {
	matches := detect.CredentialMatches(f.Event.Text)
	if len(matches) == 0 {
		return "", "", false
	}
	for _, m := range matches {
		if !sample(m) {
			return Confirmed, "a value with the shape and randomness of a real secret", true
		}
	}
	return Rejected, "only documentation examples or placeholders, not real secrets", true
}

func sample(m string) bool {
	for _, k := range knownExamples {
		if strings.Contains(m, k) {
			return true
		}
	}
	if placeholderRx.MatchString(m) {
		return true
	}
	v := m
	if g := valueRx.FindStringSubmatch(m); g != nil {
		v = strings.Trim(g[1], `'"`)
	}
	if strings.HasPrefix(m, "-----BEGIN") || strings.HasPrefix(m, "ssh-") {
		return false // a key header: what follows decides, and it is not in the match
	}
	return len(v) >= 12 && entropy(v) < 2.5 // "aaaaaaaaaaaaaaaa", "1234567890123456": no real token is that regular
}

// entropy in bits per character.
func entropy(s string) float64 {
	n := map[rune]int{}
	for _, r := range s {
		n[r]++
	}
	var h float64
	l := float64(len([]rune(s)))
	for _, c := range n {
		p := float64(c) / l
		h -= p * math.Log2(p)
	}
	return h
}

func inbound(f detect.Finding) (Verdict, string, bool) {
	switch f.Event.Fields["spoofable"] {
	case "0":
		return Confirmed, "the address completed a connection, so it is the real sender", true
	case "1":
		return NeedsValidation, "these packets never completed a connection, so the source address may be forged", true
	}
	return "", "", false
}

// Text in the person's own message is usually theirs to write; it is the same text in a file or a tool result that is
// an attack. Only the open fact is named; the severity stays.
func typedByPerson(f detect.Finding) (Verdict, string, bool) {
	switch f.Event.Fields["role"] {
	case "user":
		return NeedsValidation, "in the person's own message (what they typed or said, and anything their desktop put in front of it), not in a tool result: check where it came from", true
	case "tool", "assistant":
		return Confirmed, "it arrived through " + f.Event.Fields["role"] + " output, not from the person", true
	}
	return "", "", false
}
