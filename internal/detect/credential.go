package detect

import "regexp"

// credentialPatterns mirrors Sarina's memory_security.py credential-shape
// list: secrets that should never end up embedded in a session transcript,
// a tool result, or curated memory.
var credentialPatterns = []*regexp.Regexp{
	regexp.MustCompile(`-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----`),
	regexp.MustCompile(`ssh-(rsa|ed25519|dss) AAAA[0-9A-Za-z+/]{10,}`),
	regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	regexp.MustCompile(`ghp_[0-9A-Za-z]{36}`),
	regexp.MustCompile(`xox[baprs]-[0-9A-Za-z-]{10,}`),
	regexp.MustCompile(`(?i)api[_-]?key\s*[:=]\s*['"]?[0-9A-Za-z_\-]{16,}`),
	regexp.MustCompile(`(?i)password\s*[:=]\s*\S+`),
	regexp.MustCompile(`(?i)secret[_-]?(key|token)?\s*[:=]\s*['"]?[0-9A-Za-z_\-]{12,}`),
	// Common provider formats that carry no "key=" label: OpenAI/Anthropic (sk-, sk-ant-, sk-proj-), GitHub
	// (fine-grained and gho_/ghu_/ghs_/ghr_), Google, Stripe, npm, Hugging Face, JWTs and Bearer headers.
	regexp.MustCompile(`\bsk-[0-9A-Za-z_\-]{20,}`),
	regexp.MustCompile(`github_pat_[0-9A-Za-z_]{22,}`),
	regexp.MustCompile(`\bgh[ousr]_[0-9A-Za-z]{36}`),
	regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{35}`),
	regexp.MustCompile(`\b[sr]k_live_[0-9A-Za-z]{16,}`),
	regexp.MustCompile(`\bnpm_[0-9A-Za-z]{36}`),
	regexp.MustCompile(`\bhf_[0-9A-Za-z]{30,}`),
	regexp.MustCompile(`\beyJ[0-9A-Za-z_\-]{10,}\.eyJ[0-9A-Za-z_\-]{10,}\.[0-9A-Za-z_\-]{10,}`),
	regexp.MustCompile(`(?i)\bbearer\s+[0-9A-Za-z._~+/\-]{24,}=*`),
}

// CredentialDetector flags Event text that looks like a leaked secret --
// most often a sign that a tool call read a file it shouldn't have, or that
// a session transcript is unsafe to keep around unredacted.
type CredentialDetector struct{}

func NewCredentialDetector() *CredentialDetector { return &CredentialDetector{} }

func (d *CredentialDetector) ID() string { return "credential-shape" }

// CredentialMatches returns every piece of text that has a credential's shape (for a verifier that checks each one).
func CredentialMatches(text string) []string {
	var out []string
	for _, pattern := range credentialPatterns {
		out = append(out, pattern.FindAllString(text, 20)...)
	}
	return out
}

func (d *CredentialDetector) Inspect(e Event) []Finding {
	for _, pattern := range credentialPatterns {
		if pattern.MatchString(e.Text) {
			return []Finding{{
				DetectorID: d.ID(),
				Severity:   SeverityCritical,
				Summary:    "text contains what looks like a credential or secret",
				Event:      e,
			}}
		}
	}
	return nil
}
