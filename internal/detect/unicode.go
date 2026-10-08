package detect

import (
	"fmt"
	"unicode"
)

// invisibleCodepoints mirrors memory_security.py's _INVISIBLE_CODEPOINTS:
// zero-width, BOM, and soft-hyphen characters with no benign use in short
// agent-facing text, and a known technique for hiding instructions from a
// human skimming a transcript while the model still reads them.
var invisibleCodepoints = map[rune]bool{
	0x200B: true, // zero width space
	0x200C: true, // zero width non-joiner
	0x200D: true, // zero width joiner
	0x2060: true, // word joiner
	0xFEFF: true, // BOM / zero width no-break space
	0x00AD: true, // soft hyphen
}

func isBidiOverride(r rune) bool { return r >= 0x202A && r < 0x202F }
func isIsolate(r rune) bool      { return r >= 0x2066 && r < 0x206A }
func isTagBlock(r rune) bool     { return r >= 0xE0000 && r < 0xE0080 }

// UnicodeDetector flags invisible, bidi-override, isolate, or Unicode "tag"
// characters -- the same check Sarina applies to curated memory writes,
// applied here to anything Heimdall observes rather than only agent-written
// memory.
type UnicodeDetector struct{}

func NewUnicodeDetector() *UnicodeDetector { return &UnicodeDetector{} }

func (d *UnicodeDetector) ID() string { return "invisible-unicode" }

func (d *UnicodeDetector) Inspect(e Event) []Finding {
	for _, r := range e.Text {
		if invisibleCodepoints[r] || isBidiOverride(r) || isIsolate(r) || isTagBlock(r) || unicode.Is(unicode.Cf, r) {
			return []Finding{{
				DetectorID: d.ID(),
				Severity:   SeverityWarning,
				Summary:    fmt.Sprintf("text contains an invisible/formatting Unicode character (U+%04X)", r),
				Event:      e,
			}}
		}
	}
	return nil
}
