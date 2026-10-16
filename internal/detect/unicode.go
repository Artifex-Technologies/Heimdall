package detect

import (
	"fmt"
	"regexp"
	"strconv"
	"unicode"
	"unicode/utf16"
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

// escapeRE finds JSON-style \uXXXX escapes. Sarina stores a tool result as a JSON document inside a JSON string, so a
// zero-width or tag character that a file contained arrives here as the six ASCII characters \u200b (or a surrogate pair
// \udb40\udc69 for the Tag block), not as the character. Looking only at the raw text would miss exactly the characters this
// detector exists for, so the text is also checked with those escapes decoded.
var escapeRE = regexp.MustCompile(`\\u[0-9a-fA-F]{4}`)

// decodeEscapes returns text with every \uXXXX escape replaced by its character (surrogate pairs combined).
func decodeEscapes(text string) string {
	if !escapeRE.MatchString(text) {
		return text
	}
	var out []rune
	units := []rune{}
	flush := func() {
		if len(units) == 0 {
			return
		}
		u16 := make([]uint16, len(units))
		for i, u := range units {
			u16[i] = uint16(u)
		}
		out = append(out, utf16.Decode(u16)...)
		units = units[:0]
	}
	rs := []rune(text)
	for i := 0; i < len(rs); {
		if rs[i] == '\\' && i+5 < len(rs)+0 && rs[i+1] == 'u' {
			if v, err := strconv.ParseUint(string(rs[i+2:i+6]), 16, 16); err == nil {
				units = append(units, rune(v))
				i += 6
				continue
			}
		}
		flush()
		out = append(out, rs[i])
		i++
	}
	flush()
	return string(out)
}

func (d *UnicodeDetector) Inspect(e Event) []Finding {
	for _, text := range []string{e.Text, decodeEscapes(e.Text)} {
		if f := d.inspect(e, text); f != nil {
			return f
		}
	}
	return nil
}

func (d *UnicodeDetector) inspect(e Event, text string) []Finding {
	for _, r := range text {
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
