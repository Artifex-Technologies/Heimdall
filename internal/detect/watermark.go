package detect

import (
	"fmt"
	"strings"
	"unicode"
)

// AgentWatermarkDetector looks through what an AI agent wrote into a file for marks a reader does not see (HEI-9, Sarina's
// E16): the kinds Sarina's stego_inspect watermark scan finds. agentsource gives each write as an agent_write event
// (write_file, edit_file, vault_write, forge_write), the text taken from the tool call itself, so nothing is read from the
// agent's files. The marks: invisible characters (zero-width, tag, direction and the other format characters), variation
// selectors that are not emoji styling (each can carry a byte), letters from another alphabet inside Latin words (a
// Cyrillic a, U+0430, in "password"), and lines whose trailing spaces and tabs read as text. Trailing whitespace that spells nothing
// is no mark: editors leave it all the time.
type AgentWatermarkDetector struct{}

func NewAgentWatermarkDetector() *AgentWatermarkDetector { return &AgentWatermarkDetector{} }

func (d *AgentWatermarkDetector) ID() string { return "agent-watermark" }

// hiddenRunes are the invisible characters Sarina's scan names that are not format characters (unicode.Cf): a joiner and
// the fillers, letters or marks to Unicode that show nothing.
var hiddenRunes = map[rune]bool{0x034F: true, 0x115F: true, 0x1160: true, 0x3164: true, 0xFFA0: true}

func isHiddenRune(r rune) bool {
	return unicode.Is(unicode.Cf, r) || hiddenRunes[r] || (r >= 0xE0000 && r <= 0xE007F)
}

// variationByte is a variation selector's byte value, or -1: VS1-16 (U+FE00-FE0F) are 0-15, VS17-256 (U+E0100-E01EF) 16-255.
func variationByte(r rune) int {
	switch {
	case r >= 0xFE00 && r <= 0xFE0F:
		return int(r - 0xFE00)
	case r >= 0xE0100 && r <= 0xE01EF:
		return int(r-0xE0100) + 16
	}
	return -1
}

// emojiStyled is a variation selector used as meant: VS15 or VS16 right after a symbol or an emoji (U+2665 then U+FE0F: a red heart).
func emojiStyled(prev, r rune) bool {
	return (r == 0xFE0E || r == 0xFE0F) &&
		(unicode.Is(unicode.So, prev) || unicode.Is(unicode.Sm, prev) || prev >= 0x1F000 || (prev >= 0x2190 && prev <= 0x2BFF))
}

// asciiText is b as text when every byte is printable ASCII (or a line break or tab) and there are at least two; else "".
func asciiText(b []byte) string {
	if len(b) < 2 {
		return ""
	}
	for _, c := range b {
		if (c < 0x20 || c > 0x7e) && c != '\n' && c != '\t' {
			return ""
		}
	}
	return string(b)
}

// clipASCII is at most 80 characters of an ASCII text, "..." marking a cut.
func clipASCII(s string) string {
	if len(s) > 80 {
		return s[:80] + "..."
	}
	return s
}

// watermarkMarks are the marks found in one text, each kind in words ("" when none), in a fixed order.
func watermarkMarks(s string) (marks []string, kinds []string) {
	invisible := 0
	var tags []byte
	var sel []byte
	selectors := 0
	var prev rune
	for _, r := range s {
		if isHiddenRune(r) {
			invisible++
			if r >= 0xE0020 && r <= 0xE007E {
				tags = append(tags, byte(r-0xE0000))
			}
		}
		if v := variationByte(r); v >= 0 && !emojiStyled(prev, r) {
			selectors++
			sel = append(sel, byte(v))
		}
		prev = r
	}
	words, firstWord, firstLine := 0, "", 0
	var bits strings.Builder
	for i, line := range strings.Split(s, "\n") {
		line = strings.TrimRight(line, "\r")
		for _, c := range line[len(strings.TrimRight(line, " \t")):] {
			if c == ' ' {
				bits.WriteByte('0')
			} else {
				bits.WriteByte('1')
			}
		}
		for _, w := range strings.FieldsFunc(line, func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_' }) {
			latin, foreign := false, false
			for _, r := range w {
				switch {
				case unicode.Is(unicode.Latin, r):
					latin = true
				case unicode.Is(unicode.Cyrillic, r) || unicode.Is(unicode.Greek, r) || unicode.Is(unicode.Armenian, r) || (r >= 0xFF01 && r <= 0xFF5E):
					foreign = true
				}
			}
			if latin && foreign {
				if words == 0 {
					firstWord, firstLine = w, i+1
				}
				words++
			}
		}
	}
	if invisible > 0 {
		m := fmt.Sprintf("%d invisible characters (zero-width, tag, direction or other format characters)", invisible)
		if t := asciiText(tags); t != "" {
			m += fmt.Sprintf(", the tag characters reading %q", clipASCII(t))
		}
		marks, kinds = append(marks, m), append(kinds, "invisible")
	}
	if selectors > 0 {
		m := fmt.Sprintf("%d variation selectors that are not emoji styling (each can carry a byte)", selectors)
		if t := asciiText(sel); t != "" {
			m += fmt.Sprintf(", reading %q", clipASCII(t))
		}
		marks, kinds = append(marks, m), append(kinds, "variation-selectors")
	}
	if words > 0 {
		marks = append(marks, fmt.Sprintf("letters from another alphabet inside %d Latin words (the first %q, line %d)", words, firstWord, firstLine))
		kinds = append(kinds, "look-alike-letters")
	}
	if b := bits.String(); len(b) >= 16 {
		var raw []byte
		for i := 0; i+8 <= len(b); i += 8 {
			var c byte
			for _, x := range b[i : i+8] {
				c = c<<1 | byte(x-'0')
			}
			raw = append(raw, c)
		}
		if t := asciiText(raw); t != "" {
			marks = append(marks, fmt.Sprintf("trailing spaces and tabs that read as %q", clipASCII(t)))
			kinds = append(kinds, "trailing-bits")
		}
	}
	return marks, kinds
}

func (d *AgentWatermarkDetector) Inspect(e Event) []Finding {
	if e.Source != "agent-session" || e.Kind != "agent_write" {
		return nil
	}
	marks, kinds := watermarkMarks(e.Fields["content"])
	if len(marks) == 0 {
		return nil
	}
	// the alert names the file and the marks, never carries what was written
	ev := e
	ev.Fields = make(map[string]string, len(e.Fields))
	for k, v := range e.Fields {
		if k != "content" {
			ev.Fields[k] = v
		}
	}
	ev.Fields["marks"] = strings.Join(kinds, ",")
	return []Finding{{DetectorID: d.ID(), Severity: SeverityWarning, Event: ev, Summary: fmt.Sprintf(
		"an AI agent wrote %q (%s) with marks a reader does not see: %s", e.Fields["path"], e.Fields["tool"], strings.Join(marks, "; "))}}
}
