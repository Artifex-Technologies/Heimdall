package detect

import "strings"

// A literal prefilter for the text detectors' regular expressions. Almost all text Heimdall sees (agent messages, tool
// results, connection summaries) matches none of the patterns, and running every pattern over all of it was most of the cost
// of a message: each pattern scans the whole text, and a case-insensitive one is slower still. Each pattern here has words it
// cannot match without, and the pattern runs only when the text holds one of them. The text is case-folded once per
// inspection for the case-insensitive patterns. A pattern that does run runs on the original text, exactly as before, so
// findings, match text and order are unchanged (TestPrefilteredDetectorsMatchTheOldOnes checks it on a large mixed corpus).
// 45 times less work on benign text, measured 2026-11-09.

// literals are the words a pattern cannot match without: the text must contain at least one of them. folded: the pattern is
// case-insensitive ((?i)) and the words are looked for, lowercase, in foldText's copy of the text.
type literals struct {
	folded bool
	any    []string
}

// in reports whether the pattern can match: text is the original, folded its foldText copy.
func (l literals) in(text, folded string) bool {
	t := text
	if l.folded {
		t = folded
	}
	for _, w := range l.any {
		if strings.Contains(t, w) {
			return true
		}
	}
	return false
}

// foldText lowercases ASCII letters and turns the two non-ASCII letters that Go's case-insensitive matching treats as ASCII
// ones into those: U+017F (long s) matches s and U+212A (Kelvin sign) matches k under (?i), so `(?i)password` matches
// "paſsword". Nothing else can fold onto an ASCII letter (TestFoldTextCoversEveryFoldOfAnASCIILetter checks the Unicode
// tables). Text without capitals or those two letters is returned as it is, without a copy.
func foldText(s string) string {
	i := 0
	for ; i < len(s); i++ {
		if c := s[i]; ('A' <= c && c <= 'Z') || c == 0xC5 || c == 0xE2 {
			break
		}
	}
	if i == len(s) {
		return s
	}
	b := make([]byte, i, len(s))
	copy(b, s[:i])
	for ; i < len(s); i++ {
		c := s[i]
		switch {
		case 'A' <= c && c <= 'Z':
			b = append(b, c+('a'-'A'))
		case c == 0xC5 && i+1 < len(s) && s[i+1] == 0xBF: // U+017F, long s
			b = append(b, 's')
			i++
		case c == 0xE2 && i+2 < len(s) && s[i+1] == 0x84 && s[i+2] == 0xAA: // U+212A, Kelvin sign
			b = append(b, 'k')
			i += 2
		default:
			b = append(b, c)
		}
	}
	return string(b)
}
