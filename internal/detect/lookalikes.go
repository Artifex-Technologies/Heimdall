package detect

import "strings"

// Look-alike letters before the case-insensitive patterns (approved by the owner, 2026-11-10).
//
// Go's case-insensitive matching folds two non-ASCII letters onto ASCII ones: U+017F (long s) matches s and U+212A (Kelvin
// sign) matches k, so `(?i)password` matches "paſsword". But \b and \w are ASCII: to them those two letters are not word
// characters. So "ſystem notice to the assistant", with a long s first, slipped past `\b(system|...) notice to ...` while
// "system notice to the assistant" did not (found by the Rust port's differential corpus). The case-insensitive patterns
// now run on a copy of the text with those letters written as s and k; a match is cut from the original text through the
// offsets kept, so a summary and a redaction show what was really there. These two are the only letters that fold onto
// ASCII (TestFoldTextCoversEveryFoldOfAnASCIILetter checks the Unicode tables), and the Rust port does the same.

const (
	longS  = "\xc5\xbf"     // U+017F
	kelvin = "\xe2\x84\xaa" // U+212A
)

// lookalikes returns the text with the long s and the Kelvin sign written as "s" and "k", and for each byte of that text
// (and its end) the offset in the original; the text itself and nil when it has neither.
func lookalikes(s string) (string, []int) {
	if !strings.Contains(s, longS) && !strings.Contains(s, kelvin) {
		return s, nil
	}
	b := make([]byte, 0, len(s))
	at := make([]int, 0, len(s)+1)
	for i := 0; i < len(s); {
		switch {
		case strings.HasPrefix(s[i:], longS):
			b, at = append(b, 's'), append(at, i)
			i += len(longS)
		case strings.HasPrefix(s[i:], kelvin):
			b, at = append(b, 'k'), append(at, i)
			i += len(kelvin)
		default:
			b, at = append(b, s[i]), append(at, i)
			i++
		}
	}
	return string(b), append(at, len(s))
}

// span maps a match [a, b) of lookalikes' text back to the original.
func span(at []int, a, b int) (int, int) {
	if at == nil {
		return a, b
	}
	return at[a], at[b]
}

// foldedText is the text a pattern runs on: the look-alike copy for a case-insensitive pattern, the original otherwise.
func foldedText(l literals, text, norm string) string {
	if l.folded {
		return norm
	}
	return text
}
