package macvendor

import (
	"strings"
	"unicode/utf8"
)

// MaxName is the longest name kept, in bytes.
const MaxName = 128

// Clean makes a registered name safe to show (Rust: src/name.rs, clean): bytes that are not UTF-8 make the whole name read
// byte by byte (each byte above 0x7F becomes U+FFFD); control, invisible and direction-changing characters are dropped; runs
// of spaces (any kind) become one; no space at either end; at most MaxName bytes, cut at a character.
func Clean(raw []byte) string {
	var b strings.Builder
	space := false
	add := func(c rune) bool {
		if isSpace(c) {
			space = true
			return true
		}
		if isDropped(c) {
			return true
		}
		need := utf8.RuneLen(c)
		if space && b.Len() > 0 {
			need++
		}
		if b.Len()+need > MaxName {
			return false
		}
		if space && b.Len() > 0 {
			b.WriteByte(' ')
		}
		space = false
		b.WriteRune(c)
		return true
	}
	if utf8.Valid(raw) {
		for _, c := range string(raw) {
			if !add(c) {
				break
			}
		}
	} else {
		for _, x := range raw {
			c := rune(x)
			if x >= 0x80 {
				c = utf8.RuneError
			}
			if !add(c) {
				break
			}
		}
	}
	return b.String()
}

func isSpace(c rune) bool {
	switch {
	case c == ' ', c == '\t', c == '\n', c == 0x0b, c == 0x0c, c == '\r', c == 0xa0, c == 0x1680, c >= 0x2000 && c <= 0x200a,
		c == 0x2028, c == 0x2029, c == 0x202f, c == 0x205f, c == 0x3000:
		return true
	}
	return false
}

func isDropped(c rune) bool {
	switch {
	case c <= 0x1f, c >= 0x7f && c <= 0x9f, c == 0xad, c == 0x34f, c == 0x61c, c == 0x115f, c == 0x1160, c == 0x17b4, c == 0x17b5,
		c >= 0x180b && c <= 0x180f, c >= 0x200b && c <= 0x200f, c >= 0x202a && c <= 0x202e, c >= 0x2060 && c <= 0x206f, c == 0x3164,
		c >= 0xfe00 && c <= 0xfe0f, c == 0xfeff, c == 0xffa0, c >= 0xfff0 && c <= 0xfffb, c >= 0xe0000 && c <= 0xe0fff:
		return true
	}
	return false
}

// cuts are company endings cut from the short name, matched in any ASCII case, those ending in a letter as whole words only.
var cuts = []string{" co.,ltd", " co., ltd", " co.ltd", " co ltd", ",", " incorporated", " inc.", " inc", " corporation",
	" corporate", " corp.", " corp", " co.", " ltd.", " ltd", " llc", " gmbh", " ag", " s.a.", " b.v.", " pte", " pty",
	" limited", " technologies", " technology", " international"}

// Short is what people call a company (Rust: src/name.rs, short): a cleaned name in ASCII capitals only (more than 4 bytes)
// gets a capital per word, words of up to 3 bytes staying; company endings are cut and trailing dots, commas, dashes and
// spaces removed. Never empty for a non-empty name.
func Short(full string) string {
	s := []byte(full)
	if len(s) > 4 && hasASCII(s, 'A', 'Z') && !hasASCII(s, 'a', 'z') {
		start := 0
		for i := 0; i <= len(s); i++ {
			if i == len(s) || s[i] == ' ' {
				if i-start > 3 {
					for j := start + 1; j < i; j++ {
						if s[j] >= 'A' && s[j] <= 'Z' {
							s[j] += 'a' - 'A'
						}
					}
				}
				start = i + 1
			}
		}
	}
	for _, cut := range cuts {
		if i := findWord(s, []byte(cut)); i >= 0 {
			s = s[:i]
		}
	}
	for len(s) > 0 {
		switch s[len(s)-1] {
		case ' ', '.', ',', '-':
			s = s[:len(s)-1]
			continue
		}
		break
	}
	if len(s) == 0 {
		return full
	}
	return string(s)
}

func hasASCII(s []byte, lo, hi byte) bool {
	for _, c := range s {
		if c >= lo && c <= hi {
			return true
		}
	}
	return false
}

func isAlnum(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func lowerASCII(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + 'a' - 'A'
	}
	return c
}

func asciiEqualFold(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if lowerASCII(a[i]) != lowerASCII(b[i]) {
			return false
		}
	}
	return true
}

// findWord is the first place after the start where cut matches in any ASCII case and, when it ends in a letter or digit, is
// not followed by another; -1 if none.
func findWord(s, cut []byte) int {
	word := len(cut) > 0 && isAlnum(cut[len(cut)-1])
	for i := 1; i < len(s); i++ {
		if len(s)-i < len(cut) || !asciiEqualFold(s[i:i+len(cut)], cut) {
			continue
		}
		if word && i+len(cut) < len(s) && isAlnum(s[i+len(cut)]) {
			continue
		}
		return i
	}
	return -1
}
